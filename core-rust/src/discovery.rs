// Network Discovery Module - Advanced reconnaissance
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::collections::HashMap;
use std::time::Duration;
use pnet::packet::{
    arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    icmp::{IcmpTypes, IcmpPacket, MutableIcmpPacket, echo_request},
    icmpv6::{Icmpv6Types, Icmpv6Packet, MutableIcmpv6Packet},
    ip::{IpNextHeaderProtocols},
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    ipv6::{Ipv6Packet, MutableIpv6Packet},
    Packet,
};
use pnet::datalink::{self, NetworkInterface};
use pnet::transport::{icmp_packet_iter, icmpv6_packet_iter, transport_channel, TransportProtocol, TransportChannelType};
use pnet::util::MacAddr;
use tokio::time::{timeout, sleep};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct NetworkDiscovery {
    target_network: String,
    discovered_hosts: Arc<Mutex<Vec<HostInfo>>>,
    interface: Option<NetworkInterface>,
}

#[derive(Clone, Debug)]
pub struct HostInfo {
    pub ip: IpAddr,
    pub mac: Option<MacAddr>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub os_fingerprint: Option<String>,
    pub ports: Vec<u16>,
    pub services: HashMap<u16, String>,
}

static MAC_VENDORS: &[(&str, &str)] = &[
    ("00:00:5E", "IANA"),
    ("00:01:42", "Cisco"),
    ("00:03:93", "Apple"),
    ("00:04:AC", "IBM"),
    ("00:05:69", "VMware"),
    ("00:0C:29", "VMware"),
    ("00:0F:4B", "Oracle"),
    ("00:10:DB", "Juniper"),
    ("00:11:32", "Synology"),
    ("00:15:5D", "Microsoft Hyper-V"),
    ("00:16:3E", "Xen"),
    ("00:1B:21", "Intel"),
    ("00:1C:42", "Parallels"),
    ("00:1D:D8", "Microsoft"),
    ("00:25:AE", "Microsoft Xbox"),
    ("00:50:56", "VMware"),
    ("08:00:20", "Oracle/Sun"),
    ("08:00:27", "VirtualBox"),
    ("18:03:73", "Dell"),
    ("2C:F0:5D", "Amazon"),
    ("3C:5A:B4", "Google"),
    ("44:38:39", "Cumulus Networks"),
    ("52:54:00", "QEMU/KVM"),
    ("AC:1F:6B", "Super Micro"),
    ("B8:27:EB", "Raspberry Pi"),
    ("DC:A6:32", "Raspberry Pi"),
    ("E4:5F:01", "Raspberry Pi"),
];

impl NetworkDiscovery {
    pub fn new(network: &str) -> Self {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
            .clone();
            
        Self {
            target_network: network.to_string(),
            discovered_hosts: Arc::new(Mutex::new(Vec::new())),
            interface,
        }
    }

    pub async fn discover(&mut self) -> Result<Vec<HostInfo>, Box<dyn std::error::Error>> {
        println!("[*] Starting comprehensive network discovery on: {}", self.target_network);
        
        // Parse network range
        let hosts = self.parse_network_range()?;
        
        println!("[*] Scanning {} potential hosts...", hosts.len());
        
        // Run multiple discovery techniques in parallel
        let mut tasks = vec![];
        
        // ARP scan for local network
        if let Some(ref iface) = self.interface {
            println!("[*] Running ARP scan on interface: {}", iface.name);
            let arp_task = self.arp_scan(hosts.clone());
            tasks.push(arp_task);
        }
        
        // ICMP sweep
        println!("[*] Running ICMP sweep...");
        let icmp_task = self.icmp_sweep(hosts.clone());
        tasks.push(icmp_task);
        
        // IPv6 discovery
        println!("[*] Running IPv6 neighbor discovery...");
        let ipv6_task = self.ipv6_discovery();
        tasks.push(ipv6_task);
        
        // Wait for all tasks
        for task in tasks {
            task.await;
        }
        
        // Device fingerprinting
        self.fingerprint_devices().await;
        
        let hosts = self.discovered_hosts.lock().await;
        println!("[+] Discovery complete. Found {} hosts", hosts.len());
        
        Ok(hosts.clone())
    }
    
    fn parse_network_range(&self) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
        let mut hosts = Vec::new();
        
        // Parse CIDR notation (e.g., 192.168.1.0/24)
        if self.target_network.contains('/') {
            let parts: Vec<&str> = self.target_network.split('/').collect();
            if parts.len() != 2 {
                return Err("Invalid CIDR notation".into());
            }
            
            let base_ip: Ipv4Addr = parts[0].parse()?;
            let prefix_len: u32 = parts[1].parse()?;
            
            let mask = !((1 << (32 - prefix_len)) - 1);
            let network = u32::from(base_ip) & mask;
            let broadcast = network | !mask;
            
            for ip in (network + 1)..broadcast {
                hosts.push(IpAddr::V4(Ipv4Addr::from(ip)));
            }
        } else {
            // Single host
            hosts.push(self.target_network.parse()?);
        }
        
        Ok(hosts)
    }
    
    async fn arp_scan(&self, targets: Vec<IpAddr>) -> () {
        // ARP scan implementation
        for target in targets {
            if let IpAddr::V4(ipv4) = target {
                // Send ARP request
                if let Some(ref iface) = self.interface {
                    // In real implementation, would send actual ARP packets
                    // For now, using system ARP cache
                    if let Ok(output) = std::process::Command::new("arp")
                        .arg("-a")
                        .arg(ipv4.to_string())
                        .output() {
                        
                        let result = String::from_utf8_lossy(&output.stdout);
                        if !result.contains("no entry") && !result.contains("incomplete") {
                            // Parse MAC address from output
                            let mac = self.extract_mac_from_arp(&result);
                            
                            let mut hosts = self.discovered_hosts.lock().await;
                            hosts.push(HostInfo {
                                ip: target,
                                mac,
                                vendor: mac.and_then(|m| self.lookup_mac_vendor(m)),
                                hostname: self.reverse_dns_lookup(target).await,
                                os_fingerprint: None,
                                ports: Vec::new(),
                                services: HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
    }
    
    async fn icmp_sweep(&self, targets: Vec<IpAddr>) -> () {
        use std::process::Command;
        
        for target in targets {
            // Simple ping implementation
            let ping_cmd = if cfg!(target_os = "windows") {
                Command::new("ping")
                    .arg("-n")
                    .arg("1")
                    .arg("-w")
                    .arg("1000")
                    .arg(target.to_string())
                    .output()
            } else {
                Command::new("ping")
                    .arg("-c")
                    .arg("1")
                    .arg("-W")
                    .arg("1")
                    .arg(target.to_string())
                    .output()
            };
            
            if let Ok(output) = ping_cmd {
                if output.status.success() {
                    let mut hosts = self.discovered_hosts.lock().await;
                    
                    // Check if already discovered
                    if !hosts.iter().any(|h| h.ip == target) {
                        hosts.push(HostInfo {
                            ip: target,
                            mac: None,
                            vendor: None,
                            hostname: self.reverse_dns_lookup(target).await,
                            os_fingerprint: self.ttl_os_fingerprint(&output),
                            ports: Vec::new(),
                            services: HashMap::new(),
                        });
                    }
                }
            }
        }
    }
    
    async fn ipv6_discovery(&self) -> () {
        // IPv6 neighbor discovery using multicast
        use std::process::Command;
        
        // Send IPv6 neighbor discovery
        let output = if cfg!(target_os = "windows") {
            Command::new("netsh")
                .arg("interface")
                .arg("ipv6")
                .arg("show")
                .arg("neighbors")
                .output()
        } else {
            Command::new("ip")
                .arg("-6")
                .arg("neigh")
                .output()
        };
        
        if let Ok(output) = output {
            let result = String::from_utf8_lossy(&output.stdout);
            // Parse IPv6 neighbors
            for line in result.lines() {
                if let Some(ipv6) = self.extract_ipv6_from_line(line) {
                    let mut hosts = self.discovered_hosts.lock().await;
                    
                    if !hosts.iter().any(|h| h.ip == IpAddr::V6(ipv6)) {
                        hosts.push(HostInfo {
                            ip: IpAddr::V6(ipv6),
                            mac: self.extract_mac_from_neighbor(line),
                            vendor: None,
                            hostname: self.reverse_dns_lookup(IpAddr::V6(ipv6)).await,
                            os_fingerprint: None,
                            ports: Vec::new(),
                            services: HashMap::new(),
                        });
                    }
                }
            }
        }
    }
    
    async fn fingerprint_devices(&self) {
        let hosts = self.discovered_hosts.lock().await.clone();
        
        for host in hosts {
            // TCP/IP stack fingerprinting
            let fingerprint = self.tcp_fingerprint(&host.ip).await;
            
            let mut hosts_mut = self.discovered_hosts.lock().await;
            if let Some(h) = hosts_mut.iter_mut().find(|h| h.ip == host.ip) {
                h.os_fingerprint = fingerprint;
            }
        }
    }
    
    async fn tcp_fingerprint(&self, ip: &IpAddr) -> Option<String> {
        // TCP/IP stack fingerprinting based on responses
        // This is simplified - real implementation would analyze TCP options, window sizes, etc.
        use std::net::{TcpStream, SocketAddr};
        use std::time::Duration;
        
        let ports = [22, 80, 443, 445, 3389]; // Common ports for fingerprinting
        let mut signatures = Vec::new();
        
        for port in &ports {
            let addr = SocketAddr::new(*ip, *port);
            match TcpStream::connect_timeout(&addr, Duration::from_millis(100)) {
                Ok(stream) => {
                    signatures.push(format!("{}:open", port));
                    drop(stream);
                },
                Err(_) => signatures.push(format!("{}:closed", port)),
            }
        }
        
        // Match signatures to known OS patterns
        let signature = signatures.join(",");
        
        if signature.contains("22:open") && signature.contains("80:open") {
            Some("Linux/Unix".to_string())
        } else if signature.contains("445:open") && signature.contains("3389:open") {
            Some("Windows".to_string())
        } else if signature.contains("22:open") {
            Some("Linux/Unix/Network Device".to_string())
        } else {
            None
        }
    }
    
    fn ttl_os_fingerprint(&self, ping_output: &std::process::Output) -> Option<String> {
        let output = String::from_utf8_lossy(&ping_output.stdout);
        
        // Extract TTL value
        if let Some(ttl) = self.extract_ttl(&output) {
            // OS fingerprinting based on default TTL values
            match ttl {
                64 => Some("Linux/Unix/macOS".to_string()),
                128 => Some("Windows".to_string()),
                255 => Some("Cisco/Network Device".to_string()),
                _ if ttl <= 64 => Some("Linux/Unix (hops: {})".to_string()),
                _ if ttl <= 128 => Some("Windows (hops: {})".to_string()),
                _ => None,
            }
        } else {
            None
        }
    }
    
    fn extract_ttl(&self, output: &str) -> Option<u8> {
        // Extract TTL from ping output
        if let Some(pos) = output.find("TTL=") {
            let ttl_str = &output[pos+4..];
            if let Some(end) = ttl_str.find(|c: char| !c.is_ascii_digit()) {
                ttl_str[..end].parse().ok()
            } else {
                None
            }
        } else if let Some(pos) = output.find("ttl=") {
            let ttl_str = &output[pos+4..];
            if let Some(end) = ttl_str.find(|c: char| !c.is_ascii_digit()) {
                ttl_str[..end].parse().ok()
            } else {
                None
            }
        } else {
            None
        }
    }
    
    fn extract_mac_from_arp(&self, arp_output: &str) -> Option<MacAddr> {
        // Parse MAC address from arp command output
        // Format varies by OS
        for part in arp_output.split_whitespace() {
            if part.contains(':') || part.contains('-') {
                // Try to parse as MAC address
                let normalized = part.replace('-', ":");
                if let Ok(mac) = normalized.parse::<MacAddr>() {
                    return Some(mac);
                }
            }
        }
        None
    }
    
    fn extract_mac_from_neighbor(&self, line: &str) -> Option<MacAddr> {
        // Extract MAC from ip neighbor output
        for part in line.split_whitespace() {
            if part.contains(':') && part.len() == 17 {
                if let Ok(mac) = part.parse::<MacAddr>() {
                    return Some(mac);
                }
            }
        }
        None
    }
    
    fn extract_ipv6_from_line(&self, line: &str) -> Option<Ipv6Addr> {
        // Extract IPv6 address from line
        for part in line.split_whitespace() {
            if part.contains(':') && !part.contains('.') {
                if let Ok(ipv6) = part.parse::<Ipv6Addr>() {
                    return Some(ipv6);
                }
            }
        }
        None
    }
    
    fn lookup_mac_vendor(&self, mac: MacAddr) -> Option<String> {
        let mac_str = mac.to_string().to_uppercase();
        let prefix = &mac_str[..8]; // First 3 octets
        
        for (oui, vendor) in MAC_VENDORS {
            if prefix.starts_with(oui) {
                return Some(vendor.to_string());
            }
        }
        None
    }
    
    async fn reverse_dns_lookup(&self, ip: IpAddr) -> Option<String> {
        use tokio::net::lookup_host;
        
        match dns_lookup::lookup_addr(&ip) {
            Ok(hostname) => Some(hostname),
            Err(_) => None,
        }
    }
    
    pub async fn display_results(&self) {
        let hosts = self.discovered_hosts.lock().await;
        
        println!("\n╔═══════════════════════════════════════════════════════╗");
        println!("║          NETWORK DISCOVERY RESULTS                     ║");
        println!("╚═══════════════════════════════════════════════════════╝\n");
        
        for host in hosts.iter() {
            println!("[+] Host: {}", host.ip);
            if let Some(mac) = &host.mac {
                println!("    MAC: {}", mac);
            }
            if let Some(vendor) = &host.vendor {
                println!("    Vendor: {}", vendor);
            }
            if let Some(hostname) = &host.hostname {
                println!("    Hostname: {}", hostname);
            }
            if let Some(os) = &host.os_fingerprint {
                println!("    OS: {}", os);
            }
            println!();
        }
        
        println!("Total hosts discovered: {}", hosts.len());
    }
}
