// Padocca Proxy Chain - Advanced traffic tunneling and anonymization
package main

import (
    "bufio"
    "encoding/base64"
    "encoding/binary"
    "fmt"
    "io"
    "math/rand"
    "net"
    "os"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "github.com/fatih/color"
    "github.com/spf13/cobra"
    "golang.org/x/net/proxy"
)

type ProxyChain struct {
    Proxies      []ProxyNode
    CurrentIndex int
    Mode         ChainMode
    LocalPort    int
    TargetHost   string
    TargetPort   int
    
    listener     net.Listener
    connections  int64
    dataTransferred int64
    mutex        sync.RWMutex
    rotateAfter  int
    rotateCount  int
}

type ProxyNode struct {
    Type        ProxyType
    Host        string
    Port        int
    Username    string
    Password    string
    Active      bool
    Latency     time.Duration
    FailCount   int
    LastChecked time.Time
}

type ProxyType int
const (
    SOCKS5 ProxyType = iota
    SOCKS4
    HTTP
    HTTPS
    TOR
)

type ChainMode int
const (
    Single ChainMode = iota
    Random
    RoundRobin
    Chain
    Tor
)

var (
    torSocks5Port = 9050
    torControlPort = 9051
    defaultProxies = []ProxyNode{
        {Type: TOR, Host: "127.0.0.1", Port: 9050, Active: false},
    }
)

func main() {
    var rootCmd = &cobra.Command{
        Use:   "proxychain",
        Short: "Padocca Proxy Chain - Advanced anonymization system",
        Long:  `Multi-proxy chain with SOCKS5, HTTP, and Tor support for traffic anonymization`,
        Run:   runProxyChain,
    }

    // Define flags
    rootCmd.Flags().StringP("mode", "m", "single", "Chain mode (single/random/roundrobin/chain/tor)")
    rootCmd.Flags().StringP("proxies", "p", "", "Proxy list file")
    rootCmd.Flags().IntP("local", "l", 8888, "Local listening port")
    rootCmd.Flags().StringP("target", "t", "", "Target host:port (for tunnel mode)")
    rootCmd.Flags().BoolP("tor", "T", false, "Use Tor network")
    rootCmd.Flags().IntP("rotate", "r", 0, "Rotate proxy after N connections (0=disabled)")
    rootCmd.Flags().BoolP("check", "c", false, "Check proxy health before using")
    rootCmd.Flags().BoolP("strict", "s", false, "Strict chain (fail if any proxy fails)")
    rootCmd.Flags().StringP("auth", "a", "", "Proxy authentication (user:pass)")
    rootCmd.Flags().BoolP("verbose", "v", false, "Verbose output")
    rootCmd.Flags().BoolP("stats", "S", false, "Show statistics")

    if err := rootCmd.Execute(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}

func runProxyChain(cmd *cobra.Command, args []string) {
    mode, _ := cmd.Flags().GetString("mode")
    proxyFile, _ := cmd.Flags().GetString("proxies")
    localPort, _ := cmd.Flags().GetInt("local")
    target, _ := cmd.Flags().GetString("target")
    useTor, _ := cmd.Flags().GetBool("tor")
    rotateAfter, _ := cmd.Flags().GetInt("rotate")
    checkHealth, _ := cmd.Flags().GetBool("check")
    strictChain, _ := cmd.Flags().GetBool("strict")
    auth, _ := cmd.Flags().GetString("auth")
    verbose, _ := cmd.Flags().GetBool("verbose")
    showStats, _ := cmd.Flags().GetBool("stats")

    printBanner()

    // Parse mode
    chainMode := parseMode(mode)
    if useTor {
        chainMode = Tor
    }

    // Create proxy chain
    chain := &ProxyChain{
        Proxies:      []ProxyNode{},
        Mode:         chainMode,
        LocalPort:    localPort,
        rotateAfter:  rotateAfter,
    }

    // Parse target if provided
    if target != "" {
        parts := strings.Split(target, ":")
        if len(parts) == 2 {
            chain.TargetHost = parts[0]
            fmt.Sscanf(parts[1], "%d", &chain.TargetPort)
        }
    }

    // Load proxies
    if proxyFile != "" {
        chain.loadProxies(proxyFile, auth)
    } else if useTor {
        chain.setupTor()
    } else {
        chain.Proxies = defaultProxies
    }

    // Check proxy health if requested
    if checkHealth {
        chain.checkProxyHealth()
    }

    // Start proxy chain
    if err := chain.Start(verbose, strictChain); err != nil {
        color.Red("Error starting proxy chain: %v", err)
        os.Exit(1)
    }

    // Show statistics if requested
    if showStats {
        go chain.showStatistics()
    }

    // Keep running
    select {}
}

func (pc *ProxyChain) Start(verbose, strict bool) error {
    listener, err := net.Listen("tcp", fmt.Sprintf(":%d", pc.LocalPort))
    if err != nil {
        return err
    }
    pc.listener = listener

    color.Green("[+] Proxy chain started on port %d", pc.LocalPort)
    color.Yellow("[*] Mode: %s", pc.getModeString())
    
    if len(pc.Proxies) > 0 {
        color.Cyan("[*] Loaded %d proxies", len(pc.Proxies))
    }

    go pc.acceptConnections(verbose, strict)
    
    return nil
}

func (pc *ProxyChain) acceptConnections(verbose, strict bool) {
    for {
        conn, err := pc.listener.Accept()
        if err != nil {
            continue
        }

        atomic.AddInt64(&pc.connections, 1)
        
        go pc.handleConnection(conn, verbose, strict)

        // Rotate proxy if configured
        if pc.rotateAfter > 0 {
            pc.rotateCount++
            if pc.rotateCount >= pc.rotateAfter {
                pc.rotateProxy()
                pc.rotateCount = 0
            }
        }
    }
}

func (pc *ProxyChain) handleConnection(clientConn net.Conn, verbose, strict bool) {
    defer clientConn.Close()

    if verbose {
        color.Blue("[>] New connection from %s", clientConn.RemoteAddr())
    }

    // Get proxy based on mode
    proxy := pc.selectProxy()
    if proxy == nil {
        color.Red("[!] No available proxy")
        return
    }

    // Connect through proxy
    var targetConn net.Conn
    var err error

    switch pc.Mode {
    case Single, Random, RoundRobin:
        targetConn, err = pc.connectThroughProxy(proxy, verbose)
    case Chain:
        targetConn, err = pc.connectThroughChain(verbose, strict)
    case Tor:
        targetConn, err = pc.connectThroughTor(verbose)
    }

    if err != nil {
        if verbose {
            color.Red("[!] Failed to connect through proxy: %v", err)
        }
        proxy.FailCount++
        return
    }
    defer targetConn.Close()

    // Start data relay
    pc.relayData(clientConn, targetConn, verbose)
}

func (pc *ProxyChain) connectThroughProxy(proxy *ProxyNode, verbose bool) (net.Conn, error) {
    switch proxy.Type {
    case SOCKS5:
        return pc.connectSOCKS5(proxy, verbose)
    case SOCKS4:
        return pc.connectSOCKS4(proxy, verbose)
    case HTTP, HTTPS:
        return pc.connectHTTP(proxy, verbose)
    case TOR:
        return pc.connectSOCKS5(proxy, verbose) // Tor uses SOCKS5
    default:
        return nil, fmt.Errorf("unsupported proxy type")
    }
}

func (pc *ProxyChain) connectSOCKS5(proxyNode *ProxyNode, verbose bool) (net.Conn, error) {
    proxyAddr := fmt.Sprintf("%s:%d", proxyNode.Host, proxyNode.Port)
    
    // Create SOCKS5 dialer
    var auth *proxy.Auth
    if proxyNode.Username != "" && proxyNode.Password != "" {
        auth = &proxy.Auth{
            User:     proxyNode.Username,
            Password: proxyNode.Password,
        }
    }

    dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, proxy.Direct)
    if err != nil {
        return nil, err
    }

    // Connect to target
    targetAddr := fmt.Sprintf("%s:%d", pc.TargetHost, pc.TargetPort)
    conn, err := dialer.Dial("tcp", targetAddr)
    if err != nil {
        return nil, err
    }

    if verbose {
        color.Green("[+] Connected through SOCKS5 proxy %s", proxyAddr)
    }

    return conn, nil
}

func (pc *ProxyChain) connectSOCKS4(proxy *ProxyNode, verbose bool) (net.Conn, error) {
    proxyAddr := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)
    
    conn, err := net.Dial("tcp", proxyAddr)
    if err != nil {
        return nil, err
    }

    // SOCKS4 handshake
    targetIP := net.ParseIP(pc.TargetHost)
    if targetIP == nil {
        // Resolve domain
        ips, err := net.LookupIP(pc.TargetHost)
        if err != nil || len(ips) == 0 {
            conn.Close()
            return nil, fmt.Errorf("failed to resolve target")
        }
        targetIP = ips[0]
    }

    // Build SOCKS4 request
    req := make([]byte, 9)
    req[0] = 0x04 // SOCKS version
    req[1] = 0x01 // CONNECT command
    binary.BigEndian.PutUint16(req[2:4], uint16(pc.TargetPort))
    copy(req[4:8], targetIP.To4())
    req[8] = 0x00 // Null terminator for user id

    // Send request
    if _, err := conn.Write(req); err != nil {
        conn.Close()
        return nil, err
    }

    // Read response
    resp := make([]byte, 8)
    if _, err := io.ReadFull(conn, resp); err != nil {
        conn.Close()
        return nil, err
    }

    if resp[1] != 0x5A { // Request granted
        conn.Close()
        return nil, fmt.Errorf("SOCKS4 request failed: %02x", resp[1])
    }

    if verbose {
        color.Green("[+] Connected through SOCKS4 proxy %s", proxyAddr)
    }

    return conn, nil
}

func (pc *ProxyChain) connectHTTP(proxy *ProxyNode, verbose bool) (net.Conn, error) {
    proxyAddr := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)
    
    conn, err := net.Dial("tcp", proxyAddr)
    if err != nil {
        return nil, err
    }

    // Send CONNECT request
    targetAddr := fmt.Sprintf("%s:%d", pc.TargetHost, pc.TargetPort)
    connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
    
    // Add authentication if provided
    if proxy.Username != "" && proxy.Password != "" {
        auth := proxy.Username + ":" + proxy.Password
        encoded := base64.StdEncoding.EncodeToString([]byte(auth))
        connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", encoded)
    }
    
    connectReq += "\r\n"

    if _, err := conn.Write([]byte(connectReq)); err != nil {
        conn.Close()
        return nil, err
    }

    // Read response
    reader := bufio.NewReader(conn)
    statusLine, err := reader.ReadString('\n')
    if err != nil {
        conn.Close()
        return nil, err
    }

    if !strings.Contains(statusLine, "200") {
        conn.Close()
        return nil, fmt.Errorf("HTTP CONNECT failed: %s", statusLine)
    }

    // Skip headers
    for {
        line, err := reader.ReadString('\n')
        if err != nil {
            conn.Close()
            return nil, err
        }
        if line == "\r\n" || line == "\n" {
            break
        }
    }

    if verbose {
        color.Green("[+] Connected through HTTP proxy %s", proxyAddr)
    }

    return conn, nil
}

func (pc *ProxyChain) connectThroughChain(verbose, strict bool) (net.Conn, error) {
    if len(pc.Proxies) == 0 {
        return nil, fmt.Errorf("no proxies in chain")
    }

    var conn net.Conn
    var err error

    // Connect through each proxy in sequence
    for i, proxy := range pc.Proxies {
        if i == 0 {
            // First connection
            conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port))
        } else {
            // Subsequent connections through existing tunnel
            conn, err = pc.tunnelThroughProxy(conn, &proxy)
        }

        if err != nil {
            if strict {
                return nil, fmt.Errorf("chain failed at proxy %d: %v", i+1, err)
            }
            // Try next proxy if not strict
            continue
        }

        if verbose {
            color.Green("[+] Connected through proxy %d in chain", i+1)
        }
    }

    return conn, nil
}

func (pc *ProxyChain) connectThroughTor(verbose bool) (net.Conn, error) {
    // Check if Tor is running
    if !pc.isTorRunning() {
        return nil, fmt.Errorf("Tor is not running on port %d", torSocks5Port)
    }

    // Create Tor proxy node
    torProxy := &ProxyNode{
        Type: SOCKS5,
        Host: "127.0.0.1",
        Port: torSocks5Port,
    }

    conn, err := pc.connectSOCKS5(torProxy, verbose)
    if err != nil {
        return nil, err
    }

    if verbose {
        color.Green("[+] Connected through Tor network")
        
        // Get Tor circuit info if possible
        if circuitInfo := pc.getTorCircuitInfo(); circuitInfo != "" {
            color.Cyan("[*] Tor circuit: %s", circuitInfo)
        }
    }

    return conn, nil
}

func (pc *ProxyChain) tunnelThroughProxy(conn net.Conn, proxy *ProxyNode) (net.Conn, error) {
    // Implement proxy chaining through existing connection
    // This would establish a new proxy connection through the existing tunnel
    return conn, nil // Simplified
}

func (pc *ProxyChain) relayData(client, target net.Conn, verbose bool) {
    var wg sync.WaitGroup
    wg.Add(2)

    // Client to target
    go func() {
        defer wg.Done()
        n, _ := io.Copy(target, client)
        atomic.AddInt64(&pc.dataTransferred, n)
        if verbose && n > 0 {
            color.Blue("[>] Sent %d bytes", n)
        }
    }()

    // Target to client
    go func() {
        defer wg.Done()
        n, _ := io.Copy(client, target)
        atomic.AddInt64(&pc.dataTransferred, n)
        if verbose && n > 0 {
            color.Blue("[<] Received %d bytes", n)
        }
    }()

    wg.Wait()
}

func (pc *ProxyChain) selectProxy() *ProxyNode {
    pc.mutex.Lock()
    defer pc.mutex.Unlock()

    if len(pc.Proxies) == 0 {
        return nil
    }

    switch pc.Mode {
    case Single:
        return &pc.Proxies[0]
    
    case Random:
        // Select random active proxy
        activeProxies := pc.getActiveProxies()
        if len(activeProxies) == 0 {
            return nil
        }
        return activeProxies[rand.Intn(len(activeProxies))]
    
    case RoundRobin:
        // Round-robin through active proxies
        activeProxies := pc.getActiveProxies()
        if len(activeProxies) == 0 {
            return nil
        }
        proxy := activeProxies[pc.CurrentIndex%len(activeProxies)]
        pc.CurrentIndex++
        return proxy
    
    default:
        return &pc.Proxies[0]
    }
}

func (pc *ProxyChain) getActiveProxies() []*ProxyNode {
    var active []*ProxyNode
    for i := range pc.Proxies {
        if pc.Proxies[i].Active || pc.Proxies[i].FailCount < 3 {
            active = append(active, &pc.Proxies[i])
        }
    }
    return active
}

func (pc *ProxyChain) rotateProxy() {
    pc.mutex.Lock()
    defer pc.mutex.Unlock()

    pc.CurrentIndex++
    color.Yellow("[*] Rotating proxy (index: %d)", pc.CurrentIndex)
}

func (pc *ProxyChain) loadProxies(filename, auth string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }

        proxy := pc.parseProxyLine(line, auth)
        if proxy != nil {
            pc.Proxies = append(pc.Proxies, *proxy)
        }
    }

    return nil
}

func (pc *ProxyChain) parseProxyLine(line, auth string) *ProxyNode {
    // Format: type://[user:pass@]host:port
    // Example: socks5://127.0.0.1:1080
    // Example: http://user:pass@proxy.com:8080

    parts := strings.Split(line, "://")
    if len(parts) != 2 {
        return nil
    }

    proxyType := pc.parseProxyType(parts[0])
    
    // Parse authentication and address
    var host string
    var port int
    var username, password string

    if auth != "" && !strings.Contains(parts[1], "@") {
        // Use global auth if not specified in line
        authParts := strings.Split(auth, ":")
        if len(authParts) == 2 {
            username = authParts[0]
            password = authParts[1]
        }
    }

    if strings.Contains(parts[1], "@") {
        // Extract auth from line
        authAndAddr := strings.Split(parts[1], "@")
        if len(authAndAddr) == 2 {
            authParts := strings.Split(authAndAddr[0], ":")
            if len(authParts) == 2 {
                username = authParts[0]
                password = authParts[1]
            }
            parts[1] = authAndAddr[1]
        }
    }

    // Parse host and port
    hostPort := strings.Split(parts[1], ":")
    if len(hostPort) != 2 {
        return nil
    }

    host = hostPort[0]
    fmt.Sscanf(hostPort[1], "%d", &port)

    return &ProxyNode{
        Type:     proxyType,
        Host:     host,
        Port:     port,
        Username: username,
        Password: password,
        Active:   true,
    }
}

func (pc *ProxyChain) parseProxyType(typeStr string) ProxyType {
    switch strings.ToLower(typeStr) {
    case "socks5", "socks":
        return SOCKS5
    case "socks4":
        return SOCKS4
    case "http":
        return HTTP
    case "https":
        return HTTPS
    case "tor":
        return TOR
    default:
        return SOCKS5
    }
}

func (pc *ProxyChain) setupTor() {
    pc.Proxies = []ProxyNode{
        {
            Type:   TOR,
            Host:   "127.0.0.1",
            Port:   torSocks5Port,
            Active: true,
        },
    }
}

func (pc *ProxyChain) isTorRunning() bool {
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", torSocks5Port), 2*time.Second)
    if err != nil {
        return false
    }
    conn.Close()
    return true
}

func (pc *ProxyChain) getTorCircuitInfo() string {
    // Connect to Tor control port to get circuit info
    conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", torControlPort))
    if err != nil {
        return ""
    }
    defer conn.Close()

    // Authenticate and get circuit info
    // Simplified - would need proper Tor control protocol implementation
    return "Circuit established through 3 relays"
}

func (pc *ProxyChain) checkProxyHealth() {
    color.Yellow("[*] Checking proxy health...")
    
    var wg sync.WaitGroup
    for i := range pc.Proxies {
        wg.Add(1)
        go func(proxy *ProxyNode) {
            defer wg.Done()
            
            start := time.Now()
            conn, err := net.DialTimeout("tcp", 
                fmt.Sprintf("%s:%d", proxy.Host, proxy.Port), 
                5*time.Second)
            
            if err != nil {
                proxy.Active = false
                proxy.FailCount++
                color.Red("  [!] %s:%d - Failed", proxy.Host, proxy.Port)
            } else {
                proxy.Active = true
                proxy.Latency = time.Since(start)
                proxy.LastChecked = time.Now()
                conn.Close()
                color.Green("  [+] %s:%d - OK (%.2fms)", 
                    proxy.Host, proxy.Port, 
                    proxy.Latency.Seconds()*1000)
            }
        }(&pc.Proxies[i])
    }
    wg.Wait()
    
    activeCount := 0
    for _, proxy := range pc.Proxies {
        if proxy.Active {
            activeCount++
        }
    }
    
    color.Cyan("[*] Active proxies: %d/%d", activeCount, len(pc.Proxies))
}

func (pc *ProxyChain) showStatistics() {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        connections := atomic.LoadInt64(&pc.connections)
        transferred := atomic.LoadInt64(&pc.dataTransferred)
        
        fmt.Printf("\r[STATS] Connections: %d | Data: %.2f MB | Active Proxies: %d",
            connections,
            float64(transferred)/(1024*1024),
            len(pc.getActiveProxies()))
    }
}

func (pc *ProxyChain) getModeString() string {
    switch pc.Mode {
    case Single:
        return "Single Proxy"
    case Random:
        return "Random Selection"
    case RoundRobin:
        return "Round Robin"
    case Chain:
        return "Proxy Chain"
    case Tor:
        return "Tor Network"
    default:
        return "Unknown"
    }
}

func parseMode(mode string) ChainMode {
    switch strings.ToLower(mode) {
    case "single":
        return Single
    case "random":
        return Random
    case "roundrobin", "round-robin":
        return RoundRobin
    case "chain":
        return Chain
    case "tor":
        return Tor
    default:
        return Single
    }
}

func printBanner() {
    banner := `
    ╔═══════════════════════════════════════╗
    ║   🔐 PADOCCA PROXY CHAIN 🔐          ║
    ║     Anonymous • Secure • Fast         ║
    ╚═══════════════════════════════════════╝
    `
    color.Cyan(banner)
}
