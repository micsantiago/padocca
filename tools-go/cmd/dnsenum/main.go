// Padocca DNS Enumeration Module - Advanced DNS reconnaissance
package main

import (
    "bufio"
    "context"
    "fmt"
    "net"
    "os"
    "strings"
    "sync"
    "time"

    "github.com/fatih/color"
    "github.com/miekg/dns"
    "github.com/schollz/progressbar/v3"
    "github.com/spf13/cobra"
    "golang.org/x/sync/semaphore"
)

type DNSEnumerator struct {
    Domain      string
    Wordlist    []string
    Resolvers   []string
    Workers     int64
    Timeout     time.Duration
    
    sem         *semaphore.Weighted
    results     []DNSResult
    mutex       sync.Mutex
    totalChecked int64
}

type DNSResult struct {
    Subdomain   string
    Type        string
    Records     []string
    Timestamp   time.Time
}

func main() {
    var rootCmd = &cobra.Command{
        Use:   "dnsenum",
        Short: "Padocca DNS Enumerator - Advanced DNS reconnaissance",
        Long:  `Comprehensive DNS enumeration including subdomains, zone transfers, and record discovery`,
        Run:   runDNSEnum,
    }

    // Define flags
    rootCmd.Flags().StringP("domain", "d", "", "Target domain (required)")
    rootCmd.Flags().StringP("wordlist", "w", "", "Subdomain wordlist file")
    rootCmd.Flags().StringP("resolvers", "r", "", "Custom DNS resolvers file")
    rootCmd.Flags().IntP("workers", "t", 20, "Number of concurrent workers")
    rootCmd.Flags().IntP("timeout", "T", 2, "DNS query timeout in seconds")
    rootCmd.Flags().BoolP("zone", "z", true, "Attempt zone transfer")
    rootCmd.Flags().BoolP("reverse", "R", true, "Reverse DNS lookup")
    rootCmd.Flags().BoolP("brute", "b", true, "Brute force subdomains")
    rootCmd.Flags().StringP("output", "o", "", "Output file for results")
    rootCmd.Flags().BoolP("json", "j", false, "Output in JSON format")
    
    rootCmd.MarkFlagRequired("domain")

    if err := rootCmd.Execute(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}

func runDNSEnum(cmd *cobra.Command, args []string) {
    domain, _ := cmd.Flags().GetString("domain")
    wordlistFile, _ := cmd.Flags().GetString("wordlist")
    resolversFile, _ := cmd.Flags().GetString("resolvers")
    workers, _ := cmd.Flags().GetInt("workers")
    timeout, _ := cmd.Flags().GetInt("timeout")
    attemptZone, _ := cmd.Flags().GetBool("zone")
    doReverse, _ := cmd.Flags().GetBool("reverse")
    doBrute, _ := cmd.Flags().GetBool("brute")
    outputFile, _ := cmd.Flags().GetString("output")
    jsonOutput, _ := cmd.Flags().GetBool("json")

    printBanner()

    // Load wordlist
    var wordlist []string
    if wordlistFile != "" {
        wordlist = loadWordlist(wordlistFile)
    } else {
        wordlist = getDefaultSubdomains()
    }

    // Load resolvers
    var resolvers []string
    if resolversFile != "" {
        resolvers = loadWordlist(resolversFile)
    } else {
        resolvers = getDefaultResolvers()
    }

    enum := &DNSEnumerator{
        Domain:    domain,
        Wordlist:  wordlist,
        Resolvers: resolvers,
        Workers:   int64(workers),
        Timeout:   time.Duration(timeout) * time.Second,
        sem:       semaphore.NewWeighted(int64(workers)),
        results:   []DNSResult{},
    }

    color.Cyan("🔍 Starting DNS enumeration for: %s", domain)
    fmt.Println()

    // Basic DNS records
    enum.queryBasicRecords()
    
    // Zone transfer attempt
    if attemptZone {
        enum.attemptZoneTransfer()
    }
    
    // Subdomain brute force
    if doBrute {
        enum.bruteForceSubdomains()
    }
    
    // Reverse DNS
    if doReverse {
        enum.reverseDNSLookup()
    }

    // Display results
    enum.displayResults(jsonOutput)

    // Save results if requested
    if outputFile != "" {
        enum.saveResults(outputFile, jsonOutput)
    }
}

func (e *DNSEnumerator) queryBasicRecords() {
    color.Yellow("📋 Querying basic DNS records...")
    
    recordTypes := []uint16{
        dns.TypeA,
        dns.TypeAAAA,
        dns.TypeMX,
        dns.TypeNS,
        dns.TypeTXT,
        dns.TypeSOA,
        dns.TypeCNAME,
        dns.TypeSRV,
        dns.TypeCAA,
    }
    
    recordNames := map[uint16]string{
        dns.TypeA:     "A",
        dns.TypeAAAA:  "AAAA",
        dns.TypeMX:    "MX",
        dns.TypeNS:    "NS",
        dns.TypeTXT:   "TXT",
        dns.TypeSOA:   "SOA",
        dns.TypeCNAME: "CNAME",
        dns.TypeSRV:   "SRV",
        dns.TypeCAA:   "CAA",
    }
    
    for _, recordType := range recordTypes {
        records := e.queryDNS(e.Domain, recordType)
        if len(records) > 0 {
            e.mutex.Lock()
            e.results = append(e.results, DNSResult{
                Subdomain: e.Domain,
                Type:      recordNames[recordType],
                Records:   records,
                Timestamp: time.Now(),
            })
            e.mutex.Unlock()
            
            color.Green("[+] %s records:", recordNames[recordType])
            for _, record := range records {
                fmt.Printf("    %s\n", record)
            }
        }
    }
}

func (e *DNSEnumerator) attemptZoneTransfer() {
    color.Yellow("\n🔄 Attempting zone transfer...")
    
    // Get NS records first
    nsRecords := e.queryDNS(e.Domain, dns.TypeNS)
    
    for _, ns := range nsRecords {
        ns = strings.TrimSuffix(ns, ".")
        color.Cyan("  Trying AXFR on %s", ns)
        
        transfer := &dns.Transfer{}
        msg := &dns.Msg{}
        msg.SetAxfr(e.Domain)
        
        conn, err := net.DialTimeout("tcp", ns+":53", e.Timeout)
        if err != nil {
            continue
        }
        defer conn.Close()
        
        channel, err := transfer.In(msg, ns+":53")
        if err != nil {
            continue
        }
        
        color.Green("[+] Zone transfer successful on %s!", ns)
        
        for envelope := range channel {
            if envelope.Error != nil {
                break
            }
            
            for _, rr := range envelope.RR {
                e.mutex.Lock()
                e.results = append(e.results, DNSResult{
                    Subdomain: rr.Header().Name,
                    Type:      dns.TypeToString[rr.Header().Rrtype],
                    Records:   []string{rr.String()},
                    Timestamp: time.Now(),
                })
                e.mutex.Unlock()
                fmt.Printf("    %s\n", rr.String())
            }
        }
    }
}

func (e *DNSEnumerator) bruteForceSubdomains() {
    color.Yellow("\n🔨 Brute forcing subdomains...")
    
    bar := progressbar.Default(int64(len(e.Wordlist)))
    var wg sync.WaitGroup
    ctx := context.Background()
    
    for _, subdomain := range e.Wordlist {
        wg.Add(1)
        e.sem.Acquire(ctx, 1)
        
        go func(sub string) {
            defer wg.Done()
            defer e.sem.Release(1)
            defer bar.Add(1)
            
            target := sub + "." + e.Domain
            records := e.queryDNS(target, dns.TypeA)
            
            if len(records) > 0 {
                e.mutex.Lock()
                e.results = append(e.results, DNSResult{
                    Subdomain: target,
                    Type:      "A",
                    Records:   records,
                    Timestamp: time.Now(),
                })
                e.mutex.Unlock()
                
                color.Green("\n[+] Found: %s -> %s", target, strings.Join(records, ", "))
            }
        }(subdomain)
    }
    
    wg.Wait()
    bar.Finish()
}

func (e *DNSEnumerator) reverseDNSLookup() {
    color.Yellow("\n🔄 Performing reverse DNS lookups...")
    
    // Get A records for the domain
    aRecords := e.queryDNS(e.Domain, dns.TypeA)
    
    for _, ip := range aRecords {
        names, err := net.LookupAddr(ip)
        if err != nil {
            continue
        }
        
        if len(names) > 0 {
            color.Green("[+] Reverse DNS for %s:", ip)
            for _, name := range names {
                fmt.Printf("    %s\n", name)
            }
        }
    }
}

func (e *DNSEnumerator) queryDNS(domain string, recordType uint16) []string {
    var results []string
    
    c := new(dns.Client)
    c.Timeout = e.Timeout
    
    m := new(dns.Msg)
    m.SetQuestion(dns.Fqdn(domain), recordType)
    m.RecursionDesired = true
    
    for _, resolver := range e.Resolvers {
        r, _, err := c.Exchange(m, resolver+":53")
        if err != nil {
            continue
        }
        
        for _, answer := range r.Answer {
            switch recordType {
            case dns.TypeA:
                if a, ok := answer.(*dns.A); ok {
                    results = append(results, a.A.String())
                }
            case dns.TypeAAAA:
                if aaaa, ok := answer.(*dns.AAAA); ok {
                    results = append(results, aaaa.AAAA.String())
                }
            case dns.TypeMX:
                if mx, ok := answer.(*dns.MX); ok {
                    results = append(results, fmt.Sprintf("%d %s", mx.Preference, mx.Mx))
                }
            case dns.TypeNS:
                if ns, ok := answer.(*dns.NS); ok {
                    results = append(results, ns.Ns)
                }
            case dns.TypeTXT:
                if txt, ok := answer.(*dns.TXT); ok {
                    results = append(results, strings.Join(txt.Txt, " "))
                }
            case dns.TypeCNAME:
                if cname, ok := answer.(*dns.CNAME); ok {
                    results = append(results, cname.Target)
                }
            default:
                results = append(results, answer.String())
            }
        }
        
        if len(results) > 0 {
            break
        }
    }
    
    return results
}

func (e *DNSEnumerator) displayResults(jsonOutput bool) {
    fmt.Println()
    color.Yellow("═══════════════════════════════════════════════════════")
    color.Cyan("                 DNS ENUMERATION RESULTS                ")
    color.Yellow("═══════════════════════════════════════════════════════")
    
    if jsonOutput {
        // JSON output implementation
        fmt.Printf("\n{\"domain\":\"%s\",\"results\":[\n", e.Domain)
        for i, result := range e.results {
            fmt.Printf("  {\"subdomain\":\"%s\",\"type\":\"%s\",\"records\":%q}",
                result.Subdomain, result.Type, result.Records)
            if i < len(e.results)-1 {
                fmt.Print(",")
            }
            fmt.Println()
        }
        fmt.Println("]}")
    } else {
        uniqueSubdomains := make(map[string]bool)
        for _, result := range e.results {
            uniqueSubdomains[result.Subdomain] = true
        }
        
        fmt.Printf("\n📊 Summary:\n")
        fmt.Printf("   • Domain: %s\n", e.Domain)
        fmt.Printf("   • Total records found: %d\n", len(e.results))
        fmt.Printf("   • Unique subdomains: %d\n", len(uniqueSubdomains))
        
        fmt.Println("\n📝 Discovered Subdomains:")
        for subdomain := range uniqueSubdomains {
            fmt.Printf("   • %s\n", subdomain)
        }
    }
}

func (e *DNSEnumerator) saveResults(filename string, jsonOutput bool) {
    file, err := os.Create(filename)
    if err != nil {
        color.Red("Error creating output file: %v", err)
        return
    }
    defer file.Close()
    
    if jsonOutput {
        fmt.Fprintf(file, "{\"domain\":\"%s\",\"results\":[\n", e.Domain)
        for i, result := range e.results {
            fmt.Fprintf(file, "  {\"subdomain\":\"%s\",\"type\":\"%s\",\"records\":%q}",
                result.Subdomain, result.Type, result.Records)
            if i < len(e.results)-1 {
                fmt.Fprint(file, ",")
            }
            fmt.Fprintln(file)
        }
        fmt.Fprintln(file, "]}")
    } else {
        for _, result := range e.results {
            fmt.Fprintf(file, "%s,%s,%s\n", 
                result.Subdomain, result.Type, strings.Join(result.Records, ";"))
        }
    }
    
    color.Green("\n✅ Results saved to %s", filename)
}

func loadWordlist(filename string) []string {
    file, err := os.Open(filename)
    if err != nil {
        return []string{}
    }
    defer file.Close()
    
    var lines []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line != "" && !strings.HasPrefix(line, "#") {
            lines = append(lines, line)
        }
    }
    
    return lines
}

func getDefaultSubdomains() []string {
    return []string{
        "www", "mail", "remote", "blog", "webmail", "server",
        "ns1", "ns2", "smtp", "secure", "vpn", "admin", "test",
        "portal", "dev", "staging", "api", "beta", "app",
        "support", "ftp", "ssh", "localhost", "mysql", "web",
        "cloud", "git", "svn", "jenkins", "gitlab", "jira",
        "confluence", "wiki", "help", "docs", "cdn", "assets",
        "static", "media", "upload", "download", "img", "image",
        "mobile", "m", "gateway", "proxy", "firewall", "backup",
        "demo", "legacy", "old", "new", "portal2", "dashboard",
        "data", "db", "database", "sql", "postgres", "redis",
        "elastic", "search", "analytics", "metrics", "monitor",
        "nagios", "zabbix", "grafana", "prometheus", "logs",
    }
}

func getDefaultResolvers() []string {
    return []string{
        "8.8.8.8",        // Google
        "8.8.4.4",        // Google
        "1.1.1.1",        // Cloudflare
        "1.0.0.1",        // Cloudflare
        "208.67.222.222", // OpenDNS
        "208.67.220.220", // OpenDNS
    }
}

func printBanner() {
    banner := `
    ╔═══════════════════════════════════════╗
    ║   🌐 PADOCCA DNS ENUMERATOR 🌐       ║
    ║     Deep • Fast • Comprehensive       ║
    ╚═══════════════════════════════════════╝
    `
    color.Cyan(banner)
}
