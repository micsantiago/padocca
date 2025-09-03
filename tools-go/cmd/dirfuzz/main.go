// Padocca Directory Fuzzer - Advanced directory and file discovery
package main

import (
    "bufio"
    "context"
    "crypto/tls"
    "fmt"
    "io/ioutil"
    "net/http"
    "net/url"
    "os"
    "path"
    "regexp"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "github.com/fatih/color"
    "github.com/schollz/progressbar/v3"
    "github.com/spf13/cobra"
    "golang.org/x/sync/semaphore"
)

type DirFuzzer struct {
    Target       string
    Wordlist     []string
    Extensions   []string
    Workers      int64
    Timeout      time.Duration
    FollowRedirect bool
    UserAgent    string
    Cookies      string
    
    sem          *semaphore.Weighted
    results      []FuzzResult
    mutex        sync.Mutex
    checked      int64
    found        int64
    client       *http.Client
}

type FuzzResult struct {
    URL          string
    StatusCode   int
    Size         int64
    ContentType  string
    Title        string
    Interesting  bool
    Notes        string
}

var interestingFiles = []string{
    ".git/config", ".git/HEAD", ".gitignore",
    ".svn/entries", ".svn/wc.db",
    ".env", ".env.local", ".env.production",
    "config.php", "config.json", "config.yml", "config.xml",
    "database.yml", "database.json", "db.sqlite",
    "backup.sql", "dump.sql", "backup.zip", "backup.tar.gz",
    "admin.php", "login.php", "shell.php", "upload.php",
    "phpinfo.php", "info.php", "test.php",
    ".htaccess", ".htpasswd", "web.config",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "package.json", "composer.json", "requirements.txt",
    "Dockerfile", "docker-compose.yml",
    ".DS_Store", "Thumbs.db",
    "id_rsa", "id_rsa.pub", "authorized_keys",
    "wp-config.php", "wp-login.php",
    "api/swagger.json", "api-docs", "swagger-ui",
}

var interestingDirs = []string{
    "admin", "administrator", "panel", "cpanel",
    "backup", "backups", "old", "temp", "tmp",
    "upload", "uploads", "files", "documents",
    "api", "v1", "v2", "graphql", "rest",
    "config", "conf", "configuration",
    ".git", ".svn", ".hg", ".bzr",
    "vendor", "node_modules", "bower_components",
    "test", "tests", "testing", "debug",
    "dev", "development", "stage", "staging",
    "private", "secret", "secure", "hidden",
    "logs", "log", "error_log", "access_log",
    "cache", "cached", "temp",
    "includes", "inc", "lib", "libs", "src",
    "cgi-bin", "scripts", "bin",
    "wp-admin", "wp-content", "wp-includes",
    "phpmyadmin", "pma", "mysql", "database",
}

func main() {
    var rootCmd = &cobra.Command{
        Use:   "dirfuzz",
        Short: "Padocca Directory Fuzzer - Advanced web content discovery",
        Long:  `Intelligent directory and file fuzzing with automatic detection of interesting content`,
        Run:   runDirFuzz,
    }

    // Define flags
    rootCmd.Flags().StringP("url", "u", "", "Target URL (required)")
    rootCmd.Flags().StringP("wordlist", "w", "", "Custom wordlist file")
    rootCmd.Flags().StringSliceP("extensions", "x", []string{}, "File extensions to test (e.g., php,asp,js)")
    rootCmd.Flags().IntP("workers", "t", 20, "Number of concurrent workers")
    rootCmd.Flags().IntP("timeout", "T", 10, "Request timeout in seconds")
    rootCmd.Flags().BoolP("follow", "f", false, "Follow redirects")
    rootCmd.Flags().StringP("user-agent", "a", "Padocca/1.0", "User-Agent string")
    rootCmd.Flags().StringP("cookies", "c", "", "Cookies to include")
    rootCmd.Flags().StringSliceP("status", "s", []string{"200", "301", "302", "401", "403"}, "Status codes to display")
    rootCmd.Flags().BoolP("recursive", "r", false, "Recursive fuzzing")
    rootCmd.Flags().StringP("output", "o", "", "Output file for results")
    rootCmd.Flags().BoolP("json", "j", false, "JSON output format")
    rootCmd.Flags().BoolP("smart", "S", true, "Smart mode - check for interesting files")
    
    rootCmd.MarkFlagRequired("url")

    if err := rootCmd.Execute(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}

func runDirFuzz(cmd *cobra.Command, args []string) {
    targetURL, _ := cmd.Flags().GetString("url")
    wordlistFile, _ := cmd.Flags().GetString("wordlist")
    extensions, _ := cmd.Flags().GetStringSlice("extensions")
    workers, _ := cmd.Flags().GetInt("workers")
    timeout, _ := cmd.Flags().GetInt("timeout")
    followRedirect, _ := cmd.Flags().GetBool("follow")
    userAgent, _ := cmd.Flags().GetString("user-agent")
    cookies, _ := cmd.Flags().GetString("cookies")
    statusCodes, _ := cmd.Flags().GetStringSlice("status")
    recursive, _ := cmd.Flags().GetBool("recursive")
    outputFile, _ := cmd.Flags().GetString("output")
    jsonOutput, _ := cmd.Flags().GetBool("json")
    smartMode, _ := cmd.Flags().GetBool("smart")

    // Validate and normalize URL
    if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
        targetURL = "http://" + targetURL
    }
    targetURL = strings.TrimRight(targetURL, "/")

    printBanner()

    // Load wordlist
    var wordlist []string
    if wordlistFile != "" {
        wordlist = loadWordlist(wordlistFile)
    } else {
        wordlist = getDefaultWordlist()
    }

    // Create fuzzer
    fuzzer := &DirFuzzer{
        Target:      targetURL,
        Wordlist:    wordlist,
        Extensions:  extensions,
        Workers:     int64(workers),
        Timeout:     time.Duration(timeout) * time.Second,
        FollowRedirect: followRedirect,
        UserAgent:   userAgent,
        Cookies:     cookies,
        sem:         semaphore.NewWeighted(int64(workers)),
        results:     []FuzzResult{},
        client: &http.Client{
            Timeout: time.Duration(timeout) * time.Second,
            CheckRedirect: func(req *http.Request, via []*http.Request) error {
                if !followRedirect {
                    return http.ErrUseLastResponse
                }
                return nil
            },
            Transport: &http.Transport{
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
            },
        },
    }

    color.Cyan("🎯 Starting directory fuzzing on: %s", targetURL)
    color.Yellow("Wordlist: %d entries | Extensions: %v", len(wordlist), extensions)
    fmt.Println()

    // Smart mode - check interesting files first
    if smartMode {
        fuzzer.checkInterestingFiles()
    }

    // Main fuzzing
    fuzzer.fuzz(statusCodes)

    // Recursive fuzzing
    if recursive {
        fuzzer.recursiveFuzz(statusCodes)
    }

    // Display results
    fuzzer.displayResults(jsonOutput)

    // Save results
    if outputFile != "" {
        fuzzer.saveResults(outputFile, jsonOutput)
    }
}

func (f *DirFuzzer) checkInterestingFiles() {
    color.Yellow("🔍 Checking for interesting files...")
    
    var wg sync.WaitGroup
    ctx := context.Background()

    for _, file := range interestingFiles {
        wg.Add(1)
        f.sem.Acquire(ctx, 1)
        
        go func(filename string) {
            defer wg.Done()
            defer f.sem.Release(1)
            
            testURL := f.Target + "/" + filename
            if result := f.checkURL(testURL); result != nil {
                if result.StatusCode == 200 || result.StatusCode == 403 {
                    result.Interesting = true
                    result.Notes = "Sensitive file detected!"
                    
                    f.mutex.Lock()
                    f.results = append(f.results, *result)
                    f.mutex.Unlock()
                    
                    if result.StatusCode == 200 {
                        color.Red("[!] FOUND SENSITIVE: %s (Status: %d)", testURL, result.StatusCode)
                    } else {
                        color.Yellow("[!] RESTRICTED: %s (Status: %d)", testURL, result.StatusCode)
                    }
                    
                    // Check for git repository
                    if strings.Contains(filename, ".git") {
                        f.checkGitExposure(testURL)
                    }
                }
            }
        }(file)
    }
    
    wg.Wait()
    fmt.Println()
}

func (f *DirFuzzer) checkGitExposure(gitURL string) {
    gitFiles := []string{
        "/config", "/HEAD", "/index", "/packed-refs",
        "/logs/HEAD", "/info/refs", "/description",
        "/hooks/pre-commit", "/objects/info/packs",
    }
    
    color.Red("[!!] Git repository exposed! Checking additional files...")
    
    baseURL := strings.TrimSuffix(gitURL, "/.git")
    for _, file := range gitFiles {
        testURL := baseURL + "/.git" + file
        if result := f.checkURL(testURL); result != nil && result.StatusCode == 200 {
            color.Red("    [+] Accessible: .git%s", file)
        }
    }
}

func (f *DirFuzzer) fuzz(statusCodes []string) {
    totalTests := len(f.Wordlist)
    if len(f.Extensions) > 0 {
        totalTests = totalTests * (len(f.Extensions) + 1) // +1 for no extension
    }
    
    bar := progressbar.Default(int64(totalTests))
    var wg sync.WaitGroup
    ctx := context.Background()

    for _, word := range f.Wordlist {
        // Test without extension
        wg.Add(1)
        f.sem.Acquire(ctx, 1)
        
        go func(w string) {
            defer wg.Done()
            defer f.sem.Release(1)
            defer bar.Add(1)
            
            testURL := f.Target + "/" + w
            if result := f.checkURL(testURL); result != nil {
                if f.isInterestingStatus(result.StatusCode, statusCodes) {
                    f.mutex.Lock()
                    f.results = append(f.results, *result)
                    f.mutex.Unlock()
                    
                    f.displayResult(*result)
                    atomic.AddInt64(&f.found, 1)
                }
            }
            atomic.AddInt64(&f.checked, 1)
        }(word)
        
        // Test with extensions
        for _, ext := range f.Extensions {
            wg.Add(1)
            f.sem.Acquire(ctx, 1)
            
            go func(w, e string) {
                defer wg.Done()
                defer f.sem.Release(1)
                defer bar.Add(1)
                
                testURL := f.Target + "/" + w + "." + e
                if result := f.checkURL(testURL); result != nil {
                    if f.isInterestingStatus(result.StatusCode, statusCodes) {
                        f.mutex.Lock()
                        f.results = append(f.results, *result)
                        f.mutex.Unlock()
                        
                        f.displayResult(*result)
                        atomic.AddInt64(&f.found, 1)
                    }
                }
                atomic.AddInt64(&f.checked, 1)
            }(word, ext)
        }
    }
    
    wg.Wait()
    bar.Finish()
}

func (f *DirFuzzer) recursiveFuzz(statusCodes []string) {
    color.Yellow("\n🔄 Recursive fuzzing on discovered directories...")
    
    var directories []string
    for _, result := range f.results {
        if result.StatusCode == 200 || result.StatusCode == 301 || result.StatusCode == 302 {
            if !strings.Contains(path.Base(result.URL), ".") { // Likely a directory
                directories = append(directories, result.URL)
            }
        }
    }
    
    for _, dir := range directories {
        color.Cyan("  Fuzzing: %s", dir)
        originalTarget := f.Target
        f.Target = dir
        f.fuzz(statusCodes)
        f.Target = originalTarget
    }
}

func (f *DirFuzzer) checkURL(testURL string) *FuzzResult {
    req, err := http.NewRequest("GET", testURL, nil)
    if err != nil {
        return nil
    }
    
    req.Header.Set("User-Agent", f.UserAgent)
    if f.Cookies != "" {
        req.Header.Set("Cookie", f.Cookies)
    }
    
    resp, err := f.client.Do(req)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()
    
    body, _ := ioutil.ReadAll(resp.Body)
    
    result := &FuzzResult{
        URL:         testURL,
        StatusCode:  resp.StatusCode,
        Size:        int64(len(body)),
        ContentType: resp.Header.Get("Content-Type"),
        Title:       f.extractTitle(string(body)),
    }
    
    // Check for interesting patterns
    f.analyzeContent(result, string(body))
    
    return result
}

func (f *DirFuzzer) extractTitle(html string) string {
    re := regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)
    matches := re.FindStringSubmatch(html)
    if len(matches) > 1 {
        return strings.TrimSpace(matches[1])
    }
    return ""
}

func (f *DirFuzzer) analyzeContent(result *FuzzResult, content string) {
    // Check for API endpoints
    if strings.Contains(content, "swagger") || strings.Contains(content, "\"api\"") {
        result.Interesting = true
        result.Notes = "API endpoint detected"
    }
    
    // Check for error messages
    errorPatterns := []string{
        "SQL syntax", "mysql_fetch", "ORA-[0-9]+",
        "PostgreSQL", "pg_query", "sqlite_",
        "Exception", "Stack Trace", "Error",
        "Warning:", "Notice:", "Fatal error:",
    }
    
    for _, pattern := range errorPatterns {
        if strings.Contains(content, pattern) {
            result.Interesting = true
            result.Notes = "Error message detected: " + pattern
            break
        }
    }
    
    // Check for sensitive information patterns
    sensitivePatterns := []string{
        "password", "passwd", "pwd",
        "api_key", "apikey", "api-key",
        "secret", "token", "bearer",
        "private", "priv_key", "private_key",
        "BEGIN RSA", "BEGIN DSA", "BEGIN EC",
        "aws_access_key", "aws_secret",
    }
    
    for _, pattern := range sensitivePatterns {
        if strings.Contains(strings.ToLower(content), pattern) {
            result.Interesting = true
            result.Notes = "Potential sensitive data: " + pattern
            break
        }
    }
}

func (f *DirFuzzer) isInterestingStatus(status int, allowed []string) bool {
    statusStr := fmt.Sprintf("%d", status)
    for _, s := range allowed {
        if s == statusStr {
            return true
        }
    }
    return false
}

func (f *DirFuzzer) displayResult(result FuzzResult) {
    u, _ := url.Parse(result.URL)
    path := u.Path
    
    statusColor := color.FgGreen
    if result.StatusCode >= 300 && result.StatusCode < 400 {
        statusColor = color.FgYellow
    } else if result.StatusCode >= 400 && result.StatusCode < 500 {
        statusColor = color.FgCyan
    } else if result.StatusCode >= 500 {
        statusColor = color.FgRed
    }
    
    color.New(statusColor).Printf("[%d] ", result.StatusCode)
    fmt.Printf("%-50s [Size: %d]", path, result.Size)
    
    if result.Title != "" {
        fmt.Printf(" [%s]", result.Title)
    }
    
    if result.Interesting {
        color.Red(" [!] %s", result.Notes)
    }
    
    fmt.Println()
}

func (f *DirFuzzer) displayResults(jsonOutput bool) {
    fmt.Println()
    color.Yellow("═══════════════════════════════════════════════════════")
    color.Cyan("                 DIRECTORY FUZZING RESULTS              ")
    color.Yellow("═══════════════════════════════════════════════════════")
    
    fmt.Printf("\n📊 Statistics:\n")
    fmt.Printf("   • Total requests: %d\n", atomic.LoadInt64(&f.checked))
    fmt.Printf("   • Found: %d\n", atomic.LoadInt64(&f.found))
    fmt.Printf("   • Interesting findings: %d\n", f.countInteresting())
    
    if f.countInteresting() > 0 {
        fmt.Println("\n🔥 Interesting Findings:")
        for _, result := range f.results {
            if result.Interesting {
                color.Red("   • %s - %s", result.URL, result.Notes)
            }
        }
    }
    
    fmt.Println("\n📁 Discovered Paths:")
    for _, result := range f.results {
        if !result.Interesting {
            fmt.Printf("   • [%d] %s\n", result.StatusCode, result.URL)
        }
    }
}

func (f *DirFuzzer) countInteresting() int {
    count := 0
    for _, result := range f.results {
        if result.Interesting {
            count++
        }
    }
    return count
}

func (f *DirFuzzer) saveResults(filename string, jsonOutput bool) {
    file, err := os.Create(filename)
    if err != nil {
        color.Red("Error creating output file: %v", err)
        return
    }
    defer file.Close()
    
    if jsonOutput {
        fmt.Fprintf(file, "[\n")
        for i, result := range f.results {
            fmt.Fprintf(file, "  {\"url\":\"%s\",\"status\":%d,\"size\":%d,\"title\":\"%s\",\"interesting\":%t,\"notes\":\"%s\"}",
                result.URL, result.StatusCode, result.Size, 
                strings.ReplaceAll(result.Title, "\"", "\\\""),
                result.Interesting,
                strings.ReplaceAll(result.Notes, "\"", "\\\""))
            if i < len(f.results)-1 {
                fmt.Fprintf(file, ",")
            }
            fmt.Fprintf(file, "\n")
        }
        fmt.Fprintf(file, "]\n")
    } else {
        for _, result := range f.results {
            fmt.Fprintf(file, "%d,%s,%d,%s,%s\n", 
                result.StatusCode, result.URL, result.Size, result.Title, result.Notes)
        }
    }
    
    color.Green("\n✅ Results saved to %s", filename)
}

func loadWordlist(filename string) []string {
    file, err := os.Open(filename)
    if err != nil {
        return getDefaultWordlist()
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

func getDefaultWordlist() []string {
    return append(interestingDirs, []string{
        "index", "home", "default", "main",
        "login", "signin", "signup", "register",
        "dashboard", "portal", "console",
        "user", "users", "profile", "account",
        "search", "query", "find",
        "download", "downloads", "file", "files",
        "image", "images", "img", "imgs",
        "css", "js", "javascript", "style",
        "font", "fonts", "assets", "static",
        "media", "video", "audio", "music",
        "doc", "docs", "documentation",
        "help", "support", "faq", "contact",
        "about", "info", "information",
        "news", "blog", "posts", "articles",
        "forum", "forums", "community",
        "shop", "store", "cart", "checkout",
        "payment", "payments", "order", "orders",
        "service", "services", "api", "apis",
        "data", "database", "db", "sql",
        "backup", "bak", "old", "new",
        "test", "demo", "example", "sample",
        "tmp", "temp", "cache", "cached",
    }...)
}

func printBanner() {
    banner := `
    ╔═══════════════════════════════════════╗
    ║   📂 PADOCCA DIRECTORY FUZZER 📂     ║
    ║     Smart • Fast • Thorough           ║
    ╚═══════════════════════════════════════╝
    `
    color.Cyan(banner)
}
