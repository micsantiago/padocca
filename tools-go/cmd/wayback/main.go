// PADOCCA Wayback URLs Module - Historical URL discovery
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"golang.org/x/sync/semaphore"
)

type WaybackDiscovery struct {
	Targets       []string
	Workers       int64
	Timeout       time.Duration
	ValidateURLs  bool
	OutputFile    string
	MaxResults    int
	IncludeParams bool
	
	sem          *semaphore.Weighted
	client       *http.Client
	results      map[string]*URLInfo
	mutex        sync.RWMutex
	totalFound   int64
	totalChecked int64
}

type URLInfo struct {
	URL         string    `json:"url"`
	Status      int       `json:"status,omitempty"`
	StatusText  string    `json:"status_text,omitempty"`
	ContentType string    `json:"content_type,omitempty"`
	Length      int64     `json:"length,omitempty"`
	FirstSeen   string    `json:"first_seen"`
	LastSeen    string    `json:"last_seen"`
	Source      string    `json:"source"`
	Valid       bool      `json:"valid,omitempty"`
	Parameters  []string  `json:"parameters,omitempty"`
}

type ArchiveResponse [][]interface{}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "wayback",
		Short: "PADOCCA Wayback URLs - Historical URL discovery",
		Long: `Discover historical URLs from Archive.org, Common Crawl, and other sources.
		
Features:
  • Multiple archive sources (Archive.org, Common Crawl, URLScan, AlienVault)
  • URL validation with status codes
  • Parameter extraction and analysis
  • Duplicate removal and smart filtering
  • Export to multiple formats`,
		Run: runWayback,
	}

	// Flags
	rootCmd.Flags().StringSliceP("targets", "t", []string{}, "Target domains/subdomains (required)")
	rootCmd.Flags().StringP("input", "i", "", "Input file with targets")
	rootCmd.Flags().IntP("workers", "w", 10, "Number of workers")
	rootCmd.Flags().IntP("timeout", "T", 30, "Timeout in seconds")
	rootCmd.Flags().BoolP("validate", "v", false, "Validate URLs (check if alive)")
	rootCmd.Flags().StringP("output", "o", "", "Output file")
	rootCmd.Flags().IntP("max", "m", 0, "Max URLs per domain (0 = unlimited)")
	rootCmd.Flags().BoolP("params", "p", true, "Include URLs with parameters")
	rootCmd.Flags().BoolP("json", "j", false, "Output in JSON format")
	rootCmd.Flags().BoolP("quiet", "q", false, "Quiet mode")
	rootCmd.Flags().StringSliceP("exclude", "e", []string{}, "Exclude patterns")
	rootCmd.Flags().StringSliceP("include", "I", []string{}, "Include patterns")
	rootCmd.Flags().BoolP("subs", "s", true, "Include subdomains")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runWayback(cmd *cobra.Command, args []string) {
	targets, _ := cmd.Flags().GetStringSlice("targets")
	inputFile, _ := cmd.Flags().GetString("input")
	workers, _ := cmd.Flags().GetInt("workers")
	timeout, _ := cmd.Flags().GetInt("timeout")
	validate, _ := cmd.Flags().GetBool("validate")
	outputFile, _ := cmd.Flags().GetString("output")
	maxResults, _ := cmd.Flags().GetInt("max")
	includeParams, _ := cmd.Flags().GetBool("params")
	jsonOutput, _ := cmd.Flags().GetBool("json")
	quiet, _ := cmd.Flags().GetBool("quiet")
	excludePatterns, _ := cmd.Flags().GetStringSlice("exclude")
	includePatterns, _ := cmd.Flags().GetStringSlice("include")
	includeSubs, _ := cmd.Flags().GetBool("subs")

	// Load targets from file if provided
	if inputFile != "" {
		fileTargets := loadTargetsFromFile(inputFile)
		targets = append(targets, fileTargets...)
	}

	if len(targets) == 0 {
		color.Red("[!] No targets specified")
		os.Exit(1)
	}

	if !quiet {
		printBanner()
	}

	discovery := &WaybackDiscovery{
		Targets:       targets,
		Workers:       int64(workers),
		Timeout:       time.Duration(timeout) * time.Second,
		ValidateURLs:  validate,
		OutputFile:    outputFile,
		MaxResults:    maxResults,
		IncludeParams: includeParams,
		sem:          semaphore.NewWeighted(int64(workers)),
		results:      make(map[string]*URLInfo),
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	// Start discovery
	discovery.run(excludePatterns, includePatterns, includeSubs, quiet, jsonOutput)
}

func (w *WaybackDiscovery) run(exclude, include []string, subs, quiet, jsonOutput bool) {
	color.Cyan("🔍 Starting historical URL discovery...")
	fmt.Println()

	var wg sync.WaitGroup
	ctx := context.Background()

	for _, target := range w.Targets {
		wg.Add(1)
		w.sem.Acquire(ctx, 1)

		go func(t string) {
			defer wg.Done()
			defer w.sem.Release(1)

			if !quiet {
				color.Yellow("[*] Processing: %s", t)
			}

			// Query multiple sources
			w.queryArchiveOrg(t, subs)
			w.queryCommonCrawl(t)
			w.queryURLScan(t)
			w.queryAlienVault(t)
		}(target)
	}

	wg.Wait()

	// Filter results
	w.filterResults(exclude, include)

	// Validate URLs if requested
	if w.ValidateURLs {
		w.validateURLs(quiet)
	}

	// Display results
	w.displayResults(quiet, jsonOutput)

	// Save results
	if w.OutputFile != "" {
		w.saveResults(jsonOutput)
	}
}

func (w *WaybackDiscovery) queryArchiveOrg(target string, includeSubs bool) {
	query := target
	if includeSubs {
		query = "*." + target
	}

	apiURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&collapse=urlkey&fl=original,timestamp,statuscode,mimetype,length", query)

	resp, err := w.client.Get(apiURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var results ArchiveResponse
	if err := json.Unmarshal(body, &results); err != nil {
		return
	}

	// Skip header row
	if len(results) > 0 {
		results = results[1:]
	}

	for _, record := range results {
		if len(record) < 5 {
			continue
		}

		urlStr, ok := record[0].(string)
		if !ok {
			continue
		}

		timestamp, _ := record[1].(string)
		statusCode := 0
		if sc, ok := record[2].(string); ok {
			fmt.Sscanf(sc, "%d", &statusCode)
		}
		
		mimeType, _ := record[3].(string)
		length := int64(0)
		if l, ok := record[4].(string); ok {
			fmt.Sscanf(l, "%d", &length)
		}

		// Extract parameters
		params := w.extractParameters(urlStr)

		w.mutex.Lock()
		if existing, ok := w.results[urlStr]; ok {
			// Update last seen
			if timestamp > existing.LastSeen {
				existing.LastSeen = formatTimestamp(timestamp)
			}
			if timestamp < existing.FirstSeen {
				existing.FirstSeen = formatTimestamp(timestamp)
			}
		} else {
			w.results[urlStr] = &URLInfo{
				URL:         urlStr,
				Status:      statusCode,
				StatusText:  getStatusText(statusCode),
				ContentType: mimeType,
				Length:      length,
				FirstSeen:   formatTimestamp(timestamp),
				LastSeen:    formatTimestamp(timestamp),
				Source:      "Archive.org",
				Parameters:  params,
			}
			atomic.AddInt64(&w.totalFound, 1)
		}
		w.mutex.Unlock()
	}
}

func (w *WaybackDiscovery) queryCommonCrawl(target string) {
	// Common Crawl Index API
	apiURL := fmt.Sprintf("https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.%s&output=json", target)

	resp, err := w.client.Get(apiURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		var result map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			continue
		}

		if urlStr, ok := result["url"].(string); ok {
			timestamp := time.Now().Format("2006-01-02")
			if ts, ok := result["timestamp"].(string); ok {
				timestamp = ts
			}

			params := w.extractParameters(urlStr)

			w.mutex.Lock()
			if _, ok := w.results[urlStr]; !ok {
				w.results[urlStr] = &URLInfo{
					URL:        urlStr,
					FirstSeen:  timestamp,
					LastSeen:   timestamp,
					Source:     "CommonCrawl",
					Parameters: params,
				}
				atomic.AddInt64(&w.totalFound, 1)
			}
			w.mutex.Unlock()
		}
	}
}

func (w *WaybackDiscovery) queryURLScan(target string) {
	// URLScan.io API (public, no auth required)
	apiURL := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=1000", target)

	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("User-Agent", "PADOCCA/2.0")

	resp, err := w.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Results []struct {
			Page struct {
				URL    string `json:"url"`
				Status string `json:"status"`
			} `json:"page"`
			Stats struct {
				DataLength int `json:"dataLength"`
			} `json:"stats"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}

	for _, r := range result.Results {
		params := w.extractParameters(r.Page.URL)
		
		w.mutex.Lock()
		if _, ok := w.results[r.Page.URL]; !ok {
			statusCode := 0
			fmt.Sscanf(r.Page.Status, "%d", &statusCode)
			
			w.results[r.Page.URL] = &URLInfo{
				URL:        r.Page.URL,
				Status:     statusCode,
				StatusText: getStatusText(statusCode),
				Length:     int64(r.Stats.DataLength),
				FirstSeen:  time.Now().Format("2006-01-02"),
				LastSeen:   time.Now().Format("2006-01-02"),
				Source:     "URLScan",
				Parameters: params,
			}
			atomic.AddInt64(&w.totalFound, 1)
		}
		w.mutex.Unlock()
	}
}

func (w *WaybackDiscovery) queryAlienVault(target string) {
	// AlienVault OTX API
	apiURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list", target)

	resp, err := w.client.Get(apiURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var result struct {
		URLList []struct {
			URL      string `json:"url"`
			Date     string `json:"date"`
			HTTPCode int    `json:"httpcode"`
		} `json:"url_list"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}

	for _, u := range result.URLList {
		params := w.extractParameters(u.URL)
		
		w.mutex.Lock()
		if _, ok := w.results[u.URL]; !ok {
			w.results[u.URL] = &URLInfo{
				URL:        u.URL,
				Status:     u.HTTPCode,
				StatusText: getStatusText(u.HTTPCode),
				FirstSeen:  u.Date,
				LastSeen:   u.Date,
				Source:     "AlienVault",
				Parameters: params,
			}
			atomic.AddInt64(&w.totalFound, 1)
		}
		w.mutex.Unlock()
	}
}

func (w *WaybackDiscovery) validateURLs(quiet bool) {
	if !quiet {
		color.Yellow("\n⚡ Validating discovered URLs...")
	}

	var urls []string
	w.mutex.RLock()
	for url := range w.results {
		urls = append(urls, url)
	}
	w.mutex.RUnlock()

	bar := progressbar.Default(int64(len(urls)))
	var wg sync.WaitGroup
	ctx := context.Background()

	for _, urlStr := range urls {
		wg.Add(1)
		w.sem.Acquire(ctx, 1)

		go func(u string) {
			defer wg.Done()
			defer w.sem.Release(1)
			defer bar.Add(1)

			req, err := http.NewRequest("HEAD", u, nil)
			if err != nil {
				return
			}

			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; PADOCCA/2.0)")
			
			resp, err := w.client.Do(req)
			if err != nil {
				w.mutex.Lock()
				w.results[u].Valid = false
				w.mutex.Unlock()
				return
			}
			defer resp.Body.Close()

			w.mutex.Lock()
			w.results[u].Status = resp.StatusCode
			w.results[u].StatusText = resp.Status
			w.results[u].Valid = resp.StatusCode < 400
			if ct := resp.Header.Get("Content-Type"); ct != "" {
				w.results[u].ContentType = ct
			}
			if cl := resp.ContentLength; cl > 0 {
				w.results[u].Length = cl
			}
			w.mutex.Unlock()

			atomic.AddInt64(&w.totalChecked, 1)

			if resp.StatusCode == 200 && !quiet {
				color.Green("\n[+] ALIVE: %s", u)
			}
		}(urlStr)
	}

	wg.Wait()
	bar.Finish()
}

func (w *WaybackDiscovery) filterResults(exclude, include []string) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	filtered := make(map[string]*URLInfo)

	for url, info := range w.results {
		// Check exclude patterns
		excluded := false
		for _, pattern := range exclude {
			if strings.Contains(url, pattern) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		// Check include patterns
		if len(include) > 0 {
			included := false
			for _, pattern := range include {
				if strings.Contains(url, pattern) {
					included = true
					break
				}
			}
			if !included {
				continue
			}
		}

		// Check parameters filter
		if !w.IncludeParams && len(info.Parameters) > 0 {
			continue
		}

		filtered[url] = info
	}

	w.results = filtered
}

func (w *WaybackDiscovery) extractParameters(urlStr string) []string {
	params := []string{}
	
	u, err := url.Parse(urlStr)
	if err != nil {
		return params
	}

	for key := range u.Query() {
		params = append(params, key)
	}

	sort.Strings(params)
	return params
}

func (w *WaybackDiscovery) displayResults(quiet, jsonOutput bool) {
	if quiet && !jsonOutput {
		return
	}

	w.mutex.RLock()
	defer w.mutex.RUnlock()

	// Sort URLs
	var urls []string
	for url := range w.results {
		urls = append(urls, url)
	}
	sort.Strings(urls)

	if jsonOutput {
		output := make([]URLInfo, 0, len(urls))
		for _, url := range urls {
			output = append(output, *w.results[url])
		}
		
		data, _ := json.MarshalIndent(output, "", "  ")
		fmt.Println(string(data))
		return
	}

	// Terminal output
	fmt.Println()
	color.Yellow("═══════════════════════════════════════════════════════")
	color.Cyan("             WAYBACK URL DISCOVERY RESULTS             ")
	color.Yellow("═══════════════════════════════════════════════════════")
	
	color.White("\n📊 Statistics:")
	fmt.Printf("  Total URLs found: %d\n", len(w.results))
	if w.ValidateURLs {
		alive := 0
		for _, info := range w.results {
			if info.Valid {
				alive++
			}
		}
		fmt.Printf("  Alive URLs: %d\n", alive)
		fmt.Printf("  Dead URLs: %d\n", len(w.results)-alive)
	}

	// Show top 10 URLs for frontend
	color.White("\n🔗 Sample URLs (max 10):")
	count := 0
	for _, url := range urls {
		info := w.results[url]
		if count >= 10 {
			break
		}
		
		statusColor := color.FgRed
		if info.Status > 0 && info.Status < 400 {
			statusColor = color.FgGreen
		}
		
		color.New(statusColor).Printf("  [%d] %s\n", info.Status, url)
		if len(info.Parameters) > 0 {
			fmt.Printf("      Parameters: %s\n", strings.Join(info.Parameters, ", "))
		}
		fmt.Printf("      Source: %s | First: %s | Last: %s\n", 
			info.Source, info.FirstSeen, info.LastSeen)
		count++
	}

	if len(urls) > 10 {
		color.Yellow("\n  ... and %d more URLs", len(urls)-10)
		if w.OutputFile != "" {
			color.Cyan("  Full results saved to: %s", w.OutputFile)
		}
	}
}

func (w *WaybackDiscovery) saveResults(jsonFormat bool) {
	w.mutex.RLock()
	defer w.mutex.RUnlock()

	file, err := os.Create(w.OutputFile)
	if err != nil {
		color.Red("[!] Error creating output file: %v", err)
		return
	}
	defer file.Close()

	if jsonFormat {
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		
		var urls []URLInfo
		for _, info := range w.results {
			urls = append(urls, *info)
		}
		encoder.Encode(urls)
	} else {
		// Simple text format
		var urls []string
		for url := range w.results {
			urls = append(urls, url)
		}
		sort.Strings(urls)
		
		for _, url := range urls {
			file.WriteString(url + "\n")
		}
	}

	color.Green("[+] Results saved to: %s", w.OutputFile)
}

func loadTargetsFromFile(filename string) []string {
	targets := []string{}
	
	file, err := os.Open(filename)
	if err != nil {
		return targets
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())
		if target != "" && !strings.HasPrefix(target, "#") {
			targets = append(targets, target)
		}
	}

	return targets
}

func formatTimestamp(ts string) string {
	if len(ts) >= 8 {
		return fmt.Sprintf("%s-%s-%s", ts[0:4], ts[4:6], ts[6:8])
	}
	return ts
}

func getStatusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 301, 302:
		return "Redirect"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 500:
		return "Server Error"
	default:
		return fmt.Sprintf("HTTP %d", code)
	}
}

func printBanner() {
	color.Cyan(`
╔══════════════════════════════════════════════════════╗
║        🕰️  PADOCCA WAYBACK URLs DISCOVERY 🕰️         ║
║         Historical URL Intelligence Gathering        ║
╚══════════════════════════════════════════════════════╝
`)
}
