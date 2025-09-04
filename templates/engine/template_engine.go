// PADOCCA Template Engine - Nuclei-like vulnerability detection system
package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"golang.org/x/sync/semaphore"
	"gopkg.in/yaml.v3"
)

// Template represents a vulnerability detection template
type Template struct {
	ID          string            `yaml:"id" json:"id"`
	Name        string            `yaml:"name" json:"name"`
	Author      string            `yaml:"author" json:"author"`
	Severity    string            `yaml:"severity" json:"severity"`
	Description string            `yaml:"description" json:"description"`
	Reference   []string          `yaml:"reference" json:"reference"`
	Tags        []string          `yaml:"tags" json:"tags"`
	Metadata    map[string]string `yaml:"metadata" json:"metadata"`
	
	// Request definitions
	Requests []Request `yaml:"requests" json:"requests"`
	
	// Validation rules
	Matchers    []Matcher    `yaml:"matchers" json:"matchers"`
	Extractors  []Extractor  `yaml:"extractors" json:"extractors"`
	
	// Advanced features
	Variables   map[string]interface{} `yaml:"variables" json:"variables"`
	Payloads    map[string][]string    `yaml:"payloads" json:"payloads"`
	Attack      string                 `yaml:"attack" json:"attack"` // batteringram, pitchfork, clusterbomb
	
	// Behavioral checks
	BehaviorChecks []BehaviorCheck `yaml:"behavior_checks" json:"behavior_checks"`
	
	// Exploitability validation
	ExploitValidation *ExploitValidation `yaml:"exploit_validation" json:"exploit_validation"`
}

// Request represents a single HTTP request in a template
type Request struct {
	Method          string            `yaml:"method" json:"method"`
	Path            []string          `yaml:"path" json:"path"`
	Headers         map[string]string `yaml:"headers" json:"headers"`
	Body            string            `yaml:"body" json:"body"`
	FollowRedirects bool              `yaml:"follow_redirects" json:"follow_redirects"`
	MaxRedirects    int               `yaml:"max_redirects" json:"max_redirects"`
	
	// Advanced options
	RawRequest      string            `yaml:"raw" json:"raw"`
	Payloads        map[string]string `yaml:"payloads" json:"payloads"`
	AttackType      string            `yaml:"attack" json:"attack"`
	Threads         int               `yaml:"threads" json:"threads"`
	RateLimit       int               `yaml:"rate_limit" json:"rate_limit"`
	
	// Stealth options
	RandomUserAgent bool              `yaml:"random_user_agent" json:"random_user_agent"`
	RandomDelay     [2]int            `yaml:"random_delay" json:"random_delay"` // min, max in ms
}

// Matcher represents matching conditions for vulnerability detection
type Matcher struct {
	Type      string   `yaml:"type" json:"type"` // word, regex, binary, status, size, time
	Part      string   `yaml:"part" json:"part"` // body, header, all
	Words     []string `yaml:"words" json:"words"`
	Regex     []string `yaml:"regex" json:"regex"`
	Binary    []string `yaml:"binary" json:"binary"`
	Status    []int    `yaml:"status" json:"status"`
	Size      []int    `yaml:"size" json:"size"`
	Condition string   `yaml:"condition" json:"condition"` // and, or
	Negative  bool     `yaml:"negative" json:"negative"`
	
	// Advanced matchers
	DSL        []string `yaml:"dsl" json:"dsl"`
	Encoding   string   `yaml:"encoding" json:"encoding"`
	CaseSensitive bool  `yaml:"case_sensitive" json:"case_sensitive"`
}

// Extractor extracts information from responses
type Extractor struct {
	Type     string   `yaml:"type" json:"type"` // regex, kval, json, xpath
	Part     string   `yaml:"part" json:"part"`
	Regex    []string `yaml:"regex" json:"regex"`
	Group    int      `yaml:"group" json:"group"`
	KVal     []string `yaml:"kval" json:"kval"`
	JSON     []string `yaml:"json" json:"json"`
	XPath    []string `yaml:"xpath" json:"xpath"`
	Internal bool     `yaml:"internal" json:"internal"`
	Name     string   `yaml:"name" json:"name"`
}

// BehaviorCheck validates vulnerability through behavior analysis
type BehaviorCheck struct {
	Type        string `yaml:"type" json:"type"` // timing, response_diff, oob
	Description string `yaml:"description" json:"description"`
	
	// Timing-based detection
	TimingBaseline  int `yaml:"timing_baseline" json:"timing_baseline"`   // ms
	TimingThreshold int `yaml:"timing_threshold" json:"timing_threshold"` // ms
	
	// Response differential
	ResponseDiff struct {
		MinDifference float64 `yaml:"min_difference" json:"min_difference"` // percentage
		CheckPoints   []string `yaml:"check_points" json:"check_points"`
	} `yaml:"response_diff" json:"response_diff"`
	
	// Out-of-band detection
	OOBCheck struct {
		Protocol string `yaml:"protocol" json:"protocol"` // dns, http
		Callback string `yaml:"callback" json:"callback"`
		Timeout  int    `yaml:"timeout" json:"timeout"`
	} `yaml:"oob_check" json:"oob_check"`
}

// ExploitValidation validates if vulnerability is actually exploitable
type ExploitValidation struct {
	Type        string `yaml:"type" json:"type"` // command_exec, file_read, ssrf
	Validation  string `yaml:"validation" json:"validation"`
	
	// Command execution validation
	CommandExec struct {
		TestCommand string   `yaml:"test_command" json:"test_command"`
		Expected    []string `yaml:"expected" json:"expected"`
	} `yaml:"command_exec" json:"command_exec"`
	
	// File read validation  
	FileRead struct {
		TestFile string   `yaml:"test_file" json:"test_file"`
		Contains []string `yaml:"contains" json:"contains"`
	} `yaml:"file_read" json:"file_read"`
	
	// SSRF validation
	SSRF struct {
		Callback string `yaml:"callback" json:"callback"`
		Timeout  int    `yaml:"timeout" json:"timeout"`
	} `yaml:"ssrf" json:"ssrf"`
}

// TemplateEngine manages and executes templates
type TemplateEngine struct {
	Templates     map[string]*Template
	TemplateDir   string
	Workers       int64
	Timeout       time.Duration
	RateLimit     int
	StealthMode   bool
	
	sem           *semaphore.Weighted
	client        *http.Client
	mutex         sync.RWMutex
	
	// Statistics
	totalScans    int64
	totalMatches  int64
	falsePositives int64
	
	// Results
	Results       []VulnerabilityResult
	
	// User agents for rotation
	userAgents    []string
}

// VulnerabilityResult represents a detected vulnerability
type VulnerabilityResult struct {
	TemplateID    string                 `json:"template_id"`
	TemplateName  string                 `json:"template_name"`
	Severity      string                 `json:"severity"`
	URL           string                 `json:"url"`
	Matched       bool                   `json:"matched"`
	Exploitable   bool                   `json:"exploitable"`
	Confidence    float64                `json:"confidence"`
	Evidence      map[string]interface{} `json:"evidence"`
	Timestamp     time.Time              `json:"timestamp"`
	FalsePositive bool                   `json:"false_positive"`
}

// NewTemplateEngine creates a new template engine
func NewTemplateEngine(templateDir string, workers int, stealthMode bool) *TemplateEngine {
	return &TemplateEngine{
		Templates:   make(map[string]*Template),
		TemplateDir: templateDir,
		Workers:     int64(workers),
		Timeout:     30 * time.Second,
		StealthMode: stealthMode,
		sem:        semaphore.NewWeighted(int64(workers)),
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
				},
				MaxIdleConns:       100,
				MaxConnsPerHost:    10,
				DisableCompression: false,
			},
		},
		userAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
		},
		Results: []VulnerabilityResult{},
	}
}

// LoadTemplates loads all templates from directory
func (e *TemplateEngine) LoadTemplates() error {
	// Create template directory if not exists
	if err := os.MkdirAll(e.TemplateDir, 0755); err != nil {
		return err
	}
	
	// Walk through template directory
	err := filepath.Walk(e.TemplateDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// Load YAML templates
		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			template, err := e.loadTemplate(path)
			if err != nil {
				color.Red("[!] Error loading template %s: %v", path, err)
				return nil // Continue loading other templates
			}
			
			e.mutex.Lock()
			e.Templates[template.ID] = template
			e.mutex.Unlock()
			
			color.Green("[+] Loaded template: %s", template.Name)
		}
		
		return nil
	})
	
	if err != nil {
		return err
	}
	
	color.Cyan("[*] Loaded %d templates", len(e.Templates))
	return nil
}

// loadTemplate loads a single template from file
func (e *TemplateEngine) loadTemplate(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	
	var template Template
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, err
	}
	
	// Validate template
	if template.ID == "" {
		return nil, fmt.Errorf("template missing ID")
	}
	
	if len(template.Requests) == 0 {
		return nil, fmt.Errorf("template missing requests")
	}
	
	return &template, nil
}

// ScanTarget scans a target with all loaded templates
func (e *TemplateEngine) ScanTarget(target string, tags []string) []VulnerabilityResult {
	var results []VulnerabilityResult
	var wg sync.WaitGroup
	ctx := context.Background()
	
	color.Cyan("[*] Scanning %s with %d templates", target, len(e.Templates))
	
	for _, template := range e.Templates {
		// Filter by tags if specified
		if len(tags) > 0 && !e.hasMatchingTag(template.Tags, tags) {
			continue
		}
		
		wg.Add(1)
		e.sem.Acquire(ctx, 1)
		
		go func(tmpl *Template) {
			defer wg.Done()
			defer e.sem.Release(1)
			
			result := e.executeTemplate(target, tmpl)
			if result.Matched {
				e.mutex.Lock()
				results = append(results, result)
				e.Results = append(e.Results, result)
				e.mutex.Unlock()
				
				atomic.AddInt64(&e.totalMatches, 1)
				
				// Display result
				severityColor := e.getSeverityColor(result.Severity)
				color.New(severityColor).Printf("[%s] %s - %s\n", 
					result.Severity, result.TemplateName, result.URL)
				
				if result.Exploitable {
					color.Green("  ✓ Exploitable (Confidence: %.2f%%)", result.Confidence*100)
				}
			}
			
			atomic.AddInt64(&e.totalScans, 1)
		}(template)
	}
	
	wg.Wait()
	
	// Calculate false positive rate
	e.calculateFalsePositiveRate()
	
	return results
}

// executeTemplate executes a single template against a target
func (e *TemplateEngine) executeTemplate(target string, template *Template) VulnerabilityResult {
	result := VulnerabilityResult{
		TemplateID:   template.ID,
		TemplateName: template.Name,
		Severity:     template.Severity,
		URL:          target,
		Matched:      false,
		Exploitable:  false,
		Confidence:   0.0,
		Evidence:     make(map[string]interface{}),
		Timestamp:    time.Now(),
	}
	
	for _, request := range template.Requests {
		// Execute request with payloads if defined
		if len(template.Payloads) > 0 {
			e.executePayloadRequest(target, template, request, &result)
		} else {
			e.executeSingleRequest(target, template, request, &result)
		}
		
		if result.Matched {
			break // Stop on first match unless configured otherwise
		}
	}
	
	// Perform behavioral checks if matched
	if result.Matched && len(template.BehaviorChecks) > 0 {
		result.Confidence = e.performBehaviorChecks(target, template)
		
		// Mark as false positive if confidence is too low
		if result.Confidence < 0.5 {
			result.FalsePositive = true
			atomic.AddInt64(&e.falsePositives, 1)
		}
	}
	
	// Validate exploitability
	if result.Matched && !result.FalsePositive && template.ExploitValidation != nil {
		result.Exploitable = e.validateExploitability(target, template)
	}
	
	return result
}

// executeSingleRequest executes a single HTTP request
func (e *TemplateEngine) executeSingleRequest(target string, template *Template, request Request, result *VulnerabilityResult) {
	for _, path := range request.Path {
		url := target + path
		
		// Apply stealth delay if enabled
		if e.StealthMode && request.RandomDelay[1] > 0 {
			e.applyStealthDelay(request.RandomDelay[0], request.RandomDelay[1])
		}
		
		// Create HTTP request
		req, err := e.createHTTPRequest(request.Method, url, request.Body)
		if err != nil {
			continue
		}
		
		// Set headers
		for key, value := range request.Headers {
			req.Header.Set(key, value)
		}
		
		// Random user agent if stealth mode
		if e.StealthMode || request.RandomUserAgent {
			req.Header.Set("User-Agent", e.getRandomUserAgent())
		}
		
		// Execute request
		resp, err := e.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		body, _ := io.ReadAll(resp.Body)
		
		// Check matchers
		matched := e.checkMatchers(template.Matchers, resp, body)
		
		if matched {
			result.Matched = true
			result.URL = url
			
			// Extract evidence
			result.Evidence["status_code"] = resp.StatusCode
			result.Evidence["response_size"] = len(body)
			
			// Run extractors
			if len(template.Extractors) > 0 {
				extracts := e.runExtractors(template.Extractors, resp, body)
				result.Evidence["extracted"] = extracts
			}
			
			return
		}
	}
}

// executePayloadRequest executes requests with payloads
func (e *TemplateEngine) executePayloadRequest(target string, template *Template, request Request, result *VulnerabilityResult) {
	// Implementation depends on attack type
	switch template.Attack {
	case "batteringram":
		e.executeBatteringram(target, template, request, result)
	case "pitchfork":
		e.executePitchfork(target, template, request, result)
	case "clusterbomb":
		e.executeClusterbomb(target, template, request, result)
	default:
		e.executeBatteringram(target, template, request, result)
	}
}

// checkMatchers checks if response matches conditions
func (e *TemplateEngine) checkMatchers(matchers []Matcher, resp *http.Response, body []byte) bool {
	if len(matchers) == 0 {
		return true // No matchers means always match
	}
	
	for _, matcher := range matchers {
		matched := false
		
		switch matcher.Type {
		case "status":
			for _, status := range matcher.Status {
				if resp.StatusCode == status {
					matched = true
					break
				}
			}
			
		case "word":
			bodyStr := string(body)
			if !matcher.CaseSensitive {
				bodyStr = strings.ToLower(bodyStr)
			}
			
			for _, word := range matcher.Words {
				if !matcher.CaseSensitive {
					word = strings.ToLower(word)
				}
				if strings.Contains(bodyStr, word) {
					matched = true
					break
				}
			}
			
		case "regex":
			for _, pattern := range matcher.Regex {
				if match, _ := regexp.Match(pattern, body); match {
					matched = true
					break
				}
			}
			
		case "size":
			bodySize := len(body)
			for _, size := range matcher.Size {
				if bodySize == size {
					matched = true
					break
				}
			}
		}
		
		// Handle negative matching
		if matcher.Negative {
			matched = !matched
		}
		
		// Check condition (and/or)
		if matcher.Condition == "and" && !matched {
			return false
		} else if matcher.Condition == "or" && matched {
			return true
		}
	}
	
	return true
}

// runExtractors extracts information from response
func (e *TemplateEngine) runExtractors(extractors []Extractor, resp *http.Response, body []byte) map[string][]string {
	results := make(map[string][]string)
	
	for _, extractor := range extractors {
		name := extractor.Name
		if name == "" {
			name = extractor.Type
		}
		
		switch extractor.Type {
		case "regex":
			for _, pattern := range extractor.Regex {
				re, err := regexp.Compile(pattern)
				if err != nil {
					continue
				}
				
				matches := re.FindAllStringSubmatch(string(body), -1)
				for _, match := range matches {
					if extractor.Group < len(match) {
						results[name] = append(results[name], match[extractor.Group])
					}
				}
			}
			
		case "json":
			// JSON extraction logic
			var jsonData interface{}
			if err := json.Unmarshal(body, &jsonData); err == nil {
				// Extract JSON paths
				for _, path := range extractor.JSON {
					// Simplified JSON path extraction
					results[name] = append(results[name], fmt.Sprintf("%v", jsonData))
				}
			}
		}
	}
	
	return results
}

// performBehaviorChecks performs behavioral validation
func (e *TemplateEngine) performBehaviorChecks(target string, template *Template) float64 {
	totalChecks := len(template.BehaviorChecks)
	passedChecks := 0
	
	for _, check := range template.BehaviorChecks {
		switch check.Type {
		case "timing":
			if e.checkTimingBehavior(target, template, check) {
				passedChecks++
			}
			
		case "response_diff":
			if e.checkResponseDifferential(target, template, check) {
				passedChecks++
			}
			
		case "oob":
			if e.checkOutOfBand(target, template, check) {
				passedChecks++
			}
		}
	}
	
	if totalChecks == 0 {
		return 1.0
	}
	
	return float64(passedChecks) / float64(totalChecks)
}

// validateExploitability validates if vulnerability is exploitable
func (e *TemplateEngine) validateExploitability(target string, template *Template) bool {
	if template.ExploitValidation == nil {
		return false
	}
	
	switch template.ExploitValidation.Type {
	case "command_exec":
		return e.validateCommandExecution(target, template)
		
	case "file_read":
		return e.validateFileRead(target, template)
		
	case "ssrf":
		return e.validateSSRF(target, template)
	}
	
	return false
}

// Helper methods

func (e *TemplateEngine) hasMatchingTag(templateTags []string, filterTags []string) bool {
	for _, filterTag := range filterTags {
		for _, templateTag := range templateTags {
			if filterTag == templateTag {
				return true
			}
		}
	}
	return false
}

func (e *TemplateEngine) getSeverityColor(severity string) color.Attribute {
	switch strings.ToLower(severity) {
	case "critical":
		return color.FgHiRed
	case "high":
		return color.FgRed
	case "medium":
		return color.FgYellow
	case "low":
		return color.FgBlue
	default:
		return color.FgWhite
	}
}

func (e *TemplateEngine) getRandomUserAgent() string {
	return e.userAgents[time.Now().UnixNano()%int64(len(e.userAgents))]
}

func (e *TemplateEngine) applyStealthDelay(min, max int) {
	if max <= min {
		return
	}
	delay := time.Duration(min + int(time.Now().UnixNano()%(int64(max-min))))
	time.Sleep(delay * time.Millisecond)
}

func (e *TemplateEngine) createHTTPRequest(method, url, body string) (*http.Request, error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = bytes.NewBufferString(body)
	}
	
	return http.NewRequest(method, url, bodyReader)
}

func (e *TemplateEngine) calculateFalsePositiveRate() {
	if e.totalMatches > 0 {
		rate := float64(e.falsePositives) / float64(e.totalMatches) * 100
		if rate > 20 {
			color.Yellow("[!] High false positive rate: %.2f%%", rate)
		}
	}
}

// Stub implementations for complex checks

func (e *TemplateEngine) checkTimingBehavior(target string, template *Template, check BehaviorCheck) bool {
	// Implement timing-based behavior validation
	return true
}

func (e *TemplateEngine) checkResponseDifferential(target string, template *Template, check BehaviorCheck) bool {
	// Implement response differential analysis
	return true
}

func (e *TemplateEngine) checkOutOfBand(target string, template *Template, check BehaviorCheck) bool {
	// Implement out-of-band detection
	return false
}

func (e *TemplateEngine) validateCommandExecution(target string, template *Template) bool {
	// Implement command execution validation
	return false
}

func (e *TemplateEngine) validateFileRead(target string, template *Template) bool {
	// Implement file read validation
	return false
}

func (e *TemplateEngine) validateSSRF(target string, template *Template) bool {
	// Implement SSRF validation
	return false
}

func (e *TemplateEngine) executeBatteringram(target string, template *Template, request Request, result *VulnerabilityResult) {
	// All payloads in same position
	for name, payloads := range template.Payloads {
		for _, payload := range payloads {
			// Replace placeholder with payload
			path := strings.ReplaceAll(request.Path[0], fmt.Sprintf("{{%s}}", name), payload)
			body := strings.ReplaceAll(request.Body, fmt.Sprintf("{{%s}}", name), payload)
			
			// Execute request
			modifiedRequest := request
			modifiedRequest.Path = []string{path}
			modifiedRequest.Body = body
			
			e.executeSingleRequest(target, template, modifiedRequest, result)
			
			if result.Matched {
				result.Evidence["payload"] = payload
				return
			}
		}
	}
}

func (e *TemplateEngine) executePitchfork(target string, template *Template, request Request, result *VulnerabilityResult) {
	// Payloads in parallel positions
	// Implementation here
}

func (e *TemplateEngine) executeClusterbomb(target string, template *Template, request Request, result *VulnerabilityResult) {
	// All combinations of payloads
	// Implementation here
}
