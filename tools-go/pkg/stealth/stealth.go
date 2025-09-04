// Package stealth provides advanced evasion and stealth capabilities
package stealth

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"golang.org/x/net/proxy"
)

// StealthManager handles advanced stealth operations
type StealthManager struct {
	// Configuration
	config *StealthConfig
	
	// Proxies
	proxies      []ProxyConfig
	currentProxy int
	proxyMutex   sync.Mutex
	
	// User Agents
	userAgents []string
	
	// Headers
	headerSets []map[string]string
	
	// Attack Profile
	profile        AttackProfile
	profileAdapter *ProfileAdapter
	
	// Statistics
	stats      *StealthStats
	statsMutex sync.RWMutex
}

// StealthConfig holds stealth configuration
type StealthConfig struct {
	// Basic Settings
	Enabled bool
	Level   int // 0=off, 1=low, 2=medium, 3=high, 4=paranoid
	
	// Timing
	MinDelay       int // milliseconds
	MaxDelay       int
	JitterEnabled  bool
	AdaptiveTiming bool
	
	// Headers
	RandomUserAgent  bool
	RandomHeaders    bool
	SpoofReferrer    bool
	SpoofOrigin      bool
	
	// Proxies
	UseProxies       bool
	ProxyRotation    bool
	ResidentialOnly  bool
	ProxyTimeout     time.Duration
	
	// Packet Level
	FragmentPackets  bool
	FragmentSize     int
	TCPWindowSize    int
	
	// Evasion
	EncodePayloads   bool
	ObfuscateQueries bool
	TunnelTraffic    bool
	UseDecoys        bool
	
	// Adaptive
	AdaptiveProfile  bool
	MaxRetries       int
	BackoffMultiplier float64
}

// ProxyConfig represents a proxy configuration
type ProxyConfig struct {
	Type        string // http, socks5, residential
	Address     string
	Username    string
	Password    string
	Country     string
	City        string
	Residential bool
	Latency     time.Duration
	LastUsed    time.Time
	FailCount   int
	Alive       bool
}

// AttackProfile represents current attack profile
type AttackProfile int

const (
	ProfileStealth AttackProfile = iota
	ProfileLow
	ProfileMedium
	ProfileHigh
	ProfileAggressive
)

// ProfileAdapter adapts attack profile based on target responses
type ProfileAdapter struct {
	currentProfile AttackProfile
	mutex          sync.RWMutex
	
	// Detection indicators
	blockedRequests   int
	successfulRequests int
	rateLimit        int
	wafDetected      bool
	captchaDetected  bool
	
	// Thresholds
	blockThreshold    int
	successThreshold  int
	adaptInterval     time.Duration
	lastAdaptation    time.Time
}

// StealthStats tracks stealth statistics
type StealthStats struct {
	RequestsSent      int64
	RequestsBlocked   int64
	ProxiesRotated    int64
	ProfileAdaptations int64
	AvgLatency        time.Duration
	DetectionEvents   int64
}

// NewStealthManager creates a new stealth manager
func NewStealthManager(config *StealthConfig) *StealthManager {
	if config == nil {
		config = DefaultStealthConfig()
	}
	
	sm := &StealthManager{
		config:     config,
		proxies:    []ProxyConfig{},
		userAgents: loadUserAgents(),
		headerSets: loadHeaderSets(),
		profile:    ProfileMedium,
		stats:      &StealthStats{},
	}
	
	// Initialize profile adapter
	if config.AdaptiveProfile {
		sm.profileAdapter = &ProfileAdapter{
			currentProfile:   ProfileMedium,
			blockThreshold:   5,
			successThreshold: 10,
			adaptInterval:    30 * time.Second,
			lastAdaptation:   time.Now(),
		}
	}
	
	// Load proxies if enabled
	if config.UseProxies {
		sm.loadProxies()
	}
	
	return sm
}

// DefaultStealthConfig returns default stealth configuration
func DefaultStealthConfig() *StealthConfig {
	return &StealthConfig{
		Enabled:          true,
		Level:            2, // Medium
		MinDelay:         100,
		MaxDelay:         2000,
		JitterEnabled:    true,
		AdaptiveTiming:   true,
		RandomUserAgent:  true,
		RandomHeaders:    true,
		SpoofReferrer:    true,
		UseProxies:       false,
		ProxyRotation:    true,
		FragmentPackets:  false,
		FragmentSize:     8,
		EncodePayloads:   true,
		AdaptiveProfile:  true,
		MaxRetries:       3,
		BackoffMultiplier: 1.5,
	}
}

// ApplyStealthToRequest applies stealth techniques to HTTP request
func (sm *StealthManager) ApplyStealthToRequest(req *http.Request) error {
	if !sm.config.Enabled {
		return nil
	}
	
	// Apply delay
	sm.applyDelay()
	
	// Randomize headers
	if sm.config.RandomUserAgent {
		req.Header.Set("User-Agent", sm.getRandomUserAgent())
	}
	
	if sm.config.RandomHeaders {
		sm.applyRandomHeaders(req)
	}
	
	if sm.config.SpoofReferrer {
		req.Header.Set("Referer", sm.generateReferrer(req.URL))
	}
	
	if sm.config.SpoofOrigin {
		req.Header.Set("Origin", sm.generateOrigin(req.URL))
	}
	
	// Apply additional evasion headers
	sm.applyEvasionHeaders(req)
	
	return nil
}

// GetStealthClient returns HTTP client with stealth configuration
func (sm *StealthManager) GetStealthClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		},
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: false,
	}
	
	// Apply proxy if enabled
	if sm.config.UseProxies {
		proxyConfig := sm.getNextProxy()
		if proxyConfig != nil {
			transport.Proxy = sm.createProxyFunc(proxyConfig)
		}
	}
	
	// Apply packet fragmentation if enabled
	if sm.config.FragmentPackets {
		transport.DialContext = sm.createFragmentedDialer()
	}
	
	// Custom TCP settings for evasion
	if sm.config.TCPWindowSize > 0 {
		transport.DialContext = sm.createCustomTCPDialer()
	}
	
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			// Apply stealth to redirect requests too
			sm.ApplyStealthToRequest(req)
			return nil
		},
	}
}

// AdaptProfile adapts attack profile based on responses
func (sm *StealthManager) AdaptProfile(response *http.Response, blocked bool) {
	if !sm.config.AdaptiveProfile || sm.profileAdapter == nil {
		return
	}
	
	sm.profileAdapter.mutex.Lock()
	defer sm.profileAdapter.mutex.Unlock()
	
	if blocked {
		sm.profileAdapter.blockedRequests++
		sm.stats.RequestsBlocked++
	} else {
		sm.profileAdapter.successfulRequests++
	}
	
	// Check if adaptation is needed
	if time.Since(sm.profileAdapter.lastAdaptation) < sm.profileAdapter.adaptInterval {
		return
	}
	
	// Calculate block rate
	total := sm.profileAdapter.blockedRequests + sm.profileAdapter.successfulRequests
	if total == 0 {
		return
	}
	
	blockRate := float64(sm.profileAdapter.blockedRequests) / float64(total)
	
	// Adapt profile based on block rate
	oldProfile := sm.profileAdapter.currentProfile
	
	switch {
	case blockRate > 0.5:
		// High block rate - increase stealth
		sm.increaseStealthLevel()
	case blockRate > 0.2:
		// Medium block rate - maintain or slightly increase
		if sm.profileAdapter.currentProfile == ProfileAggressive {
			sm.profileAdapter.currentProfile = ProfileHigh
		}
	case blockRate < 0.05:
		// Low block rate - can be more aggressive
		sm.decreaseStealthLevel()
	}
	
	if oldProfile != sm.profileAdapter.currentProfile {
		sm.stats.ProfileAdaptations++
		color.Yellow("[Stealth] Profile adapted: %s -> %s (block rate: %.2f%%)",
			profileToString(oldProfile),
			profileToString(sm.profileAdapter.currentProfile),
			blockRate*100)
		
		// Update configuration based on new profile
		sm.updateConfigForProfile()
	}
	
	// Reset counters
	sm.profileAdapter.blockedRequests = 0
	sm.profileAdapter.successfulRequests = 0
	sm.profileAdapter.lastAdaptation = time.Now()
}

// Private methods

func (sm *StealthManager) applyDelay() {
	if sm.config.MinDelay == 0 && sm.config.MaxDelay == 0 {
		return
	}
	
	delay := sm.config.MinDelay
	
	if sm.config.MaxDelay > sm.config.MinDelay {
		// Random delay between min and max
		delay += rand.Intn(sm.config.MaxDelay - sm.config.MinDelay)
	}
	
	// Apply jitter if enabled
	if sm.config.JitterEnabled {
		jitter := rand.Intn(delay/10) - delay/20 // ±5% jitter
		delay += jitter
	}
	
	// Apply profile multiplier
	if sm.profileAdapter != nil {
		delay = sm.applyProfileMultiplier(delay)
	}
	
	time.Sleep(time.Duration(delay) * time.Millisecond)
}

func (sm *StealthManager) applyProfileMultiplier(delay int) int {
	sm.profileAdapter.mutex.RLock()
	defer sm.profileAdapter.mutex.RUnlock()
	
	switch sm.profileAdapter.currentProfile {
	case ProfileStealth:
		return delay * 3
	case ProfileLow:
		return delay * 2
	case ProfileMedium:
		return delay
	case ProfileHigh:
		return delay / 2
	case ProfileAggressive:
		return delay / 4
	}
	
	return delay
}

func (sm *StealthManager) getRandomUserAgent() string {
	return sm.userAgents[rand.Intn(len(sm.userAgents))]
}

func (sm *StealthManager) applyRandomHeaders(req *http.Request) {
	headers := sm.headerSets[rand.Intn(len(sm.headerSets))]
	for key, value := range headers {
		if req.Header.Get(key) == "" { // Don't override existing headers
			req.Header.Set(key, value)
		}
	}
}

func (sm *StealthManager) applyEvasionHeaders(req *http.Request) {
	// Add common browser headers for evasion
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Cache-Control", "max-age=0")
}

func (sm *StealthManager) generateReferrer(targetURL *url.URL) string {
	referrers := []string{
		"https://www.google.com/search?q=" + targetURL.Host,
		"https://www.bing.com/search?q=" + targetURL.Host,
		"https://duckduckgo.com/?q=" + targetURL.Host,
		"https://www.linkedin.com/",
		"https://twitter.com/",
		targetURL.Scheme + "://" + targetURL.Host,
	}
	return referrers[rand.Intn(len(referrers))]
}

func (sm *StealthManager) generateOrigin(targetURL *url.URL) string {
	return targetURL.Scheme + "://" + targetURL.Host
}

// Proxy management

func (sm *StealthManager) loadProxies() {
	// Load residential proxies
	residentialProxies := []ProxyConfig{
		// Example residential proxy providers
		{
			Type:        "http",
			Address:     "residential.proxy1.com:8080",
			Residential: true,
			Country:     "US",
			Alive:       true,
		},
		// In production, load from API or file
	}
	
	// Load regular proxies
	regularProxies := []ProxyConfig{
		{
			Type:    "socks5",
			Address: "127.0.0.1:9050", // Tor
			Alive:   true,
		},
	}
	
	if sm.config.ResidentialOnly {
		sm.proxies = residentialProxies
	} else {
		sm.proxies = append(residentialProxies, regularProxies...)
	}
}

func (sm *StealthManager) getNextProxy() *ProxyConfig {
	if len(sm.proxies) == 0 {
		return nil
	}
	
	sm.proxyMutex.Lock()
	defer sm.proxyMutex.Unlock()
	
	// Find next alive proxy
	attempts := 0
	for attempts < len(sm.proxies) {
		proxy := &sm.proxies[sm.currentProxy]
		
		if sm.config.ProxyRotation {
			sm.currentProxy = (sm.currentProxy + 1) % len(sm.proxies)
			sm.stats.ProxiesRotated++
		}
		
		if proxy.Alive && proxy.FailCount < 3 {
			proxy.LastUsed = time.Now()
			return proxy
		}
		
		attempts++
	}
	
	return nil
}

func (sm *StealthManager) createProxyFunc(proxyConfig *ProxyConfig) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		proxyURL := &url.URL{
			Scheme: proxyConfig.Type,
			Host:   proxyConfig.Address,
		}
		
		if proxyConfig.Username != "" {
			proxyURL.User = url.UserPassword(proxyConfig.Username, proxyConfig.Password)
		}
		
		return proxyURL, nil
	}
}

// Packet fragmentation

func (sm *StealthManager) createFragmentedDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Create connection
		conn, err := net.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		
		// Wrap with fragmented connection
		return &fragmentedConn{
			Conn:         conn,
			fragmentSize: sm.config.FragmentSize,
		}, nil
	}
}

// fragmentedConn implements packet fragmentation
type fragmentedConn struct {
	net.Conn
	fragmentSize int
}

func (fc *fragmentedConn) Write(b []byte) (n int, err error) {
	// Fragment large packets
	if len(b) <= fc.fragmentSize {
		return fc.Conn.Write(b)
	}
	
	totalWritten := 0
	for i := 0; i < len(b); i += fc.fragmentSize {
		end := i + fc.fragmentSize
		if end > len(b) {
			end = len(b)
		}
		
		// Write fragment
		written, err := fc.Conn.Write(b[i:end])
		totalWritten += written
		if err != nil {
			return totalWritten, err
		}
		
		// Small delay between fragments
		time.Sleep(time.Millisecond * time.Duration(rand.Intn(10)))
	}
	
	return totalWritten, nil
}

// Custom TCP dialer

func (sm *StealthManager) createCustomTCPDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		
		// Set custom TCP options
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			// Set TCP window size
			tcpConn.SetNoDelay(false)
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(30 * time.Second)
			
			// Set socket options for evasion
			// This would require syscall level access in production
		}
		
		return conn, nil
	}
}

// Profile management

func (sm *StealthManager) increaseStealthLevel() {
	switch sm.profileAdapter.currentProfile {
	case ProfileAggressive:
		sm.profileAdapter.currentProfile = ProfileHigh
	case ProfileHigh:
		sm.profileAdapter.currentProfile = ProfileMedium
	case ProfileMedium:
		sm.profileAdapter.currentProfile = ProfileLow
	case ProfileLow:
		sm.profileAdapter.currentProfile = ProfileStealth
	}
}

func (sm *StealthManager) decreaseStealthLevel() {
	switch sm.profileAdapter.currentProfile {
	case ProfileStealth:
		sm.profileAdapter.currentProfile = ProfileLow
	case ProfileLow:
		sm.profileAdapter.currentProfile = ProfileMedium
	case ProfileMedium:
		sm.profileAdapter.currentProfile = ProfileHigh
	case ProfileHigh:
		sm.profileAdapter.currentProfile = ProfileAggressive
	}
}

func (sm *StealthManager) updateConfigForProfile() {
	sm.profileAdapter.mutex.RLock()
	profile := sm.profileAdapter.currentProfile
	sm.profileAdapter.mutex.RUnlock()
	
	switch profile {
	case ProfileStealth:
		sm.config.MinDelay = 5000
		sm.config.MaxDelay = 15000
		sm.config.FragmentPackets = true
		sm.config.UseProxies = true
		sm.config.ProxyRotation = true
		
	case ProfileLow:
		sm.config.MinDelay = 2000
		sm.config.MaxDelay = 8000
		sm.config.FragmentPackets = false
		sm.config.ProxyRotation = true
		
	case ProfileMedium:
		sm.config.MinDelay = 500
		sm.config.MaxDelay = 3000
		sm.config.FragmentPackets = false
		sm.config.ProxyRotation = false
		
	case ProfileHigh:
		sm.config.MinDelay = 100
		sm.config.MaxDelay = 1000
		sm.config.FragmentPackets = false
		sm.config.UseProxies = false
		
	case ProfileAggressive:
		sm.config.MinDelay = 0
		sm.config.MaxDelay = 200
		sm.config.FragmentPackets = false
		sm.config.UseProxies = false
	}
}

// EncodingObfuscation provides payload encoding and obfuscation
func (sm *StealthManager) EncodePayload(payload string) string {
	if !sm.config.EncodePayloads {
		return payload
	}
	
	// Apply multiple encoding layers based on profile
	encoded := payload
	
	// URL encoding
	encoded = url.QueryEscape(encoded)
	
	// Double encoding for high stealth
	if sm.profileAdapter != nil && sm.profileAdapter.currentProfile <= ProfileLow {
		encoded = url.QueryEscape(encoded)
	}
	
	// Unicode encoding for special characters
	encoded = sm.unicodeEncode(encoded)
	
	// Case variation
	if rand.Intn(2) == 0 {
		encoded = sm.randomCase(encoded)
	}
	
	return encoded
}

func (sm *StealthManager) unicodeEncode(s string) string {
	var result strings.Builder
	for _, r := range s {
		if rand.Intn(3) == 0 && r < 128 { // Randomly encode ASCII chars
			result.WriteString(fmt.Sprintf("\\u00%02x", r))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

func (sm *StealthManager) randomCase(s string) string {
	var result strings.Builder
	for _, r := range s {
		if rand.Intn(2) == 0 {
			result.WriteString(strings.ToUpper(string(r)))
		} else {
			result.WriteString(strings.ToLower(string(r)))
		}
	}
	return result.String()
}

// GetStatistics returns stealth statistics
func (sm *StealthManager) GetStatistics() *StealthStats {
	sm.statsMutex.RLock()
	defer sm.statsMutex.RUnlock()
	return sm.stats
}

// Helper functions

func profileToString(p AttackProfile) string {
	switch p {
	case ProfileStealth:
		return "Stealth"
	case ProfileLow:
		return "Low"
	case ProfileMedium:
		return "Medium"
	case ProfileHigh:
		return "High"
	case ProfileAggressive:
		return "Aggressive"
	default:
		return "Unknown"
	}
}

func loadUserAgents() []string {
	return []string{
		// Chrome variants
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		
		// Firefox variants
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		
		// Safari variants
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
		
		// Edge variants
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		
		// Mobile variants
		"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
		
		// Bot variants (for specific scenarios)
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	}
}

func loadHeaderSets() []map[string]string {
	return []map[string]string{
		// Standard browser headers
		{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
		},
		// Mobile headers
		{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.8",
			"Accept-Encoding": "gzip, deflate",
		},
		// API client headers
		{
			"Accept":          "application/json, text/plain, */*",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
			"Content-Type":    "application/json",
		},
	}
}

// TunnelConnection creates a tunneled connection for traffic
func (sm *StealthManager) TunnelConnection(target string) (net.Conn, error) {
	if !sm.config.TunnelTraffic {
		return net.Dial("tcp", target)
	}
	
	// Create SSH tunnel or VPN tunnel
	// This is a simplified implementation
	// In production, would use proper SSH/VPN libraries
	
	proxyConfig := sm.getNextProxy()
	if proxyConfig == nil {
		return net.Dial("tcp", target)
	}
	
	// Connect through proxy
	dialer, err := proxy.SOCKS5("tcp", proxyConfig.Address, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	
	return dialer.Dial("tcp", target)
}

// DecoyTraffic generates decoy traffic to obscure real requests
func (sm *StealthManager) GenerateDecoyTraffic(target string, numDecoys int) {
	if !sm.config.UseDecoys {
		return
	}
	
	// Generate benign-looking requests to hide real payloads
	decoyPaths := []string{
		"/robots.txt",
		"/favicon.ico",
		"/sitemap.xml",
		"/index.html",
		"/about",
		"/contact",
		"/privacy",
		"/terms",
	}
	
	client := sm.GetStealthClient()
	
	for i := 0; i < numDecoys; i++ {
		go func(path string) {
			url := target + path
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}
			
			sm.ApplyStealthToRequest(req)
			client.Do(req)
		}(decoyPaths[rand.Intn(len(decoyPaths))])
		
		// Random delay between decoys
		time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)
	}
}
