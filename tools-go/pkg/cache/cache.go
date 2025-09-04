// Package cache provides intelligent caching with Redis for scan results
package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/fatih/color"
)

// CacheManager handles intelligent result caching
type CacheManager struct {
	// In-memory cache (fallback when Redis not available)
	memCache map[string]*CacheEntry
	mutex    sync.RWMutex
	
	// Configuration
	DefaultTTL   time.Duration
	MaxEntries   int
	EnableRedis  bool
	RedisAddr    string
	
	// Statistics
	hits   int64
	misses int64
	
	// Cleanup
	stopCleanup chan bool
}

// CacheEntry represents a cached scan result
type CacheEntry struct {
	Key        string                 `json:"key"`
	Type       string                 `json:"type"` // subdomain, url, vulnerability, port
	Target     string                 `json:"target"`
	Result     interface{}            `json:"result"`
	Hash       string                 `json:"hash"`
	Timestamp  time.Time              `json:"timestamp"`
	TTL        time.Duration          `json:"ttl"`
	HitCount   int                    `json:"hit_count"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// CacheConfig holds cache configuration
type CacheConfig struct {
	DefaultTTL   time.Duration
	MaxEntries   int
	EnableRedis  bool
	RedisAddr    string
	CleanupTime  time.Duration
}

// NewCacheManager creates a new cache manager
func NewCacheManager(config *CacheConfig) *CacheManager {
	if config == nil {
		config = &CacheConfig{
			DefaultTTL:  1 * time.Hour,
			MaxEntries:  10000,
			EnableRedis: false,
			CleanupTime: 5 * time.Minute,
		}
	}
	
	cm := &CacheManager{
		memCache:    make(map[string]*CacheEntry),
		DefaultTTL:  config.DefaultTTL,
		MaxEntries:  config.MaxEntries,
		EnableRedis: config.EnableRedis,
		RedisAddr:   config.RedisAddr,
		stopCleanup: make(chan bool),
	}
	
	// Start cleanup routine
	go cm.cleanupRoutine(config.CleanupTime)
	
	return cm
}

// GenerateKey creates a unique cache key for a scan
func (cm *CacheManager) GenerateKey(scanType, target string, options map[string]interface{}) string {
	data := fmt.Sprintf("%s:%s", scanType, target)
	
	// Add options to key generation
	if options != nil {
		optJson, _ := json.Marshal(options)
		data += ":" + string(optJson)
	}
	
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:16]) // Use first 16 bytes for shorter keys
}

// Get retrieves a cached entry
func (cm *CacheManager) Get(key string) (*CacheEntry, bool) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	entry, exists := cm.memCache[key]
	if !exists {
		cm.misses++
		return nil, false
	}
	
	// Check if entry is expired
	if time.Since(entry.Timestamp) > entry.TTL {
		// Entry expired, remove it
		cm.mutex.RUnlock()
		cm.mutex.Lock()
		delete(cm.memCache, key)
		cm.mutex.Unlock()
		cm.mutex.RLock()
		
		cm.misses++
		return nil, false
	}
	
	entry.HitCount++
	cm.hits++
	return entry, true
}

// Set stores a scan result in cache
func (cm *CacheManager) Set(key, scanType, target string, result interface{}, ttl time.Duration) {
	if ttl == 0 {
		ttl = cm.DefaultTTL
	}
	
	entry := &CacheEntry{
		Key:       key,
		Type:      scanType,
		Target:    target,
		Result:    result,
		Timestamp: time.Now(),
		TTL:       ttl,
		HitCount:  0,
		Metadata:  make(map[string]interface{}),
	}
	
	// Generate hash of result for comparison
	resultJson, _ := json.Marshal(result)
	hash := sha256.Sum256(resultJson)
	entry.Hash = fmt.Sprintf("%x", hash)
	
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	// Check max entries limit
	if len(cm.memCache) >= cm.MaxEntries {
		// Remove oldest entry
		cm.evictOldest()
	}
	
	cm.memCache[key] = entry
}

// ShouldScan checks if a target needs scanning based on cache
func (cm *CacheManager) ShouldScan(scanType, target string, options map[string]interface{}, forceTTL time.Duration) bool {
	key := cm.GenerateKey(scanType, target, options)
	
	entry, exists := cm.Get(key)
	if !exists {
		return true // Not in cache, should scan
	}
	
	// Check if custom TTL is provided and entry is older
	if forceTTL > 0 && time.Since(entry.Timestamp) > forceTTL {
		return true // Entry too old for requested TTL
	}
	
	color.Yellow("[Cache] Skipping %s scan for %s (cached %v ago)", 
		scanType, target, time.Since(entry.Timestamp).Round(time.Second))
	
	return false
}

// GetOrScan retrieves from cache or performs scan
func (cm *CacheManager) GetOrScan(scanType, target string, options map[string]interface{}, 
	scanFunc func() (interface{}, error), ttl time.Duration) (interface{}, bool, error) {
	
	key := cm.GenerateKey(scanType, target, options)
	
	// Check cache first
	if entry, exists := cm.Get(key); exists {
		color.Green("[Cache HIT] %s for %s", scanType, target)
		return entry.Result, true, nil
	}
	
	// Not in cache, perform scan
	color.Yellow("[Cache MISS] Scanning %s: %s", scanType, target)
	result, err := scanFunc()
	if err != nil {
		return nil, false, err
	}
	
	// Store in cache
	cm.Set(key, scanType, target, result, ttl)
	
	return result, false, nil
}

// InvalidatePattern removes entries matching a pattern
func (cm *CacheManager) InvalidatePattern(pattern string) int {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	removed := 0
	for key, entry := range cm.memCache {
		if matchPattern(entry.Target, pattern) || matchPattern(entry.Type, pattern) {
			delete(cm.memCache, key)
			removed++
		}
	}
	
	return removed
}

// Clear removes all cache entries
func (cm *CacheManager) Clear() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	cm.memCache = make(map[string]*CacheEntry)
	color.Yellow("[Cache] Cleared all entries")
}

// GetStatistics returns cache statistics
func (cm *CacheManager) GetStatistics() map[string]interface{} {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	totalEntries := len(cm.memCache)
	hitRate := float64(0)
	if cm.hits+cm.misses > 0 {
		hitRate = float64(cm.hits) / float64(cm.hits+cm.misses) * 100
	}
	
	// Calculate memory usage (approximate)
	memoryUsage := 0
	for _, entry := range cm.memCache {
		data, _ := json.Marshal(entry)
		memoryUsage += len(data)
	}
	
	return map[string]interface{}{
		"total_entries": totalEntries,
		"hits":         cm.hits,
		"misses":       cm.misses,
		"hit_rate":     fmt.Sprintf("%.2f%%", hitRate),
		"memory_usage": formatBytes(memoryUsage),
		"max_entries":  cm.MaxEntries,
		"default_ttl":  cm.DefaultTTL.String(),
	}
}

// Prioritize updates cache priority based on target criticality
func (cm *CacheManager) Prioritize(targets []string) []string {
	priorities := make([]struct{
		target   string
		priority int
		cached   bool
		age      time.Duration
	}, len(targets))
	
	for i, target := range targets {
		key := cm.GenerateKey("priority_check", target, nil)
		entry, exists := cm.Get(key)
		
		priority := 0
		age := time.Duration(0)
		
		if exists {
			age = time.Since(entry.Timestamp)
			// Lower priority for recently scanned
			priority = int(age.Hours())
		} else {
			// Higher priority for never scanned
			priority = 1000
		}
		
		// Adjust priority based on target characteristics
		if isHighValueTarget(target) {
			priority += 500
		}
		
		priorities[i] = struct{
			target   string
			priority int
			cached   bool
			age      time.Duration
		}{
			target:   target,
			priority: priority,
			cached:   exists,
			age:      age,
		}
	}
	
	// Sort by priority (higher first)
	sortByPriority(priorities)
	
	// Return sorted targets
	sorted := make([]string, len(priorities))
	for i, p := range priorities {
		sorted[i] = p.target
		if p.cached {
			color.Cyan("[Priority] %s (cached %v ago, priority: %d)", 
				p.target, p.age.Round(time.Second), p.priority)
		} else {
			color.Yellow("[Priority] %s (never scanned, priority: %d)", 
				p.target, p.priority)
		}
	}
	
	return sorted
}

// Helper functions

func (cm *CacheManager) evictOldest() {
	if len(cm.memCache) == 0 {
		return
	}
	
	var oldestKey string
	var oldestTime time.Time
	
	for key, entry := range cm.memCache {
		if oldestKey == "" || entry.Timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.Timestamp
		}
	}
	
	if oldestKey != "" {
		delete(cm.memCache, oldestKey)
	}
}

func (cm *CacheManager) cleanupRoutine(interval time.Duration) {
	// Ensure interval is positive
	if interval <= 0 {
		interval = 5 * time.Minute // Default to 5 minutes
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			cm.cleanupExpired()
		case <-cm.stopCleanup:
			return
		}
	}
}

func (cm *CacheManager) cleanupExpired() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	expired := []string{}
	now := time.Now()
	
	for key, entry := range cm.memCache {
		if now.Sub(entry.Timestamp) > entry.TTL {
			expired = append(expired, key)
		}
	}
	
	for _, key := range expired {
		delete(cm.memCache, key)
	}
	
	if len(expired) > 0 {
		color.Yellow("[Cache] Cleaned up %d expired entries", len(expired))
	}
}

func matchPattern(text, pattern string) bool {
	// Simple pattern matching (can be enhanced with regex)
	return text == pattern || 
		   (len(pattern) > 0 && pattern[0] == '*' && len(text) >= len(pattern)-1 && 
		    text[len(text)-(len(pattern)-1):] == pattern[1:])
}

func isHighValueTarget(target string) bool {
	// Identify high-value targets
	highValueKeywords := []string{
		"admin", "api", "auth", "login", "portal",
		"payment", "checkout", "account", "user",
		"secure", "private", "internal", "vpn",
	}
	
	for _, keyword := range highValueKeywords {
		if matchPattern(target, "*"+keyword+"*") {
			return true
		}
	}
	
	return false
}

func sortByPriority(priorities []struct{
	target   string
	priority int
	cached   bool
	age      time.Duration
}) {
	// Simple bubble sort (can be replaced with more efficient algorithm)
	n := len(priorities)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if priorities[j].priority < priorities[j+1].priority {
				priorities[j], priorities[j+1] = priorities[j+1], priorities[j]
			}
		}
	}
}

func formatBytes(bytes int) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// Close stops the cache manager
func (cm *CacheManager) Close() {
	close(cm.stopCleanup)
	cm.Clear()
}
