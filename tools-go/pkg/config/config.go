// Package config provides centralized configuration management for PADOCCA
package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete PADOCCA configuration
type Config struct {
	Global      GlobalConfig      `yaml:"global"`
	Network     NetworkConfig     `yaml:"network"`
	Scanner     ScannerConfig     `yaml:"scanner"`
	Bruteforce  BruteforceConfig  `yaml:"bruteforce"`
	Exploit     ExploitConfig     `yaml:"exploit"`
	OSINT       OSINTConfig       `yaml:"osint"`
	Reporting   ReportingConfig   `yaml:"reporting"`
	Security    SecurityConfig    `yaml:"security"`
	Development DevelopmentConfig `yaml:"development"`
	Profiles    map[string]map[string]interface{} `yaml:"profiles"`
}

// GlobalConfig holds global settings
type GlobalConfig struct {
	LogLevel     string           `yaml:"log_level"`
	OutputFormat string           `yaml:"output_format"`
	ResultsDir   string           `yaml:"results_dir"`
	Cache        CacheConfig      `yaml:"cache"`
	Performance  PerformanceConfig `yaml:"performance"`
}

// CacheConfig holds cache settings
type CacheConfig struct {
	Enabled bool  `yaml:"enabled"`
	TTL     int   `yaml:"ttl"`
	MaxSize int   `yaml:"max_size"`
}

// PerformanceConfig holds performance settings
type PerformanceConfig struct {
	MaxWorkers int `yaml:"max_workers"`
	MaxMemory  int `yaml:"max_memory"`
	CPULimit   int `yaml:"cpu_limit"`
}

// NetworkConfig holds network settings
type NetworkConfig struct {
	Connection ConnectionConfig `yaml:"connection"`
	SSL        SSLConfig        `yaml:"ssl"`
	Proxy      ProxyConfig      `yaml:"proxy"`
	RateLimit  RateLimitConfig  `yaml:"rate_limit"`
	UserAgents UserAgentConfig  `yaml:"user_agents"`
}

// ConnectionConfig holds connection settings
type ConnectionConfig struct {
	Timeout    int `yaml:"timeout"`
	RetryCount int `yaml:"retry_count"`
	RetryDelay int `yaml:"retry_delay"`
}

// SSLConfig holds SSL/TLS settings
type SSLConfig struct {
	Verify       bool     `yaml:"verify"`
	MinVersion   string   `yaml:"min_version"`
	CipherSuites []string `yaml:"cipher_suites"`
}

// ProxyConfig holds proxy settings
type ProxyConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Type     string `yaml:"type"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// RateLimitConfig holds rate limiting settings
type RateLimitConfig struct {
	Enabled            bool `yaml:"enabled"`
	RequestsPerSecond  int  `yaml:"requests_per_second"`
	BurstSize          int  `yaml:"burst_size"`
}

// UserAgentConfig holds user agent settings
type UserAgentConfig struct {
	Rotate      bool     `yaml:"rotate"`
	CustomList  []string `yaml:"custom_list"`
	DefaultList []string `yaml:"default_list"`
}

// ScannerConfig holds scanner settings
type ScannerConfig struct {
	PortScan   PortScanConfig   `yaml:"port_scan"`
	WebCrawler WebCrawlerConfig `yaml:"web_crawler"`
	DNSEnum    DNSEnumConfig    `yaml:"dns_enum"`
}

// PortScanConfig holds port scanner settings
type PortScanConfig struct {
	Technique string `yaml:"technique"`
	Ports     string `yaml:"ports"`
	Threads   int    `yaml:"threads"`
	Timeout   int    `yaml:"timeout"`
}

// WebCrawlerConfig holds web crawler settings
type WebCrawlerConfig struct {
	MaxDepth         int  `yaml:"max_depth"`
	MaxPages         int  `yaml:"max_pages"`
	FollowRedirects  bool `yaml:"follow_redirects"`
	ParseJavascript  bool `yaml:"parse_javascript"`
	RespectRobots    bool `yaml:"respect_robots"`
}

// DNSEnumConfig holds DNS enumeration settings
type DNSEnumConfig struct {
	Recursive     bool     `yaml:"recursive"`
	ZoneTransfer  bool     `yaml:"zone_transfer"`
	Bruteforce    bool     `yaml:"bruteforce"`
	Resolvers     []string `yaml:"resolvers"`
}

// BruteforceConfig holds bruteforce settings
type BruteforceConfig struct {
	General     GeneralBruteConfig    `yaml:"general"`
	Timing      TimingConfig          `yaml:"timing"`
	Stealth     StealthConfig         `yaml:"stealth"`
	Intelligent IntelligentConfig     `yaml:"intelligent"`
	WAFBypass   WAFBypassConfig       `yaml:"waf_bypass"`
	Protocols   map[string]ProtoConfig `yaml:"protocols"`
}

// GeneralBruteConfig holds general bruteforce settings
type GeneralBruteConfig struct {
	StopOnSuccess  bool `yaml:"stop_on_success"`
	RandomizeOrder bool `yaml:"randomize_order"`
	SmartMode      bool `yaml:"smart_mode"`
}

// TimingConfig holds timing settings
type TimingConfig struct {
	DelayMin int  `yaml:"delay_min"`
	DelayMax int  `yaml:"delay_max"`
	Adaptive bool `yaml:"adaptive"`
}

// StealthConfig holds stealth mode settings
type StealthConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Level      int      `yaml:"level"`
	Techniques []string `yaml:"techniques"`
}

// IntelligentConfig holds intelligent mode settings
type IntelligentConfig struct {
	Enabled           bool `yaml:"enabled"`
	FingerprintFirst  bool `yaml:"fingerprint_first"`
	DetectWAF         bool `yaml:"detect_waf"`
	CheckDefaultCreds bool `yaml:"check_default_creds"`
	GenerateVariants  bool `yaml:"generate_variants"`
}

// WAFBypassConfig holds WAF bypass settings
type WAFBypassConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Techniques []string `yaml:"techniques"`
}

// ProtoConfig holds protocol-specific settings
type ProtoConfig struct {
	Port           int               `yaml:"port"`
	Timeout        int               `yaml:"timeout"`
	AuthMethods    []string          `yaml:"auth_methods,omitempty"`
	FollowRedirects bool             `yaml:"follow_redirects,omitempty"`
	MaxRedirects   int               `yaml:"max_redirects,omitempty"`
	CustomHeaders  map[string]string `yaml:"custom_headers,omitempty"`
	Passive        bool              `yaml:"passive,omitempty"`
	Security       string            `yaml:"security,omitempty"`
}

// ExploitConfig holds exploit framework settings
type ExploitConfig struct {
	Payload   PayloadConfig   `yaml:"payload"`
	Shellcode ShellcodeConfig `yaml:"shellcode"`
	Evasion   EvasionConfig   `yaml:"evasion"`
	ROP       ROPConfig       `yaml:"rop"`
}

// PayloadConfig holds payload settings
type PayloadConfig struct {
	Encoder  string   `yaml:"encoder"`
	BadChars []string `yaml:"bad_chars"`
	MaxSize  int      `yaml:"max_size"`
}

// ShellcodeConfig holds shellcode settings
type ShellcodeConfig struct {
	Type  string `yaml:"type"`
	LHost string `yaml:"lhost"`
	LPort int    `yaml:"lport"`
}

// EvasionConfig holds evasion settings
type EvasionConfig struct {
	AntivirusBypass   bool `yaml:"antivirus_bypass"`
	SandboxDetection  bool `yaml:"sandbox_detection"`
	DebuggerDetection bool `yaml:"debugger_detection"`
}

// ROPConfig holds ROP chain settings
type ROPConfig struct {
	AutoGenerate   bool   `yaml:"auto_generate"`
	GadgetDatabase string `yaml:"gadget_database"`
}

// OSINTConfig holds OSINT settings
type OSINTConfig struct {
	Sources    map[string]DataSourceConfig `yaml:"sources"`
	Search     SearchConfig                `yaml:"search"`
	Enrichment EnrichmentConfig            `yaml:"enrichment"`
}

// DataSourceConfig holds data source settings
type DataSourceConfig struct {
	Enabled   bool   `yaml:"enabled"`
	APIKey    string `yaml:"api_key,omitempty"`
	APIID     string `yaml:"api_id,omitempty"`
	APISecret string `yaml:"api_secret,omitempty"`
}

// SearchConfig holds search settings
type SearchConfig struct {
	MaxResults        int  `yaml:"max_results"`
	IncludeSubdomains bool `yaml:"include_subdomains"`
	CheckWayback      bool `yaml:"check_wayback"`
}

// EnrichmentConfig holds enrichment settings
type EnrichmentConfig struct {
	Whois           bool `yaml:"whois"`
	DNSRecords      bool `yaml:"dns_records"`
	SSLCertificates bool `yaml:"ssl_certificates"`
	TechnologyStack bool `yaml:"technology_stack"`
	SocialMedia     bool `yaml:"social_media"`
	EmployeeSearch  bool `yaml:"employee_search"`
}

// ReportingConfig holds reporting settings
type ReportingConfig struct {
	Formats       []string               `yaml:"formats"`
	Content       ContentConfig          `yaml:"content"`
	Templates     TemplateConfig         `yaml:"templates"`
	Notifications NotificationConfig     `yaml:"notifications"`
}

// ContentConfig holds report content settings
type ContentConfig struct {
	ExecutiveSummary     bool `yaml:"executive_summary"`
	TechnicalDetails     bool `yaml:"technical_details"`
	VulnerabilityDetails bool `yaml:"vulnerability_details"`
	Recommendations      bool `yaml:"recommendations"`
	ComplianceMapping    bool `yaml:"compliance_mapping"`
}

// TemplateConfig holds template settings
type TemplateConfig struct {
	HTML string `yaml:"html"`
	PDF  string `yaml:"pdf"`
}

// NotificationConfig holds notification settings
type NotificationConfig struct {
	Email   EmailNotifConfig   `yaml:"email"`
	Slack   SlackNotifConfig   `yaml:"slack"`
	Discord DiscordNotifConfig `yaml:"discord"`
}

// EmailNotifConfig holds email notification settings
type EmailNotifConfig struct {
	Enabled    bool     `yaml:"enabled"`
	SMTPServer string   `yaml:"smtp_server"`
	SMTPPort   int      `yaml:"smtp_port"`
	UseTLS     bool     `yaml:"use_tls"`
	Username   string   `yaml:"username"`
	Password   string   `yaml:"password"`
	From       string   `yaml:"from"`
	To         []string `yaml:"to"`
}

// SlackNotifConfig holds Slack notification settings
type SlackNotifConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
}

// DiscordNotifConfig holds Discord notification settings
type DiscordNotifConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
}

// SecurityConfig holds security settings
type SecurityConfig struct {
	Authentication AuthConfig          `yaml:"authentication"`
	Encryption     EncryptionConfig    `yaml:"encryption"`
	Audit          AuditConfig         `yaml:"audit"`
	Compliance     ComplianceConfig    `yaml:"compliance"`
	AntiForensics  AntiForensicsConfig `yaml:"anti_forensics"`
}

// AuthConfig holds authentication settings
type AuthConfig struct {
	Required bool   `yaml:"required"`
	Method   string `yaml:"method"`
}

// EncryptionConfig holds encryption settings
type EncryptionConfig struct {
	Algorithm     string `yaml:"algorithm"`
	KeyDerivation string `yaml:"key_derivation"`
}

// AuditConfig holds audit settings
type AuditConfig struct {
	Enabled   bool   `yaml:"enabled"`
	LogFile   string `yaml:"log_file"`
	LogFormat string `yaml:"log_format"`
}

// ComplianceConfig holds compliance settings
type ComplianceConfig struct {
	GDPRMode         bool `yaml:"gdpr_mode"`
	LogRetentionDays int  `yaml:"log_retention_days"`
}

// AntiForensicsConfig holds anti-forensics settings
type AntiForensicsConfig struct {
	ClearLogs    bool `yaml:"clear_logs"`
	SecureDelete bool `yaml:"secure_delete"`
	MemoryWipe   bool `yaml:"memory_wipe"`
}

// DevelopmentConfig holds development settings
type DevelopmentConfig struct {
	Debug     DebugConfig     `yaml:"debug"`
	Testing   TestingConfig   `yaml:"testing"`
	Profiling ProfilingConfig `yaml:"profiling"`
}

// DebugConfig holds debug settings
type DebugConfig struct {
	Enabled       bool `yaml:"enabled"`
	Verbose       bool `yaml:"verbose"`
	SaveRequests  bool `yaml:"save_requests"`
	SaveResponses bool `yaml:"save_responses"`
}

// TestingConfig holds testing settings
type TestingConfig struct {
	MockMode    bool     `yaml:"mock_mode"`
	TestTargets []string `yaml:"test_targets"`
}

// ProfilingConfig holds profiling settings
type ProfilingConfig struct {
	Enabled       bool `yaml:"enabled"`
	CPUProfile    bool `yaml:"cpu_profile"`
	MemoryProfile bool `yaml:"memory_profile"`
	Trace         bool `yaml:"trace"`
}

var (
	globalConfig *Config
	configPath   string
)

// Load loads the configuration from file
func Load(path string) (*Config, error) {
	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Try to find config in common locations
		locations := []string{
			"config.yaml",
			"config.yml",
			"./config.yaml",
			"../config.yaml",
			filepath.Join(os.Getenv("HOME"), ".padocca", "config.yaml"),
			"/etc/padocca/config.yaml",
		}
		
		found := false
		for _, loc := range locations {
			if _, err := os.Stat(loc); err == nil {
				path = loc
				found = true
				break
			}
		}
		
		if !found {
			// Use config.template.yaml as fallback
			if _, err := os.Stat("config.template.yaml"); err == nil {
				path = "config.template.yaml"
			} else {
				return nil, fmt.Errorf("config file not found")
			}
		}
	}

	// Read file
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	// Expand environment variables
	data = []byte(expandEnvVars(string(data)))

	// Parse YAML
	config := &Config{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Apply environment overrides
	applyEnvOverrides(config)

	// Validate configuration
	if err := validate(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Store globally
	globalConfig = config
	configPath = path

	return config, nil
}

// Get returns the global configuration
func Get() *Config {
	if globalConfig == nil {
		// Try to load default config
		config, err := Load("")
		if err != nil {
			// Return default config
			return DefaultConfig()
		}
		return config
	}
	return globalConfig
}

// GetPath returns the loaded config file path
func GetPath() string {
	return configPath
}

// Reload reloads the configuration
func Reload() error {
	if configPath == "" {
		return fmt.Errorf("no config path set")
	}
	
	config, err := Load(configPath)
	if err != nil {
		return err
	}
	
	globalConfig = config
	return nil
}

// ApplyProfile applies a named profile to the config
func ApplyProfile(config *Config, profileName string) error {
	profile, ok := config.Profiles[profileName]
	if !ok {
		return fmt.Errorf("profile '%s' not found", profileName)
	}

	// Apply profile settings
	for key, value := range profile {
		applyProfileSetting(config, key, value)
	}

	return nil
}

// Helper functions

func expandEnvVars(s string) string {
	return os.Expand(s, func(key string) string {
		if val := os.Getenv(key); val != "" {
			return val
		}
		// Check for PADOCCA_ prefix
		if val := os.Getenv("PADOCCA_" + key); val != "" {
			return val
		}
		return "${" + key + "}"
	})
}

func applyEnvOverrides(config *Config) {
	// Check for PADOCCA_ environment variables
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "PADOCCA_") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimPrefix(parts[0], "PADOCCA_")
				value := parts[1]
				applyEnvSetting(config, key, value)
			}
		}
	}
}

func applyEnvSetting(config *Config, key, value string) {
	// Convert env key to config path
	// e.g., PADOCCA_NETWORK_SSL_VERIFY -> network.ssl.verify
	path := strings.ToLower(strings.Replace(key, "_", ".", -1))
	applyProfileSetting(config, path, value)
}

func applyProfileSetting(config *Config, key string, value interface{}) {
	// This would use reflection to set the value
	// Implementation depends on specific requirements
}

func validate(config *Config) error {
	// Basic validation
	if config.Global.LogLevel == "" {
		config.Global.LogLevel = "info"
	}
	
	if config.Global.ResultsDir == "" {
		config.Global.ResultsDir = "./results"
	}
	
	if config.Network.Connection.Timeout <= 0 {
		config.Network.Connection.Timeout = 30
	}
	
	if config.Global.Performance.MaxWorkers <= 0 {
		config.Global.Performance.MaxWorkers = 50
	}
	
	return nil
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Global: GlobalConfig{
			LogLevel:     "info",
			OutputFormat: "text",
			ResultsDir:   "./results",
			Cache: CacheConfig{
				Enabled: true,
				TTL:     3600,
				MaxSize: 100,
			},
			Performance: PerformanceConfig{
				MaxWorkers: 50,
				MaxMemory:  2048,
				CPULimit:   80,
			},
		},
		Network: NetworkConfig{
			Connection: ConnectionConfig{
				Timeout:    30,
				RetryCount: 3,
				RetryDelay: 2,
			},
			SSL: SSLConfig{
				Verify:     true,
				MinVersion: "TLS1.2",
			},
			RateLimit: RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 10,
				BurstSize:         20,
			},
			UserAgents: UserAgentConfig{
				Rotate: true,
				DefaultList: []string{
					"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
					"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
					"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
				},
			},
		},
		Bruteforce: BruteforceConfig{
			General: GeneralBruteConfig{
				StopOnSuccess:  true,
				RandomizeOrder: true,
				SmartMode:      true,
			},
			Stealth: StealthConfig{
				Enabled: true,
				Level:   3,
			},
			Intelligent: IntelligentConfig{
				Enabled:          true,
				DetectWAF:        true,
				FingerprintFirst: true,
			},
		},
	}
}

// GetTimeout returns timeout as Duration
func (c *ConnectionConfig) GetTimeout() time.Duration {
	return time.Duration(c.Timeout) * time.Second
}

// GetRetryDelay returns retry delay as Duration
func (c *ConnectionConfig) GetRetryDelay() time.Duration {
	return time.Duration(c.RetryDelay) * time.Second
}

// IsStealthEnabled checks if stealth mode is enabled
func (c *Config) IsStealthEnabled() bool {
	return c.Bruteforce.Stealth.Enabled
}

// GetUserAgent returns a user agent string
func (c *Config) GetUserAgent() string {
	if !c.Network.UserAgents.Rotate {
		if len(c.Network.UserAgents.DefaultList) > 0 {
			return c.Network.UserAgents.DefaultList[0]
		}
		return "PADOCCA/2.0"
	}
	
	// Rotate through user agents
	list := c.Network.UserAgents.DefaultList
	if len(c.Network.UserAgents.CustomList) > 0 {
		list = c.Network.UserAgents.CustomList
	}
	
	if len(list) == 0 {
		return "PADOCCA/2.0"
	}
	
	// Simple rotation (in real implementation, would track index)
	return list[time.Now().Unix()%int64(len(list))]
}
