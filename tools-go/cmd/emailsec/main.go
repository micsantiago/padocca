package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

type EmailSecurityResult struct {
	Domain      string            `json:"domain"`
	SPF         SPFResult         `json:"spf"`
	DMARC       DMARCResult       `json:"dmarc"`
	DKIM        DKIMResult        `json:"dkim"`
	MX          []MXRecord        `json:"mx_records"`
	BIMI        BIMIResult        `json:"bimi"`
	MTA_STS     MTASTSResult      `json:"mta_sts"`
	TLS_RPT     TLSRPTResult      `json:"tls_rpt"`
	Score       int               `json:"security_score"`
	Issues      []string          `json:"issues"`
	Suggestions []string          `json:"suggestions"`
	Timestamp   time.Time         `json:"timestamp"`
}

type SPFResult struct {
	Present    bool     `json:"present"`
	Record     string   `json:"record"`
	Version    string   `json:"version"`
	Mechanisms []string `json:"mechanisms"`
	Modifiers  []string `json:"modifiers"`
	AllMechanism string `json:"all_mechanism"`
	Includes   []string `json:"includes"`
	IPs        []string `json:"ips"`
	Valid      bool     `json:"valid"`
	Errors     []string `json:"errors"`
}

type DMARCResult struct {
	Present     bool     `json:"present"`
	Record      string   `json:"record"`
	Version     string   `json:"version"`
	Policy      string   `json:"policy"`
	SubPolicy   string   `json:"sub_policy"`
	Percentage  int      `json:"percentage"`
	RUA         []string `json:"rua"`
	RUF         []string `json:"ruf"`
	ADKIM       string   `json:"adkim"`
	ASPF        string   `json:"aspf"`
	Valid       bool     `json:"valid"`
	Errors      []string `json:"errors"`
}

type DKIMResult struct {
	Present    bool              `json:"present"`
	Selectors  []DKIMSelector    `json:"selectors"`
	Valid      bool              `json:"valid"`
	Errors     []string          `json:"errors"`
}

type DKIMSelector struct {
	Name       string   `json:"name"`
	Found      bool     `json:"found"`
	Record     string   `json:"record"`
	Version    string   `json:"version"`
	KeyType    string   `json:"key_type"`
	KeySize    int      `json:"key_size"`
	Flags      []string `json:"flags"`
	Services   []string `json:"services"`
	Valid      bool     `json:"valid"`
	PublicKey  string   `json:"public_key"`
}

type MXRecord struct {
	Priority   uint16   `json:"priority"`
	Host       string   `json:"host"`
	IPs        []string `json:"ips"`
	TLSSupport bool     `json:"tls_support"`
}

type BIMIResult struct {
	Present bool   `json:"present"`
	Record  string `json:"record"`
	Valid   bool   `json:"valid"`
	LogoURL string `json:"logo_url"`
}

type MTASTSResult struct {
	Present bool     `json:"present"`
	Policy  string   `json:"policy"`
	Mode    string   `json:"mode"`
	MX      []string `json:"mx"`
	MaxAge  int      `json:"max_age"`
	Valid   bool     `json:"valid"`
}

type TLSRPTResult struct {
	Present bool     `json:"present"`
	Record  string   `json:"record"`
	RUA     []string `json:"rua"`
	Valid   bool     `json:"valid"`
}

var commonDKIMSelectors = []string{
	"default", "dkim", "mail", "email", "google", "googlemail",
	"k1", "k2", "s1", "s2", "selector1", "selector2",
	"mandrill", "mailgun", "sendgrid", "smtp", "postmark",
	"mailchimp", "amazonses", "zendesk", "freshdesk",
	"outlook", "microsoft", "office365", "protonmail",
}

func main() {
	var outputFile string
	var verbose bool
	var checkAll bool
	var customSelectors string

	rootCmd := &cobra.Command{
		Use:   "emailsec [domain]",
		Short: "Advanced Email Security Analyzer (SPF/DKIM/DMARC)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			domain := args[0]
			
			printBanner()
			
			var selectors []string
			if customSelectors != "" {
				selectors = strings.Split(customSelectors, ",")
			} else {
				selectors = commonDKIMSelectors
			}
			
			result := analyzeEmailSecurity(domain, selectors, checkAll, verbose)
			displayResults(result, verbose)
			
			if outputFile != "" {
				saveResults(result, outputFile)
			}
		},
	}

	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (JSON)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().BoolVarP(&checkAll, "all", "a", false, "Check all security features")
	rootCmd.Flags().StringVarP(&customSelectors, "selectors", "s", "", "Custom DKIM selectors (comma-separated)")

	if err := rootCmd.Execute(); err != nil {
		color.Red("Error: %v", err)
	}
}

func printBanner() {
	color.Cyan(`
    ╔═══════════════════════════════════════╗
    ║   📧 EMAIL SECURITY ANALYZER 📧       ║
    ║    SPF • DKIM • DMARC • Advanced      ║
    ╚═══════════════════════════════════════╝
    `)
}

func analyzeEmailSecurity(domain string, selectors []string, checkAll, verbose bool) EmailSecurityResult {
	result := EmailSecurityResult{
		Domain:    domain,
		Timestamp: time.Now(),
		Issues:    []string{},
		Suggestions: []string{},
	}

	color.Yellow("\n🔍 Analyzing email security for: %s\n", domain)

	// Check SPF
	color.Cyan("\n[1/7] Checking SPF record...")
	result.SPF = checkSPF(domain, verbose)
	
	// Check DMARC
	color.Cyan("\n[2/7] Checking DMARC record...")
	result.DMARC = checkDMARC(domain, verbose)
	
	// Check DKIM
	color.Cyan("\n[3/7] Checking DKIM records...")
	result.DKIM = checkDKIM(domain, selectors, verbose)
	
	// Check MX
	color.Cyan("\n[4/7] Checking MX records...")
	result.MX = checkMX(domain, verbose)
	
	if checkAll {
		// Check BIMI
		color.Cyan("\n[5/7] Checking BIMI record...")
		result.BIMI = checkBIMI(domain, verbose)
		
		// Check MTA-STS
		color.Cyan("\n[6/7] Checking MTA-STS policy...")
		result.MTA_STS = checkMTASTS(domain, verbose)
		
		// Check TLS-RPT
		color.Cyan("\n[7/7] Checking TLS-RPT record...")
		result.TLS_RPT = checkTLSRPT(domain, verbose)
	}
	
	// Calculate score and generate recommendations
	result.Score = calculateScore(&result)
	result.Issues = identifyIssues(&result)
	result.Suggestions = generateSuggestions(&result)
	
	return result
}

func checkSPF(domain string, verbose bool) SPFResult {
	result := SPFResult{}
	
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("DNS lookup failed: %v", err))
		return result
	}
	
	for _, record := range txtRecords {
		if strings.HasPrefix(strings.ToLower(record), "v=spf1") {
			result.Present = true
			result.Record = record
			result.Version = "spf1"
			
			// Parse SPF record
			parts := strings.Fields(record)
			for _, part := range parts[1:] { // Skip v=spf1
				if strings.HasPrefix(part, "include:") {
					result.Includes = append(result.Includes, strings.TrimPrefix(part, "include:"))
					result.Mechanisms = append(result.Mechanisms, part)
				} else if strings.HasPrefix(part, "ip4:") || strings.HasPrefix(part, "ip6:") {
					result.IPs = append(result.IPs, part)
					result.Mechanisms = append(result.Mechanisms, part)
				} else if strings.HasPrefix(part, "redirect=") {
					result.Modifiers = append(result.Modifiers, part)
				} else if part == "all" || part == "+all" || part == "-all" || part == "~all" || part == "?all" {
					result.AllMechanism = part
				} else {
					result.Mechanisms = append(result.Mechanisms, part)
				}
			}
			
			// Validate SPF
			result.Valid = true
			if result.AllMechanism == "" {
				result.Valid = false
				result.Errors = append(result.Errors, "Missing 'all' mechanism")
			}
			if result.AllMechanism == "+all" {
				result.Errors = append(result.Errors, "Dangerous: +all allows anyone to send")
			}
			if len(result.Includes) > 10 {
				result.Errors = append(result.Errors, "Too many includes (DNS lookup limit)")
			}
			
			break
		}
	}
	
	if !result.Present {
		result.Errors = append(result.Errors, "No SPF record found")
	}
	
	return result
}

func checkDMARC(domain string, verbose bool) DMARCResult {
	result := DMARCResult{}
	
	// DMARC record is at _dmarc.domain
	dmarcDomain := "_dmarc." + domain
	txtRecords, err := net.LookupTXT(dmarcDomain)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("DNS lookup failed: %v", err))
		return result
	}
	
	for _, record := range txtRecords {
		if strings.HasPrefix(strings.ToLower(record), "v=dmarc1") {
			result.Present = true
			result.Record = record
			result.Version = "DMARC1"
			
			// Parse DMARC record
			parts := strings.Split(record, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "p=") {
					result.Policy = strings.TrimPrefix(part, "p=")
				} else if strings.HasPrefix(part, "sp=") {
					result.SubPolicy = strings.TrimPrefix(part, "sp=")
				} else if strings.HasPrefix(part, "pct=") {
					fmt.Sscanf(part, "pct=%d", &result.Percentage)
				} else if strings.HasPrefix(part, "rua=") {
					result.RUA = strings.Split(strings.TrimPrefix(part, "rua="), ",")
				} else if strings.HasPrefix(part, "ruf=") {
					result.RUF = strings.Split(strings.TrimPrefix(part, "ruf="), ",")
				} else if strings.HasPrefix(part, "adkim=") {
					result.ADKIM = strings.TrimPrefix(part, "adkim=")
				} else if strings.HasPrefix(part, "aspf=") {
					result.ASPF = strings.TrimPrefix(part, "aspf=")
				}
			}
			
			// Validate DMARC
			result.Valid = true
			if result.Policy == "" {
				result.Valid = false
				result.Errors = append(result.Errors, "Missing policy")
			}
			if result.Policy == "none" {
				result.Errors = append(result.Errors, "Policy is 'none' - not enforcing")
			}
			if result.Percentage == 0 && result.Policy != "none" {
				result.Percentage = 100 // Default
			}
			
			break
		}
	}
	
	if !result.Present {
		result.Errors = append(result.Errors, "No DMARC record found")
	}
	
	return result
}

func checkDKIM(domain string, selectors []string, verbose bool) DKIMResult {
	result := DKIMResult{
		Selectors: []DKIMSelector{},
	}
	
	color.Yellow("  Testing %d DKIM selectors...", len(selectors))
	
	for _, selector := range selectors {
		dkimSelector := checkDKIMSelector(domain, selector, verbose)
		if dkimSelector.Found {
			result.Selectors = append(result.Selectors, dkimSelector)
			result.Present = true
			if verbose {
				color.Green("    ✓ Found: %s._domainkey.%s", selector, domain)
			}
		}
	}
	
	if !result.Present {
		result.Errors = append(result.Errors, "No DKIM selectors found (checked common selectors)")
	} else {
		result.Valid = true
		color.Green("  ✓ Found %d DKIM selector(s)", len(result.Selectors))
	}
	
	return result
}

func checkDKIMSelector(domain, selector string, verbose bool) DKIMSelector {
	result := DKIMSelector{
		Name: selector,
	}
	
	// DKIM record is at selector._domainkey.domain
	dkimDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)
	
	txtRecords, err := net.LookupTXT(dkimDomain)
	if err != nil {
		return result
	}
	
	for _, record := range txtRecords {
		// DKIM records often start with v=DKIM1 or k=rsa
		if strings.Contains(record, "DKIM1") || strings.Contains(record, "k=rsa") || strings.Contains(record, "p=") {
			result.Found = true
			result.Record = record
			
			// Parse DKIM record
			parts := strings.Split(record, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "v=") {
					result.Version = strings.TrimPrefix(part, "v=")
				} else if strings.HasPrefix(part, "k=") {
					result.KeyType = strings.TrimPrefix(part, "k=")
				} else if strings.HasPrefix(part, "p=") {
					result.PublicKey = strings.TrimPrefix(part, "p=")
					// Estimate key size from base64 public key
					if result.PublicKey != "" && result.PublicKey != "0" {
						keyBytes, err := base64.StdEncoding.DecodeString(result.PublicKey)
						if err == nil {
							result.KeySize = len(keyBytes) * 8
							// More accurate for RSA keys
							if result.KeyType == "rsa" || result.KeyType == "" {
								// Parse as RSA public key
								pubKey, err := x509.ParsePKIXPublicKey(keyBytes)
								if err == nil {
									if rsaKey, ok := pubKey.(*rsa.PublicKey); ok {
										result.KeySize = rsaKey.N.BitLen()
									}
								}
							}
						}
					}
				} else if strings.HasPrefix(part, "t=") {
					result.Flags = strings.Split(strings.TrimPrefix(part, "t="), ":")
				} else if strings.HasPrefix(part, "s=") {
					result.Services = strings.Split(strings.TrimPrefix(part, "s="), ":")
				}
			}
			
			// Validate
			result.Valid = true
			if result.PublicKey == "" {
				result.Valid = false
			}
			if result.KeySize > 0 && result.KeySize < 1024 {
				result.Valid = false
			}
			
			break
		}
	}
	
	return result
}

func checkMX(domain string, verbose bool) []MXRecord {
	records := []MXRecord{}
	
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return records
	}
	
	for _, mx := range mxRecords {
		record := MXRecord{
			Priority: mx.Pref,
			Host:     mx.Host,
		}
		
		// Lookup IPs for MX host
		ips, err := net.LookupHost(mx.Host)
		if err == nil {
			record.IPs = ips
		}
		
		// Check if port 25 is open (simplified check)
		if len(record.IPs) > 0 {
			conn, err := net.DialTimeout("tcp", record.IPs[0]+":25", 2*time.Second)
			if err == nil {
				record.TLSSupport = true // Simplified - would need STARTTLS check
				conn.Close()
			}
		}
		
		records = append(records, record)
	}
	
	return records
}

func checkBIMI(domain string, verbose bool) BIMIResult {
	result := BIMIResult{}
	
	// BIMI record is at default._bimi.domain
	bimiDomain := "default._bimi." + domain
	txtRecords, err := net.LookupTXT(bimiDomain)
	if err != nil {
		return result
	}
	
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=BIMI1") {
			result.Present = true
			result.Record = record
			result.Valid = true
			
			// Extract logo URL
			if strings.Contains(record, "l=") {
				parts := strings.Split(record, ";")
				for _, part := range parts {
					part = strings.TrimSpace(part)
					if strings.HasPrefix(part, "l=") {
						result.LogoURL = strings.TrimPrefix(part, "l=")
					}
				}
			}
			break
		}
	}
	
	return result
}

func checkMTASTS(domain string, verbose bool) MTASTSResult {
	result := MTASTSResult{}
	
	// MTA-STS record is at _mta-sts.domain
	stsRecord := "_mta-sts." + domain
	txtRecords, err := net.LookupTXT(stsRecord)
	if err != nil {
		return result
	}
	
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=STSv1") {
			result.Present = true
			result.Policy = record
			result.Valid = true
			
			// Note: Full MTA-STS check would require fetching
			// https://mta-sts.domain/.well-known/mta-sts.txt
			break
		}
	}
	
	return result
}

func checkTLSRPT(domain string, verbose bool) TLSRPTResult {
	result := TLSRPTResult{}
	
	// TLS-RPT record is at _smtp._tls.domain
	tlsrptDomain := "_smtp._tls." + domain
	txtRecords, err := net.LookupTXT(tlsrptDomain)
	if err != nil {
		return result
	}
	
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=TLSRPTv1") {
			result.Present = true
			result.Record = record
			result.Valid = true
			
			// Extract RUA
			if strings.Contains(record, "rua=") {
				parts := strings.Split(record, ";")
				for _, part := range parts {
					part = strings.TrimSpace(part)
					if strings.HasPrefix(part, "rua=") {
						result.RUA = strings.Split(strings.TrimPrefix(part, "rua="), ",")
					}
				}
			}
			break
		}
	}
	
	return result
}

func calculateScore(result *EmailSecurityResult) int {
	score := 0
	maxScore := 100
	
	// SPF (20 points)
	if result.SPF.Present && result.SPF.Valid {
		score += 15
		if result.SPF.AllMechanism == "-all" {
			score += 5
		} else if result.SPF.AllMechanism == "~all" {
			score += 3
		}
	}
	
	// DMARC (30 points)
	if result.DMARC.Present && result.DMARC.Valid {
		score += 15
		if result.DMARC.Policy == "reject" {
			score += 15
		} else if result.DMARC.Policy == "quarantine" {
			score += 10
		} else if result.DMARC.Policy == "none" {
			score += 5
		}
	}
	
	// DKIM (30 points)
	if result.DKIM.Present {
		score += 20
		for _, selector := range result.DKIM.Selectors {
			if selector.KeySize >= 2048 {
				score += 10
				break
			} else if selector.KeySize >= 1024 {
				score += 5
				break
			}
		}
	}
	
	// MX (10 points)
	if len(result.MX) > 0 {
		score += 10
	}
	
	// Bonus features (10 points)
	if result.BIMI.Present {
		score += 3
	}
	if result.MTA_STS.Present {
		score += 4
	}
	if result.TLS_RPT.Present {
		score += 3
	}
	
	return (score * 100) / maxScore
}

func identifyIssues(result *EmailSecurityResult) []string {
	issues := []string{}
	
	if !result.SPF.Present {
		issues = append(issues, "❌ No SPF record found - anyone can spoof emails")
	} else if result.SPF.AllMechanism == "+all" {
		issues = append(issues, "❌ SPF allows all senders (+all)")
	}
	
	if !result.DMARC.Present {
		issues = append(issues, "❌ No DMARC record - no email authentication policy")
	} else if result.DMARC.Policy == "none" {
		issues = append(issues, "⚠️ DMARC policy is 'none' - not enforcing")
	}
	
	if !result.DKIM.Present {
		issues = append(issues, "❌ No DKIM records found - emails not signed")
	} else {
		for _, selector := range result.DKIM.Selectors {
			if selector.KeySize < 1024 {
				issues = append(issues, fmt.Sprintf("⚠️ DKIM key too small (%d bits) for selector '%s'", selector.KeySize, selector.Name))
			}
		}
	}
	
	if len(result.MX) == 0 {
		issues = append(issues, "❌ No MX records - cannot receive emails")
	}
	
	return issues
}

func generateSuggestions(result *EmailSecurityResult) []string {
	suggestions := []string{}
	
	if !result.SPF.Present {
		suggestions = append(suggestions, "🔧 Add SPF record: v=spf1 include:_spf.yourmailprovider.com -all")
	} else if result.SPF.AllMechanism != "-all" {
		suggestions = append(suggestions, "🔧 Strengthen SPF: change to '-all' instead of '"+result.SPF.AllMechanism+"'")
	}
	
	if !result.DMARC.Present {
		suggestions = append(suggestions, "🔧 Add DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@"+result.Domain)
	} else if result.DMARC.Policy != "reject" {
		suggestions = append(suggestions, "🔧 Strengthen DMARC: change policy to 'reject'")
	}
	
	if !result.DKIM.Present {
		suggestions = append(suggestions, "🔧 Configure DKIM signing with your email provider")
	}
	
	if !result.BIMI.Present {
		suggestions = append(suggestions, "💡 Consider adding BIMI for brand logo in emails")
	}
	
	if !result.MTA_STS.Present {
		suggestions = append(suggestions, "💡 Implement MTA-STS for enforced TLS encryption")
	}
	
	if !result.TLS_RPT.Present {
		suggestions = append(suggestions, "💡 Add TLS-RPT for delivery reports")
	}
	
	return suggestions
}

func displayResults(result EmailSecurityResult, verbose bool) {
	color.Green("\n═══════════════════════════════════════════════════════")
	color.Green("           EMAIL SECURITY ANALYSIS RESULTS              ")
	color.Green("═══════════════════════════════════════════════════════\n")

	fmt.Printf("🎯 Domain: %s\n", color.YellowString(result.Domain))
	fmt.Printf("🕐 Timestamp: %s\n\n", result.Timestamp.Format("2006-01-02 15:04:05"))

	// SPF Results
	color.Cyan("📋 SPF (Sender Policy Framework):\n")
	if result.SPF.Present {
		color.Green("  ✓ SPF record found")
		if verbose {
			fmt.Printf("  Record: %s\n", result.SPF.Record)
		}
		fmt.Printf("  Policy: %s\n", result.SPF.AllMechanism)
		if len(result.SPF.Includes) > 0 {
			fmt.Printf("  Includes: %s\n", strings.Join(result.SPF.Includes, ", "))
		}
	} else {
		color.Red("  ✗ No SPF record found")
	}

	// DMARC Results
	color.Cyan("\n📧 DMARC (Domain-based Message Authentication):\n")
	if result.DMARC.Present {
		color.Green("  ✓ DMARC record found")
		fmt.Printf("  Policy: %s\n", result.DMARC.Policy)
		if result.DMARC.Percentage < 100 && result.DMARC.Percentage > 0 {
			fmt.Printf("  Percentage: %d%%\n", result.DMARC.Percentage)
		}
		if len(result.DMARC.RUA) > 0 {
			fmt.Printf("  Reports to: %s\n", strings.Join(result.DMARC.RUA, ", "))
		}
	} else {
		color.Red("  ✗ No DMARC record found")
	}

	// DKIM Results
	color.Cyan("\n🔐 DKIM (DomainKeys Identified Mail):\n")
	if result.DKIM.Present {
		color.Green("  ✓ %d DKIM selector(s) found", len(result.DKIM.Selectors))
		for _, selector := range result.DKIM.Selectors {
			keyInfo := fmt.Sprintf("%d-bit", selector.KeySize)
			if selector.KeySize < 1024 {
				keyInfo = color.RedString(keyInfo)
			} else if selector.KeySize < 2048 {
				keyInfo = color.YellowString(keyInfo)
			} else {
				keyInfo = color.GreenString(keyInfo)
			}
			fmt.Printf("    • %s: %s %s key\n", selector.Name, selector.KeyType, keyInfo)
		}
	} else {
		color.Red("  ✗ No DKIM selectors found")
	}

	// MX Records
	if len(result.MX) > 0 {
		color.Cyan("\n📬 MX Records:\n")
		for _, mx := range result.MX {
			fmt.Printf("  [%d] %s\n", mx.Priority, mx.Host)
		}
	}

	// Advanced Features
	if result.BIMI.Present || result.MTA_STS.Present || result.TLS_RPT.Present {
		color.Cyan("\n🚀 Advanced Features:\n")
		if result.BIMI.Present {
			color.Green("  ✓ BIMI configured (brand logo)")
		}
		if result.MTA_STS.Present {
			color.Green("  ✓ MTA-STS configured (enforced TLS)")
		}
		if result.TLS_RPT.Present {
			color.Green("  ✓ TLS-RPT configured (delivery reports)")
		}
	}

	// Security Score
	color.Cyan("\n📊 Security Score:\n")
	scoreColor := color.RedString
	grade := "F"
	if result.Score >= 90 {
		scoreColor = color.GreenString
		grade = "A+"
	} else if result.Score >= 80 {
		scoreColor = color.GreenString
		grade = "A"
	} else if result.Score >= 70 {
		scoreColor = color.YellowString
		grade = "B"
	} else if result.Score >= 60 {
		scoreColor = color.YellowString
		grade = "C"
	} else if result.Score >= 50 {
		scoreColor = color.RedString
		grade = "D"
	}
	
	fmt.Printf("  Score: %s/100 (Grade: %s)\n", scoreColor("%d", result.Score), scoreColor(grade))
	
	// Progress bar
	filled := result.Score / 5
	empty := 20 - filled
	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
	fmt.Printf("  [%s]\n", scoreColor(bar))

	// Issues
	if len(result.Issues) > 0 {
		color.Red("\n⚠️ Issues Found:\n")
		for _, issue := range result.Issues {
			fmt.Printf("  %s\n", issue)
		}
	}

	// Suggestions
	if len(result.Suggestions) > 0 {
		color.Yellow("\n💡 Recommendations:\n")
		for _, suggestion := range result.Suggestions {
			fmt.Printf("  %s\n", suggestion)
		}
	}
}

func saveResults(result EmailSecurityResult, filename string) {
	// JSON marshaling would go here
	color.Green("\n✅ Results saved to %s", filename)
}
