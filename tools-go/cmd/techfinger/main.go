package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

type Technology struct {
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	Version    string   `json:"version,omitempty"`
	Confidence int      `json:"confidence"`
	Evidence   []string `json:"evidence"`
}

type Fingerprint struct {
	URL          string                 `json:"url"`
	Technologies []Technology           `json:"technologies"`
	Headers      map[string]string      `json:"headers"`
	Cookies      []string               `json:"cookies"`
	MetaTags     map[string]string      `json:"meta_tags"`
	JavaScript   []string               `json:"javascript_libs"`
	CSS          []string               `json:"css_frameworks"`
	Server       string                 `json:"server"`
	PoweredBy    string                 `json:"powered_by"`
	Generator    string                 `json:"generator"`
	Timestamp    time.Time              `json:"timestamp"`
}

type TechSignature struct {
	Name      string
	Category  string
	Headers   map[string]*regexp.Regexp
	HTML      []*regexp.Regexp
	Script    []*regexp.Regexp
	Meta      map[string]*regexp.Regexp
	Cookies   map[string]*regexp.Regexp
	URL       []*regexp.Regexp
	Implies   []string
}

var signatures = []TechSignature{
	// CMS Detection
	{
		Name:     "WordPress",
		Category: "CMS",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`/wp-content/`),
			regexp.MustCompile(`/wp-includes/`),
			regexp.MustCompile(`wordpress\.org`),
		},
		Meta: map[string]*regexp.Regexp{
			"generator": regexp.MustCompile(`WordPress\s*([\d.]+)?`),
		},
		Headers: map[string]*regexp.Regexp{
			"X-Powered-By": regexp.MustCompile(`W3 Total Cache`),
		},
	},
	{
		Name:     "Joomla",
		Category: "CMS",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`/components/com_`),
			regexp.MustCompile(`Joomla!`),
			regexp.MustCompile(`joomla\.org`),
		},
		Meta: map[string]*regexp.Regexp{
			"generator": regexp.MustCompile(`Joomla!\s*([\d.]+)?`),
		},
	},
	{
		Name:     "Drupal",
		Category: "CMS",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`/sites/all/`),
			regexp.MustCompile(`/sites/default/`),
			regexp.MustCompile(`Drupal\.settings`),
		},
		Headers: map[string]*regexp.Regexp{
			"X-Drupal-Cache": regexp.MustCompile(`.+`),
			"X-Generator":    regexp.MustCompile(`Drupal\s*([\d.]+)?`),
		},
	},
	{
		Name:     "Magento",
		Category: "E-commerce",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`/skin/frontend/`),
			regexp.MustCompile(`Mage\.Cookies`),
			regexp.MustCompile(`/mage/`),
		},
		Cookies: map[string]*regexp.Regexp{
			"frontend": regexp.MustCompile(`.+`),
		},
	},
	// Frameworks
	{
		Name:     "Laravel",
		Category: "Framework",
		Headers: map[string]*regexp.Regexp{
			"Set-Cookie": regexp.MustCompile(`laravel_session`),
		},
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`csrf-token`),
		},
	},
	{
		Name:     "Django",
		Category: "Framework",
		Headers: map[string]*regexp.Regexp{
			"Set-Cookie": regexp.MustCompile(`csrftoken`),
		},
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`csrfmiddlewaretoken`),
		},
	},
	{
		Name:     "Ruby on Rails",
		Category: "Framework",
		Headers: map[string]*regexp.Regexp{
			"X-Powered-By": regexp.MustCompile(`Phusion Passenger`),
			"Server":       regexp.MustCompile(`Phusion Passenger`),
		},
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`csrf-token`),
			regexp.MustCompile(`rails`),
		},
	},
	{
		Name:     "ASP.NET",
		Category: "Framework",
		Headers: map[string]*regexp.Regexp{
			"X-AspNet-Version": regexp.MustCompile(`(.+)`),
			"X-Powered-By":     regexp.MustCompile(`ASP\.NET`),
		},
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`__VIEWSTATE`),
			regexp.MustCompile(`aspnet`),
		},
	},
	// JavaScript Frameworks
	{
		Name:     "React",
		Category: "JavaScript Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`react(?:\.production)?(?:\.min)?\.js`),
			regexp.MustCompile(`data-reactroot`),
			regexp.MustCompile(`_reactRootContainer`),
		},
	},
	{
		Name:     "Angular",
		Category: "JavaScript Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`ng-app`),
			regexp.MustCompile(`angular(?:\.min)?\.js`),
			regexp.MustCompile(`ng-version`),
		},
	},
	{
		Name:     "Vue.js",
		Category: "JavaScript Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`vue(?:\.min)?\.js`),
			regexp.MustCompile(`v-for`),
			regexp.MustCompile(`v-if`),
		},
	},
	{
		Name:     "jQuery",
		Category: "JavaScript Library",
		Script: []*regexp.Regexp{
			regexp.MustCompile(`jquery[.-]?([\d.]+)?(?:\.min)?\.js`),
			regexp.MustCompile(`\$\.fn\.jquery`),
		},
	},
	// Web Servers
	{
		Name:     "Nginx",
		Category: "Web Server",
		Headers: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`nginx(?:/([\d.]+))?`),
		},
	},
	{
		Name:     "Apache",
		Category: "Web Server",
		Headers: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`Apache(?:/([\d.]+))?`),
		},
	},
	{
		Name:     "IIS",
		Category: "Web Server",
		Headers: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`Microsoft-IIS(?:/([\d.]+))?`),
		},
	},
	{
		Name:     "Cloudflare",
		Category: "CDN",
		Headers: map[string]*regexp.Regexp{
			"CF-Ray":    regexp.MustCompile(`.+`),
			"Server":    regexp.MustCompile(`cloudflare`),
		},
	},
	// Analytics
	{
		Name:     "Google Analytics",
		Category: "Analytics",
		Script: []*regexp.Regexp{
			regexp.MustCompile(`google-analytics\.com/(?:ga|analytics)\.js`),
			regexp.MustCompile(`googletagmanager\.com/gtag/js`),
		},
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`UA-\d+-\d+`),
			regexp.MustCompile(`G-[A-Z0-9]+`),
		},
	},
	// Databases
	{
		Name:     "MySQL",
		Category: "Database",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`mysql`),
		},
		Headers: map[string]*regexp.Regexp{
			"X-Powered-By": regexp.MustCompile(`MySQL`),
		},
	},
	{
		Name:     "PostgreSQL",
		Category: "Database",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`postgresql`),
			regexp.MustCompile(`postgres`),
		},
	},
	{
		Name:     "MongoDB",
		Category: "Database",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`mongodb`),
			regexp.MustCompile(`mongoose`),
		},
	},
	// Programming Languages
	{
		Name:     "PHP",
		Category: "Language",
		Headers: map[string]*regexp.Regexp{
			"X-Powered-By": regexp.MustCompile(`PHP/([\d.]+)`),
			"Server":       regexp.MustCompile(`PHP/([\d.]+)`),
		},
		Cookies: map[string]*regexp.Regexp{
			"PHPSESSID": regexp.MustCompile(`.+`),
		},
	},
	{
		Name:     "Python",
		Category: "Language",
		Headers: map[string]*regexp.Regexp{
			"Server": regexp.MustCompile(`Python/([\d.]+)`),
		},
	},
	{
		Name:     "Java",
		Category: "Language",
		Headers: map[string]*regexp.Regexp{
			"Set-Cookie": regexp.MustCompile(`JSESSIONID`),
		},
	},
	// Security
	{
		Name:     "reCAPTCHA",
		Category: "Security",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`google\.com/recaptcha`),
			regexp.MustCompile(`g-recaptcha`),
		},
	},
	// CSS Frameworks
	{
		Name:     "Bootstrap",
		Category: "CSS Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`bootstrap(?:\.min)?\.css`),
			regexp.MustCompile(`class="[^"]*\b(?:container|row|col-)[^"]*"`),
		},
	},
	{
		Name:     "Tailwind CSS",
		Category: "CSS Framework",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`tailwindcss`),
			regexp.MustCompile(`class="[^"]*\b(?:flex|grid|p-\d|m-\d)[^"]*"`),
		},
	},
}

func main() {
	var outputFile string
	var verbose bool

	rootCmd := &cobra.Command{
		Use:   "techfinger [URL]",
		Short: "Advanced Technology Fingerprinting Tool",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			targetURL := args[0]
			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				targetURL = "https://" + targetURL
			}

			printBanner()
			fingerprint := analyzeTarget(targetURL, verbose)
			displayResults(fingerprint)

			if outputFile != "" {
				saveResults(fingerprint, outputFile)
			}
		},
	}

	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (JSON)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	if err := rootCmd.Execute(); err != nil {
		color.Red("Error: %v", err)
	}
}

func printBanner() {
	color.Cyan(`
    ╔═══════════════════════════════════════╗
    ║   🔍 TECHNOLOGY FINGERPRINTING 🔍     ║
    ║      Advanced • Deep • Accurate       ║
    ╚═══════════════════════════════════════╝
    `)
}

func analyzeTarget(targetURL string, verbose bool) Fingerprint {
	fingerprint := Fingerprint{
		URL:          targetURL,
		Technologies: []Technology{},
		Headers:      make(map[string]string),
		MetaTags:     make(map[string]string),
		JavaScript:   []string{},
		CSS:          []string{},
		Cookies:      []string{},
		Timestamp:    time.Now(),
	}

	color.Yellow("\n🔍 Analyzing %s...\n", targetURL)

	// Make HTTP request
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Don't follow redirects automatically
		},
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		color.Red("Error creating request: %v", err)
		return fingerprint
	}

	// Set user agent to avoid blocking
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		color.Red("Error fetching URL: %v", err)
		return fingerprint
	}
	defer resp.Body.Close()

	// Read body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		color.Red("Error reading response: %v", err)
		return fingerprint
	}

	bodyStr := string(body)

	// Store headers
	for key, values := range resp.Header {
		fingerprint.Headers[key] = strings.Join(values, ", ")
	}

	// Parse cookies
	for _, cookie := range resp.Cookies() {
		fingerprint.Cookies = append(fingerprint.Cookies, cookie.Name)
	}

	// Parse HTML
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(bodyStr))
	if err != nil {
		color.Red("Error parsing HTML: %v", err)
	} else {
		// Extract meta tags
		doc.Find("meta").Each(func(i int, s *goquery.Selection) {
			if name, exists := s.Attr("name"); exists {
				content, _ := s.Attr("content")
				fingerprint.MetaTags[name] = content
			}
			if property, exists := s.Attr("property"); exists {
				content, _ := s.Attr("content")
				fingerprint.MetaTags[property] = content
			}
		})

		// Extract JavaScript libraries
		doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
			if src, exists := s.Attr("src"); exists {
				fingerprint.JavaScript = append(fingerprint.JavaScript, src)
			}
		})

		// Extract CSS frameworks
		doc.Find("link[rel='stylesheet']").Each(func(i int, s *goquery.Selection) {
			if href, exists := s.Attr("href"); exists {
				fingerprint.CSS = append(fingerprint.CSS, href)
			}
		})
	}

	// Detect technologies
	detected := make(map[string]*Technology)
	
	for _, sig := range signatures {
		confidence := 0
		evidence := []string{}

		// Check headers
		for header, pattern := range sig.Headers {
			if value, exists := fingerprint.Headers[header]; exists {
				if pattern.MatchString(value) {
					confidence += 30
					evidence = append(evidence, fmt.Sprintf("Header %s: %s", header, value))
					
					// Extract version if present
					if matches := pattern.FindStringSubmatch(value); len(matches) > 1 {
						if tech, exists := detected[sig.Name]; exists {
							if matches[1] != "" {
								tech.Version = matches[1]
							}
						}
					}
				}
			}
		}

		// Check HTML patterns
		for _, pattern := range sig.HTML {
			if pattern.MatchString(bodyStr) {
				confidence += 20
				match := pattern.FindString(bodyStr)
				if len(match) > 50 {
					match = match[:50] + "..."
				}
				evidence = append(evidence, fmt.Sprintf("HTML pattern: %s", match))
			}
		}

		// Check scripts
		for _, pattern := range sig.Script {
			for _, script := range fingerprint.JavaScript {
				if pattern.MatchString(script) {
					confidence += 25
					evidence = append(evidence, fmt.Sprintf("Script: %s", script))
					
					// Extract version
					if matches := pattern.FindStringSubmatch(script); len(matches) > 1 {
						if tech, exists := detected[sig.Name]; exists {
							if matches[1] != "" {
								tech.Version = matches[1]
							}
						}
					}
				}
			}
		}

		// Check meta tags
		for metaName, pattern := range sig.Meta {
			if value, exists := fingerprint.MetaTags[metaName]; exists {
				if pattern.MatchString(value) {
					confidence += 30
					evidence = append(evidence, fmt.Sprintf("Meta %s: %s", metaName, value))
					
					// Extract version
					if matches := pattern.FindStringSubmatch(value); len(matches) > 1 {
						if _, exists := detected[sig.Name]; !exists {
							detected[sig.Name] = &Technology{
								Name:     sig.Name,
								Category: sig.Category,
								Version:  matches[1],
							}
						}
					}
				}
			}
		}

		// Check cookies
		for cookieName, _ := range sig.Cookies {
			for _, cookie := range fingerprint.Cookies {
				if cookie == cookieName {
					confidence += 20
					evidence = append(evidence, fmt.Sprintf("Cookie: %s", cookieName))
				}
			}
		}

		// Add technology if confidence is high enough
		if confidence > 0 {
			if tech, exists := detected[sig.Name]; exists {
				tech.Confidence = confidence
				tech.Evidence = evidence
			} else {
				detected[sig.Name] = &Technology{
					Name:       sig.Name,
					Category:   sig.Category,
					Confidence: confidence,
					Evidence:   evidence,
				}
			}
		}
	}

	// Convert map to slice
	for _, tech := range detected {
		fingerprint.Technologies = append(fingerprint.Technologies, *tech)
	}

	// Extract server info
	if server, exists := fingerprint.Headers["Server"]; exists {
		fingerprint.Server = server
	}
	if poweredBy, exists := fingerprint.Headers["X-Powered-By"]; exists {
		fingerprint.PoweredBy = poweredBy
	}
	if generator, exists := fingerprint.MetaTags["generator"]; exists {
		fingerprint.Generator = generator
	}

	return fingerprint
}

func displayResults(fingerprint Fingerprint) {
	color.Green("\n═══════════════════════════════════════════════════════")
	color.Green("               TECHNOLOGY FINGERPRINT RESULTS           ")
	color.Green("═══════════════════════════════════════════════════════\n")

	fmt.Printf("🎯 Target: %s\n", color.YellowString(fingerprint.URL))
	fmt.Printf("🕐 Timestamp: %s\n\n", fingerprint.Timestamp.Format("2006-01-02 15:04:05"))

	// Group technologies by category
	categories := make(map[string][]Technology)
	for _, tech := range fingerprint.Technologies {
		categories[tech.Category] = append(categories[tech.Category], tech)
	}

	// Display by category
	for category, techs := range categories {
		color.Cyan("\n📦 %s:\n", category)
		for _, tech := range techs {
			confidence := ""
			if tech.Confidence >= 70 {
				confidence = color.GreenString("[High]")
			} else if tech.Confidence >= 40 {
				confidence = color.YellowString("[Medium]")
			} else {
				confidence = color.RedString("[Low]")
			}

			version := ""
			if tech.Version != "" {
				version = fmt.Sprintf(" v%s", color.MagentaString(tech.Version))
			}

			fmt.Printf("  ✓ %s%s %s\n", tech.Name, version, confidence)
			
			// Show evidence in verbose mode
			if len(tech.Evidence) > 0 && len(tech.Evidence) <= 2 {
				for _, ev := range tech.Evidence {
					fmt.Printf("    └─ %s\n", color.HiBlackString(ev))
				}
			}
		}
	}

	// Server Information
	if fingerprint.Server != "" || fingerprint.PoweredBy != "" {
		color.Cyan("\n🖥️  Server Information:\n")
		if fingerprint.Server != "" {
			fmt.Printf("  Server: %s\n", fingerprint.Server)
		}
		if fingerprint.PoweredBy != "" {
			fmt.Printf("  Powered By: %s\n", fingerprint.PoweredBy)
		}
		if fingerprint.Generator != "" {
			fmt.Printf("  Generator: %s\n", fingerprint.Generator)
		}
	}

	// Security Headers
	color.Cyan("\n🔒 Security Headers:\n")
	securityHeaders := []string{
		"Strict-Transport-Security",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Content-Security-Policy",
		"X-XSS-Protection",
	}

	for _, header := range securityHeaders {
		if _, exists := fingerprint.Headers[header]; exists {
			fmt.Printf("  ✓ %s: %s\n", header, color.GreenString("Present"))
		} else {
			fmt.Printf("  ✗ %s: %s\n", header, color.RedString("Missing"))
		}
	}

	// Summary
	color.Cyan("\n📊 Summary:\n")
	fmt.Printf("  Total technologies detected: %d\n", len(fingerprint.Technologies))
	fmt.Printf("  Categories identified: %d\n", len(categories))
	
	// Security score based on headers
	secScore := 0
	maxScore := len(securityHeaders)
	for _, header := range securityHeaders {
		if _, exists := fingerprint.Headers[header]; exists {
			secScore++
		}
	}
	
	scorePercent := (secScore * 100) / maxScore
	scoreColor := color.RedString
	if scorePercent >= 80 {
		scoreColor = color.GreenString
	} else if scorePercent >= 50 {
		scoreColor = color.YellowString
	}
	
	fmt.Printf("  Security header score: %s\n", scoreColor("%d/%d", secScore, maxScore))
}

func saveResults(fingerprint Fingerprint, filename string) {
	data, err := json.MarshalIndent(fingerprint, "", "  ")
	if err != nil {
		color.Red("Error marshaling results: %v", err)
		return
	}

	if err := ioutil.WriteFile(filename, data, 0644); err != nil {
		color.Red("Error saving results: %v", err)
		return
	}

	color.Green("\n✅ Results saved to %s", filename)
}
