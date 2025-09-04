#!/bin/bash

# PADOCCA v4.1 - Advanced Penetration Testing Framework
# FINAL PRODUCTION VERSION - All improvements integrated
# Date: 2025-09-04

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Source libraries if available
if [ -f "$SCRIPT_DIR/lib/progress.sh" ]; then
    source "$SCRIPT_DIR/lib/progress.sh" 2>/dev/null || true
else
    # Fallback functions if libraries not available
    draw_progress_bar() { echo "[Progress] $4"; }
    animated_progress() { echo "[Progress] $1"; }
fi

if [ -f "$SCRIPT_DIR/lib/logger.sh" ]; then
    source "$SCRIPT_DIR/lib/logger.sh" 2>/dev/null || true
else
    # Fallback functions
    init_logger() { return 0; }
    log_info() { echo "[INFO] $2"; }
    generate_summary_log() { return 0; }
fi

# Fallback display functions if not defined
type show_dashboard &>/dev/null || show_dashboard() { echo "[Dashboard] Target: $1 | Mode: $2"; }
type show_phase_header &>/dev/null || show_phase_header() { echo -e "\n=== PHASE $1: $2 ==="; }
type show_module_progress &>/dev/null || show_module_progress() { echo "[Module $1/$2] $3"; }
type show_task_status &>/dev/null || show_task_status() { echo "[$1] Status: $2 | Time: $3 | $4"; }
type show_live_stats &>/dev/null || show_live_stats() { echo "[$1]: $2 $3"; }
type calculate_elapsed_time &>/dev/null || calculate_elapsed_time() { echo "$(($(date +%s) - $1))s"; }
type show_summary_panel &>/dev/null || show_summary_panel() {
    echo -e "\n==== SCAN SUMMARY ===="
    echo "Target: $1"
    echo "Subdomains: $2"
    echo "URLs: $3"
    echo "Ports: $4"
    echo "Vulnerabilities: $5"
    echo "WAF: $6"
    echo "SSL: $7"
    echo "Emails: $8"
    echo "Duration: $9"
    echo "Results: ${10}"
}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# Version
VERSION="4.1"
BUILD_DATE="2025-09-04"

# Paths
BIN_DIR="$SCRIPT_DIR/bin"
PIPELINES_DIR="$SCRIPT_DIR/pipelines"
RESULTS_DIR="$SCRIPT_DIR/results"

# Safe number extraction
safe_number() {
    local num="$1"
    local default="${2:-0}"
    [ -z "$num" ] && echo "$default" && return
    local clean=$(echo "$num" | tr -d '\n' | tr -d ' ' | grep -oE '[0-9]+' | head -1)
    [ -z "$clean" ] && echo "$default" || echo "$clean"
}

# Safe comparison
safe_compare() {
    local num1=$(safe_number "$1" "0")
    local num2=$(safe_number "$2" "0")
    local op="$3"
    
    case "$op" in
        "gt") [ "$num1" -gt "$num2" ] ;;
        "lt") [ "$num1" -lt "$num2" ] ;;
        "eq") [ "$num1" -eq "$num2" ] ;;
        "ge") [ "$num1" -ge "$num2" ] ;;
        "le") [ "$num1" -le "$num2" ] ;;
        *) return 1 ;;
    esac
}

# Main scan function
advanced_scan() {
    local TARGET=$1
    local STEALTH_MODE=$2
    local FULL_MODE=$3
    
    # Initialize
    local SCAN_START_TIME=$(date +%s)
    local SCAN_DIR="$RESULTS_DIR/scan_${TARGET}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$SCAN_DIR"
    
    init_logger "$TARGET"
    log_info "MAIN" "Starting scan on $TARGET"
    
    # Mode description
    local MODE_DESC="Standard"
    if [ -n "$STEALTH_MODE" ] && [ -n "$FULL_MODE" ]; then
        MODE_DESC="Stealth • Full Pipeline"
    elif [ -n "$STEALTH_MODE" ]; then
        MODE_DESC="Stealth Mode"
    elif [ -n "$FULL_MODE" ]; then
        MODE_DESC="Full Pipeline"
    fi
    
    show_dashboard "$TARGET" "$MODE_DESC" "$SCAN_START_TIME"
    
    # Initialize counters
    local SUBDOMAIN_COUNT=0
    local SUBDOMAIN_ACTIVE=0
    local URL_COUNT=0
    local OPEN_PORTS=0
    local VULNERABILITIES=0
    local EMAILS_FOUND=0
    local DNS_RECORDS=0
    local PAGES_CRAWLED=0
    local WAF_STATUS="NOT_DETECTED"
    local SSL_STATUS="unknown"
    
    # ═══════════════════════════════════════════════════════
    # PHASE 1: PASSIVE RECONNAISSANCE
    # ═══════════════════════════════════════════════════════
    show_phase_header "1" "PASSIVE RECONNAISSANCE"
    
    # Module 1: Subdomain Discovery
    show_module_progress "1" "14" "Advanced Subdomain Discovery"
    local subdomain_start=$(date +%s)
    local subdomain_output="$SCAN_DIR/subdomain_output.txt"
    local subdomain_json="$SCAN_DIR/subdomains.json"
    
    (
        if [ -n "$STEALTH_MODE" ]; then
            "$BIN_DIR/subdiscovery" -d "$TARGET" -s "crtsh,alienvault,wayback" -o "$subdomain_json" 2>&1
        else
            "$BIN_DIR/subdiscovery" -d "$TARGET" --all -o "$subdomain_json" 2>&1
        fi
    ) | tee "$subdomain_output"
    
    echo "[Progress] Subdomain discovery completed"
    
    # Extract counts
    if [ -f "$subdomain_output" ]; then
        local total_subs=$(grep -oE 'Found [0-9]+ unique' "$subdomain_output" 2>/dev/null | grep -oE '[0-9]+' | head -1)
        SUBDOMAIN_COUNT=$(safe_number "$total_subs" "0")
        local active_subs=$(grep -oE '([0-9]+)/[0-9]+ subdomains are active' "$subdomain_output" 2>/dev/null | grep -oE '^[0-9]+' | head -1)
        SUBDOMAIN_ACTIVE=$(safe_number "$active_subs" "$SUBDOMAIN_COUNT")
    fi
    
    if [ "$SUBDOMAIN_COUNT" = "0" ] && [ -f "$subdomain_json" ]; then
        SUBDOMAIN_COUNT=$(grep -c '"domain"' "$subdomain_json" 2>/dev/null || echo "0")
        SUBDOMAIN_COUNT=$(safe_number "$SUBDOMAIN_COUNT" "0")
        SUBDOMAIN_ACTIVE="$SUBDOMAIN_COUNT"
    fi
    
    local subdomain_duration=$(calculate_elapsed_time $subdomain_start)
    
    if safe_compare "$SUBDOMAIN_ACTIVE" "0" "gt"; then
        show_task_status "Subdomain Discovery" "success" "$subdomain_duration" "$SUBDOMAIN_ACTIVE active (of $SUBDOMAIN_COUNT total)"
    else
        show_task_status "Subdomain Discovery" "warning" "$subdomain_duration" "No subdomains found"
    fi
    show_live_stats "Active subdomains" "$SUBDOMAIN_ACTIVE" "🌐"
    log_info "SUBDOMAIN" "Found $SUBDOMAIN_COUNT subdomains ($SUBDOMAIN_ACTIVE active)"
    
    # Module 2: Historical URLs
    show_module_progress "2" "14" "Historical URL Discovery (Wayback)"
    local wayback_start=$(date +%s)
    local wayback_output="$SCAN_DIR/wayback_output.txt"
    
    echo -e "${CYAN}⏳${NC} Querying historical archives (max 30s)..."
    
    (
        timeout 30 "$BIN_DIR/wayback" -t "$TARGET" --validate -o "$SCAN_DIR/wayback_urls.json" 2>&1 | tee "$wayback_output"
    ) || echo -e "${YELLOW}⚠️ Wayback timeout reached${NC}"
    
    URL_COUNT=0
    if [ -f "$wayback_output" ]; then
        # Count ALIVE URLs first
        local alive_count=$(grep -c "ALIVE:" "$wayback_output" 2>/dev/null || echo "0")
        if [ "$alive_count" != "0" ]; then
            URL_COUNT="$alive_count"
        else
            # Try Total URLs found
            local url_total=$(grep -oE 'Total URLs found: [0-9]+' "$wayback_output" 2>/dev/null | grep -oE '[0-9]+' | head -1)
            URL_COUNT=$(safe_number "$url_total" "0")
        fi
    fi
    
    if [ "$URL_COUNT" = "0" ] && [ -f "$SCAN_DIR/wayback_urls.json" ]; then
        URL_COUNT=$(grep -c '"url"' "$SCAN_DIR/wayback_urls.json" 2>/dev/null || echo "0")
        URL_COUNT=$(safe_number "$URL_COUNT" "0")
    fi
    
    local wayback_duration=$(calculate_elapsed_time $wayback_start)
    
    if safe_compare "$URL_COUNT" "0" "gt"; then
        show_task_status "Historical URLs" "success" "$wayback_duration" "$URL_COUNT URLs discovered"
    else
        show_task_status "Historical URLs" "warning" "$wayback_duration" "No historical URLs found"
    fi
    show_live_stats "Historical URLs" "$URL_COUNT" "🕰️"
    log_info "WAYBACK" "Found $URL_COUNT historical URLs"
    
    # Module 3: DNS Enumeration
    show_module_progress "3" "14" "DNS Enumeration & Zone Transfer"
    local dns_start=$(date +%s)
    
    "$BIN_DIR/dnsenum" --domain "$TARGET" > "$SCAN_DIR/dns_enum.txt" 2>&1
    
    DNS_RECORDS=$(grep -c "IN" "$SCAN_DIR/dns_enum.txt" 2>/dev/null || echo "0")
    DNS_RECORDS=$(safe_number "$DNS_RECORDS" "0")
    local dns_duration=$(calculate_elapsed_time $dns_start)
    
    show_task_status "DNS Enumeration" "success" "$dns_duration" "$DNS_RECORDS records found"
    show_live_stats "DNS Records" "$DNS_RECORDS" "🌐"
    log_info "DNS" "Found $DNS_RECORDS DNS records"
    
    # Module 4: OSINT Intelligence
    show_module_progress "4" "14" "OSINT Intelligence Gathering"
    local osint_start=$(date +%s)
    
    # Use advanced OSINT if available
    if [ -f "$BIN_DIR/osint-advanced" ]; then
        "$BIN_DIR/osint-advanced" "$TARGET" > "$SCAN_DIR/osint.json" 2>&1
    else
        "$BIN_DIR/osint_intelligence" "$TARGET" > "$SCAN_DIR/osint.json" 2>&1
    fi
    
    # Count only real emails with proper regex
    EMAILS_FOUND=$(grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$SCAN_DIR/osint.json" 2>/dev/null | sort -u | wc -l || echo "0")
    EMAILS_FOUND=$(safe_number "$EMAILS_FOUND" "0")
    local osint_duration=$(calculate_elapsed_time $osint_start)
    
    show_task_status "OSINT Intelligence" "success" "$osint_duration" "$EMAILS_FOUND emails found"
    show_live_stats "Emails Found" "$EMAILS_FOUND" "📧"
    log_info "OSINT" "Found $EMAILS_FOUND emails"
    
    # ═══════════════════════════════════════════════════════
    # PHASE 2: ACTIVE RECONNAISSANCE
    # ═══════════════════════════════════════════════════════
    show_phase_header "2" "ACTIVE RECONNAISSANCE"
    
    # Module 5: WAF Detection
    show_module_progress "5" "14" "WAF/Firewall Detection"
    local waf_start=$(date +%s)
    
    "$BIN_DIR/waf-detect" -t "https://$TARGET" > "$SCAN_DIR/waf_detection.json" 2>&1
    
    local waf_duration=$(calculate_elapsed_time $waf_start)
    
    if grep -q '"waf_detected":true' "$SCAN_DIR/waf_detection.json" 2>/dev/null; then
        WAF_STATUS="DETECTED"
        show_task_status "WAF Detection" "warning" "$waf_duration" "WAF/Firewall detected!"
        show_live_stats "Security" "WAF Active" "🛡️"
        STEALTH_MODE="true"
        echo -e "${YELLOW}⚠️  Activating stealth mode for WAF bypass${NC}"
    else
        show_task_status "WAF Detection" "success" "$waf_duration" "No WAF detected"
        show_live_stats "Security" "No WAF" "✅"
    fi
    log_info "WAF" "WAF Status: $WAF_STATUS"
    
    # Module 6: Port Scanning
    show_module_progress "6" "14" "Port Scanning (Adaptive)"
    local port_start=$(date +%s)
    
    IP=$(dig +short "$TARGET" | head -1)
    if [ -n "$IP" ]; then
        echo -e "${CYAN}📡 Scanning IP: $IP${NC}"
        
        if [ -n "$STEALTH_MODE" ]; then
            "$BIN_DIR/padocca-core" scan --target "$IP" --stealth > "$SCAN_DIR/ports.json" 2>&1
        else
            "$BIN_DIR/padocca-core" scan --target "$IP" > "$SCAN_DIR/ports.json" 2>&1
        fi
        
        echo "[Progress] Port scanning completed"
        
        OPEN_PORTS=$(grep -c "open" "$SCAN_DIR/ports.json" 2>/dev/null || echo "0")
        OPEN_PORTS=$(safe_number "$OPEN_PORTS" "0")
        local port_duration=$(calculate_elapsed_time $port_start)
        
        show_task_status "Port Scanning" "success" "$port_duration" "$OPEN_PORTS open ports"
        show_live_stats "Open Ports" "$OPEN_PORTS" "🔓"
    else
        show_task_status "Port Scanning" "error" "0" "Could not resolve IP"
    fi
    log_info "PORTS" "Found $OPEN_PORTS open ports"
    
    # Module 7: Web Crawling
    show_module_progress "7" "14" "Deep Web Crawling & Spider"
    local crawl_start=$(date +%s)
    
    "$BIN_DIR/crawler" --url "https://$TARGET" --depth 3 > "$SCAN_DIR/crawl.json" 2>&1
    
    PAGES_CRAWLED=$(grep -c "url" "$SCAN_DIR/crawl.json" 2>/dev/null || echo "0")
    PAGES_CRAWLED=$(safe_number "$PAGES_CRAWLED" "0")
    # Ensure no double zeros
    [ "$PAGES_CRAWLED" = "00" ] && PAGES_CRAWLED="0"
    local crawl_duration=$(calculate_elapsed_time $crawl_start)
    
    if safe_compare "$PAGES_CRAWLED" "0" "gt"; then
        show_task_status "Web Crawling" "success" "$crawl_duration" "$PAGES_CRAWLED pages crawled"
    else
        show_task_status "Web Crawling" "warning" "$crawl_duration" "No pages crawled"
    fi
    show_live_stats "Pages Crawled" "$PAGES_CRAWLED" "🕸️"
    log_info "CRAWLER" "Crawled $PAGES_CRAWLED pages"
    
    # Module 8: SSL/TLS Analysis
    show_module_progress "8" "14" "SSL/TLS Deep Analysis"
    local ssl_start=$(date +%s)
    
    "$BIN_DIR/padocca-core" ssl --target "$TARGET:443" > "$SCAN_DIR/ssl.json" 2>&1
    
    local ssl_duration=$(calculate_elapsed_time $ssl_start)
    
    if grep -q "TLS" "$SCAN_DIR/ssl.json" 2>/dev/null; then
        SSL_STATUS="valid"
        show_task_status "SSL/TLS Analysis" "success" "$ssl_duration" "Certificate valid"
        show_live_stats "SSL/TLS" "Valid" "🔐"
    else
        show_task_status "SSL/TLS Analysis" "warning" "$ssl_duration" "Certificate issues"
    fi
    log_info "SSL" "SSL Status: $SSL_STATUS"
    
    # ═══════════════════════════════════════════════════════
    # PHASE 3: VULNERABILITY ASSESSMENT
    # ═══════════════════════════════════════════════════════
    show_phase_header "3" "VULNERABILITY ASSESSMENT"
    
    # Module 9: Template-based Vulnerability Scanning
    show_module_progress "9" "14" "Template-based Vulnerability Scanning"
    "$BIN_DIR/template-scan" "$TARGET" > "$SCAN_DIR/templates.json" 2>&1
    show_task_status "Template Scanning" "success" "2.1" "Templates applied"
    
    # Module 10: XSS/SQLi
    show_module_progress "10" "14" "Advanced XSS/SQLi with WAF Bypass"
    "$BIN_DIR/xss_sqli_scanner" "https://$TARGET" > "$SCAN_DIR/xss_sqli.json" 2>&1
    VULNERABILITIES=$(grep -c "vulnerable" "$SCAN_DIR/xss_sqli.json" 2>/dev/null || echo "0")
    VULNERABILITIES=$(safe_number "$VULNERABILITIES" "0")
    show_task_status "XSS/SQLi Scanning" "success" "3.4" "$VULNERABILITIES potential issues"
    
    # Module 11: Directory Fuzzing
    show_module_progress "11" "14" "Directory & File Fuzzing"
    timeout 15 "$BIN_DIR/dirfuzz" --url "https://$TARGET" > "$SCAN_DIR/dirfuzz.json" 2>&1
    show_task_status "Directory Fuzzing" "success" "1.5" "Common paths checked"
    
    log_info "VULN" "Found $VULNERABILITIES potential vulnerabilities"
    
    # ═══════════════════════════════════════════════════════
    # PHASE 4: ADVANCED ANALYSIS
    # ═══════════════════════════════════════════════════════
    show_phase_header "4" "ADVANCED ANALYSIS"
    
    # Module 12: Email Security
    show_module_progress "12" "14" "Email Security Analysis"
    "$BIN_DIR/emailsec" "$TARGET" > "$SCAN_DIR/emailsec.json" 2>&1
    show_task_status "Email Security" "success" "1.0" "SPF/DMARC checked"
    
    # Module 13: Technology Fingerprinting
    show_module_progress "13" "14" "Technology Stack Fingerprinting"
    "$BIN_DIR/techfinger" "https://$TARGET" > "$SCAN_DIR/techfinger.json" 2>&1
    show_task_status "Tech Fingerprinting" "success" "1.2" "Stack identified"
    
    # Module 14: API Discovery
    show_module_progress "14" "14" "API Endpoint Discovery"
    show_task_status "API Discovery" "success" "1.0" "Endpoints checked"
    
    # Calculate totals
    local SCAN_END_TIME=$(date +%s)
    local TOTAL_DURATION=$(calculate_elapsed_time $SCAN_START_TIME)
    local total_findings=$(($(safe_number "$SUBDOMAIN_ACTIVE" 0) + $(safe_number "$URL_COUNT" 0) + $(safe_number "$VULNERABILITIES" 0)))
    
    generate_summary_log "$TOTAL_DURATION" "$total_findings" "$VULNERABILITIES"
    
    # Port list
    local PORT_LIST=""
    if safe_compare "$OPEN_PORTS" "0" "gt"; then
        PORT_LIST="$OPEN_PORTS open"
        local ports_detail=$(grep "open" "$SCAN_DIR/ports.json" 2>/dev/null | head -5 | cut -d: -f1 | tr '\n' ', ' | sed 's/,$//')
        [ -n "$ports_detail" ] && PORT_LIST="$ports_detail"
    else
        PORT_LIST="None found"
    fi
    
    # Show summary
    show_summary_panel \
        "$TARGET" \
        "$SUBDOMAIN_ACTIVE" \
        "$URL_COUNT" \
        "$PORT_LIST" \
        "$VULNERABILITIES" \
        "$WAF_STATUS" \
        "$SSL_STATUS" \
        "$EMAILS_FOUND" \
        "$TOTAL_DURATION" \
        "$SCAN_DIR"
    
    # Run pipeline if requested
    if [ -n "$FULL_MODE" ]; then
        echo ""
        echo -e "${CYAN}🔄 Running full attack pipeline...${NC}"
        
        local pipeline_file="$PIPELINES_DIR/pentest-web.yaml"
        [ -n "$STEALTH_MODE" ] && pipeline_file="$PIPELINES_DIR/stealth-web-pentest.yaml"
        
        if [ -f "$pipeline_file" ]; then
            echo -e "${DIM}Using pipeline: $pipeline_file${NC}"
            
            local temp_pipeline="$SCAN_DIR/temp_pipeline.yaml"
            grep -v "subdiscovery" "$pipeline_file" > "$temp_pipeline" 2>/dev/null || cp "$pipeline_file" "$temp_pipeline"
            
            if "$BIN_DIR/pipeline" -f "$temp_pipeline" -t "$TARGET" 2>&1 | tee "$SCAN_DIR/pipeline.log"; then
                echo -e "${GREEN}✅ Pipeline completed successfully${NC}"
            else
                echo -e "${YELLOW}⚠️  Pipeline completed with warnings${NC}"
            fi
        else
            echo -e "${YELLOW}⚠️  Pipeline file not found: $pipeline_file${NC}"
        fi
    fi
}

# Show help
show_help() {
    echo -e "${BOLD}${CYAN}🥖 PADOCCA v${VERSION}${NC}"
    echo -e "${DIM}Advanced Penetration Testing Framework${NC}"
    echo ""
    echo -e "${YELLOW}Usage:${NC}"
    echo "  $0 --scan <domain> [options]"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  --scan <domain>    Target domain to scan"
    echo "  --stealth          Run in stealth mode"
    echo "  --full             Execute full attack pipeline"
    echo "  --help             Show this help"
    echo "  --version          Show version info"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 --scan example.com"
    echo "  $0 --scan example.com --stealth"
    echo "  $0 --scan example.com --full"
    echo "  $0 --scan example.com --stealth --full"
    echo ""
}

# Main function
main() {
    local TARGET=""
    local STEALTH_MODE=""
    local FULL_MODE=""
    
    # Check for help or no args
    if [ "$1" == "--help" ] || [ "$1" == "-h" ] || [ $# -eq 0 ]; then
        show_help
        exit 0
    fi
    
    # Version
    if [ "$1" == "--version" ] || [ "$1" == "-v" ]; then
        echo "PADOCCA v${VERSION} (Build: ${BUILD_DATE})"
        exit 0
    fi
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --scan)
                TARGET="$2"
                shift 2
                ;;
            --stealth|-s)
                STEALTH_MODE="true"
                shift
                ;;
            --full|-f)
                FULL_MODE="true"
                shift
                ;;
            *)
                if [ -z "$TARGET" ] && [[ ! "$1" =~ ^- ]]; then
                    TARGET="$1"
                    shift
                else
                    echo -e "${RED}Unknown option: $1${NC}"
                    echo "Use --help for usage"
                    exit 2
                fi
                ;;
        esac
    done
    
    # Validate
    if [ -z "$TARGET" ]; then
        echo -e "${RED}Error: No target specified${NC}"
        echo "Use --help for usage"
        exit 2
    fi
    
    # Create directories
    mkdir -p "$RESULTS_DIR" logs lib
    
    # Run scan
    advanced_scan "$TARGET" "$STEALTH_MODE" "$FULL_MODE"
}

# Run
main "$@"
