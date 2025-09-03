#!/bin/bash

# PADOCCA v2.0 - Advanced Penetration Testing Framework
# Ultimate Security Scanner with AI-powered capabilities

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Banner
show_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════╗"
    echo "║       🥖 PADOCCA SECURITY FRAMEWORK v2.0 🥖       ║"
    echo "║         Elite • Stealth • Undetectable            ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Help
show_help() {
    echo -e "${BOLD}Usage: $0 <command> [options]${NC}"
    echo ""
    echo -e "${YELLOW}Core Commands:${NC}"
    echo "  --scan <domain>      - Full comprehensive scan"
    echo "  --dns <domain>       - DNS enumeration"
    echo "  --ports <domain>     - Port scanning"
    echo "  --crawl <url>        - Web crawler for emails and URLs"
    echo "  --fuzzer <url>       - Directory fuzzing"
    echo "  --ssl <domain>       - SSL/TLS deep analysis"
    echo "  --email <domain>     - Email security analysis"
    echo ""
    echo -e "${CYAN}Advanced Attack Modules:${NC}"
    echo "  --xss-sqli <url>     - Advanced XSS/SQLi scanner with WAF bypass"
    echo "  --osint <domain>     - Deep OSINT intelligence gathering"
    echo "  --bruteforce <url>   - Intelligent stealth bruteforce"
    echo "  --exploit <options>  - Exploit development framework"
    echo ""
    echo -e "${PURPLE}Exploit Framework Commands:${NC}"
    echo "  --exploit rop-chain <binary>    - Generate ROP chain"
    echo "  --exploit bypass <target>        - Bypass ASLR/DEP protections"
    echo "  --exploit shellcode <type>      - Generate advanced shellcode"
    echo "  --exploit fuzz <target>          - Fuzzing for zero-days"
    echo "  --exploit analyze <binary>       - Analyze binary protections"
    echo ""
    echo -e "${GREEN}Examples:${NC}"
    echo "  $0 --scan example.com"
    echo "  $0 --xss-sqli https://example.com/login"
    echo "  $0 --osint example.com"
    echo "  $0 --bruteforce https://example.com/admin"
    echo "  $0 --exploit analyze /usr/bin/program"
}

# Check dependencies
check_dependencies() {
    local missing=()
    
    # Check Go tools
    if ! command -v go &> /dev/null; then
        missing+=("go")
    fi
    
    # Check Rust tools
    if ! command -v cargo &> /dev/null; then
        missing+=("rust/cargo")
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        missing+=("python3")
    fi
    
    # Check network tools
    for tool in nmap dig whois curl; do
        if ! command -v $tool &> /dev/null; then
            missing+=($tool)
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing dependencies: ${missing[*]}${NC}"
        echo -e "${YELLOW}[*] Please run: ./install.sh${NC}"
        exit 1
    fi
}

# Set paths - resolve symlinks to get real directory
# Get the real path of the script, resolving symlinks
if [ -L "${BASH_SOURCE[0]}" ]; then
    # Script is a symlink, resolve it
    SCRIPT_PATH=$(readlink "${BASH_SOURCE[0]}")
    # If readlink returns relative path, make it absolute
    if [[ "$SCRIPT_PATH" != /* ]]; then
        SCRIPT_PATH="$(dirname "${BASH_SOURCE[0]}")/$SCRIPT_PATH"
    fi
else
    # Script is not a symlink
    SCRIPT_PATH="${BASH_SOURCE[0]}"
fi

SCRIPT_DIR="$( cd "$( dirname "$SCRIPT_PATH" )" && pwd )"
BIN_DIR="$SCRIPT_DIR/bin"
TOOLS_GO="$SCRIPT_DIR/tools-go"
CORE_RUST="$SCRIPT_DIR/core-rust"
EXPLOIT_FRAMEWORK="$SCRIPT_DIR/exploit_framework"

# Main script
main() {
    show_banner
    
    if [ $# -eq 0 ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
        show_help
        exit 0
    fi
    
    check_dependencies
    
    case "$1" in
        --scan)
            if [ -z "$2" ]; then
                echo -e "${RED}[!] Please provide a domain${NC}"
                exit 1
            fi
            echo -e "${CYAN}[*] Starting comprehensive scan on $2${NC}"
            
            # DNS Enumeration
            echo -e "\n${YELLOW}[1/8] DNS Enumeration${NC}"
            "$BIN_DIR/dnsenum" --domain "$2"
            
            # Port Scanning
            echo -e "\n${YELLOW}[2/8] Port Scanning${NC}"
            IP=$(dig +short "$2" | head -1)
            if [ -n "$IP" ]; then
                "$BIN_DIR/padocca-core" scan --target "$IP"
            else
                echo "[-] Could not resolve IP for $2"
            fi
            
            # Web Crawling
            echo -e "\n${YELLOW}[3/8] Web Crawling${NC}"
            "$BIN_DIR/crawler" --url "https://$2"
            
            # XSS/SQLi Scanning
            echo -e "\n${YELLOW}[4/8] XSS/SQLi Scanning with WAF Bypass${NC}"
            "$BIN_DIR/xss_sqli_scanner" "https://$2"
            
            # OSINT Intelligence
            echo -e "\n${YELLOW}[5/8] OSINT Intelligence Gathering${NC}"
            "$BIN_DIR/osint_intelligence" "$2"
            
            # SSL Analysis
            echo -e "\n${YELLOW}[6/8] SSL/TLS Analysis${NC}"
            "$BIN_DIR/padocca-core" ssl --target "$2:443" || echo "SSL analysis not available"
            
            # Email Security
            echo -e "\n${YELLOW}[7/8] Email Security Analysis${NC}"
            echo "[*] Checking email security configurations..."
            dig +short TXT "$2" | grep -E "v=spf" || echo "[-] No SPF record found"
            dig +short TXT "_dmarc.$2" | grep -E "v=DMARC" || echo "[-] No DMARC record found"
            
            # Technology Fingerprinting
            echo -e "\n${YELLOW}[8/8] Technology Fingerprinting${NC}"
            # Integrated in OSINT module
            
            echo -e "\n${GREEN}[+] Scan complete!${NC}"
            ;;
            
        --dns)
            if [ -z "$2" ]; then
                echo -e "${RED}[!] Please provide a domain${NC}"
                exit 1
            fi
            echo -e "${CYAN}[*] DNS Enumeration for $2${NC}"
            "$BIN_DIR/dnsenum" --domain "$2"
            ;;
            
        --ports)
            if [ -z "$2" ]; then
                echo -e "${RED}[!] Please provide a target${NC}"
                exit 1
            fi
            echo -e "${CYAN}[*] Port Scanning $2${NC}"
            IP=$(dig +short "$2" | head -1)
            if [ -n "$IP" ]; then
                "$BIN_DIR/padocca-core" scan --target "$IP"
            else
                echo "[-] Could not resolve IP for $2"
            fi
            ;;
            
        --crawl)
            if [ -z "$2" ]; then
                echo -e "${RED}[!] Please provide a URL${NC}"
                exit 1
            fi
            echo -e "${CYAN}[*] Web Crawling $2${NC}"
            "$BIN_DIR/crawler" --url "$2"
            ;;
            
        --fuzzer)
            if [ -z "$2" ]; then
                echo -e "${RED}[!] Please provide a URL${NC}"
                exit 1
            fi
            echo -e "${CYAN}[*] Directory Fuzzing $2${NC}"
            "$BIN_DIR/dirfuzz" "$2"
            ;;
            
        --ssl)
            if [ -z "$2" ]; then
                echo -e "${RED}[!] Please provide a domain${NC}"
                exit 1
            fi
            echo -e "${CYAN}[*] SSL/TLS Analysis for $2${NC}"
            "$BIN_DIR/padocca-core" ssl --target "$2:443" || echo "SSL analysis not available"
            ;;
            
        --email)
            if [ -z "$2" ]; then
                echo -e "${RED}[!] Please provide a domain${NC}"
                exit 1
            fi
            echo -e "${CYAN}[*] Email Security Analysis for $2${NC}"
            python3 "$SCRIPT_DIR/padocca" --email "$2"
            ;;
            
        --xss-sqli)
            if [ -z "$2" ]; then
                echo -e "${RED}[!] Please provide a URL${NC}"
                exit 1
            fi
            echo -e "${CYAN}[*] Advanced XSS/SQLi Scanning with WAF Bypass${NC}"
            "$BIN_DIR/xss_sqli_scanner" "$2"
            ;;
            
        --osint)
            if [ -z "$2" ]; then
                echo -e "${RED}[!] Please provide a domain${NC}"
                exit 1
            fi
            echo -e "${CYAN}[*] Deep OSINT Intelligence Gathering${NC}"
            "$BIN_DIR/osint_intelligence" "$2"
            ;;
            
        --bruteforce)
            if [ -z "$2" ]; then
                echo -e "${RED}[!] Please provide a URL${NC}"
                exit 1
            fi
            echo -e "${CYAN}[*] Intelligent Stealth Bruteforce${NC}"
            echo -e "${YELLOW}[!] WARNING: Use only on authorized targets!${NC}"
            read -p "Are you authorized to test this target? (yes/no): " confirm
            if [ "$confirm" == "yes" ]; then
                "$BIN_DIR/intelligent_bruteforce" "$2"
            else
                echo -e "${RED}[!] Aborted. Only test authorized targets.${NC}"
            fi
            ;;
            
        --exploit)
            case "$2" in
                rop-chain)
                    if [ -z "$3" ]; then
                        echo -e "${RED}[!] Please provide a binary path${NC}"
                        exit 1
                    fi
                    echo -e "${CYAN}[*] Generating ROP chain for $3${NC}"
                    cd "$EXPLOIT_FRAMEWORK" && cargo run --release -- rop-chain -b "$3"
                    ;;
                    
                bypass)
                    if [ -z "$3" ]; then
                        echo -e "${RED}[!] Please provide a target${NC}"
                        exit 1
                    fi
                    echo -e "${CYAN}[*] Bypassing protections for $3${NC}"
                    cd "$EXPLOIT_FRAMEWORK" && cargo run --release -- bypass -t "$3"
                    ;;
                    
                shellcode)
                    if [ -z "$3" ]; then
                        echo -e "${RED}[!] Please specify shellcode type${NC}"
                        echo "Options: reverse_shell, bind_shell, exec"
                        exit 1
                    fi
                    echo -e "${CYAN}[*] Generating $3 shellcode${NC}"
                    if [ "$3" == "reverse_shell" ]; then
                        read -p "Enter IP:PORT: " params
                        cd "$EXPLOIT_FRAMEWORK" && cargo run --release -- shellcode -p reverse_shell --params "$params"
                    else
                        cd "$EXPLOIT_FRAMEWORK" && cargo run --release -- shellcode -p "$3"
                    fi
                    ;;
                    
                fuzz)
                    if [ -z "$3" ]; then
                        echo -e "${RED}[!] Please provide a target${NC}"
                        exit 1
                    fi
                    echo -e "${CYAN}[*] Fuzzing $3 for vulnerabilities${NC}"
                    cd "$EXPLOIT_FRAMEWORK" && cargo run --release -- fuzz -t "$3"
                    ;;
                    
                analyze)
                    if [ -z "$3" ]; then
                        echo -e "${RED}[!] Please provide a binary path${NC}"
                        exit 1
                    fi
                    echo -e "${CYAN}[*] Analyzing binary protections for $3${NC}"
                    cd "$EXPLOIT_FRAMEWORK" && cargo run --release -- analyze -b "$3"
                    ;;
                    
                *)
                    echo -e "${RED}[!] Unknown exploit command: $2${NC}"
                    echo "Available: rop-chain, bypass, shellcode, fuzz, analyze"
                    exit 1
                    ;;
            esac
            ;;
            
        *)
            echo -e "${RED}[!] Unknown command: $1${NC}"
            show_help
            exit 1
            ;;
    esac
}

# Run main
main "$@"
