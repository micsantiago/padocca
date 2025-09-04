#!/bin/bash

# PADOCCA Configuration Script
# Setup and configure PADOCCA Security Framework

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   PADOCCA CONFIGURATION WIZARD v1.4a     ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
    else
        OS="unknown"
    fi
    echo -e "${GREEN}[+] Detected OS: $OS${NC}"
}

# Check dependencies
check_dependency() {
    local cmd=$1
    local name=$2
    
    if command -v $cmd &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $name installed"
        return 0
    else
        echo -e "  ${RED}✗${NC} $name not found"
        return 1
    fi
}

# Install missing dependencies
install_dependencies() {
    echo -e "\n${YELLOW}[*] Checking dependencies...${NC}"
    
    local missing=()
    
    check_dependency "go" "Go" || missing+=("go")
    check_dependency "cargo" "Rust/Cargo" || missing+=("rust")
    check_dependency "python3" "Python3" || missing+=("python3")
    check_dependency "nmap" "Nmap" || missing+=("nmap")
    check_dependency "dig" "Dig" || missing+=("dnsutils")
    check_dependency "whois" "Whois" || missing+=("whois")
    check_dependency "curl" "Curl" || missing+=("curl")
    check_dependency "git" "Git" || missing+=("git")
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}[!] Missing dependencies: ${missing[*]}${NC}"
        read -p "Would you like to install them? (y/n): " -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if [ "$OS" == "macos" ]; then
                if ! command -v brew &> /dev/null; then
                    echo -e "${YELLOW}Installing Homebrew...${NC}"
                    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
                fi
                
                for dep in "${missing[@]}"; do
                    echo -e "${YELLOW}Installing $dep...${NC}"
                    brew install $dep
                done
            elif [ "$OS" == "linux" ]; then
                for dep in "${missing[@]}"; do
                    echo -e "${YELLOW}Installing $dep...${NC}"
                    sudo apt-get install -y $dep
                done
            fi
        fi
    else
        echo -e "${GREEN}[+] All dependencies are installed!${NC}"
    fi
}

# Setup directories
setup_directories() {
    echo -e "\n${YELLOW}[*] Setting up directories...${NC}"
    
    mkdir -p bin
    mkdir -p lib
    mkdir -p logs
    mkdir -p results
    mkdir -p config
    mkdir -p pipelines
    mkdir -p templates/{sqli,xss,xxe,rce,stealth}
    mkdir -p docs
    mkdir -p tools-go/{cmd,pkg}
    mkdir -p core-rust/src
    
    echo -e "${GREEN}[+] Directories created${NC}"
}

# Setup configuration files
setup_config() {
    echo -e "\n${YELLOW}[*] Creating configuration files...${NC}"
    
    # Create default config
    if [ ! -f "config/padocca.yaml" ]; then
        cat > config/padocca.yaml << 'EOF'
# PADOCCA Default Configuration
version: 1.4a

# Default settings
defaults:
  stealth_mode: false
  threads: 20
  timeout: 10
  output_dir: ./results
  log_level: INFO

# Stealth configuration
stealth:
  level: 2  # 0-4
  min_delay: 1000
  max_delay: 5000
  user_agent_rotation: true
  proxy_rotation: true

# Network settings
network:
  max_retries: 3
  connection_timeout: 10
  read_timeout: 30

# Cache settings
cache:
  enabled: true
  ttl: 3600
  max_entries: 10000

# Output formats
output:
  formats:
    - json
    - html
  generate_report: true
EOF
        echo -e "  ${GREEN}✓${NC} Created config/padocca.yaml"
    fi
    
    # Create example pipeline
    if [ ! -f "pipelines/example.yaml" ]; then
        cat > pipelines/example.yaml << 'EOF'
name: "Example Pipeline"
description: "Basic security scan pipeline"
version: "1.0"

settings:
  cache:
    enabled: true
    ttl: 3600
  stealth:
    enabled: false
  parallel:
    max_workers: 10

stages:
  - name: "reconnaissance"
    steps:
      - module: "subdiscovery"
        config:
          sources: ["all"]
      - module: "wayback"
        config:
          validate: true

  - name: "scanning"
    parallel: true
    steps:
      - module: "portscan"
      - module: "waf_detection"
EOF
        echo -e "  ${GREEN}✓${NC} Created pipelines/example.yaml"
    fi
}

# Compile Go modules
compile_go_modules() {
    echo -e "\n${YELLOW}[*] Compiling Go modules...${NC}"
    
    cd tools-go
    
    # List of modules to compile
    modules=("subdiscovery" "wayback" "pipeline" "bruteforce")
    
    for module in "${modules[@]}"; do
        if [ -f "cmd/$module/main.go" ]; then
            echo -n "  Compiling $module... "
            if go build -o ../bin/$module cmd/$module/main.go 2>/dev/null; then
                echo -e "${GREEN}OK${NC}"
            else
                echo -e "${YELLOW}SKIP${NC}"
            fi
        fi
    done
    
    cd ..
}

# Setup the new version
setup_new_version() {
    echo -e "\n${YELLOW}[*] Setting up PADOCCA v1.4a...${NC}"
    
    # Backup old version if exists
    if [ -f "padocca.sh" ] && [ ! -L "padocca.sh" ]; then
        mv padocca.sh padocca_old.sh.backup
        echo -e "  ${GREEN}✓${NC} Backed up old version"
    fi
    
    # Remove old symlink if exists
    if [ -L "padocca.sh" ]; then
        rm padocca.sh
    fi
    
    # Use the fixed v3 version
    if [ -f "padocca_v3_fixed.sh" ]; then
        ln -s padocca_v3_fixed.sh padocca.sh
        chmod +x padocca_v3_fixed.sh
        echo -e "  ${GREEN}✓${NC} Linked to v3.1 (fixed version)"
    elif [ -f "padocca_v3.sh" ]; then
        ln -s padocca_v3.sh padocca.sh
        chmod +x padocca_v3.sh
        echo -e "  ${GREEN}✓${NC} Linked to v3.0"
    else
        echo -e "  ${RED}✗${NC} No v3 script found"
    fi
    
    # Make all scripts executable
    chmod +x *.sh 2>/dev/null
    chmod +x lib/*.sh 2>/dev/null
    chmod +x bin/* 2>/dev/null
}

# Create aliases
create_aliases() {
    echo -e "\n${YELLOW}[*] Creating aliases...${NC}"
    
    CURRENT_DIR=$(pwd)
    ALIAS_CMD="alias padocca='$CURRENT_DIR/padocca.sh'"
    
    # Check which shell config to use
    if [ -f "$HOME/.bashrc" ]; then
        if ! grep -q "alias padocca=" "$HOME/.bashrc"; then
            echo "$ALIAS_CMD" >> "$HOME/.bashrc"
            echo -e "  ${GREEN}✓${NC} Added to .bashrc"
        fi
    fi
    
    if [ -f "$HOME/.zshrc" ]; then
        if ! grep -q "alias padocca=" "$HOME/.zshrc"; then
            echo "$ALIAS_CMD" >> "$HOME/.zshrc"
            echo -e "  ${GREEN}✓${NC} Added to .zshrc"
        fi
    fi
    
    echo -e "  ${CYAN}Run 'source ~/.bashrc' or 'source ~/.zshrc' to activate${NC}"
}

# Test installation
test_installation() {
    echo -e "\n${YELLOW}[*] Testing installation...${NC}"
    
    if ./padocca.sh --version &>/dev/null; then
        VERSION=$(./padocca.sh --version | grep -oE '[0-9]+\.[0-9]+')
        echo -e "  ${GREEN}✓${NC} PADOCCA v${VERSION} is working!"
    else
        echo -e "  ${RED}✗${NC} PADOCCA is not working properly"
        return 1
    fi
    
    # Test help
    if ./padocca.sh --help &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Help command works"
    fi
    
    # Test modules
    for module in subdiscovery wayback pipeline; do
        if [ -f "bin/$module" ] && [ -x "bin/$module" ]; then
            echo -e "  ${GREEN}✓${NC} Module $module is ready"
        else
            echo -e "  ${YELLOW}!${NC} Module $module not found"
        fi
    done
}

# Main setup flow
main() {
    detect_os
    install_dependencies
    setup_directories
    setup_config
    compile_go_modules
    setup_new_version
    create_aliases
    test_installation
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     CONFIGURATION COMPLETE!               ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Quick Start:${NC}"
    echo "  ./padocca.sh --help           # Show help"
    echo "  ./padocca.sh --help-full      # Complete documentation"
    echo "  ./padocca.sh --scan domain.com # Basic scan"
    echo ""
    echo -e "${YELLOW}Remember to source your shell config:${NC}"
    echo "  source ~/.bashrc  # For bash"
    echo "  source ~/.zshrc   # For zsh"
    echo ""
}

# Run main
main
