#!/bin/bash

# PADOCCA - Dependency Update Script
# Updates all dependencies to latest stable versions

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════╗"
echo "║   PADOCCA DEPENDENCY UPDATE SYSTEM                 ║"
echo "║   Updating to latest stable versions               ║"
echo "╚════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running from project root
if [ ! -f "Makefile" ]; then
    echo -e "${RED}[!] Please run this script from the project root directory${NC}"
    exit 1
fi

# Create backup
echo -e "${YELLOW}[*] Creating dependency backup...${NC}"
mkdir -p backups/$(date +%Y%m%d)
cp -f tools-go/go.mod backups/$(date +%Y%m%d)/go.mod.backup 2>/dev/null || true
cp -f tools-go/go.sum backups/$(date +%Y%m%d)/go.sum.backup 2>/dev/null || true
cp -f core-rust/Cargo.toml backups/$(date +%Y%m%d)/Cargo.toml.backup 2>/dev/null || true
cp -f requirements.txt backups/$(date +%Y%m%d)/requirements.txt.backup 2>/dev/null || true

# Update Go dependencies
echo -e "${YELLOW}[*] Updating Go dependencies...${NC}"
cd tools-go

# Update go.mod to latest Go version
go mod edit -go=1.25

# Update all dependencies
go get -u ./...
go mod tidy
go mod verify

echo -e "${GREEN}[✓] Go dependencies updated${NC}"
cd ..

# Update Rust dependencies
echo -e "${YELLOW}[*] Updating Rust dependencies...${NC}"
cd core-rust

# Update Cargo.toml dependencies
cargo update

# Check for outdated dependencies
echo -e "${BLUE}[i] Checking for outdated Rust dependencies...${NC}"
if command -v cargo-outdated &> /dev/null; then
    cargo outdated
else
    echo -e "${YELLOW}[!] Install cargo-outdated for better dependency management:${NC}"
    echo "    cargo install cargo-outdated"
fi

echo -e "${GREEN}[✓] Rust dependencies updated${NC}"
cd ..

# Update Python dependencies
echo -e "${YELLOW}[*] Updating Python dependencies...${NC}"

# Create new requirements file with latest versions
cat > requirements-new.txt << 'EOF'
# Core dependencies - Latest stable versions
requests>=2.32.0
colorama>=0.4.6
dnspython>=2.6.0
python-whois>=0.9.0
beautifulsoup4>=4.12.0
lxml>=5.2.0
pyyaml>=6.0.2
urllib3>=2.2.0

# Security and crypto
cryptography>=42.0.0
paramiko>=3.4.0

# Network tools
netaddr>=1.2.0
python-nmap>=0.7.1

# API clients
shodan>=1.31.0
censys>=2.2.0

# CLI and display
rich>=13.7.0
click>=8.1.0
tabulate>=0.9.0

# Additional tools
aiohttp>=3.9.0
selenium>=4.18.0
pyppeteer>=2.0.0
validators>=0.22.0

# Configuration
python-dotenv>=1.0.0
pydantic>=2.6.0

# Testing
pytest>=8.1.0
pytest-cov>=5.0.0
pytest-asyncio>=0.23.0

# Development
black>=24.3.0
flake8>=7.0.0
mypy>=1.9.0
EOF

mv requirements-new.txt requirements.txt
echo -e "${GREEN}[✓] Python dependencies updated${NC}"

# Update exploit framework dependencies
if [ -d "exploit_framework" ]; then
    echo -e "${YELLOW}[*] Updating Exploit Framework dependencies...${NC}"
    cd exploit_framework
    cargo update
    cd ..
    echo -e "${GREEN}[✓] Exploit Framework dependencies updated${NC}"
fi

# Verify all updates
echo -e "${BLUE}"
echo "═══════════════════════════════════════════════════════"
echo "           DEPENDENCY UPDATE SUMMARY"
echo "═══════════════════════════════════════════════════════"
echo -e "${NC}"

# Show Go version
echo -e "${CYAN}Go Dependencies:${NC}"
cd tools-go
go version
echo "  Modules updated: $(go list -m all | wc -l)"
cd ..

# Show Rust version
echo -e "${CYAN}Rust Dependencies:${NC}"
rustc --version
cargo --version

# Show Python version
echo -e "${CYAN}Python Dependencies:${NC}"
python3 --version
echo "  Packages in requirements.txt: $(grep -c '^[^#]' requirements.txt)"

# Build test
echo -e "${YELLOW}[*] Running build test...${NC}"
make clean > /dev/null 2>&1
if make build > /dev/null 2>&1; then
    echo -e "${GREEN}[✓] Build test successful!${NC}"
else
    echo -e "${RED}[!] Build test failed. Rolling back...${NC}"
    
    # Restore backups
    cp -f backups/$(date +%Y%m%d)/go.mod.backup tools-go/go.mod 2>/dev/null || true
    cp -f backups/$(date +%Y%m%d)/go.sum.backup tools-go/go.sum 2>/dev/null || true
    cp -f backups/$(date +%Y%m%d)/Cargo.toml.backup core-rust/Cargo.toml 2>/dev/null || true
    cp -f backups/$(date +%Y%m%d)/requirements.txt.backup requirements.txt 2>/dev/null || true
    
    echo -e "${YELLOW}[*] Dependencies restored to previous versions${NC}"
    exit 1
fi

echo -e "${GREEN}"
echo "═══════════════════════════════════════════════════════"
echo "     ✅ ALL DEPENDENCIES SUCCESSFULLY UPDATED!"
echo "═══════════════════════════════════════════════════════"
echo -e "${NC}"
echo -e "${BLUE}[i] Backups saved in: backups/$(date +%Y%m%d)/${NC}"
echo -e "${BLUE}[i] Run 'make test' to verify everything works${NC}"
