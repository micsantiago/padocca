#!/bin/bash

# PADOCCA - Clean Build Script
# Removes all build artifacts and creates fresh build

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════╗"
echo "║      PADOCCA CLEAN BUILD SYSTEM                    ║"
echo "║      Removing artifacts and rebuilding             ║"
echo "╚════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running from project root
if [ ! -f "Makefile" ]; then
    echo -e "${RED}[!] Please run this script from the project root directory${NC}"
    exit 1
fi

# Calculate size before cleaning
BEFORE_SIZE=$(du -sh . 2>/dev/null | cut -f1)
echo -e "${BLUE}[i] Project size before cleaning: ${BEFORE_SIZE}${NC}"

# Step 1: Remove build artifacts
echo -e "${YELLOW}[1/6] Removing build artifacts...${NC}"

# Remove Rust artifacts
if [ -d "core-rust/target" ]; then
    echo "  • Removing Rust target directory..."
    rm -rf core-rust/target
fi

if [ -d "exploit_framework/target" ]; then
    echo "  • Removing Exploit Framework target directory..."
    rm -rf exploit_framework/target
fi

# Remove Go artifacts
echo "  • Cleaning Go cache..."
cd tools-go 2>/dev/null && go clean -cache -modcache -testcache 2>/dev/null || true
cd - > /dev/null 2>&1

# Remove Python artifacts
echo "  • Removing Python cache..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
find . -type f -name "*.pyo" -delete 2>/dev/null || true
find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true

# Remove binaries
if [ -d "bin" ]; then
    echo "  • Removing compiled binaries..."
    rm -rf bin/*
fi

if [ -d "build" ]; then
    echo "  • Removing build directory..."
    rm -rf build/*
fi

echo -e "${GREEN}[✓] Build artifacts removed${NC}"

# Step 2: Remove temporary files
echo -e "${YELLOW}[2/6] Removing temporary files...${NC}"

# Remove OS-specific files
find . -name ".DS_Store" -delete 2>/dev/null || true
find . -name "Thumbs.db" -delete 2>/dev/null || true
find . -name "*~" -delete 2>/dev/null || true

# Remove log files
find . -name "*.log" -delete 2>/dev/null || true

# Remove report files
rm -f osint_report_*.txt 2>/dev/null
rm -f osint_report_*.json 2>/dev/null
rm -f padocca_report_*.json 2>/dev/null
rm -f padocca_report_*.txt 2>/dev/null

echo -e "${GREEN}[✓] Temporary files removed${NC}"

# Step 3: Create necessary directories
echo -e "${YELLOW}[3/6] Creating directory structure...${NC}"

mkdir -p bin
mkdir -p build/{linux,macos,windows}
mkdir -p results
mkdir -p logs
mkdir -p tmp
mkdir -p backups

echo -e "${GREEN}[✓] Directory structure created${NC}"

# Step 4: Initialize git (if needed)
if [ ! -d ".git" ]; then
    echo -e "${YELLOW}[4/6] Initializing git repository...${NC}"
    git init
    git add .gitignore
    git commit -m "Initial commit with .gitignore" > /dev/null 2>&1
    echo -e "${GREEN}[✓] Git repository initialized${NC}"
else
    echo -e "${BLUE}[4/6] Git repository already exists${NC}"
fi

# Step 5: Build the project
echo -e "${YELLOW}[5/6] Building PADOCCA...${NC}"

# Build Rust components
echo -e "${CYAN}  Building Rust core...${NC}"
cd core-rust
cargo build --release
cp target/release/padocca-core ../bin/
cd ..
echo -e "${GREEN}  ✓ Rust core built${NC}"

# Build Go components
echo -e "${CYAN}  Building Go tools...${NC}"
cd tools-go

# Build each tool
tools=("bruteforce" "crawler" "dirfuzz" "dnsenum" "emailsec" "proxychain" "techfinger")
for tool in "${tools[@]}"; do
    if [ -d "cmd/$tool" ]; then
        echo "    • Building $tool..."
        go build -ldflags="-s -w" -o ../bin/$tool ./cmd/$tool/ 2>/dev/null || \
            echo -e "${YELLOW}      Warning: Failed to build $tool${NC}"
    fi
done
cd ..
echo -e "${GREEN}  ✓ Go tools built${NC}"

# Build additional Go tools from root
echo -e "${CYAN}  Building additional tools...${NC}"

if [ -f "intelligent_bruteforce.go" ]; then
    echo "    • Building intelligent_bruteforce..."
    go build -ldflags="-s -w" -o bin/intelligent_bruteforce intelligent_bruteforce.go
fi

if [ -f "osint_intelligence.go" ]; then
    echo "    • Building osint_intelligence..."
    go build -ldflags="-s -w" -o bin/osint_intelligence osint_intelligence.go
fi

if [ -f "xss_sqli_scanner.go" ]; then
    echo "    • Building xss_sqli_scanner..."
    go build -ldflags="-s -w" -o bin/xss_sqli_scanner xss_sqli_scanner.go
fi

echo -e "${GREEN}  ✓ Additional tools built${NC}"

# Build Exploit Framework
if [ -d "exploit_framework" ]; then
    echo -e "${CYAN}  Building Exploit Framework...${NC}"
    cd exploit_framework
    cargo build --release
    cp target/release/exploit-framework ../bin/ 2>/dev/null || true
    cd ..
    echo -e "${GREEN}  ✓ Exploit Framework built${NC}"
fi

echo -e "${GREEN}[✓] Build completed${NC}"

# Step 6: Verify build
echo -e "${YELLOW}[6/6] Verifying build...${NC}"

# Count built binaries
BINARY_COUNT=$(ls -1 bin/ 2>/dev/null | wc -l)
echo -e "${BLUE}  • Built binaries: $BINARY_COUNT${NC}"

# Check binary sizes
TOTAL_SIZE=$(du -sh bin/ 2>/dev/null | cut -f1)
echo -e "${BLUE}  • Total binary size: $TOTAL_SIZE${NC}"

# Calculate size after cleaning
AFTER_SIZE=$(du -sh . 2>/dev/null | cut -f1)
echo -e "${BLUE}  • Project size after clean build: ${AFTER_SIZE}${NC}"

# List built tools
echo -e "${CYAN}  • Available tools:${NC}"
ls -1 bin/ | while read tool; do
    echo "      ✓ $tool"
done

echo -e "${GREEN}"
echo "═══════════════════════════════════════════════════════"
echo "      ✅ CLEAN BUILD COMPLETED SUCCESSFULLY!"
echo "═══════════════════════════════════════════════════════"
echo -e "${NC}"
echo -e "${BLUE}[i] Project size: ${BEFORE_SIZE} -> ${AFTER_SIZE}${NC}"
echo -e "${BLUE}[i] Run './padocca.sh --help' to get started${NC}"
