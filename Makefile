# Padocca Build System
# Cross-platform build for Linux, macOS, and Windows

.PHONY: all clean build-rust build-go build-python install test

# Variables
RUST_DIR = core-rust
GO_DIR = tools-go
PYTHON_DIR = interface-python
BUILD_DIR = build
BINARY_NAME = padocca

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
NC = \033[0m # No Color

# Default target
all: banner clean build

banner:
	@echo "$(BLUE)"
	@echo "╔══════════════════════════════════════╗"
	@echo "║   🥖 PADOCCA BUILD SYSTEM 🥖        ║"
	@echo "║   Building Elite Pentesting Tool     ║"
	@echo "╚══════════════════════════════════════╝"
	@echo "$(NC)"

# Build all components
build: build-rust build-go build-python package
	@echo "$(GREEN)✅ Build complete!$(NC)"

# Build Rust core
build-rust:
	@echo "$(YELLOW)🦀 Building Rust core...$(NC)"
	@cd $(RUST_DIR) && cargo build --release
	@mkdir -p $(BUILD_DIR)
	@cp $(RUST_DIR)/target/release/padocca-core $(BUILD_DIR)/
	@echo "$(GREEN)✓ Rust core built$(NC)"

# Build Go tools
build-go:
	@echo "$(YELLOW)🐹 Building Go tools...$(NC)"
	@cd $(GO_DIR) && go build -ldflags="-s -w" -o ../$(BUILD_DIR)/padocca-crawler cmd/crawler/main.go
	@cd $(GO_DIR) && go build -ldflags="-s -w" -o ../$(BUILD_DIR)/padocca-brute cmd/bruteforce/main.go 2>/dev/null || true
	@echo "$(GREEN)✓ Go tools built$(NC)"

# Setup Python interface
build-python:
	@echo "$(YELLOW)🐍 Setting up Python interface...$(NC)"
	@cd $(PYTHON_DIR) && pip install -r requirements.txt 2>/dev/null || true
	@chmod +x $(PYTHON_DIR)/padocca.py
	@echo "$(GREEN)✓ Python interface ready$(NC)"

# Package everything
package:
	@echo "$(YELLOW)📦 Packaging Padocca...$(NC)"
	@cp $(PYTHON_DIR)/padocca.py $(BUILD_DIR)/$(BINARY_NAME)
	@chmod +x $(BUILD_DIR)/$(BINARY_NAME)
	@echo "$(GREEN)✓ Packaging complete$(NC)"

# Cross-platform builds
build-linux:
	@echo "$(YELLOW)🐧 Building for Linux...$(NC)"
	@cd $(RUST_DIR) && cargo build --release --target x86_64-unknown-linux-gnu
	@cd $(GO_DIR) && GOOS=linux GOARCH=amd64 go build -o ../$(BUILD_DIR)/linux/

build-macos:
	@echo "$(YELLOW)🍎 Building for macOS...$(NC)"
	@cd $(RUST_DIR) && cargo build --release --target x86_64-apple-darwin
	@cd $(GO_DIR) && GOOS=darwin GOARCH=amd64 go build -o ../$(BUILD_DIR)/macos/

build-windows:
	@echo "$(YELLOW)🪟 Building for Windows...$(NC)"
	@cd $(RUST_DIR) && cargo build --release --target x86_64-pc-windows-gnu
	@cd $(GO_DIR) && GOOS=windows GOARCH=amd64 go build -o ../$(BUILD_DIR)/windows/

# Install locally
install: build
	@echo "$(YELLOW)📥 Installing Padocca...$(NC)"
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@sudo cp $(BUILD_DIR)/padocca-* /usr/local/bin/
	@echo "$(GREEN)✅ Padocca installed to /usr/local/bin/$(NC)"

# Run tests
test:
	@echo "$(YELLOW)🧪 Running tests...$(NC)"
	@cd $(RUST_DIR) && cargo test
	@cd $(GO_DIR) && go test ./...
	@echo "$(GREEN)✓ All tests passed$(NC)"

# Clean build artifacts
clean:
	@echo "$(YELLOW)🧹 Cleaning build artifacts...$(NC)"
	@rm -rf $(BUILD_DIR)/*
	@cd $(RUST_DIR) && cargo clean
	@cd $(GO_DIR) && go clean
	@echo "$(GREEN)✓ Cleaned$(NC)"

# Development mode
dev:
	@echo "$(YELLOW)👨‍💻 Starting development mode...$(NC)"
	@cd $(RUST_DIR) && cargo watch -x run

# Help
help:
	@echo "$(BLUE)Padocca Build System$(NC)"
	@echo ""
	@echo "Available targets:"
	@echo "  $(GREEN)all$(NC)          - Build everything (default)"
	@echo "  $(GREEN)build$(NC)        - Build all components"
	@echo "  $(GREEN)build-rust$(NC)   - Build Rust core only"
	@echo "  $(GREEN)build-go$(NC)     - Build Go tools only"
	@echo "  $(GREEN)build-python$(NC) - Setup Python interface"
	@echo "  $(GREEN)build-linux$(NC)  - Cross-compile for Linux"
	@echo "  $(GREEN)build-macos$(NC)  - Cross-compile for macOS"
	@echo "  $(GREEN)build-windows$(NC)- Cross-compile for Windows"
	@echo "  $(GREEN)install$(NC)      - Install to /usr/local/bin"
	@echo "  $(GREEN)test$(NC)         - Run all tests"
	@echo "  $(GREEN)clean$(NC)        - Clean build artifacts"
	@echo "  $(GREEN)dev$(NC)          - Start development mode"
	@echo "  $(GREEN)help$(NC)         - Show this help message"

.DEFAULT_GOAL := all
