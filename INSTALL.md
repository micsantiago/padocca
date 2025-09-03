# 🥖 PADOCCA Installation Guide

## 🚀 Quick Installation (Recommended)

### One-Line Installation

#### For Kali Linux / Parrot OS / BlackArch:
```bash
curl -sSL https://raw.githubusercontent.com/yourusername/padocca/main/install-kali.sh | sudo bash
```

#### Alternative (if curl is not available):
```bash
wget -qO- https://raw.githubusercontent.com/yourusername/padocca/main/install-kali.sh | sudo bash
```

## 📦 Supported Systems

- ✅ **Kali Linux** (2020.1+)
- ✅ **Parrot OS** (4.0+)
- ✅ **BlackArch Linux**
- ✅ **Ubuntu** (20.04+)
- ✅ **Debian** (10+)
- ✅ **Fedora** (32+)
- ✅ **Arch Linux**
- ✅ **Manjaro**

## 🔧 Manual Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/padocca.git
cd padocca
```

### 2. Run the installer
```bash
sudo bash install-kali.sh
```

## 🐳 Docker Installation

### Using Docker Hub:
```bash
docker pull padocca/padocca:latest
docker run -it padocca/padocca
```

### Build from source:
```bash
git clone https://github.com/yourusername/padocca.git
cd padocca
docker build -t padocca .
docker run -it padocca
```

## 📱 Installation Methods Comparison

| Method | Command | Time | Size | Updates |
|--------|---------|------|------|---------|
| **One-liner** | `curl -sSL ... \| sudo bash` | ~2 min | ~150MB | Manual |
| **Docker** | `docker pull padocca/padocca` | ~1 min | ~500MB | Auto |
| **Git Clone** | `git clone ...` | ~3 min | ~150MB | Git pull |
| **Package** | `apt install padocca` | ~1 min | ~100MB | Auto |

## 🔍 Post-Installation

After installation, Padocca will be available system-wide:

```bash
# Check installation
padocca --version

# Show help
padocca --help

# Run your first scan
padocca scan example.com
```

## 🛠️ Dependencies

The installer automatically installs all dependencies:

- **Go** 1.18+
- **Rust** 1.60+
- **Python** 3.8+
- **Nmap**
- **Whois**
- **Dig** (dnsutils)

## 📁 Installation Locations

- **Main Binary**: `/usr/local/bin/padocca`
- **Tools**: `/opt/padocca/bin/`
- **Config**: `/opt/padocca/config/`
- **Wordlists**: `/opt/padocca/wordlists/`

## ⚙️ Configuration

### Add to PATH (if needed):
```bash
echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Enable auto-completion:
```bash
source /etc/bash_completion.d/padocca
```

## 🔄 Updating

### Update to latest version:
```bash
padocca update
# OR
sudo bash install-kali.sh --update
```

### Check for updates:
```bash
padocca version --check
```

## 🗑️ Uninstallation

### Complete removal:
```bash
sudo bash install-kali.sh --uninstall
```

### Manual removal:
```bash
sudo rm -rf /opt/padocca
sudo rm /usr/local/bin/padocca
sudo rm /etc/bash_completion.d/padocca
```

## 🐛 Troubleshooting

### Common Issues:

#### 1. "padocca: command not found"
```bash
# Add to PATH
export PATH="/usr/local/bin:$PATH"
source ~/.bashrc
```

#### 2. "Permission denied"
```bash
# Fix permissions
sudo chmod +x /usr/local/bin/padocca
```

#### 3. "Go/Rust not found"
```bash
# Reinstall dependencies
sudo bash install-kali.sh --deps-only
```

#### 4. Compilation errors
```bash
# Clean and rebuild
cd /opt/padocca
sudo make clean
sudo make all
```

## 🔒 Security Considerations

1. **Always run as non-root** (except installation)
2. **Use only on authorized targets**
3. **Keep Padocca updated**
4. **Review code before installation**

## 💻 Platform-Specific Instructions

### Kali Linux (Recommended)
```bash
# Everything works out of the box
curl -sSL https://padocca.io/install | sudo bash
```

### Ubuntu/Debian
```bash
# May need to add Go repository
sudo add-apt-repository ppa:longsleep/golang-backports
sudo apt update
curl -sSL https://padocca.io/install | sudo bash
```

### Arch/BlackArch
```bash
# Use AUR helper if available
yay -S padocca
# OR use the installer
curl -sSL https://padocca.io/install | sudo bash
```

### macOS
```bash
# Install Homebrew first
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install go rust python nmap

# Run installer
curl -sSL https://padocca.io/install | bash
```

### Windows (WSL2)
```powershell
# Install WSL2 with Kali
wsl --install -d kali-linux

# Inside WSL2
curl -sSL https://padocca.io/install | sudo bash
```

## 📊 Verification

### Verify installation integrity:
```bash
# Check all components
padocca doctor

# Expected output:
✅ Go modules: OK
✅ Rust modules: OK
✅ Python modules: OK
✅ Network tools: OK
✅ Permissions: OK
```

## 🎯 Next Steps

1. **Read the documentation**: `padocca docs`
2. **Run test scan**: `padocca scan testphp.vulnweb.com`
3. **Configure settings**: `padocca config`
4. **Update signatures**: `padocca update-db`

## 🤝 Getting Help

- **Documentation**: https://padocca.io/docs
- **Issues**: https://github.com/yourusername/padocca/issues
- **Discord**: https://discord.gg/padocca
- **Email**: support@padocca.io

## 📝 License

Padocca is released under the MIT License. See LICENSE file for details.

---

**⚠️ Legal Notice**: Padocca is designed for authorized security testing only. Users are responsible for complying with all applicable laws and regulations.
