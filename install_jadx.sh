#!/bin/bash
#
# JADX Installation Script for AndroSleuth
# Installs JADX (Dex to Java decompiler)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  JADX Installation for AndroSleuth${NC}"
echo -e "${BLUE}============================================${NC}"
echo

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check OS
check_os() {
    print_info "Checking operating system..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        print_success "Linux detected"
        OS_TYPE="linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        print_success "macOS detected"
        OS_TYPE="mac"
    else
        print_error "Unsupported OS: $OSTYPE"
        exit 1
    fi
}

# Check if JADX is already installed
check_existing() {
    print_info "Checking for existing JADX installation..."
    
    if command -v jadx &> /dev/null; then
        JADX_VERSION=$(jadx --version 2>&1 | head -n1)
        print_warning "JADX already installed: $JADX_VERSION"
        read -p "Do you want to reinstall? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Installation cancelled"
            exit 0
        fi
    else
        print_info "JADX not found - proceeding with installation"
    fi
}

# Install dependencies
install_dependencies() {
    print_info "Installing dependencies..."
    
    if [[ "$OS_TYPE" == "linux" ]]; then
        # Check if running as root or with sudo
        if [ "$EUID" -ne 0 ]; then
            print_warning "This script may require sudo privileges"
        fi
        
        # Detect package manager
        if command -v apt-get &> /dev/null; then
            print_info "Using apt package manager"
            sudo apt-get update -qq
            sudo apt-get install -y openjdk-11-jre-headless wget unzip
        elif command -v dnf &> /dev/null; then
            print_info "Using dnf package manager"
            sudo dnf install -y java-11-openjdk-headless wget unzip
        elif command -v pacman &> /dev/null; then
            print_info "Using pacman package manager"
            sudo pacman -S --noconfirm jre11-openjdk wget unzip
        else
            print_error "Unsupported package manager"
            exit 1
        fi
        
        print_success "Dependencies installed"
        
    elif [[ "$OS_TYPE" == "mac" ]]; then
        if ! command -v brew &> /dev/null; then
            print_error "Homebrew not found. Please install Homebrew first"
            exit 1
        fi
        
        print_info "Using Homebrew"
        brew install openjdk@11
        print_success "Dependencies installed"
    fi
}

# Download and install JADX
install_jadx() {
    print_info "Installing JADX..."
    
    JADX_VERSION="1.5.0"
    JADX_URL="https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
    INSTALL_DIR="/opt/jadx"
    
    print_info "Downloading JADX v${JADX_VERSION}..."
    
    # Create temporary directory
    TMP_DIR=$(mktemp -d)
    cd "$TMP_DIR"
    
    # Download JADX
    if ! wget -q --show-progress "$JADX_URL" -O jadx.zip; then
        print_error "Failed to download JADX"
        exit 1
    fi
    
    print_success "Downloaded JADX"
    
    # Extract
    print_info "Extracting JADX..."
    unzip -q jadx.zip -d jadx
    
    # Install to /opt/jadx
    print_info "Installing to ${INSTALL_DIR}..."
    sudo rm -rf "$INSTALL_DIR"
    sudo mkdir -p "$INSTALL_DIR"
    sudo mv jadx/* "$INSTALL_DIR/"
    
    # Make executables
    sudo chmod +x "$INSTALL_DIR/bin/jadx"
    sudo chmod +x "$INSTALL_DIR/bin/jadx-gui"
    
    # Create symlinks
    print_info "Creating symlinks..."
    sudo ln -sf "$INSTALL_DIR/bin/jadx" /usr/local/bin/jadx
    sudo ln -sf "$INSTALL_DIR/bin/jadx-gui" /usr/local/bin/jadx-gui
    
    # Cleanup
    cd - > /dev/null
    rm -rf "$TMP_DIR"
    
    print_success "JADX installed successfully"
}

# Alternative: Install via package manager (if available)
install_via_package_manager() {
    print_info "Checking package manager availability..."
    
    if [[ "$OS_TYPE" == "linux" ]]; then
        if command -v apt-get &> /dev/null; then
            print_info "Attempting to install JADX from apt repository..."
            if sudo apt-get install -y jadx 2>/dev/null; then
                print_success "JADX installed from apt repository"
                return 0
            else
                print_warning "JADX not available in apt, using manual installation"
                return 1
            fi
        fi
    elif [[ "$OS_TYPE" == "mac" ]]; then
        print_info "Attempting to install JADX from Homebrew..."
        if brew install jadx 2>/dev/null; then
            print_success "JADX installed from Homebrew"
            return 0
        else
            print_warning "JADX not available in Homebrew, using manual installation"
            return 1
        fi
    fi
    
    return 1
}

# Verify installation
verify_installation() {
    print_info "Verifying installation..."
    
    if command -v jadx &> /dev/null; then
        JADX_VERSION=$(jadx --version 2>&1 | head -n1)
        print_success "JADX is accessible: $JADX_VERSION"
        
        # Test JADX
        print_info "Testing JADX..."
        if jadx --help &> /dev/null; then
            print_success "JADX is working correctly"
        else
            print_warning "JADX may not be working correctly"
        fi
    else
        print_error "JADX installation failed - command not found"
        exit 1
    fi
}

# Main installation flow
main() {
    check_os
    check_existing
    install_dependencies
    
    # Try package manager first, fall back to manual installation
    if ! install_via_package_manager; then
        install_jadx
    fi
    
    verify_installation
    
    echo
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}  JADX Installation Complete!${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo
    echo -e "${BLUE}Usage:${NC}"
    echo "  jadx [options] <input file> (.apk, .dex, .jar, .class, .zip, .aar, .arsc)"
    echo
    echo -e "${BLUE}Examples:${NC}"
    echo "  jadx app.apk                      # Decompile to ./app directory"
    echo "  jadx -d output_dir app.apk        # Specify output directory"
    echo "  jadx --no-res app.apk             # Skip resources"
    echo "  jadx --deobf app.apk              # Enable deobfuscation"
    echo
    echo -e "${BLUE}GUI Version:${NC}"
    echo "  jadx-gui app.apk"
    echo
    print_success "JADX is ready to use with AndroSleuth!"
}

# Run main installation
main
