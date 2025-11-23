#!/bin/bash
#
# AndroSleuth Installation Script (Poetry Version)
# Advanced Android APK Forensic Analysis Tool
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     █████╗ ███╗   ██╗██████╗ ██████╗  ██████╗           ║
║    ██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗          ║
║    ███████║██╔██╗ ██║██║  ██║██████╔╝██║   ██║          ║
║    ██╔══██║██║╚██╗██║██║  ██║██╔══██╗██║   ██║          ║
║    ██║  ██║██║ ╚████║██████╔╝██║  ██║╚██████╔╝          ║
║    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝           ║
║                                                           ║
║    ███████╗██╗     ███████╗██╗   ██╗████████╗██╗  ██╗   ║
║    ██╔════╝██║     ██╔════╝██║   ██║╚══██╔══╝██║  ██║   ║
║    ███████╗██║     █████╗  ██║   ██║   ██║   ███████║   ║
║    ╚════██║██║     ██╔══╝  ██║   ██║   ██║   ██╔══██║   ║
║    ███████║███████╗███████╗╚██████╔╝   ██║   ██║  ██║   ║
║    ╚══════╝╚══════╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝   ║
║                                                           ║
║          Advanced APK Forensic Analysis Tool             ║
║                  Poetry Installation                     ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${BLUE}[INFO]${NC} Starting AndroSleuth installation with Poetry...\n"

# Check for Python 3.8+
echo -e "${BLUE}[INFO]${NC} Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR]${NC} Python 3 not found. Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.8"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
    echo -e "${RED}[ERROR]${NC} Python 3.8 or higher required. Found: Python ${PYTHON_VERSION}"
    exit 1
fi

echo -e "${GREEN}[✓]${NC} Python ${PYTHON_VERSION} found\n"

# Check for Poetry
echo -e "${BLUE}[INFO]${NC} Checking for Poetry..."
if ! command -v poetry &> /dev/null; then
    echo -e "${YELLOW}[WARN]${NC} Poetry not found. Installing Poetry..."
    curl -sSL https://install.python-poetry.org | python3 -
    
    # Add Poetry to PATH
    export PATH="$HOME/.local/bin:$PATH"
    
    if ! command -v poetry &> /dev/null; then
        echo -e "${RED}[ERROR]${NC} Poetry installation failed. Please install manually:"
        echo -e "  curl -sSL https://install.python-poetry.org | python3 -"
        exit 1
    fi
    echo -e "${GREEN}[✓]${NC} Poetry installed successfully"
else
    POETRY_VERSION=$(poetry --version | awk '{print $3}')
    echo -e "${GREEN}[✓]${NC} Poetry ${POETRY_VERSION} found"
fi

echo ""

# Installation mode selection
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Select Installation Profile:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${GREEN}1)${NC} Basic      - Core features only (smallest)"
echo -e "  ${GREEN}2)${NC} Standard   - Core + YARA + Shellcode analysis"
echo -e "  ${GREEN}3)${NC} Full       - All features including Frida & Unicorn ${YELLOW}(recommended)${NC}"
echo -e "  ${GREEN}4)${NC} Developer  - Full + development tools"
echo ""
echo -ne "${BLUE}[?]${NC} Select option [1-4] (default: 3): "
read INSTALL_MODE

# Set default
INSTALL_MODE=${INSTALL_MODE:-3}

# Configure Poetry
echo ""
echo -e "${BLUE}[INFO]${NC} Configuring Poetry..."
poetry config virtualenvs.in-project true
echo -e "${GREEN}[✓]${NC} Poetry configured to use .venv in project"

# Install dependencies based on selection
echo ""
case $INSTALL_MODE in
    1)
        echo -e "${BLUE}[INFO]${NC} Installing Basic profile..."
        poetry install --no-dev
        ;;
    2)
        echo -e "${BLUE}[INFO]${NC} Installing Standard profile..."
        poetry install --no-dev -E emulation
        ;;
    3)
        echo -e "${BLUE}[INFO]${NC} Installing Full profile..."
        poetry install --no-dev -E full
        ;;
    4)
        echo -e "${BLUE}[INFO]${NC} Installing Developer profile..."
        poetry install -E full
        ;;
    *)
        echo -e "${RED}[ERROR]${NC} Invalid option. Exiting."
        exit 1
        ;;
esac

echo -e "${GREEN}[✓]${NC} Dependencies installed successfully"

# VirusTotal API Key Configuration
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}VirusTotal API Configuration (Optional)${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "AndroSleuth can check APK reputation using VirusTotal API."
echo -e "Get your free API key at: ${BLUE}https://www.virustotal.com/gui/my-apikey${NC}"
echo ""
echo -ne "${BLUE}[?]${NC} Configure VirusTotal API key now? [y/N]: "
read CONFIGURE_VT

if [[ "$CONFIGURE_VT" =~ ^[Yy]$ ]]; then
    echo -ne "${BLUE}[?]${NC} Enter your VirusTotal API key: "
    read VT_API_KEY
    
    if [ ! -z "$VT_API_KEY" ]; then
        # Create secrets.yaml if it doesn't exist
        if [ ! -f "config/secrets.yaml" ]; then
            cp config/secrets.yaml.example config/secrets.yaml
        fi
        
        # Update the API key
        sed -i.bak "s/your_virustotal_api_key_here/$VT_API_KEY/" config/secrets.yaml
        rm -f config/secrets.yaml.bak
        
        echo -e "${GREEN}[✓]${NC} VirusTotal API key configured in config/secrets.yaml"
    else
        echo -e "${YELLOW}[WARN]${NC} No API key provided. Skipping VirusTotal configuration."
    fi
else
    echo -e "${BLUE}[INFO]${NC} Skipping VirusTotal configuration."
    echo -e "  You can configure it later by editing ${CYAN}config/secrets.yaml${NC}"
fi

# Create necessary directories
echo ""
echo -e "${BLUE}[INFO]${NC} Creating project directories..."
mkdir -p reports samples logs
echo -e "${GREEN}[✓]${NC} Directories created"

# Optional: Frida server setup information
if [ "$INSTALL_MODE" -ge 3 ]; then
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Frida Dynamic Analysis Setup (Optional)${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "For dynamic analysis with Frida, you need to:"
    echo -e "  1. Download frida-server for your Android device:"
    echo -e "     ${BLUE}https://github.com/frida/frida/releases${NC}"
    echo -e "  2. Push to device: ${CYAN}adb push frida-server /data/local/tmp/${NC}"
    echo -e "  3. Make executable: ${CYAN}adb shell 'chmod 755 /data/local/tmp/frida-server'${NC}"
    echo -e "  4. Run server: ${CYAN}adb shell '/data/local/tmp/frida-server &'${NC}"
    echo ""
fi

# Installation complete
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}[✓] Installation Complete!${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "To activate the virtual environment:"
echo -e "  ${CYAN}poetry shell${NC}"
echo ""
echo -e "Or run directly with Poetry:"
echo -e "  ${CYAN}poetry run androsleuth -a sample.apk${NC}"
echo ""
echo -e "Quick start examples:"
echo -e "  ${CYAN}poetry run androsleuth -a sample.apk -m quick${NC}         # Fast scan"
echo -e "  ${CYAN}poetry run androsleuth -a sample.apk -m standard${NC}      # Standard analysis"
echo -e "  ${CYAN}poetry run androsleuth -a sample.apk -m deep -o reports/${NC}  # Full analysis with report"
echo ""
if [ "$INSTALL_MODE" -ge 3 ]; then
    echo -e "Advanced features:"
    echo -e "  ${CYAN}poetry run androsleuth -a sample.apk --emulation${NC}  # With code emulation"
    echo -e "  ${CYAN}poetry run androsleuth -a sample.apk --frida${NC}      # With dynamic analysis"
    echo ""
fi
echo -e "For help:"
echo -e "  ${CYAN}poetry run androsleuth --help${NC}"
echo ""
echo -e "Documentation: ${BLUE}README.md${NC} | ${BLUE}QUICKSTART.md${NC} | ${BLUE}FEATURES.md${NC}"
echo ""
echo -e "${GREEN}Happy hunting! 🔍${NC}"
echo ""
