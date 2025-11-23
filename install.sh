#!/bin/bash
# Installation script for AndroSleuth

set -e

echo "========================================"
echo "   AndroSleuth - Installation Script   "
echo "========================================"
echo ""

# Check Python version
echo "[1/5] Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.8"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
    echo "❌ Error: Python 3.8+ is required (found $python_version)"
    exit 1
fi
echo "✓ Python $python_version detected"

# Create virtual environment
echo ""
echo "[2/5] Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
echo ""
echo "[3/5] Activating virtual environment..."
source venv/bin/activate
echo "✓ Virtual environment activated"

# Upgrade pip
echo ""
echo "[4/5] Upgrading pip..."
pip install --upgrade pip --quiet
echo "✓ Pip upgraded"

# Install dependencies
echo ""
echo "[5/5] Installing dependencies..."
echo "This may take a few minutes..."
pip install -r requirements.txt --quiet

if [ $? -eq 0 ]; then
    echo "✓ Dependencies installed successfully"
else
    echo "❌ Error installing dependencies"
    echo "Try running manually: pip install -r requirements.txt"
    exit 1
fi

# Create necessary directories
echo ""
echo "Creating directories..."
mkdir -p logs
mkdir -p reports
mkdir -p samples
mkdir -p temp_analysis
echo "✓ Directories created"

# Configure VirusTotal API (optional)
echo ""
echo "========================================"
echo "   VirusTotal API Configuration        "
echo "========================================"
echo ""
echo "AndroSleuth can check APK reputation using VirusTotal."
echo "This requires a free API key from: https://www.virustotal.com/gui/join-us"
echo ""
read -p "Do you have a VirusTotal API key? (y/n): " has_vt_key

if [ "$has_vt_key" = "y" ] || [ "$has_vt_key" = "Y" ]; then
    read -p "Enter your VirusTotal API key: " vt_api_key
    
    if [ ! -z "$vt_api_key" ]; then
        # Create secrets.yaml file
        cat > config/secrets.yaml << EOF
# VirusTotal API Configuration
# Keep this file secure and do not commit to git
virustotal:
  api_key: "$vt_api_key"
EOF
        chmod 600 config/secrets.yaml
        echo "✓ VirusTotal API key saved to config/secrets.yaml"
        echo "  (This file is excluded from git)"
    else
        echo "⚠ No API key provided - VirusTotal integration disabled"
    fi
else
    echo "⚠ VirusTotal integration skipped"
    echo "  You can add your API key later in config/secrets.yaml or set VIRUSTOTAL_API_KEY environment variable"
fi

echo ""
echo "========================================"
echo "✓ Installation complete!"
echo "========================================"
echo ""
echo "To get started:"
echo "  1. Activate the virtual environment:"
echo "     source venv/bin/activate"
echo ""
echo "  2. Run a test:"
echo "     python tests/test_basic.py"
echo ""
echo "  3. Analyze an APK:"
echo "     python src/androsleuth.py -a your_app.apk"
echo ""
echo "For more information, see README.md"
echo ""
