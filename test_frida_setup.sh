#!/bin/bash
# Test script for Frida analysis setup
# Tests the Frida analyzer without requiring a physical device

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║       AndroSleuth - Frida Analysis Setup Test            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Test 1: Check if Frida is installed
echo -e "${BLUE}[Test 1]${NC} Checking Frida installation..."
if command -v frida &> /dev/null; then
    FRIDA_VERSION=$(frida --version)
    echo -e "${GREEN}✓${NC} Frida installed: v${FRIDA_VERSION}"
else
    echo -e "${YELLOW}⚠${NC} Frida not found on host system"
    echo "  To install: pip install frida frida-tools"
fi

# Test 2: Check if Poetry has frida dependency
echo ""
echo -e "${BLUE}[Test 2]${NC} Checking Poetry dependencies..."
if poetry show frida &> /dev/null; then
    FRIDA_POETRY=$(poetry show frida | grep version | awk '{print $3}')
    echo -e "${GREEN}✓${NC} Frida in Poetry environment: ${FRIDA_POETRY}"
else
    echo -e "${YELLOW}⚠${NC} Frida not in Poetry dependencies"
    echo "  Install with: poetry add frida frida-tools"
fi

# Test 3: Check ADB connectivity
echo ""
echo -e "${BLUE}[Test 3]${NC} Checking ADB setup..."
if command -v adb &> /dev/null; then
    ADB_VERSION=$(adb version | head -1)
    echo -e "${GREEN}✓${NC} ADB installed: ${ADB_VERSION}"
    
    # Check connected devices
    DEVICES=$(adb devices | tail -n +2 | grep -c "device$" 2>/dev/null || echo "0")
    if [ "$DEVICES" -gt 0 ] 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Found ${DEVICES} connected device(s)"
        adb devices | tail -n +2 | grep "device$"
    else
        echo -e "${YELLOW}⚠${NC} No Android devices connected"
        echo "  Connect a device or start an emulator"
    fi
else
    echo -e "${YELLOW}⚠${NC} ADB not found"
    echo "  Install Android SDK Platform Tools"
fi

# Test 4: Check Frida scripts
echo ""
echo -e "${BLUE}[Test 4]${NC} Checking Frida scripts..."
FRIDA_SCRIPTS_DIR="frida_scripts"
if [ -d "$FRIDA_SCRIPTS_DIR" ]; then
    SCRIPT_COUNT=$(find "$FRIDA_SCRIPTS_DIR" -name "*.js" | wc -l)
    echo -e "${GREEN}✓${NC} Frida scripts directory exists"
    echo "  Found ${SCRIPT_COUNT} JavaScript hooks"
    
    if [ $SCRIPT_COUNT -gt 0 ]; then
        echo "  Available hooks:"
        find "$FRIDA_SCRIPTS_DIR" -name "*.js" -exec basename {} \;
    fi
else
    echo -e "${YELLOW}⚠${NC} Frida scripts directory not found"
    mkdir -p "$FRIDA_SCRIPTS_DIR"
    echo "  Created $FRIDA_SCRIPTS_DIR directory"
fi

# Test 5: Check frida_analyzer module
echo ""
echo -e "${BLUE}[Test 5]${NC} Checking frida_analyzer module..."
if [ -f "src/modules/frida_analyzer.py" ]; then
    echo -e "${GREEN}✓${NC} frida_analyzer.py exists"
    
    # Check for key functions
    if grep -q "class FridaAnalyzer" src/modules/frida_analyzer.py; then
        echo -e "${GREEN}✓${NC} FridaAnalyzer class found"
    fi
    
    if grep -q "def analyze" src/modules/frida_analyzer.py; then
        echo -e "${GREEN}✓${NC} analyze() method found"
    fi
    
    if grep -q "def _setup_hooks" src/modules/frida_analyzer.py; then
        echo -e "${GREEN}✓${NC} _setup_hooks() method found"
    fi
else
    echo -e "${RED}✗${NC} frida_analyzer.py not found"
fi

# Test 6: Test syntax validation
echo ""
echo -e "${BLUE}[Test 6]${NC} Validating Python syntax..."
if python3 -m py_compile src/modules/frida_analyzer.py 2>/dev/null; then
    echo -e "${GREEN}✓${NC} frida_analyzer.py syntax valid"
else
    echo -e "${RED}✗${NC} Syntax errors in frida_analyzer.py"
fi

# Test 7: Check Docker container
echo ""
echo -e "${BLUE}[Test 7]${NC} Checking Docker setup..."
if command -v docker &> /dev/null; then
    echo -e "${GREEN}✓${NC} Docker installed"
    
    if docker ps --format "{{.Names}}" | grep -q "AndroSleuth"; then
        echo -e "${GREEN}✓${NC} AndroSleuth container is running"
        
        # Check if Frida is in container
        if docker exec AndroSleuth poetry show frida &> /dev/null; then
            CONTAINER_FRIDA=$(docker exec AndroSleuth poetry show frida | grep version | awk '{print $3}')
            echo -e "${GREEN}✓${NC} Frida in container: ${CONTAINER_FRIDA}"
        else
            echo -e "${YELLOW}⚠${NC} Frida not installed in container"
        fi
    else
        echo -e "${YELLOW}⚠${NC} AndroSleuth container not running"
        echo "  Start with: docker-compose up -d"
    fi
else
    echo -e "${YELLOW}⚠${NC} Docker not found"
fi

# Test 8: Validate CLI integration
echo ""
echo -e "${BLUE}[Test 8]${NC} Checking CLI integration..."
if grep -q "\-\-frida" src/androsleuth.py; then
    echo -e "${GREEN}✓${NC} --frida flag found in CLI"
fi

if grep -q "\-\-device" src/androsleuth.py; then
    echo -e "${GREEN}✓${NC} --device flag found in CLI"
fi

if grep -q "\-\-duration" src/androsleuth.py; then
    echo -e "${GREEN}✓${NC} --duration flag found in CLI"
fi

# Summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                   Test Summary                            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

if [ "${DEVICES:-0}" -gt 0 ] 2>/dev/null; then
    echo -e "${GREEN}✓${NC} System ready for dynamic analysis!"
    echo ""
    echo "Next steps:"
    echo "  1. Install frida-server on device:"
    echo "     adb push frida-server /data/local/tmp/"
    echo "     adb shell 'chmod 755 /data/local/tmp/frida-server'"
    echo "     adb shell '/data/local/tmp/frida-server &'"
    echo ""
    echo "  2. Run analysis:"
    echo "     poetry run androsleuth -a sample.apk --frida --duration 60"
else
    echo -e "${YELLOW}⚠${NC} No devices connected - dynamic analysis unavailable"
    echo ""
    echo "To enable dynamic analysis:"
    echo "  1. Connect Android device via USB or start emulator"
    echo "  2. Enable USB debugging on device"
    echo "  3. Install frida-server on device (see DYNAMIC_ANALYSIS.md)"
    echo "  4. Run: poetry run androsleuth -a sample.apk --frida"
fi

echo ""
echo "For detailed setup instructions, see:"
echo "  📖 DYNAMIC_ANALYSIS.md"
echo ""
