#!/bin/bash
# Fast emulator setup for Frida dynamic analysis
# Optimized for quick testing with minimal resources

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║    AndroSleuth - Fast Emulator + Frida Setup             ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Configuration
EMULATOR_PATH="$HOME/Android/Sdk/emulator/emulator"
ADB_PATH="adb"
AVD_NAME="${1:-Medium_Phone_API_36.1}"  # Accept AVD name as argument
FRIDA_VERSION="16.5.9"
FRIDA_ARCH="x86_64"
FRIDA_DIR="$HOME/.frida"
FRIDA_SERVER="frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}"

echo -e "${BLUE}Configuration:${NC}"
echo "  AVD: $AVD_NAME"
echo "  Frida: $FRIDA_VERSION"
echo "  Architecture: $FRIDA_ARCH"
echo ""

# Check if emulator is already running
if adb devices | grep -q "emulator"; then
    DEVICE_SERIAL=$(adb devices | grep emulator | head -1 | awk '{print $1}')
    echo -e "${GREEN}✓${NC} Emulator already running: $DEVICE_SERIAL"
    echo ""
    read -p "Use existing emulator? (Y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        USE_EXISTING=true
    else
        echo "Killing existing emulator..."
        adb -s $DEVICE_SERIAL emu kill
        sleep 3
        USE_EXISTING=false
    fi
else
    USE_EXISTING=false
fi

# Start emulator if needed
if [ "$USE_EXISTING" != "true" ]; then
    echo -e "${BLUE}[1/5]${NC} Starting optimized emulator..."
    echo "  Options: -no-snapshot-load, -no-audio, -accel on, -gpu swiftshader_indirect"
    
    # Start with optimized settings for speed
    nohup $EMULATOR_PATH -avd "$AVD_NAME" \
        -no-snapshot-load \
        -no-audio \
        -no-boot-anim \
        -accel on \
        -gpu swiftshader_indirect \
        -memory 2048 \
        -cores 2 \
        > /tmp/emulator_androsleuth.log 2>&1 &
    
    EMULATOR_PID=$!
    echo "  PID: $EMULATOR_PID"
    echo "  Log: /tmp/emulator_androsleuth.log"
    
    echo ""
    echo -e "${YELLOW}⏳${NC} Waiting for emulator to start..."
    
    # Wait for device
    timeout 120 adb wait-for-device || {
        echo -e "${RED}✗${NC} Timeout waiting for device"
        echo "Check log: tail -f /tmp/emulator_androsleuth.log"
        exit 1
    }
    
    DEVICE_SERIAL=$(adb devices | grep emulator | head -1 | awk '{print $1}')
    echo -e "${GREEN}✓${NC} Device connected: $DEVICE_SERIAL"
    
    # Wait for boot complete with progress
    echo -e "${YELLOW}⏳${NC} Waiting for boot to complete..."
    timeout=90
    dots=""
    while [ $timeout -gt 0 ]; do
        boot_complete=$(adb -s $DEVICE_SERIAL shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
        if [ "$boot_complete" = "1" ]; then
            echo -e "\r${GREEN}✓${NC} Boot complete!                    "
            break
        fi
        echo -ne "\r  Booting$dots (${timeout}s remaining)   "
        dots="${dots}."
        [ ${#dots} -gt 3 ] && dots=""
        sleep 2
        timeout=$((timeout - 2))
    done
    
    if [ "$boot_complete" != "1" ]; then
        echo -e "\r${RED}✗${NC} Boot timeout                         "
        exit 1
    fi
    
    # Give it a few more seconds to stabilize
    sleep 5
else
    DEVICE_SERIAL=$(adb devices | grep emulator | head -1 | awk '{print $1}')
fi

echo ""
echo -e "${BLUE}[2/5]${NC} Device Information"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

DEVICE_ABI=$(adb -s $DEVICE_SERIAL shell getprop ro.product.cpu.abi | tr -d '\r')
ANDROID_VERSION=$(adb -s $DEVICE_SERIAL shell getprop ro.build.version.release | tr -d '\r')
SDK_VERSION=$(adb -s $DEVICE_SERIAL shell getprop ro.build.version.sdk | tr -d '\r')
DEVICE_MODEL=$(adb -s $DEVICE_SERIAL shell getprop ro.product.model | tr -d '\r')

echo "  Device: $DEVICE_SERIAL"
echo "  Model: $DEVICE_MODEL"
echo "  Architecture: $DEVICE_ABI"
echo "  Android: $ANDROID_VERSION (API $SDK_VERSION)"

echo ""
echo -e "${BLUE}[3/5]${NC} Setting up frida-server..."

# Download frida-server if needed
mkdir -p "$FRIDA_DIR"

if [ ! -f "$FRIDA_DIR/$FRIDA_SERVER" ]; then
    echo "  Downloading frida-server $FRIDA_VERSION..."
    cd "$FRIDA_DIR"
    
    FRIDA_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FRIDA_SERVER}.xz"
    
    if command -v wget &> /dev/null; then
        wget -q --show-progress "$FRIDA_URL" || {
            echo -e "${RED}✗${NC} Download failed"
            exit 1
        }
    elif command -v curl &> /dev/null; then
        curl -L -# -o "${FRIDA_SERVER}.xz" "$FRIDA_URL" || {
            echo -e "${RED}✗${NC} Download failed"
            exit 1
        }
    fi
    
    echo "  Extracting..."
    xz -d "${FRIDA_SERVER}.xz"
    chmod +x "$FRIDA_SERVER"
    echo -e "  ${GREEN}✓${NC} Downloaded"
else
    echo -e "  ${GREEN}✓${NC} Already downloaded"
fi

echo ""
echo -e "${BLUE}[4/5]${NC} Installing frida-server on device..."

# Root the emulator
echo "  Requesting root access..."
adb -s $DEVICE_SERIAL root > /dev/null 2>&1
sleep 2

# Wait for device after root
adb wait-for-device

# Kill any existing frida-server
adb -s $DEVICE_SERIAL shell "pkill frida-server" 2>/dev/null || true
sleep 1

# Push frida-server
echo "  Pushing frida-server to device..."
adb -s $DEVICE_SERIAL push "$FRIDA_DIR/$FRIDA_SERVER" /data/local/tmp/frida-server > /dev/null 2>&1
adb -s $DEVICE_SERIAL shell "chmod 755 /data/local/tmp/frida-server"

echo -e "  ${GREEN}✓${NC} Installed"

echo ""
echo -e "${BLUE}[5/5]${NC} Starting frida-server..."

# Start frida-server
adb -s $DEVICE_SERIAL shell "/data/local/tmp/frida-server &" > /dev/null 2>&1 &
sleep 3

# Verify it's running
if adb -s $DEVICE_SERIAL shell "ps | grep frida-server" 2>/dev/null | grep -q frida-server; then
    echo -e "  ${GREEN}✓${NC} frida-server is running"
else
    echo -e "  ${RED}✗${NC} Failed to start frida-server"
    echo "  Debug: adb -s $DEVICE_SERIAL shell /data/local/tmp/frida-server"
    exit 1
fi

# Test Frida connection
echo ""
echo -e "${BLUE}Testing Frida connection...${NC}"

if command -v frida-ps &> /dev/null; then
    if frida-ps -U > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Frida connected successfully!"
        echo ""
        echo "Top processes:"
        frida-ps -U | head -8
    else
        echo -e "${YELLOW}⚠${NC} Frida CLI connection failed (but frida-server is running)"
        echo "  You can still use AndroSleuth with --frida flag"
    fi
else
    echo -e "${YELLOW}⚠${NC} frida-ps not installed on host"
    echo "  Install with: pip install frida-tools"
    echo "  But AndroSleuth can still use Frida (Poetry environment has it)"
fi

# Summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                🎉 Setup Complete! 🎉                      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}Ready for dynamic analysis!${NC}"
echo ""
echo -e "${MAGENTA}Quick Commands:${NC}"
echo ""
echo "  1️⃣  Test with F-Droid (safe app):"
echo "     poetry run androsleuth -a samples/fdroid.apk --frida --duration 60"
echo ""
echo "  2️⃣  Full analysis with PDF:"
echo "     poetry run androsleuth -a samples/fdroid.apk --frida --duration 90 -f pdf"
echo ""
echo "  3️⃣  Deep analysis (all modules):"
echo "     poetry run androsleuth -a samples/fdroid.apk -m deep --frida --duration 120"
echo ""
echo "  4️⃣  Check Frida connection:"
echo "     frida-ps -U"
echo ""
echo "  5️⃣  View emulator log:"
echo "     tail -f /tmp/emulator_androsleuth.log"
echo ""
echo "  6️⃣  Stop emulator when done:"
echo "     adb -s $DEVICE_SERIAL emu kill"
echo ""
echo -e "${YELLOW}Device:${NC} $DEVICE_SERIAL"
echo -e "${YELLOW}Android:${NC} $ANDROID_VERSION (API $SDK_VERSION)"
echo -e "${YELLOW}Frida:${NC} $FRIDA_VERSION"
echo ""
