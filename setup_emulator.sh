#!/bin/bash
# Script to setup Android emulator for Frida dynamic analysis
# Usage: ./setup_emulator.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     AndroSleuth - Emulator Setup for Frida               ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Configuration
EMULATOR_PATH="$HOME/Android/Sdk/emulator/emulator"
ADB_PATH="adb"
AVD_NAME="Medium_Phone_API_36.1"
FRIDA_VERSION="16.5.9"  # Compatible with API 36
FRIDA_ARCH="x86_64"     # x86_64 for emulator
FRIDA_DIR="$HOME/.frida"
FRIDA_SERVER="frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}"
FRIDA_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FRIDA_SERVER}.xz"

# Step 1: Check if emulator exists
echo -e "${BLUE}[Step 1/7]${NC} Checking emulator..."
if [ ! -f "$EMULATOR_PATH" ]; then
    echo -e "${RED}✗${NC} Emulator not found at: $EMULATOR_PATH"
    echo "Please install Android SDK and emulator"
    exit 1
fi
echo -e "${GREEN}✓${NC} Emulator found"

# Check if AVD exists
if ! $EMULATOR_PATH -list-avds | grep -q "$AVD_NAME"; then
    echo -e "${RED}✗${NC} AVD '$AVD_NAME' not found"
    echo "Available AVDs:"
    $EMULATOR_PATH -list-avds
    exit 1
fi
echo -e "${GREEN}✓${NC} AVD '$AVD_NAME' found"

# Step 2: Start emulator (if not already running)
echo ""
echo -e "${BLUE}[Step 2/7]${NC} Starting emulator..."
if $ADB_PATH devices | grep -q "emulator"; then
    echo -e "${GREEN}✓${NC} Emulator already running"
else
    echo "Starting $AVD_NAME in background..."
    nohup $EMULATOR_PATH -avd "$AVD_NAME" -no-snapshot-load -no-audio -no-boot-anim > /tmp/emulator.log 2>&1 &
    
    echo "Waiting for emulator to boot (this may take 30-60 seconds)..."
    $ADB_PATH wait-for-device
    
    # Wait for boot complete
    timeout=60
    while [ $timeout -gt 0 ]; do
        boot_complete=$($ADB_PATH shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
        if [ "$boot_complete" = "1" ]; then
            break
        fi
        sleep 2
        timeout=$((timeout - 2))
    done
    
    if [ "$boot_complete" != "1" ]; then
        echo -e "${RED}✗${NC} Emulator boot timeout"
        exit 1
    fi
    
    echo -e "${GREEN}✓${NC} Emulator booted successfully"
fi

# Step 3: Get device info
echo ""
echo -e "${BLUE}[Step 3/7]${NC} Getting device information..."
DEVICE_SERIAL=$($ADB_PATH devices | grep emulator | awk '{print $1}')
echo "Device: $DEVICE_SERIAL"

DEVICE_ABI=$($ADB_PATH -s $DEVICE_SERIAL shell getprop ro.product.cpu.abi | tr -d '\r')
echo "Architecture: $DEVICE_ABI"

ANDROID_VERSION=$($ADB_PATH -s $DEVICE_SERIAL shell getprop ro.build.version.release | tr -d '\r')
echo "Android version: $ANDROID_VERSION"

SDK_VERSION=$($ADB_PATH -s $DEVICE_SERIAL shell getprop ro.build.version.sdk | tr -d '\r')
echo "SDK version: $SDK_VERSION"

# Step 4: Download frida-server (if not exists)
echo ""
echo -e "${BLUE}[Step 4/7]${NC} Checking frida-server..."
mkdir -p "$FRIDA_DIR"

if [ ! -f "$FRIDA_DIR/$FRIDA_SERVER" ]; then
    echo "Downloading frida-server $FRIDA_VERSION for $FRIDA_ARCH..."
    cd "$FRIDA_DIR"
    
    if command -v wget &> /dev/null; then
        wget -q --show-progress "$FRIDA_URL"
    elif command -v curl &> /dev/null; then
        curl -L -o "${FRIDA_SERVER}.xz" "$FRIDA_URL"
    else
        echo -e "${RED}✗${NC} Neither wget nor curl found"
        exit 1
    fi
    
    echo "Extracting frida-server..."
    xz -d "${FRIDA_SERVER}.xz"
    chmod +x "$FRIDA_SERVER"
    
    echo -e "${GREEN}✓${NC} frida-server downloaded"
else
    echo -e "${GREEN}✓${NC} frida-server already downloaded"
fi

# Step 5: Push frida-server to device
echo ""
echo -e "${BLUE}[Step 5/7]${NC} Installing frida-server on device..."

# Root the emulator (emulator is rootable by default)
$ADB_PATH -s $DEVICE_SERIAL root
sleep 2

# Wait for device after root
$ADB_PATH wait-for-device

# Push frida-server
$ADB_PATH -s $DEVICE_SERIAL push "$FRIDA_DIR/$FRIDA_SERVER" /data/local/tmp/frida-server
$ADB_PATH -s $DEVICE_SERIAL shell "chmod 755 /data/local/tmp/frida-server"

echo -e "${GREEN}✓${NC} frida-server installed"

# Step 6: Start frida-server
echo ""
echo -e "${BLUE}[Step 6/7]${NC} Starting frida-server..."

# Kill existing frida-server if running
$ADB_PATH -s $DEVICE_SERIAL shell "pkill frida-server" 2>/dev/null || true
sleep 1

# Start frida-server in background
$ADB_PATH -s $DEVICE_SERIAL shell "/data/local/tmp/frida-server &" &
sleep 3

# Check if frida-server is running
if $ADB_PATH -s $DEVICE_SERIAL shell "ps | grep frida-server" | grep -q frida-server; then
    echo -e "${GREEN}✓${NC} frida-server is running"
else
    echo -e "${RED}✗${NC} Failed to start frida-server"
    exit 1
fi

# Step 7: Test Frida connection
echo ""
echo -e "${BLUE}[Step 7/7]${NC} Testing Frida connection..."

if command -v frida &> /dev/null; then
    # Test with frida-ps
    if frida-ps -U &> /dev/null; then
        echo -e "${GREEN}✓${NC} Frida connected successfully!"
        echo ""
        echo "Running processes:"
        frida-ps -U | head -10
    else
        echo -e "${YELLOW}⚠${NC} Frida command available but connection failed"
    fi
else
    echo -e "${YELLOW}⚠${NC} Frida not installed on host"
    echo "Install with: pip install frida-tools"
fi

# Summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                   Setup Complete!                         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}✓${NC} Emulator: $AVD_NAME"
echo -e "${GREEN}✓${NC} Device: $DEVICE_SERIAL"
echo -e "${GREEN}✓${NC} Architecture: $DEVICE_ABI"
echo -e "${GREEN}✓${NC} Android: $ANDROID_VERSION (SDK $SDK_VERSION)"
echo -e "${GREEN}✓${NC} frida-server: $FRIDA_VERSION"
echo ""
echo "Next steps:"
echo "  1. Run dynamic analysis:"
echo "     poetry run androsleuth -a samples/fdroid.apk --frida --duration 60"
echo ""
echo "  2. Or test with Docker:"
echo "     docker exec -it AndroSleuth poetry run androsleuth \\"
echo "       -a samples/fdroid.apk --frida --device $DEVICE_SERIAL"
echo ""
echo "  3. Stop emulator when done:"
echo "     adb -s $DEVICE_SERIAL emu kill"
echo ""
