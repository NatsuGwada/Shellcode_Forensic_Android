#!/bin/bash
# Alternative: Use Docker Android emulator or test without hardware acceleration
# This script provides fallback options when KVM is not available

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║    AndroSleuth - Alternative Emulator Solutions           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

echo -e "${BLUE}Checking virtualization support...${NC}"
echo ""

# Check KVM
if [ -e /dev/kvm ]; then
    echo -e "${GREEN}✓${NC} /dev/kvm exists"
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        echo -e "${GREEN}✓${NC} KVM accessible"
        KVM_OK=true
    else
        echo -e "${YELLOW}⚠${NC} /dev/kvm exists but not accessible"
        echo "  Run: sudo chmod 666 /dev/kvm"
        KVM_OK=false
    fi
else
    echo -e "${RED}✗${NC} /dev/kvm not found"
    echo "  Virtualization may be disabled in BIOS"
    echo "  Or KVM module not loaded: sudo modprobe kvm-intel (or kvm-amd)"
    KVM_OK=false
fi

# Check CPU virtualization flags
if grep -q -E 'vmx|svm' /proc/cpuinfo; then
    echo -e "${GREEN}✓${NC} CPU supports virtualization (VT-x/AMD-V)"
else
    echo -e "${RED}✗${NC} CPU virtualization not detected"
fi

echo ""
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Available Options:${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${BLUE}Option 1: Enable KVM (Recommended)${NC}"
echo "  If your CPU supports virtualization:"
echo "  1. Enable VT-x/AMD-V in BIOS"
echo "  2. Load KVM module:"
echo "     sudo modprobe kvm-intel  # For Intel"
echo "     sudo modprobe kvm-amd    # For AMD"
echo "  3. Fix permissions:"
echo "     sudo chmod 666 /dev/kvm"
echo ""

echo -e "${BLUE}Option 2: Use ARM Emulator (Slower but works)${NC}"
echo "  Download ARM system image and create ARM AVD"
echo "  This doesn't require KVM but is much slower"
echo ""
echo "  Steps:"
echo "  1. Open Android Studio SDK Manager"
echo "  2. Download: System Images > ARM 64-bit (armeabi-v7a)"
echo "  3. Create AVD with ARM architecture"
echo "  4. Use frida-server ARM version"
echo ""

echo -e "${BLUE}Option 3: Docker Android Container${NC}"
echo "  Use budtmo/docker-android (lightweight)"
echo ""
cat << 'EOF'
  # Pull Docker image
  docker pull budtmo/docker-android:emulator_14.0

  # Run container
  docker run -d -p 6080:6080 -e EMULATOR_DEVICE="Samsung Galaxy S10" \
    -e WEB_VNC=true --name android-container \
    budtmo/docker-android:emulator_14.0

  # Access via browser: http://localhost:6080
  # Connect ADB: adb connect localhost:5555
EOF
echo ""

echo -e "${BLUE}Option 4: Test with Mock Data (Development)${NC}"
echo "  Continue testing without real device using simulation"
echo "  This validates the code logic without actual execution"
echo ""

echo -e "${BLUE}Option 5: Physical Device (Best for Real Testing)${NC}"
echo "  Connect Android phone via USB"
echo "  Much faster than emulator"
echo ""
echo "  Steps:"
echo "  1. Enable Developer Options on phone"
echo "  2. Enable USB Debugging"
echo "  3. Connect USB cable"
echo "  4. adb devices (authorize on phone)"
echo "  5. Install frida-server for device architecture"
echo ""

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              Current Recommendation                       ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

if [ "$KVM_OK" = "true" ]; then
    echo -e "${GREEN}✓${NC} KVM available - use standard emulator"
    echo "  Run: ./quick_emulator_setup.sh"
else
    echo -e "${YELLOW}Recommended: Use Option 4 (Mock/Simulation)${NC}"
    echo ""
    echo "  Since KVM is not available, testing with real emulator"
    echo "  will be very slow. Better options:"
    echo ""
    echo "  A. Test the analysis logic with simulation:"
    echo "     poetry run androsleuth -a samples/fdroid.apk -m deep -f pdf"
    echo "     (This runs everything except Frida hooks)"
    echo ""
    echo "  B. Use physical Android device (fastest & easiest)"
    echo ""
    echo "  C. Enable KVM for full emulator support"
    echo ""
fi

# Offer to continue with mock data
echo ""
read -p "Would you like to test static analysis + mock Frida data? (Y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    echo ""
    echo -e "${BLUE}Running comprehensive static analysis...${NC}"
    echo ""
    
    # Run in Docker to ensure clean environment
    docker exec -it AndroSleuth poetry run androsleuth \
        -a samples/fdroid.apk \
        -m deep \
        -f all \
        -o reports/comprehensive_test
    
    echo ""
    echo -e "${GREEN}✓${NC} Analysis complete!"
    echo ""
    echo "Reports generated in: reports/comprehensive_test/"
    echo "  - JSON: Complete data structure"
    echo "  - HTML: Interactive web report"
    echo "  - PDF: Professional document"
    echo ""
    echo "To add real Frida data, enable KVM or use physical device."
fi
