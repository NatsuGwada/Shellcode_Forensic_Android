#!/bin/bash
#
# AndroSleuth - Docker Run Script
# Helper script to run AndroSleuth in Docker container
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Container name
CONTAINER_NAME="AndroSleuth"

# Banner
echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║          AndroSleuth - Docker Runner                      ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo -e "${RED}[ERROR]${NC} Docker is not running. Please start Docker first."
    exit 1
fi

# Function to build image
build_image() {
    echo -e "${BLUE}[INFO]${NC} Building AndroSleuth Docker image..."
    docker-compose build
    echo -e "${GREEN}[✓]${NC} Image built successfully"
}

# Function to start container
start_container() {
    echo -e "${BLUE}[INFO]${NC} Starting AndroSleuth container..."
    docker-compose up -d
    echo -e "${GREEN}[✓]${NC} Container started: ${CONTAINER_NAME}"
}

# Function to stop container
stop_container() {
    echo -e "${BLUE}[INFO]${NC} Stopping AndroSleuth container..."
    docker-compose down
    echo -e "${GREEN}[✓]${NC} Container stopped"
}

# Function to analyze APK
analyze_apk() {
    local apk_file=$1
    local mode=${2:-standard}
    local output=${3:-reports/docker_analysis}
    
    if [ -z "$apk_file" ]; then
        echo -e "${RED}[ERROR]${NC} No APK file specified"
        exit 1
    fi
    
    if [ ! -f "$apk_file" ]; then
        echo -e "${RED}[ERROR]${NC} APK file not found: $apk_file"
        exit 1
    fi
    
    # Copy APK to samples directory
    local apk_name=$(basename "$apk_file")
    cp "$apk_file" samples/
    
    echo -e "${BLUE}[INFO]${NC} Analyzing: ${apk_name}"
    echo -e "${BLUE}[INFO]${NC} Mode: ${mode}"
    echo -e "${BLUE}[INFO]${NC} Output: ${output}"
    
    docker exec -it $CONTAINER_NAME poetry run androsleuth \
        -a "samples/${apk_name}" \
        -m "$mode" \
        -o "$output" \
        -v
    
    echo -e "${GREEN}[✓]${NC} Analysis complete!"
    echo -e "${BLUE}[INFO]${NC} Reports saved to: ${output}"
}

# Function to run tests
run_tests() {
    echo -e "${BLUE}[INFO]${NC} Running tests in container..."
    
    docker exec -it $CONTAINER_NAME poetry run python tests/test_basic.py
    docker exec -it $CONTAINER_NAME poetry run python tests/test_shellcode.py
    docker exec -it $CONTAINER_NAME poetry run python tests/test_virustotal.py
    
    echo -e "${GREEN}[✓]${NC} All tests completed"
}

# Function to enter shell
enter_shell() {
    echo -e "${BLUE}[INFO]${NC} Entering container shell..."
    docker exec -it $CONTAINER_NAME /bin/bash
}

# Function to show logs
show_logs() {
    docker-compose logs -f androsleuth
}

# Function to show status
show_status() {
    echo -e "${BLUE}[INFO]${NC} Container status:"
    docker-compose ps
    echo ""
    echo -e "${BLUE}[INFO]${NC} Container resource usage:"
    docker stats $CONTAINER_NAME --no-stream
}

# Main menu
case "${1:-help}" in
    build)
        build_image
        ;;
    start)
        start_container
        ;;
    stop)
        stop_container
        ;;
    restart)
        stop_container
        start_container
        ;;
    analyze)
        if [ $# -lt 2 ]; then
            echo -e "${RED}[ERROR]${NC} Usage: $0 analyze <apk_file> [mode] [output]"
            echo -e "  Modes: quick, standard, deep"
            exit 1
        fi
        analyze_apk "$2" "${3:-standard}" "${4:-reports/docker_analysis}"
        ;;
    test)
        run_tests
        ;;
    shell)
        enter_shell
        ;;
    logs)
        show_logs
        ;;
    status)
        show_status
        ;;
    help|*)
        echo -e "${CYAN}Usage:${NC} $0 <command> [options]"
        echo ""
        echo -e "${CYAN}Commands:${NC}"
        echo -e "  ${GREEN}build${NC}                  - Build Docker image"
        echo -e "  ${GREEN}start${NC}                  - Start container"
        echo -e "  ${GREEN}stop${NC}                   - Stop container"
        echo -e "  ${GREEN}restart${NC}                - Restart container"
        echo -e "  ${GREEN}analyze${NC} <apk> [mode]   - Analyze APK file"
        echo -e "  ${GREEN}test${NC}                   - Run unit tests"
        echo -e "  ${GREEN}shell${NC}                  - Enter container shell"
        echo -e "  ${GREEN}logs${NC}                   - Show container logs"
        echo -e "  ${GREEN}status${NC}                 - Show container status"
        echo ""
        echo -e "${CYAN}Examples:${NC}"
        echo -e "  $0 build"
        echo -e "  $0 start"
        echo -e "  $0 analyze sample.apk"
        echo -e "  $0 analyze sample.apk deep"
        echo -e "  $0 analyze sample.apk deep reports/malware_report"
        echo -e "  $0 test"
        echo -e "  $0 shell"
        ;;
esac
