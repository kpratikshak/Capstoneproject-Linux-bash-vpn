#!/bin/bash

# Installation and System Preparation Script for WireGuard VPN Automation
# This script checks prerequisites, validates the system, and prepares for VPN deployment

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_VERSION="1.0.0"
MIN_KERNEL_VERSION="3.10"
REQUIRED_DISK_SPACE=100 # MB
PROJECT_DIR=$(pwd)

# Print banner
print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
╦ ╦┬┬─┐┌─┐╔═╗┬ ┬┌─┐┬─┐┌┬┐  ╦  ╦╔═╗╔╗╔
║║║│├┬┘├┤ ║ ╦│ │├─┤├┬┘ ││  ╚╗╔╝╠═╝║║║
╚╩╝┴┴└─└─┘╚═╝└─┘┴ ┴┴└──┴┘   ╚╝ ╩  ╝╚╝
    Automated Setup & Management
EOF
    echo -e "${NC}"
    echo -e "${BLUE}Version: $SCRIPT_VERSION${NC}"
    echo ""
}

# Print colored messages
print_msg() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Print with icon
print_status() {
    local status=$1
    local message=$2
    
    case $status in
        ok)
            echo -e "${GREEN}✓${NC} $message"
            ;;
        error)
            echo -e "${RED}✗${NC} $message"
            ;;
        warn)
            echo -e "${YELLOW}⚠${NC} $message"
            ;;
        info)
            echo -e "${BLUE}ℹ${NC} $message"
            ;;
    esac
}

# Check if running as root
check_root() {
    print_msg "$YELLOW" "[1/10] Checking privileges..."
    
    if [[ $EUID -ne 0 ]]; then
        print_status "error" "This script must be run as root"
        echo ""
        print_msg "$YELLOW" "Please run: sudo $0"
        exit 1
    fi
    
    print_status "ok" "Running with root privileges"
}

# Detect and validate OS
check_os() {
    print_msg "$YELLOW" "[2/10] Detecting operating system..."
    
    if [[ ! -f /etc/os-release ]]; then
        print_status "error" "Cannot detect operating system"
        exit 1
    fi
    
    . /etc/os-release
    
    print_status "ok" "OS: $PRETTY_NAME"
    
    # Check if OS is supported
    if [[ "$ID" == "ubuntu" ]] || [[ "$ID" == "debian" ]]; then
        print_status "ok" "Supported distribution detected"
        
        # Check version
        if [[ "$ID" == "ubuntu" ]]; then
            local version=$(echo $VERSION_ID | cut -d. -f1)
            if [[ $version -lt 18 ]]; then
                print_status "warn" "Ubuntu 18.04 or newer is recommended"
            fi
        fi
    else
        print_status "warn" "This script is optimized for Ubuntu/Debian"
        print_msg "$YELLOW" "   Detected: $PRETTY_NAME"
        print_msg "$YELLOW" "   Continuing with installation..."
    fi
}

# Check kernel version
check_kernel() {
    print_msg "$YELLOW" "[3/10] Checking kernel version..."
    
    local kernel_version=$(uname -r | cut -d. -f1,2)
    local required_version=$MIN_KERNEL_VERSION
    
    if awk -v ver="$kernel_version" -v req="$required_version" 'BEGIN{exit(!(ver>=req))}'; then
        print_status "ok" "Kernel version: $(uname -r)"
    else
        print_status "error" "Kernel version $(uname -r) is too old"
        print_msg "$RED" "   Minimum required: $MIN_KERNEL_VERSION"
        exit 1
    fi
}

# Check for virtualization environment
check_virtualization() {
    print_msg "$YELLOW" "[4/10] Checking virtualization environment..."
    
    if systemd-detect-virt &> /dev/null; then
        local virt=$(systemd-detect-virt)
        
        if [[ "$virt" != "none" ]]; then
            print_status "info" "Running in $virt environment"
            
            # Check for WSL
            if grep -qi microsoft /proc/version 2>/dev/null; then
                print_status "warn" "WSL detected - limited functionality"
                print_msg "$YELLOW" "   Some WireGuard features may not work in WSL"
            fi
            
            # Check for OpenVZ/LXC
            if [[ "$virt" == "openvz" ]] || [[ "$virt" == "lxc" ]]; then
                print_status "warn" "Container environment detected"
                print_msg "$YELLOW" "   TUN/TAP support required for WireGuard"
            fi
        else
            print_status "ok" "Running on bare metal"
        fi
    else
        print_status "ok" "Virtualization check passed"
    fi
}

# Check internet connectivity
check_internet() {
    print_msg "$YELLOW" "[5/10] Checking internet connectivity..."
    
    local hosts=("8.8.8.8" "1.1.1.1" "9.9.9.9")
    local connected=false
    
    for host in "${hosts[@]}"; do
        if ping -c 1 -W 2 "$host" &> /dev/null; then
            connected=true
            break
        fi
    done
    
    if $connected; then
        print_status "ok" "Internet connection available"
    else
        print_status "error" "No internet connection detected"
        print_msg "$RED" "   Internet access is required for installation"
        exit 1
    fi
    
    # Check DNS resolution
    if host google.com &> /dev/null || nslookup google.com &> /dev/null; then
        print_status "ok" "DNS resolution working"
    else
        print_status "warn" "DNS resolution may have issues"
    fi
}

# Check available disk space
check_disk_space() {
    print_msg "$YELLOW" "[6/10] Checking disk space..."
    
    local available=$(df /tmp | tail -1 | awk '{print $4}')
    local required=$((REQUIRED_DISK_SPACE * 1024))
    
    if [[ $available -gt $required ]]; then
        local available_mb=$((available / 1024))
        print_status "ok" "Available space: ${available_mb}MB"
    else
        print_status "error" "Insufficient disk space"
        print_msg "$RED" "   Required: ${REQUIRED_DISK_SPACE}MB"
        exit 1
    fi
}

# Check for conflicting services
check_conflicts() {
    print_msg "$YELLOW" "[7/10] Checking for conflicting services..."
    
    local conflicts=false
    
    # Check if port 51820 is already in use
    if ss -tulpn | grep -q ":51820"; then
        print_status "warn" "Port 51820 is already in use"
        conflicts=true
    fi
    
    # Check if WireGuard is already installed
    if command -v wg &> /dev/null; then
        print_status "warn" "WireGuard is already installed"
        if systemctl is-active --quiet wg-quick@wg0; then
            print_status "warn" "WireGuard service is running"
        fi
    fi
    
    if ! $conflicts; then
        print_status "ok" "No conflicts detected"
    else
        echo ""
        print_msg "$YELLOW" "   Conflicts detected. Continue anyway? (yes/no)"
        read -r response
        if [[ "$response" != "yes" ]]; then
            print_msg "$RED" "Installation cancelled"
            exit 1
        fi
    fi
}

# Install base dependencies
install_dependencies() {
    print_msg "$YELLOW" "[8/10] Installing base dependencies..."
    
    export DEBIAN_FRONTEND=noninteractive
    
    # Update package lists
    print_msg "$BLUE" "   → Updating package lists..."
    apt-get update -qq 2>&1 | grep -v "^Get:" || true
    
    # Install essential tools
    local packages=(
        "curl"
        "wget"
        "net-tools"
        "iproute2"
        "iptables"
        "gnupg"
        "ca-certificates"
        "software-properties-common"
    )
    
    print_msg "$BLUE" "   → Installing packages..."
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            apt-get install -y "$package" > /dev/null 2>&1
        fi
    done
    
    print_status "ok" "Dependencies installed"
}

# Setup project structure
setup_project() {
    print_msg "$YELLOW" "[9/10] Setting up project structure..."
    
    # Create directories
    mkdir -p "$PROJECT_DIR"/{config,utils,logs,backups}
    
    # Create config directory
    if [[ ! -d "$PROJECT_DIR/config" ]]; then
        mkdir -p "$PROJECT_DIR/config"
    fi
    
    # Create utils directory
    if [[ ! -d "$PROJECT_DIR/utils" ]]; then
        mkdir -p "$PROJECT_DIR/utils"
    fi
    
    # Create logs directory
    if [[ ! -d "$PROJECT_DIR/logs" ]]; then
        mkdir -p "$PROJECT_DIR/logs"
    fi
    
    print_status "ok" "Project structure created"
}

# Set file permissions
set_permissions() {
    print_msg "$YELLOW" "[10/10] Setting file permissions..."
    
    # Make scripts executable
    if [[ -f "$PROJECT_DIR/wireguard-setup.sh" ]]; then
        chmod +x "$PROJECT_DIR/wireguard-setup.sh"
        print_status "ok" "wireguard-setup.sh is executable"
    else
        print_status "warn" "wireguard-setup.sh not found"
    fi
    
    # Set directory permissions
    chmod 755 "$PROJECT_DIR"
    chmod 755 "$PROJECT_DIR"/{config,utils,logs,backups} 2>/dev/null || true
    
    print_status "ok" "Permissions configured"
}

# Print system information
print_system_info() {
    echo ""
    print_msg "$CYAN" "═══════════════════════════════════════"
    print_msg "$CYAN" "       System Information"
    print_msg "$CYAN" "═══════════════════════════════════════"
    echo ""
    
    print_msg "$BLUE" "Hostname:        ${NC}$(hostname)"
    print_msg "$BLUE" "Kernel:          ${NC}$(uname -r)"
    print_msg "$BLUE" "Architecture:    ${NC}$(uname -m)"
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        print_msg "$BLUE" "OS:              ${NC}$PRETTY_NAME"
    fi
    
    local ip=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n1)
    print_msg "$BLUE" "IP Address:      ${NC}${ip:-Not detected}"
    
    local mem_total=$(free -h | awk '/^Mem:/ {print $2}')
    local mem_used=$(free -h | awk '/^Mem:/ {print $3}')
    print_msg "$BLUE" "Memory:          ${NC}${mem_used} / ${mem_total}"
    
    echo ""
}

# Print next steps
show_next_steps() {
    echo ""
    print_msg "$GREEN" "═══════════════════════════════════════"
    print_msg "$GREEN" "   Installation Preparation Complete!"
    print_msg "$GREEN" "═══════════════════════════════════════"
    echo ""
    
    print_msg "$YELLOW" "Next Steps:"
    echo ""
    echo "  1. Install WireGuard VPN Server:"
    print_msg "$CYAN" "     sudo ./wireguard-setup.sh install"
    echo ""
    echo "  2. Add your first client:"
    print_msg "$CYAN" "     sudo ./wireguard-setup.sh add-client laptop"
    echo ""
    echo "  3. Check VPN status:"
    print_msg "$CYAN" "     sudo ./wireguard-setup.sh status"
    echo ""
    echo "  4. View all available commands:"
    print_msg "$CYAN" "     sudo ./wireguard-setup.sh"
    echo ""
    
    print_msg "$BLUE" "Documentation:"
    echo "  • README.md - Full documentation"
    echo "  • config/defaults.conf - Configuration options"
    echo ""
    
    print_msg "$YELLOW" "Need help? Check the README.md file"
    echo ""
}

# Error handling
trap 'print_status "error" "Installation failed at line $LINENO"; exit 1' ERR

# Main execution
main() {
    print_banner
    
    print_msg "$GREEN" "Starting installation preparation..."
    print_msg "$GREEN" "════════════════════════════════════"
    echo ""
    
    check_root
    check_os
    check_kernel
    check_virtualization
    check_internet
    check_disk_space
    check_conflicts
    install_dependencies
    setup_project
    set_permissions
    
    echo ""
    print_msg "$GREEN" "════════════════════════════════════"
    print_msg "$GREEN" "All checks passed!"
    print_msg "$GREEN" "════════════════════════════════════"
    
    print_system_info
    show_next_steps
}

main "$@"
