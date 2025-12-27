#!/bin/bash
# Manages UFW and iptables rules for VPN traffic


set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
WG_PORT="${WG_PORT:-51820}"
WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_SUBNET="${WG_SUBNET:-10.8.0.0/24}"
LOG_FILE="/var/log/wireguard-firewall.log"
IPTABLES_SAVE_FILE="/etc/iptables/rules.v4"
IPTABLES_BACKUP_DIR="/var/backups/iptables"

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Print colored messages
print_msg() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Print status with icon
print_status() {
    local status=$1
    local message=$2
    
    case $status in
        ok)
            echo -e "${GREEN}✓${NC} $message"
            log "SUCCESS: $message"
            ;;
        error)
            echo -e "${RED}✗${NC} $message"
            log "ERROR: $message"
            ;;
        warn)
            echo -e "${YELLOW}⚠${NC} $message"
            log "WARNING: $message"
            ;;
        info)
            echo -e "${BLUE}ℹ${NC} $message"
            log "INFO: $message"
            ;;
    esac
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_status "error" "This script must be run as root"
        exit 1
    fi
}

# Detect firewall type
detect_firewall() {
    if command -v ufw &> /dev/null && ufw status &> /dev/null; then
        echo "ufw"
    elif command -v iptables &> /dev/null; then
        echo "iptables"
    else
        echo "none"
    fi
}

# Get default network interface
get_default_interface() {
    ip route | grep default | awk '{print $5}' | head -n1
}

# Backup current iptables rules
backup_iptables() {
    print_msg "$YELLOW" "Creating firewall backup..."
    
    local backup_dir="$IPTABLES_BACKUP_DIR"
    local backup_file="$backup_dir/iptables-$(date +%Y%m%d-%H%M%S).rules"
    
    mkdir -p "$backup_dir"
    
    if command -v iptables-save &> /dev/null; then
        iptables-save > "$backup_file"
        print_status "ok" "Backup saved to: $backup_file"
    else
        print_status "warn" "iptables-save not available"
    fi
}

# Configure UFW firewall
configure_ufw() {
    print_msg "$CYAN" "═══════════════════════════════════════"
    print_msg "$CYAN" "  Configuring UFW Firewall"
    print_msg "$CYAN" "═══════════════════════════════════════"
    echo ""
    
    local interface=$(get_default_interface)
    
    print_status "info" "Network interface: $interface"
    print_status "info" "WireGuard port: $WG_PORT/udp"
    print_status "info" "VPN subnet: $WG_SUBNET"
    echo ""
    
    # Backup current rules
    backup_ufw_rules
    
    # Allow WireGuard port
    print_msg "$YELLOW" "[1/6] Allowing WireGuard port..."
    if ufw allow "$WG_PORT"/udp comment "WireGuard VPN" > /dev/null 2>&1; then
        print_status "ok" "Port $WG_PORT/udp allowed"
    else
        print_status "warn" "Port rule may already exist"
    fi
    
    # Allow SSH (safety measure)
    print_msg "$YELLOW" "[2/6] Ensuring SSH access..."
    if ufw allow ssh comment "SSH Access" > /dev/null 2>&1; then
        print_status "ok" "SSH access allowed"
    else
        print_status "warn" "SSH rule already exists"
    fi
    
    # Configure forwarding in UFW
    print_msg "$YELLOW" "[3/6] Configuring IP forwarding..."
    configure_ufw_forwarding "$interface"
    
    # Set default policies
    print_msg "$YELLOW" "[4/6] Setting default policies..."
    ufw default deny incoming > /dev/null 2>&1
    ufw default allow outgoing > /dev/null 2>&1
    print_status "ok" "Default policies set"
    
    # Enable UFW
    print_msg "$YELLOW" "[5/6] Enabling UFW..."
    if ufw --force enable > /dev/null 2>&1; then
        print_status "ok" "UFW enabled"
    else
        print_status "error" "Failed to enable UFW"
        return 1
    fi
    
    # Verify configuration
    print_msg "$YELLOW" "[6/6] Verifying configuration..."
    if ufw status | grep -q "$WG_PORT"; then
        print_status "ok" "WireGuard rules verified"
    else
        print_status "warn" "Rule verification inconclusive"
    fi
    
    echo ""
    print_msg "$GREEN" "✓ UFW configuration complete!"
    log "UFW configured successfully for WireGuard"
}

# Configure UFW forwarding rules
configure_ufw_forwarding() {
    local interface=$1
    local ufw_before="/etc/ufw/before.rules"
    local ufw_sysctl="/etc/ufw/sysctl.conf"
    
    # Backup before.rules
    if [[ -f "$ufw_before" ]]; then
        cp "$ufw_before" "${ufw_before}.backup-$(date +%Y%m%d)"
    fi
    
    # Check if WireGuard rules already exist
    if grep -q "WireGuard VPN" "$ufw_before" 2>/dev/null; then
        print_status "warn" "Forwarding rules already exist"
        return 0
    fi
    
    # Add NAT rules to before.rules
    cat >> "$ufw_before" <<EOF

# START WireGuard VPN rules
# NAT table rules
*nat
:POSTROUTING ACCEPT [0:0]
# Forward traffic through the default interface
-A POSTROUTING -s $WG_SUBNET -o $interface -j MASQUERADE
COMMIT
# END WireGuard VPN rules
EOF
    
    # Enable IP forwarding in UFW sysctl
    if [[ -f "$ufw_sysctl" ]]; then
        sed -i 's/#net\/ipv4\/ip_forward=1/net\/ipv4\/ip_forward=1/' "$ufw_sysctl" 2>/dev/null || true
        sed -i 's/net\/ipv4\/ip_forward=0/net\/ipv4\/ip_forward=1/' "$ufw_sysctl" 2>/dev/null || true
        
        if ! grep -q "net/ipv4/ip_forward=1" "$ufw_sysctl"; then
            echo "net/ipv4/ip_forward=1" >> "$ufw_sysctl"
        fi
    fi
    
    print_status "ok" "Forwarding rules configured"
}

# Backup UFW rules
backup_ufw_rules() {
    local backup_dir="/var/backups/ufw"
    mkdir -p "$backup_dir"
    
    if [[ -f /etc/ufw/before.rules ]]; then
        cp /etc/ufw/before.rules "$backup_dir/before.rules-$(date +%Y%m%d-%H%M%S)"
    fi
    
    if [[ -f /etc/ufw/after.rules ]]; then
        cp /etc/ufw/after.rules "$backup_dir/after.rules-$(date +%Y%m%d-%H%M%S)"
    fi
}

# Configure iptables firewall
configure_iptables() {
    print_msg "$CYAN" "═══════════════════════════════════════"
    print_msg "$CYAN" "  Configuring iptables Firewall"
    print_msg "$CYAN" "═══════════════════════════════════════"
    echo ""
    
    local interface=$(get_default_interface)
    
    print_status "info" "Network interface: $interface"
    print_status "info" "WireGuard port: $WG_PORT/udp"
    print_status "info" "VPN subnet: $WG_SUBNET"
    echo ""
    
    # Backup current rules
    backup_iptables
    
    # Allow WireGuard port
    print_msg "$YELLOW" "[1/7] Allowing WireGuard port..."
    if ! iptables -C INPUT -p udp --dport "$WG_PORT" -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -p udp --dport "$WG_PORT" -j ACCEPT
        print_status "ok" "Port $WG_PORT/udp allowed"
    else
        print_status "warn" "Rule already exists"
    fi
    
    # Allow established connections
    print_msg "$YELLOW" "[2/7] Allowing established connections..."
    if ! iptables -C INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        print_status "ok" "Established connections allowed"
    else
        print_status "warn" "Rule already exists"
    fi
    
    # Allow loopback
    print_msg "$YELLOW" "[3/7] Allowing loopback traffic..."
    if ! iptables -C INPUT -i lo -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -i lo -j ACCEPT
        print_status "ok" "Loopback allowed"
    else
        print_status "warn" "Rule already exists"
    fi
    
    # Forward WireGuard traffic
    print_msg "$YELLOW" "[4/7] Configuring forwarding rules..."
    if ! iptables -C FORWARD -i "$WG_INTERFACE" -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i "$WG_INTERFACE" -j ACCEPT
        iptables -A FORWARD -o "$WG_INTERFACE" -j ACCEPT
        print_status "ok" "Forwarding rules added"
    else
        print_status "warn" "Rules already exist"
    fi
    
    # NAT masquerading
    print_msg "$YELLOW" "[5/7] Configuring NAT..."
    if ! iptables -t nat -C POSTROUTING -s "$WG_SUBNET" -o "$interface" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s "$WG_SUBNET" -o "$interface" -j MASQUERADE
        print_status "ok" "NAT configured"
    else
        print_status "warn" "NAT rule already exists"
    fi
    
    # Enable IP forwarding
    print_msg "$YELLOW" "[6/7] Enabling IP forwarding..."
    enable_ip_forwarding
    
    # Save rules
    print_msg "$YELLOW" "[7/7] Saving iptables rules..."
    save_iptables_rules
    
    echo ""
    print_msg "$GREEN" "✓ iptables configuration complete!"
    log "iptables configured successfully for WireGuard"
}

# Enable IP forwarding
enable_ip_forwarding() {
    # Runtime
    sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
    
    # Persistent
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    else
        sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
        sed -i 's/net.ipv4.ip_forward=0/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    fi
    
    sysctl -p > /dev/null 2>&1
    print_status "ok" "IP forwarding enabled"
}

# Save iptables rules
save_iptables_rules() {
    # Try different methods to save rules
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save > /dev/null 2>&1
        print_status "ok" "Rules saved with netfilter-persistent"
    elif command -v iptables-save &> /dev/null; then
        mkdir -p "$(dirname "$IPTABLES_SAVE_FILE")"
        iptables-save > "$IPTABLES_SAVE_FILE"
        print_status "ok" "Rules saved to $IPTABLES_SAVE_FILE"
        
        # Install iptables-persistent if not present
        if ! dpkg -l | grep -q iptables-persistent; then
            print_status "info" "Installing iptables-persistent..."
            export DEBIAN_FRONTEND=noninteractive
            apt-get install -y iptables-persistent > /dev/null 2>&1
        fi
    else
        print_status "warn" "No persistent save method available"
    fi
}

# Show current firewall status
show_status() {
    local fw_type=$(detect_firewall)
    
    print_msg "$CYAN" "═══════════════════════════════════════"
    print_msg "$CYAN" "      Firewall Status"
    print_msg "$CYAN" "═══════════════════════════════════════"
    echo ""
    
    print_status "info" "Firewall type: $fw_type"
    print_status "info" "WireGuard interface: $WG_INTERFACE"
    print_status "info" "VPN subnet: $WG_SUBNET"
    echo ""
    
    case $fw_type in
        ufw)
            show_ufw_status
            ;;
        iptables)
            show_iptables_status
            ;;
        *)
            print_status "warn" "No firewall detected"
            ;;
    esac
}

# Show UFW status
show_ufw_status() {
    print_msg "$YELLOW" "UFW Status:"
    print_msg "$YELLOW" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if ufw status | grep -q "Status: active"; then
        print_status "ok" "UFW is active"
    else
        print_status "warn" "UFW is inactive"
    fi
    
    echo ""
    print_msg "$YELLOW" "WireGuard Rules:"
    ufw status numbered | grep -E "($WG_PORT|$WG_INTERFACE)" || echo "  No specific rules found"
    
    echo ""
    print_msg "$YELLOW" "IP Forwarding:"
    local forward_status=$(sysctl net.ipv4.ip_forward | awk '{print $3}')
    if [[ "$forward_status" == "1" ]]; then
        print_status "ok" "IP forwarding enabled"
    else
        print_status "warn" "IP forwarding disabled"
    fi
}

# Show iptables status
show_iptables_status() {
    print_msg "$YELLOW" "iptables Rules:"
    print_msg "$YELLOW" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    echo ""
    print_msg "$BLUE" "INPUT chain (WireGuard port):"
    iptables -L INPUT -n -v | grep -E "($WG_PORT|dpt:$WG_PORT)" || echo "  No rules found"
    
    echo ""
    print_msg "$BLUE" "FORWARD chain:"
    iptables -L FORWARD -n -v | grep -E "($WG_INTERFACE|$WG_SUBNET)" || echo "  No rules found"
    
    echo ""
    print_msg "$BLUE" "NAT table:"
    iptables -t nat -L POSTROUTING -n -v | grep -E "($WG_INTERFACE|$WG_SUBNET)" || echo "  No rules found"
    
    echo ""
    print_msg "$YELLOW" "IP Forwarding:"
    local forward_status=$(sysctl net.ipv4.ip_forward | awk '{print $3}')
    if [[ "$forward_status" == "1" ]]; then
        print_status "ok" "IP forwarding enabled"
    else
        print_status "warn" "IP forwarding disabled"
    fi
}

# Remove firewall rules
remove_rules() {
    local fw_type=$(detect_firewall)
    
    print_msg "$YELLOW" "Removing WireGuard firewall rules..."
    echo ""
    
    case $fw_type in
        ufw)
            remove_ufw_rules
            ;;
        iptables)
            remove_iptables_rules
            ;;
        *)
            print_status "warn" "No firewall detected"
            ;;
    esac
}

# Remove UFW rules
remove_ufw_rules() {
    print_msg "$YELLOW" "Removing UFW rules..."
    
    # Remove port rule
    ufw delete allow "$WG_PORT"/udp 2>/dev/null || true
    
    # Remove from before.rules
    if [[ -f /etc/ufw/before.rules ]]; then
        sed -i '/# START WireGuard VPN rules/,/# END WireGuard VPN rules/d' /etc/ufw/before.rules
    fi
    
    ufw reload > /dev/null 2>&1
    print_status "ok" "UFW rules removed"
}

# Remove iptables rules
remove_iptables_rules() {
    print_msg "$YELLOW" "Removing iptables rules..."
    
    local interface=$(get_default_interface)
    
    # Remove INPUT rules
    iptables -D INPUT -p udp --dport "$WG_PORT" -j ACCEPT 2>/dev/null || true
    
    # Remove FORWARD rules
    iptables -D FORWARD -i "$WG_INTERFACE" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "$WG_INTERFACE" -j ACCEPT 2>/dev/null || true
    
    # Remove NAT rules
    iptables -t nat -D POSTROUTING -s "$WG_SUBNET" -o "$interface" -j MASQUERADE 2>/dev/null || true
    
    save_iptables_rules
    print_status "ok" "iptables rules removed"
}

# Test firewall configuration
test_firewall() {
    print_msg "$CYAN" "═══════════════════════════════════════"
    print_msg "$CYAN" "      Testing Firewall Configuration"
    print_msg "$CYAN" "═══════════════════════════════════════"
    echo ""
    
    local tests_passed=0
    local tests_failed=0
    
    # Test 1: Check if WireGuard port is open
    print_msg "$YELLOW" "[Test 1] Checking WireGuard port..."
    if ss -tulpn | grep -q ":$WG_PORT"; then
        print_status "ok" "Port $WG_PORT is listening"
        ((tests_passed++))
    else
        print_status "warn" "Port $WG_PORT is not listening (WireGuard may not be running)"
        ((tests_failed++))
    fi
    
    # Test 2: Check IP forwarding
    print_msg "$YELLOW" "[Test 2] Checking IP forwarding..."
    if [[ $(sysctl net.ipv4.ip_forward | awk '{print $3}') == "1" ]]; then
        print_status "ok" "IP forwarding is enabled"
        ((tests_passed++))
    else
        print_status "error" "IP forwarding is disabled"
        ((tests_failed++))
    fi
    
    # Test 3: Check NAT rules
    print_msg "$YELLOW" "[Test 3] Checking NAT rules..."
    if iptables -t nat -L POSTROUTING -n | grep -q "$WG_SUBNET"; then
        print_status "ok" "NAT rules are configured"
        ((tests_passed++))
    else
        print_status "error" "NAT rules are missing"
        ((tests_failed++))
    fi
    
    # Test 4: Check forwarding rules
    print_msg "$YELLOW" "[Test 4] Checking forwarding rules..."
    if iptables -L FORWARD -n | grep -q "$WG_INTERFACE"; then
        print_status "ok" "Forwarding rules are configured"
        ((tests_passed++))
    else
        print_status "error" "Forwarding rules are missing"
        ((tests_failed++))
    fi
    
    echo ""
    print_msg "$CYAN" "═══════════════════════════════════════"
    if [[ $tests_failed -eq 0 ]]; then
        print_msg "$GREEN" "✓ All tests passed ($tests_passed/$((tests_passed + tests_failed)))"
    else
        print_msg "$YELLOW" "⚠ Some tests failed ($tests_passed/$((tests_passed + tests_failed)))"
    fi
    print_msg "$CYAN" "═══════════════════════════════════════"
}

# Show usage
show_usage() {
    cat << EOF
${GREEN}WireGuard Firewall Configuration Script${NC}
${YELLOW}════════════════════════════════════════${NC}

${BLUE}Usage:${NC} $0 <command> [options]

${BLUE}Commands:${NC}
  ${GREEN}setup${NC}             Configure firewall for WireGuard
  ${GREEN}status${NC}            Show current firewall status
  ${GREEN}test${NC}              Test firewall configuration
  ${GREEN}remove${NC}            Remove WireGuard firewall rules
  ${GREEN}backup${NC}            Backup current firewall rules
  ${GREEN}enable-forwarding${NC} Enable IP forwarding only

${BLUE}Environment Variables:${NC}
  WG_PORT         WireGuard port (default: 51820)
  WG_INTERFACE    WireGuard interface (default: wg0)
  WG_SUBNET       VPN subnet (default: 10.8.0.0/24)

${BLUE}Examples:${NC}
  $0 setup
  WG_PORT=51821 $0 setup
  $0 status
  $0 test

${YELLOW}Note: This script must be run as root${NC}
EOF
}

# Main execution
main() {
    check_root
    
    # Create log file if it doesn't exist
    touch "$LOG_FILE" 2>/dev/null || true
    
    case "$1" in
        setup)
            local fw_type=$(detect_firewall)
            case $fw_type in
                ufw)
                    configure_ufw
                    ;;
                iptables)
                    configure_iptables
                    ;;
                *)
                    print_status "error" "No firewall system detected"
                    print_msg "$YELLOW" "Installing iptables..."
                    apt-get update -qq && apt-get install -y iptables > /dev/null 2>&1
                    configure_iptables
                    ;;
            esac
            ;;
        status)
            show_status
            ;;
        test)
            test_firewall
            ;;
        remove)
            remove_rules
            ;;
        backup)
            backup_iptables
            ;;
        enable-forwarding)
            enable_ip_forwarding
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
