#!/bin/bash

# Description: Automated WireGuard VPN server deployment and client management

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
WG_DIR="/etc/wireguard"
WG_CONFIG="$WG_DIR/wg0.conf"
CLIENT_DIR="$WG_DIR/clients"
SERVER_PORT="51820"
SERVER_IP="10.8.0.1/24"
DNS_SERVERS="1.1.1.1,1.0.0.1"
LOG_FILE="/var/log/wireguard-setup.log"

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        exit 1
    fi
}

# Print colored messages
print_msg() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Get server public IP
get_public_ip() {
    local ip=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || curl -s -4 ipecho.net/plain 2>/dev/null)
    if [[ -z "$ip" ]]; then
        ip=$(ip -4 addr | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n1)
    fi
    echo "$ip"
}

# Get default network interface
get_interface() {
    ip route | grep default | awk '{print $5}' | head -n1
}

# Install WireGuard and dependencies
install_wireguard() {
    print_msg "$GREEN" "===================================="
    print_msg "$GREEN" "Installing WireGuard VPN Server"
    print_msg "$GREEN" "===================================="
    echo ""
    
    log "Starting WireGuard installation"
    
    print_msg "$YELLOW" "[1/6] Updating package lists..."
    apt update -qq
    
    print_msg "$YELLOW" "[2/6] Installing WireGuard..."
    apt install -y wireguard wireguard-tools > /dev/null 2>&1
    
    print_msg "$YELLOW" "[3/6] Installing additional tools..."
    apt install -y qrencode iptables resolvconf curl > /dev/null 2>&1
    
    print_msg "$YELLOW" "[4/6] Enabling IP forwarding..."
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    sysctl -p > /dev/null 2>&1
    
    print_msg "$YELLOW" "[5/6] Creating log file..."
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    
    print_msg "$YELLOW" "[6/6] Verifying installation..."
    if ! command -v wg &> /dev/null; then
        print_msg "$RED" "Error: WireGuard installation failed"
        log "ERROR: WireGuard installation failed"
        exit 1
    fi
    
    print_msg "$GREEN" "✓ WireGuard installed successfully!"
    log "WireGuard installation completed"
}

# Generate server configuration
setup_server() {
    print_msg "$YELLOW" ""
    print_msg "$YELLOW" "Setting up WireGuard server..."
    echo ""
    
    log "Starting server setup"
    
    # Create directories
    mkdir -p "$WG_DIR" "$CLIENT_DIR"
    chmod 700 "$WG_DIR" "$CLIENT_DIR"
    
    # Generate server keys
    print_msg "$BLUE" "→ Generating server keys..."
    cd "$WG_DIR"
    umask 077
    wg genkey | tee server_private.key | wg pubkey > server_public.key
    chmod 600 server_private.key server_public.key
    
    local server_private=$(cat server_private.key)
    local server_public=$(cat server_public.key)
    
    # Get network interface
    local iface=$(get_interface)
    print_msg "$BLUE" "→ Detected network interface: $iface"
    
    # Get public IP
    local public_ip=$(get_public_ip)
    print_msg "$BLUE" "→ Detected public IP: $public_ip"
    
    # Create server configuration
    print_msg "$BLUE" "→ Creating server configuration..."
    cat > "$WG_CONFIG" <<EOF
# WireGuard Server Configuration
# Generated: $(date)

[Interface]
Address = $SERVER_IP
ListenPort = $SERVER_PORT
PrivateKey = $server_private
SaveConfig = false

# Firewall rules
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $iface -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $iface -j MASQUERADE

# Client configurations will be added below

EOF
    
    chmod 600 "$WG_CONFIG"
    log "Server configuration created"
    
    # Configure firewall
    configure_firewall
    
    # Enable and start WireGuard
    print_msg "$BLUE" "→ Starting WireGuard service..."
    systemctl enable wg-quick@wg0 > /dev/null 2>&1
    systemctl start wg-quick@wg0
    
    if systemctl is-active --quiet wg-quick@wg0; then
        print_msg "$GREEN" "✓ WireGuard service started successfully!"
    else
        print_msg "$RED" "✗ Failed to start WireGuard service"
        log "ERROR: Failed to start WireGuard service"
        exit 1
    fi
    
    echo ""
    print_msg "$GREEN" "===================================="
    print_msg "$GREEN" "Server Setup Complete!"
    print_msg "$GREEN" "===================================="
    echo ""
    print_msg "$YELLOW" "Server Details:"
    echo "  Public IP: $public_ip"
    echo "  Port: $SERVER_PORT"
    echo "  Interface: wg0"
    echo "  Network: $SERVER_IP"
    echo ""
    print_msg "$YELLOW" "Next Steps:"
    echo "  1. Add a client: sudo $0 add-client <client-name>"
    echo "  2. Check status: sudo $0 status"
    echo ""
    
    log "Server setup completed successfully"
}

# Configure firewall
configure_firewall() {
    print_msg "$BLUE" "→ Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        # UFW is installed
        ufw allow "$SERVER_PORT"/udp > /dev/null 2>&1
        ufw --force enable > /dev/null 2>&1
        print_msg "$GREEN" "  ✓ UFW rules added"
        log "UFW firewall configured"
    else
        # Use iptables directly
        if ! iptables -C INPUT -p udp --dport "$SERVER_PORT" -j ACCEPT 2>/dev/null; then
            iptables -A INPUT -p udp --dport "$SERVER_PORT" -j ACCEPT
            print_msg "$GREEN" "  ✓ iptables rules added"
            log "iptables firewall configured"
        fi
    fi
}

# Add a new client
add_client() {
    local client_name=$1
    
    if [[ -z "$client_name" ]]; then
        print_msg "$RED" "Error: Client name is required"
        echo "Usage: $0 add-client <client-name>"
        exit 1
    fi
    
    # Validate client name
    if [[ ! "$client_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        print_msg "$RED" "Error: Client name can only contain letters, numbers, hyphens, and underscores"
        exit 1
    fi
    
    if [[ -f "$CLIENT_DIR/${client_name}.conf" ]]; then
        print_msg "$RED" "Error: Client '$client_name' already exists"
        exit 1
    fi
    
    print_msg "$YELLOW" "Creating client: $client_name"
    echo ""
    log "Creating client: $client_name"
    
    # Generate client keys
    cd "$CLIENT_DIR"
    umask 077
    wg genkey | tee "${client_name}_private.key" | wg pubkey > "${client_name}_public.key"
    
    local client_private=$(cat "${client_name}_private.key")
    local client_public=$(cat "${client_name}_public.key")
    local server_public=$(cat "$WG_DIR/server_public.key")
    local server_ip=$(get_public_ip)
    
    # Get next available IP
    local last_ip=$(grep -oP 'AllowedIPs = 10\.8\.0\.\K[0-9]+' "$WG_CONFIG" 2>/dev/null | sort -n | tail -1)
    local client_ip=$((${last_ip:-1} + 1))
    
    if [[ $client_ip -gt 254 ]]; then
        print_msg "$RED" "Error: No more IP addresses available in the subnet"
        exit 1
    fi
    
    print_msg "$BLUE" "→ Assigned IP: 10.8.0.$client_ip"
    
    # Add client to server config
    cat >> "$WG_CONFIG" <<EOF

[Peer]
# Client: $client_name
# Created: $(date)
PublicKey = $client_public
AllowedIPs = 10.8.0.$client_ip/32
EOF
    
    # Create client configuration
    cat > "$CLIENT_DIR/${client_name}.conf" <<EOF
# WireGuard Client Configuration
# Client: $client_name
# Created: $(date)

[Interface]
Address = 10.8.0.$client_ip/32
PrivateKey = $client_private
DNS = $DNS_SERVERS

[Peer]
PublicKey = $server_public
Endpoint = $server_ip:$SERVER_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    
    chmod 600 "$CLIENT_DIR/${client_name}.conf"
    chmod 600 "$CLIENT_DIR/${client_name}_private.key"
    chmod 644 "$CLIENT_DIR/${client_name}_public.key"
    
    # Restart WireGuard
    print_msg "$BLUE" "→ Reloading WireGuard..."
    systemctl restart wg-quick@wg0
    
    echo ""
    print_msg "$GREEN" "✓ Client '$client_name' created successfully!"
    echo ""
    print_msg "$YELLOW" "Configuration file saved to:"
    echo "  $CLIENT_DIR/${client_name}.conf"
    echo ""
    print_msg "$YELLOW" "To connect this client:"
    echo "  1. Copy the config file to your device"
    echo "  2. Import it into your WireGuard client app"
    echo ""
    print_msg "$YELLOW" "QR Code for mobile devices:"
    echo ""
    qrencode -t ansiutf8 < "$CLIENT_DIR/${client_name}.conf"
    echo ""
    
    log "Client $client_name created with IP 10.8.0.$client_ip"
}

# Remove a client
remove_client() {
    local client_name=$1
    
    if [[ -z "$client_name" ]]; then
        print_msg "$RED" "Error: Client name is required"
        echo "Usage: $0 remove-client <client-name>"
        exit 1
    fi
    
    if [[ ! -f "$CLIENT_DIR/${client_name}.conf" ]]; then
        print_msg "$RED" "Error: Client '$client_name' not found"
        exit 1
    fi
    
    print_msg "$YELLOW" "Removing client: $client_name"
    
    # Get client public key
    local client_public=$(cat "$CLIENT_DIR/${client_name}_public.key")
    
    # Remove client from server config
    sed -i "/# Client: $client_name/,/^$/d" "$WG_CONFIG"
    
    # Backup and remove client files
    local backup_dir="$CLIENT_DIR/removed/$(date +%Y%m%d)"
    mkdir -p "$backup_dir"
    mv "$CLIENT_DIR/${client_name}"* "$backup_dir/" 2>/dev/null || true
    
    # Restart WireGuard
    systemctl restart wg-quick@wg0
    
    print_msg "$GREEN" "✓ Client '$client_name' removed successfully!"
    print_msg "$YELLOW" "  Backup saved to: $backup_dir"
    
    log "Client $client_name removed"
}

# List all clients
list_clients() {
    print_msg "$YELLOW" "Active VPN Clients:"
    print_msg "$YELLOW" "===================="
    echo ""
    
    if [[ ! -d "$CLIENT_DIR" ]]; then
        print_msg "$RED" "No clients directory found"
        return
    fi
    
    local count=0
    for conf in "$CLIENT_DIR"/*.conf 2>/dev/null; do
        if [[ -f "$conf" ]]; then
            local name=$(basename "$conf" .conf)
            local ip=$(grep "Address" "$conf" | awk '{print $3}')
            local created=$(grep "Created:" "$conf" | cut -d: -f2- | xargs)
            
            count=$((count + 1))
            echo "$count. $name"
            echo "   IP: $ip"
            echo "   Created: $created"
            echo ""
        fi
    done
    
    if [[ $count -eq 0 ]]; then
        print_msg "$RED" "No clients found"
        echo ""
        print_msg "$YELLOW" "Add a client with: sudo $0 add-client <name>"
    else
        print_msg "$GREEN" "Total clients: $count"
    fi
}

# Show VPN status
show_status() {
    print_msg "$YELLOW" "WireGuard VPN Status"
    print_msg "$YELLOW" "===================="
    echo ""
    
    # Check if WireGuard is installed
    if ! command -v wg &> /dev/null; then
        print_msg "$RED" "WireGuard is not installed"
        echo ""
        print_msg "$YELLOW" "Install with: sudo $0 install"
        exit 1
    fi
    
    # Service status
    if systemctl is-active --quiet wg-quick@wg0; then
        print_msg "$GREEN" "✓ Service Status: Running"
    else
        print_msg "$RED" "✗ Service Status: Stopped"
    fi
    
    # Interface status
    if ip link show wg0 &> /dev/null; then
        print_msg "$GREEN" "✓ Interface: wg0 is up"
    else
        print_msg "$RED" "✗ Interface: wg0 is down"
    fi
    
    echo ""
    print_msg "$YELLOW" "Server Information:"
    echo "  Listen Port: $SERVER_PORT"
    echo "  Server IP: $(grep "Address" "$WG_CONFIG" 2>/dev/null | awk '{print $3}' || echo "N/A")"
    echo "  Public IP: $(get_public_ip)"
    
    echo ""
    print_msg "$YELLOW" "Connected Peers:"
    
    if wg show wg0 2>/dev/null | grep -q "peer:"; then
        wg show wg0 | grep -A 3 "peer:" | while read line; do
            echo "  $line"
        done
    else
        echo "  No peers connected"
    fi
    
    echo ""
    print_msg "$YELLOW" "Recent Logs:"
    if [[ -f "$LOG_FILE" ]]; then
        tail -n 5 "$LOG_FILE" | while read line; do
            echo "  $line"
        done
    else
        echo "  No logs available"
    fi
    
    echo ""
}

# Backup configuration
backup_config() {
    local backup_file="/tmp/wireguard-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    
    print_msg "$YELLOW" "Creating backup..."
    
    tar -czf "$backup_file" -C /etc wireguard 2>/dev/null
    
    print_msg "$GREEN" "✓ Backup created: $backup_file"
    log "Backup created: $backup_file"
}

# Uninstall WireGuard
uninstall() {
    print_msg "$RED" "WARNING: This will remove WireGuard and all configurations!"
    read -p "Are you sure? (yes/no): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        print_msg "$YELLOW" "Uninstall cancelled"
        exit 0
    fi
    
    print_msg "$YELLOW" "Uninstalling WireGuard..."
    
    # Create backup first
    backup_config
    
    # Stop service
    systemctl stop wg-quick@wg0 2>/dev/null || true
    systemctl disable wg-quick@wg0 2>/dev/null || true
    
    # Remove packages
    apt remove -y wireguard wireguard-tools qrencode > /dev/null 2>&1
    apt autoremove -y > /dev/null 2>&1
    
    # Remove configurations
    rm -rf "$WG_DIR"
    
    print_msg "$GREEN" "✓ WireGuard uninstalled"
    print_msg "$YELLOW" "Backup saved before removal"
    log "WireGuard uninstalled"
}

# Show usage
show_usage() {
    cat << EOF
${GREEN}WireGuard VPN Management Script${NC}
${YELLOW}=================================${NC}

${BLUE}Usage:${NC} $0 <command> [options]

${BLUE}Commands:${NC}
  ${GREEN}install${NC}              Install and setup WireGuard server
  ${GREEN}add-client${NC} <name>    Add a new VPN client
  ${GREEN}remove-client${NC} <name> Remove a VPN client
  ${GREEN}list-clients${NC}         List all configured clients
  ${GREEN}status${NC}               Show VPN server status
  ${GREEN}backup${NC}               Create configuration backup
  ${GREEN}uninstall${NC}            Remove WireGuard completely

${BLUE}Examples:${NC}
  $0 install
  $0 add-client laptop
  $0 remove-client laptop
  $0 list-clients
  $0 status

${BLUE}Configuration:${NC}
  Config directory: $WG_DIR
  Client directory: $CLIENT_DIR
  Log file: $LOG_FILE

${YELLOW}For more information, see README.md${NC}
EOF
}

# Main execution
main() {
    check_root
    
    case "$1" in
        install)
            install_wireguard
            setup_server
            ;;
        add-client)
            add_client "$2"
            ;;
        remove-client)
            remove_client "$2"
            ;;
        list-clients)
            list_clients
            ;;
        status)
            show_status
            ;;
        backup)
            backup_config
            ;;
        uninstall)
            uninstall
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
