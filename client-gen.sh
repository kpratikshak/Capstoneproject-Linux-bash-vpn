#!/bin/bash

# WireGuard Client Configuration Generator
# Automatically generates client configurations with various options

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Configuration defaults
WG_DIR="${WG_DIR:-/etc/wireguard}"
WG_CONFIG="$WG_DIR/wg0.conf"
CLIENT_DIR="${CLIENT_DIR:-$WG_DIR/clients}"
OUTPUT_DIR="${OUTPUT_DIR:-$CLIENT_DIR}"
SERVER_PORT="${SERVER_PORT:-51820}"
VPN_SUBNET="${VPN_SUBNET:-10.8.0.0/24}"
DNS_SERVERS="${DNS_SERVERS:-1.1.1.1,1.0.0.1}"
KEEPALIVE="${KEEPALIVE:-25}"
LOG_FILE="/var/log/wireguard-client-gen.log"

# Platform-specific settings
declare -A PLATFORM_SETTINGS=(
    [windows]="Windows"
    [macos]="macOS"
    [linux]="Linux"
    [android]="Android"
    [ios]="iOS"
    [router]="Router/Gateway"
)

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

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    command -v wg &> /dev/null || missing_deps+=("wireguard-tools")
    command -v qrencode &> /dev/null || missing_deps+=("qrencode")
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_status "error" "Missing dependencies: ${missing_deps[*]}"
        print_msg "$YELLOW" "Install with: apt install ${missing_deps[*]}"
        exit 1
    fi
}

# Get server public IP
get_server_ip() {
    local ip=$(curl -s -4 --max-time 5 ifconfig.me 2>/dev/null || \
               curl -s -4 --max-time 5 icanhazip.com 2>/dev/null || \
               curl -s -4 --max-time 5 ipecho.net/plain 2>/dev/null)
    
    if [[ -z "$ip" ]]; then
        ip=$(ip -4 addr | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n1)
    fi
    
    echo "$ip"
}

# Get server public key
get_server_pubkey() {
    if [[ -f "$WG_DIR/server_public.key" ]]; then
        cat "$WG_DIR/server_public.key"
    else
        print_status "error" "Server public key not found"
        exit 1
    fi
}

# Get next available IP address
get_next_ip() {
    local last_ip=$(grep -oP 'AllowedIPs = 10\.8\.0\.\K[0-9]+' "$WG_CONFIG" 2>/dev/null | sort -n | tail -1)
    local next_ip=$((${last_ip:-1} + 1))
    
    if [[ $next_ip -gt 254 ]]; then
        print_status "error" "No available IP addresses in subnet"
        exit 1
    fi
    
    echo "$next_ip"
}

# Validate client name
validate_client_name() {
    local name=$1
    
    if [[ -z "$name" ]]; then
        print_status "error" "Client name cannot be empty"
        return 1
    fi
    
    if [[ ! "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        print_status "error" "Client name can only contain letters, numbers, hyphens, and underscores"
        return 1
    fi
    
    if [[ -f "$CLIENT_DIR/${name}.conf" ]]; then
        print_status "error" "Client '$name' already exists"
        return 1
    fi
    
    return 0
}

# Generate client keys
generate_client_keys() {
    local client_name=$1
    local key_dir="$CLIENT_DIR/keys"
    
    mkdir -p "$key_dir"
    chmod 700 "$key_dir"
    
    cd "$key_dir"
    umask 077
    
    # Generate private and public keys
    wg genkey | tee "${client_name}_private.key" | wg pubkey > "${client_name}_public.key"
    
    chmod 600 "${client_name}_private.key"
    chmod 644 "${client_name}_public.key"
    
    print_status "ok" "Keys generated for $client_name"
}

# Create client configuration
create_client_config() {
    local client_name=$1
    local client_ip=$2
    local platform=${3:-generic}
    local split_tunnel=${4:-false}
    
    local client_private=$(cat "$CLIENT_DIR/keys/${client_name}_private.key")
    local server_public=$(get_server_pubkey)
    local server_ip=$(get_server_ip)
    
    # Determine AllowedIPs based on split tunnel setting
    local allowed_ips="0.0.0.0/0, ::/0"
    if [[ "$split_tunnel" == "true" ]]; then
        allowed_ips="$VPN_SUBNET"
    fi
    
    # Create configuration file
    cat > "$CLIENT_DIR/${client_name}.conf" <<EOF
# WireGuard Client Configuration
# Client: $client_name
# Platform: $platform
# Created: $(date)
# IP Address: 10.8.0.$client_ip

[Interface]
# Client private key
PrivateKey = $client_private

# Client IP address in VPN
Address = 10.8.0.$client_ip/32

# DNS servers
DNS = $DNS_SERVERS

# Uncomment to set custom MTU (useful for some networks)
# MTU = 1420

[Peer]
# Server public key
PublicKey = $server_public

# Server endpoint (IP:Port)
Endpoint = $server_ip:$SERVER_PORT

# Allowed IPs (routes through VPN)
AllowedIPs = $allowed_ips

# Keep connection alive through NAT
PersistentKeepalive = $KEEPALIVE
EOF
    
    chmod 600 "$CLIENT_DIR/${client_name}.conf"
    print_status "ok" "Configuration created: ${client_name}.conf"
}

