# WireGuard VPN Default Configuration
# Edit these values to customize your VPN setup

# Server Configuration
SERVER_PORT=51820
SERVER_SUBNET="10.8.0.0/24"
SERVER_IP="10.8.0.1"

# DNS Configuration
# Use Cloudflare DNS by default
PRIMARY_DNS="1.1.1.1"
SECONDARY_DNS="1.0.0.1"
# Alternative options:
# Google DNS: 8.8.8.8, 8.8.4.4
# Quad9: 9.9.9.9, 149.112.112.112

# Network Interface
# Leave empty for auto-detection
NETWORK_INTERFACE=""

# Client Configuration
# Starting IP for client allocation
CLIENT_START_IP=2

# Keepalive interval (seconds)
# Helps maintain connection through NAT
KEEPALIVE_INTERVAL=25

# Security Settings
# Key permissions
KEY_PERMISSIONS=600
DIR_PERMISSIONS=700

# Logging
ENABLE_LOGGING=true
LOG_FILE="/var/log/wireguard-setup.log"

# Backup
ENABLE_BACKUP=true
BACKUP_DIR="/var/backups/wireguard"

# Performance Tuning
# MTU size (usually 1420 for WireGuard)
MTU=1420

# Maximum number of clients
MAX_CLIENTS=254
