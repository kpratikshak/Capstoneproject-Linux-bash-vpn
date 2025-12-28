#!/usr/bin/env bash
# WireGuard Firewall Manager

set -Eeuo pipefail

############################################
# COLORS
############################################
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

############################################
# CONFIG
############################################
WG_PORT="${WG_PORT:-51820}"
WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_SUBNET="${WG_SUBNET:-10.8.0.0/24}"
LOG_FILE="/var/log/wireguard-firewall.log"

############################################
# LOGGING
############################################
log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG_FILE"; }

status() {
  local level="$1"; shift
  local sym color
  case "$level" in
    ok) sym="✓"; color="$GREEN";;
    warn) sym="⚠"; color="$YELLOW";;
    error) sym="✗"; color="$RED";;
    info) sym="ℹ"; color="$BLUE";;
  esac
  echo -e "${color}${sym} $*${NC}"
  log "$level: $*"
}

############################################
# SAFETY
############################################
trap 'status error "Script failed at line $LINENO"' ERR

if (( EUID != 0 )); then
  status error "Must run as root"
  exit 1
fi

touch "$LOG_FILE" || true

############################################
# DETECTION HELPERS
############################################
get_default_iface() {
  ip route | awk '/default/ {print $5; exit}'
}

detect_distro() {
  if command -v apt-get >/dev/null 2>&1; then echo "debian"
  elif command -v dnf >/dev/null 2>&1; then echo "rhel"
  elif command -v yum >/dev/null 2>&1; then echo "rhel"
  else echo "unknown"
  fi
}

detect_firewall() {
  if command -v nft >/dev/null 2>&1; then echo "nftables" && return
  if command -v firewall-cmd >/dev/null 2>&1; then echo "firewalld" && return
  if command -v ufw >/dev/null 2>&1 && ufw status >/dev/null 2>&1; then echo "ufw" && return
  if command -v iptables >/dev/null 2>&1; then echo "iptables" && return
  echo "none"
}

############################################
# SYSTEM REQUIREMENTS
############################################
install_tools() {
  case "$(detect_distro)" in
    debian)
      apt-get update -qq
      apt-get install -y iptables ufw netfilter-persistent > /dev/null
      ;;
    rhel)
      dnf install -y iptables-services firewalld > /dev/null || yum install -y iptables-services firewalld
      ;;
    *)
      status warn "Unknown distro - skipping package install"
      ;;
  esac
}

############################################
# KERNEL FORWARDING
############################################
enable_forwarding() {
  sysctl -w net.ipv4.ip_forward=1 > /dev/null
  grep -q '^net.ipv4.ip_forward' /etc/sysctl.conf \
    && sed -i 's/^net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf \
    || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

  if sysctl -a 2>/dev/null | grep -q net.ipv6.conf.all.forwarding; then
    sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null || true
  fi

  status ok "IP forwarding enabled"
}

############################################
# UFW
############################################
configure_ufw() {
  local iface
  iface="$(get_default_iface)"

  ufw allow "${WG_PORT}/udp" comment "WireGuard VPN" || true
  ufw allow ssh || true

  local ufw_before="/etc/ufw/before.rules"
  cp "$ufw_before" "${ufw_before}.bak-$(date +%s)" || true

  if ! grep -q "WireGuard VPN" "$ufw_before"; then
cat >> "$ufw_before" <<EOF

# WireGuard VPN
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s $WG_SUBNET -o $iface -j MASQUERADE
COMMIT
EOF
  fi

  ufw --force enable || true
  status ok "UFW configured"
}

############################################
# FIREWALLD
############################################
configure_firewalld() {
  firewall-cmd --add-port="${WG_PORT}/udp" --permanent
  firewall-cmd --add-masquerade --permanent
  firewall-cmd --reload
  status ok "Firewalld configured"
}

############################################
# IPTABLES
############################################
configure_iptables() {
  local iface
  iface="$(get_default_iface)"

  iptables -C INPUT -p udp --dport "$WG_PORT" -j ACCEPT 2>/dev/null || \
  iptables -A INPUT -p udp --dport "$WG_PORT" -j ACCEPT

  iptables -C FORWARD -i "$WG_INTERFACE" -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i "$WG_INTERFACE" -j ACCEPT

  iptables -t nat -C POSTROUTING -s "$WG_SUBNET" -o "$iface" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s "$WG_SUBNET" -o "$iface" -j MASQUERADE

  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save
  elif command -v service >/dev/null 2>&1; then
    service iptables save || true
  fi

  status ok "iptables configured"
}

############################################
# NFTABLES
############################################
configure_nft() {
  local iface
  iface="$(get_default_iface)"

  nft add table inet wg 2>/dev/null || true
  nft add chain inet wg input { type filter hook input priority 0 \; } 2>/dev/null || true
  nft add rule inet wg input udp dport "$WG_PORT" accept

  nft add chain inet wg post { type nat hook postrouting priority 100 \; } 2>/dev/null || true
  nft add rule inet wg post ip saddr "$WG_SUBNET" oif "$iface" masquerade

  status ok "nftables configured"
}

############################################
# STATUS
############################################
show_status() {
  local fw
  fw="$(detect_firewall)"
  status info "Firewall: $fw"
  status info "Interface: $WG_INTERFACE"
  status info "Subnet: $WG_SUBNET"

  sysctl net.ipv4.ip_forward
}

############################################
# REMOVE
############################################
remove_rules() {
  case "$(detect_firewall)" in
    ufw)
      ufw delete allow "${WG_PORT}/udp" || true
      ;;
    firewalld)
      firewall-cmd --remove-port="${WG_PORT}/udp" --permanent
      firewall-cmd --reload
      ;;
    iptables)
      iptables -D INPUT -p udp --dport "$WG_PORT" -j ACCEPT || true
      ;;
  esac
  status ok "Rules removed"
}

############################################
# MAIN
############################################
case "${1:-}" in
  setup)
    install_tools
    enable_forwarding
    case "$(detect_firewall)" in
      ufw) configure_ufw ;;
      firewalld) configure_firewalld ;;
      nftables) configure_nft ;;
      iptables) configure_iptables ;;
      none)
        status warn "No firewall detected, installing base iptables"
        install_tools
        configure_iptables
        ;;
    esac
    ;;
  status)
    show_status
    ;;
  remove)
    remove_rules
    ;;
  enable-forwarding)
    enable_forwarding
    ;;
  *)
    echo -e "${GREEN}WireGuard Firewall Manager${NC}"
    echo "Usage: $0 {setup|status|remove|enable-forwarding}"
    exit 1
    ;;
esac
