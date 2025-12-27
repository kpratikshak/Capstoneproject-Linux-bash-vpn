# WireGuard VPN Automation Script with bash and Ubuntu Linux

A bash-based automation tool for deploying and managing WireGuard VPN servers on Ubuntu Linux with user management capabilities.

## Features

- Automated WireGuard server installation and configuration
- User/client management (add, remove, list)
- Automatic firewall configuration (UFW/iptables)
- QR code generation for mobile clients
- Configuration file generation
- IPv4 forwarding setup
- Systemd service management

## Prerequisites

- Ubuntu 20.04 or newer
- Root or sudo access
- Public IP address or domain name

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/wireguard-automation.git
cd wireguard-automation
```

2. Make scripts executable:
```bash
chmod +x *.sh
```

3. Run the installation script:
```bash
sudo ./install.sh
```

## Usage

### Install WireGuard Server
```bash
sudo ./wireguard-setup.sh install
```

### Add a Client
```bash
sudo ./wireguard-setup.sh add-client <client-name>
```

### Remove a Client
```bash
sudo ./wireguard-setup.sh remove-client <client-name>
```

### List All Clients
```bash
sudo ./wireguard-setup.sh list-clients
```

### Show Server Status
```bash
sudo ./wireguard-setup.sh status
```

### Uninstall WireGuard
```bash
sudo ./wireguard-setup.sh uninstall
```

## Configuration

Default configuration is stored in `/etc/wireguard/wg0.conf`

Client configurations are saved to `/etc/wireguard/clients/`

Default settings:
- Server Port: 51820
- Server IP: 10.8.0.1/24
- DNS: 1.1.1.1, 1.0.0.1

## Project Structure

```
wireguard-automation/
├── README.md
├── install.sh              # Initial setup and dependency installation
├── wireguard-setup.sh      # Main VPN management script
├── config/
│   └── defaults.conf       # Default configuration values
└── utils/
    ├── firewall.sh         # Firewall configuration utilities
    └── client-gen.sh       # Client configuration generator
```

## Security Considerations

- All private keys are generated with appropriate permissions (600)
- Configuration directory is protected (700)
- Uses modern cryptography (Curve25519)
- Implements principle of least privilege

## Troubleshooting

**VPN not connecting:**
- Check firewall rules: `sudo ufw status`
- Verify WireGuard is running: `sudo systemctl status wg-quick@wg0`
- Check server logs: `sudo journalctl -u wg-quick@wg0`

**Port already in use:**
- Modify the port in `/etc/wireguard/wg0.conf`
- Update firewall rules accordingly

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - See LICENSE file for details

## Author

(https://github.com/kpratikshak)

## Acknowledgments

- WireGuard project
- Ubuntu Linux community
