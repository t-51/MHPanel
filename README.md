# MH Panel - Unified VPN, Tunnel & MikroTik RouterOS Management Hub

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-brightgreen.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-orange.svg)](https://ubuntu.com/)

**MH Panel** is a powerful, production-ready server management system and web dashboard designed for managing enterprise VPN protocols, high-speed anti-censorship network tunnels, dual-stack IPv4/IPv6 bridges, and automated MikroTik RouterOS integrations.

---

## 🚀 Key Features

### 🌐 High-Speed Network Tunnels & Bridges
- **Dual-Stack IPv4 & IPv6 Tunnels**:
  - `IP6GRE` (IPv6 Generic Routing Encapsulation)
  - `IP6TNL` / `IPIP6` (IPv4 encapsulated over native IPv6)
  - `SIT` / 6in4 (IPv6 traffic over IPv4 networks)
  - Standard `GRE` & `IPIP` tunnels
  - `WireGuard P2P` with full IPv6 dual-stack endpoint routing and MSS clamping
- **Anti-Censorship & Obfuscation Tunnels**:
  - **GOST v3**: Multi-protocol tunneling (Relay, TLS, WSS, KCP, Multi-hop forwarding)
  - **WSTunnel**: WebSocket tunneling for TCP and UDP bypassing deep packet inspection
  - **ReverseTlsTunnel (RTT)**: High-speed TLS reverse tunneling
  - **Chisel**: Fast TCP/UDP tunnel over HTTP/WebSocket
  - **Rathole**: Lightweight and secure NAT traversal written in Rust
  - **Phantun**: Turns UDP streams into obfuscated TCP-like connections
  - **Kcptun**: UDP-based tunnel with forward error correction (FEC)
  - **UDP2Raw**: Bypasses UDP throttling and firewalls via fake TCP handshakes
  - **FRP**: High-performance reverse proxy (FRPS / FRPC)
- **MikroTik RouterOS Integration**:
  - One-click configuration script generator for both **RouterOS v7** and **RouterOS v6**
  - Automated interfaces, `/ip/address`, `/ipv6/address`, `/ip/route`, `/ipv6/route`, and firewall NAT masquerading rules

### 🛡️ Enterprise VPN Protocols
- **WireGuard & AmneziaWG**: High-throughput P2P VPN with DPI-resistant junk packet obfuscation (Jc, Jmin, Jmax, S1, S2, H1..H4).
- **OpenVPN**: UDP & TCP dual mode, multi-port listening, XOR scramble patch, and UDPspeeder integration.
- **Cisco AnyConnect / OCServ**: Enterprise SSL VPN compatible with Cisco AnyConnect and OpenConnect clients.
- **IKEv2 StrongSwan & L2TP/IPsec**: Native OS clients support (iOS, Android, macOS, Windows).
- **Windows SSTP (sstpd)**: Native MS-SSTP SSL VPN for Windows clients.
- **TUIC v5**: High-speed proxy built on top of QUIC / 0-RTT.
- **Shadowsocks (AEAD)**: Modern obfuscated proxying.
- **BadVPN UDPGW**: Port 7300 UDP forwarder for ultra-low latency gaming and VoIP calls.

### 💻 Modern Web UI & Dashboard
- Real-time CPU, RAM, disk, and live bandwidth analytics.
- Client account management, expiry date scheduling, traffic quotas, and QR codes.
- Port 443 multiplexing (HAProxy SNI routing for Web, OCServ, SSH, OpenVPN, SSTP).
- Built-in Let's Encrypt SSL and 10-Year IP SAN SSL certificate generation.
- Bilingual interface (English & Persian) with responsive mobile layout.

---

## 📦 One-Line Installation

Execute the master installer on your Ubuntu or Debian VPS as **root**:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/t-51/MHPanel/main/install.sh)
```

### Alternatively, Install via Git Clone:

```bash
git clone https://github.com/t-51/MHPanel.git /www/wwwroot/mhpanel
cd /www/wwwroot/mhpanel
sudo bash install.sh
```

---

## ⚡ CLI Management Hub (`mhpanel`)

Once installed, you can call the interactive management CLI at any time from anywhere in your terminal by typing:

```bash
mhpanel
```
*(Alias: `hmpanel`)*

### CLI Options:
```text
  [1]  Run Full Automated Installation (Setup All Missing Components)
  [2]  Run Step-by-Step Custom Installation Wizard
  [3]  Install Lightweight Web UI Only
  [4]  Live System & Service Diagnostic Report
  [5]  Manage, Install, Uninstall & Reconfigure VPN Protocols
  [6]  Anti-Censorship Tunnels & MikroTik RouterOS Bridge Hub
  [7]  Web Dashboard Settings (Credentials, Port, Logs & Restart)
  [8]  SSL Certificate Management (Let's Encrypt & IP SAN)
  [9]  Network & Kernel Optimization (BBR, IPv4/IPv6 Forwarding)
  [10] Backup & Restore Panel Configurations
  [11] Update Script & Panel
  [0]  Exit
```

---

## 🖥️ Web Access

- **Dashboard URL**: `https://YOUR_SERVER_IP:9090`
- **Default Username**: `admin`
- **Default Password**: Printed at the conclusion of installation (or retrieved via `mhpanel` -> Option 7).

---

## ⚙️ System Requirements

| Specification | Minimum | Recommended |
|---|---|---|
| **OS** | Ubuntu 20.04+, 22.04+, 24.04+ \| Debian 11, 12 | Ubuntu 22.04 / 24.04 LTS |
| **CPU** | 1 Core (x86_64 / arm64) | 2+ Cores |
| **RAM** | 1 GB | 2 GB+ |
| **Storage** | 10 GB SSD | 20 GB+ SSD |
| **Permissions** | Root access | Root access |

---

## 🔒 Security Best Practices

- Live credentials (`admin_credentials.txt`), API keys (`api_key.txt`), and user JSON databases are automatically created during setup and are excluded from Git via `.gitignore`.
- Firewall rules (UFW/iptables) are automatically applied for each configured protocol and port.
- Dual-stack IPv4 and IPv6 masquerading and MSS clamping prevent packet fragmentation on mobile networks.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
