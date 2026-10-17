# 🚀 MH Panel - Unified Enterprise VPN, Anti-Censorship Tunnels, Sing-box Universal Suite & MikroTik Management Hub

<p align="center">
  <a href="README.md"><b>🇮🇷 فارسی (صفحه اصلی)</b></a> |
  <a href="README_EN.md"><b>🇬🇧 English Documentation</b></a> |
  <a href="README_RU.md"><b>🇷🇺 Русский</b></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/MH--Panel-v1.5.0-6366f1.svg?style=for-the-badge&logo=shield&logoColor=white" alt="MHPanel Version">
  <img src="https://img.shields.io/badge/Platform-Ubuntu%20%7C%20Debian-orange.svg?style=for-the-badge&logo=linux&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-emerald.svg?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Languages-EN%20%7C%20FA%20%7C%20AR%20%7C%20RU-purple.svg?style=for-the-badge" alt="Languages">
</p>

---

## 🌟 What's New in Version 1.5.0

Version **1.5.0** is the most significant and feature-rich release of **MH Panel**, introducing full-mesh tunnel automation, remote multi-node clustering, real-time Anti-DPI health probing, a complete **Sing-box Universal Protocol Suite**, and official Arabic localization:

### 1. 🚀 1-Click Full Mesh Tunnel Deployer
- **Simultaneous Deployment of All Tunnels:** Establish every supported tunnel between source and destination servers in a single click—no manual, one-by-one setup required!
- **Complete Tunnel Engine Coverage:**
  - **Linux Kernel L2/L3 Tunnels:** IPIP, SIT (6in4), GRE, GRETAP, IP6GRE, IP6GRETAP, WireGuard, AmneziaWG (with header obfuscation), OpenVPN static secret, VXLAN, and GENEVE.
  - **Anti-DPI Tunnels:** GOST, WSTunnel (WebSocket + TLS), Rathole (high-performance Rust), Chisel, and Sing-box Tun.
- **Smart Subnet Allocation & Keypair Generation:** Automatically generates collision-free internal subnets (`10.x.x.x/30`), WireGuard private/public keys, and OpenVPN static secrets.
- **Automated Remote SSH Execution:** Automatically executes configuration commands on the destination server via SSH with real-time progress reporting.

---

### 2. ⚡ Anti-DPI Tunnels Real-Time Latency & Health Probe
- **Live Socket & Handshake Health Check:** Instant millisecond latency and reachability probing for GOST, WSTunnel, Rathole, Chisel, and Sing-box tunnels.
- **Batch Probe Button («⚡ Probe All Anti-DPI Tunnels»):** Test all active Anti-DPI tunnels concurrently with live status updates.
- **Dynamic Visual Badges:** Green glowing badges displaying exact RTT in milliseconds when reachable, and red warning badges when unreachable or blocked by DPI firewalls.

---

### 3. 🛠️ Tunnel Engines & Binaries Manager
- **Visual Status Dashboard:** A dedicated management view under the Tunnels tab displaying installation status, binary paths, and versions for over **20 tunnel engines and tools**:
  - `sing-box`, `gost`, `wstunnel`, `rathole`, `chisel`, `hysteria`, `tuic-server`, `tun2socks`, `rtt`, `dnstt-server`, `dnstt-client`, `vaydns-server`, `vaydns-client`, `slipstream-server`, `udp2raw`, `badvpn-udpgw`, `ssserver`, `stuntls-server`, `noizdns-server`, `masterdnsvpn-server`.
- **1-Click Binary Installer & Updater:** Install or upgrade any missing binary directly from the panel with a single click.

---

### 4. 🌐 Remote Node Auto-Provisioning & Multi-Node Cluster
- **Central Master / Subordinate Node Architecture:** Manage multiple distributed servers from a central master panel while preserving full local independence on each node.
- **1-Click Remote Provisioning via SSH:** Provide destination server credentials (IP, SSH Port, User, Password) to automatically bootstrap and install MH Panel remotely.
- **Live Telemetry & Direct Access:** Real-time ping, uptime status, installation detection, and 1-click single-sign-on access to the web dashboard of any subordinate node.

---

### 5. 🎛️ Sing-box Universal Protocol Studio
- **Dedicated Sing-box Management Tab:** Full-fledged visual configuration studio for **Sing-box 1.9.x** core.
- **Exhaustive Protocol Suite with All Configurable Parameters:**
  - **VLESS Reality:** Full Reality support, 1-click X25519 keypair generation, Short ID randomization, Dest / ServerNames simulation, uTLS profile selection, and Flow control.
  - **VMess:** Multi-client UUID management, cipher selection (`auto`, `aes-128-gcm`, `chacha20-poly1305`, `none`), and legacy compatibility.
  - **Trojan:** Multi-user passwords, TCP/WS/gRPC transports, and native SSL certificate binding.
  - **Hysteria 2:** High-speed UDP-based transport, port hopping ranges, Brutal congestion control, and password auth.
  - **TUIC v5:** QUIC-native transport with UUID/token authentication and congestion control.
  - **Shadowsocks:** Modern Shadowsocks 2022 AEAD methods (`2022-blake3-aes-128-gcm`, `2022-blake3-chacha20-poly1305`, `chacha20-ietf-poly1305`).
  - **ShadowTLS:** Full TLS handshake masquerading with external server SNI.
  - **Direct, Mixed (SOCKS5/HTTP), and Tun:** Built-in core inbound interfaces.
- **1-Click Keypair & Password Generator:** Instant generation of Reality X25519 keys, Short IDs, and secure secrets.
- **Multi-Format Share Links & Dynamic QR Codes:** Instant client configuration export (`vless://`, `vmess://`, `trojan://`, `hysteria2://`, `tuic://`, `ss://`) with live QR codes compatible with v2rayN, v2rayNG, Sing-box, Nekoray, Clash Verge, Karing, and Shadowrocket.
- **Live JSON Editor with Syntax Validation:** Built-in JSON editor for `/etc/sing-box/config.json` with pre-flight configuration validation before restarting the daemon.
- **Dedicated Systemd Service:** Managed via `mhpanel-singbox.service`.

---

### 6. 🌍 Full Arabic Localization (`ar` - العربية)
- **Comprehensive Translation:** Over **3,100 technical networking, VPN, and server management terms** professionally translated into Arabic.
- **Full Right-to-Left (RTL) Layout:** Native `dir="rtl"` support across all header, sidebar, dashboard cards, modals, tables, and form controls.
- **Pan-Arab Language Selector:** Instant language switching with dedicated flags in the desktop header and mobile drawer.

---

## ⚡ One-Line Installation

Execute the following command with `root` privileges on any Ubuntu (20.04/22.04/24.04) or Debian (11/12) server:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/t-51/MHPanel/main/install.sh)
```

### Alternative Installation via Git Clone:

```bash
git clone https://github.com/t-51/MHPanel.git /www/wwwroot/mhpanel
cd /www/wwwroot/mhpanel
sudo bash install.sh
```

Upon installation, your credentials and URL will be displayed:
```text
=================================================
🌐 Web Panel URL:  https://YOUR_SERVER_IP:9090
👤 Admin Username: admin
🔑 Admin Password: [Generated Secure Password]
🔑 Public API Key: [Generated API Token]
=================================================
```

---

## 🧭 Interactive CLI Console (`mhpanel`)

Access the comprehensive server command-line management menu at any time by typing:

```bash
mhpanel
```

---

## 🛡️ Supported Protocols & Technologies

| Category | Protocols & Services |
| :--- | :--- |
| **Sing-box Core Suite** | VLESS Reality, VMess, Trojan, Hysteria 2, TUIC v5, Shadowsocks 2022, ShadowTLS, Direct, Tun |
| **Traditional VPN** | OpenVPN (TCP/UDP/XOR), WireGuard, AmneziaWG, OCserv (Cisco AnyConnect), IKEv2, SSTP, PPTP, L2TP/IPsec |
| **Anti-Censorship Proxies** | Shadowsocks-rust, TUIC, Hysteria 2, Trojan-GFW, StunTLS, NaiveProxy, SOCKS5, HTTP Proxy, MTProto Proxy |
| **DNS Tunneling (SlowDNS)** | DNSTT (Noise Curve25519), VayDNS, Slipstream, NoizDNS, MasterdnsVPN |
| **Anonymity Networks** | Tor Bridges (Snowflake, obfs4, WebTunnel) |
| **Server-to-Server Tunnels** | IPIP, GRE, GRETAP, IP6GRE, IP6GRETAP, VXLAN, GENEVE, SIT (6in4), WireGuard S2S, AmneziaWG S2S, OpenVPN P2P |
| **Anti-DPI Tunnels** | GOST (WebSocket/TLS/QUIC), WSTunnel, Rathole (Rust), Chisel, Sing-box Tun |
| **Accounting & Networking** | FreeRADIUS + SQLite, MikroTik RouterOS v6/v7 Script Generator, BadVPN UDP-GW (Port 7300), Fail2ban, UFW |

---

## 📄 License

This project is licensed under the **MIT License**.
