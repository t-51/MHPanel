# 🚀 MH Panel - Unified VPN, Tunnel & MikroTik RouterOS Management Hub

[English Documentation](README.md) | [مستندات فارسی](README_FA.md)

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-brightgreen.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-orange.svg)](https://ubuntu.com/)

**MH Panel** is an enterprise-grade, intelligent, and modular server management system engineered for Linux (Ubuntu & Debian). It provides a sleek, responsive Web Dashboard and an all-in-one Management CLI (`mhpanel`) designed to orchestrate modern VPN protocols, dual-stack anti-censorship network tunnels (IPv4 & IPv6), Port 443 SNI multiplexing, and automated MikroTik RouterOS bridging (v6 & v7).

---

## ⚡ One-Line Quick Installation

Run the master installer on your Ubuntu or Debian VPS as **root**:

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

## 🧭 Master CLI Management Hub (`mhpanel`)

Once installed, simply type **`mhpanel`** (or `hmpanel`) anywhere in your server's terminal to access the full-featured interactive management hub:

```text
  [1]  Run Full Automated Installation (Setup All Missing Components)
  [2]  Run Step-by-Step Custom Installation Wizard
  [3]  Install Lightweight Web UI Only
  ----------------------------------------------------------------------
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

## 📚 Deep Dive: Supported VPN Protocols

MH Panel integrates industry-leading VPN technologies optimized for extreme censorship evasion, low latency, and zero-client setup across all client platforms:

### 1. AmneziaWG (AWG) - Anti-DPI Obfuscated WireGuard
- **Mechanism:** A modified WireGuard implementation that introduces junk packet delivery (`Jc`, `Jmin`, `Jmax`) and protocol handshake obfuscation (`S1`, `S2`, `H1..H4`).
- **Advantage:** Deep Packet Inspection (DPI) systems can instantly detect and block standard WireGuard handshakes. AmneziaWG scrambles packet headers and injects randomized noise, rendering the traffic indistinguishable from random noise or HTTPS traffic.
- **Client Support:** Official AmneziaVPN app on Windows, Android, iOS, and macOS.
- **Performance:** Kernel-level high throughput with minimal CPU overhead.

### 2. WireGuard Standard (IPv4 & IPv6 Dual-Stack)
- **Mechanism:** State-of-the-art cryptographic tunnel using Noise protocol framework, Curve25519, and ChaCha20-Poly1305.
- **Features in MH Panel:** Dual-stack IPv4/IPv6 internal address assignment, automated MSS Clamping for mobile networks, and seamless peering with MikroTik RouterOS v7.

### 3. OpenVPN (Multi-Port, XOR Scramble & UDPspeeder)
- **Multi-Port Listening:** Run OpenVPN across multiple TCP and UDP ports simultaneously (e.g., 443, 1194, 9443) to bypass ISP-level port throttles.
- **XOR Scramble Patch (Tunnelblick):** Masks OpenVPN headers with a custom symmetric XOR key to defeat DPI fingerprinting.
- **UDPspeeder Integration:** Deploys Forward Error Correction (FEC) over lossy international links, reconstructing dropped packets without retransmission delay to maintain stable ping.

### 4. Cisco AnyConnect / OCServ (OpenConnect)
- **Mechanism:** Enterprise SSL/DTLS VPN protocol running over TCP and UDP.
- **Advantage:** Extremely resilient against restrictive firewalls and mobile network throttling (MCI, Irancell, Rightel).
- **Client Support:** Supported out of the box by official **Cisco AnyConnect / Cisco Secure Client** and OpenConnect across Windows, macOS, iOS, Android, and Linux.
- **SNI Multiplexing:** Can share port 443 alongside the web server.

### 5. IKEv2 StrongSwan (IPSec)
- **Mechanism:** High-speed, kernel-level IPSec protocol with MOBIKE support.
- **Advantage:** **Zero third-party apps required.** Native configuration on iOS, macOS, Windows, and Android settings.
- Highly resilient when switching between Wi-Fi and mobile data roaming.

### 6. L2TP/IPsec
- **Mechanism:** Layer 2 Tunneling Protocol secured with IPsec Pre-Shared Keys (PSK).
- **Use Cases:** Legacy devices, routers, and site-to-site bridges with MikroTik hardware.

### 7. Windows SSTP (sstpd)
- **Mechanism:** Microsoft Secure Socket Tunneling Protocol transporting PPP traffic over TLS 1.2/1.3.
- **Advantage:** **Built into Windows 7, 10, and 11 by default.** Requires no external software; appears as regular HTTPS web traffic to external firewalls.

### 8. SSH Tunnel (Direct & TLS WebSocket) + BadVPN
- **SSH Direct:** Hardened Linux SSH tunneling with public key or password authentication.
- **WebSocket / Stunnel Proxy:** Wraps SSH within HTTP WebSocket upgrade requests, enabling Cloudflare/CDN routing and SNI fronting.
- **BadVPN UDP-GW (Port 7300):** Enables UDP packet translation for TCP-based SSH connections, unlocking WhatsApp/Discord voice calls and low-latency online gaming.

### 9. TUIC v5 (QUIC 0-RTT)
- **Mechanism:** Next-generation proxy protocol built on top of QUIC (HTTP/3) over UDP.
- **Advantage:** 0-RTT handshakes eliminate round-trip latency, providing instant page load times and resilience against packet loss.

### 10. Shadowsocks (AEAD 2022)
- Lightweight encrypted SOCKS5 proxy leveraging ChaCha20-Poly1305 and AES-256-GCM ciphers.

### 11. MTProto Proxy (Telegram)
- Dedicated Telegram proxy protocol featuring Fake-TLS emulation (mimicking trusted domains like Google or Cloudflare) and secret hex tagging for promotional sponsor channels.

---

## 🌐 Network Tunnels (Bridge & Relay Hub)

MH Panel includes a complete suite of tunneling solutions for bridging Iran ↔ Kharej servers:

| Tunnel Type | Transport | Key Feature & Use Case |
|---|---|---|
| **`IP6GRE`** | Native IPv6 | **Top Censorship Resistance:** GRE tunnel encapsulated in IPv6. Circumvents domestic DPI filters that only inspect IPv4 traffic. |
| **`IP6TNL` (IPIP6)** | Native IPv6 | IPv4 over pure IPv6 transport. Minimal 20-byte header overhead for lowest ping. |
| **`SIT` (6in4)** | IPv4 | 6in4 encapsulation carrying IPv6 traffic across legacy IPv4 networks. |
| **`GRE` & `IPIP`** | IPv4 | Standard Linux layer 3 point-to-point tunnels. |
| **`WireGuard P2P`** | UDP (v4/v6) | Peer-to-peer modern encrypted tunnel with dual-stack masquerade. |
| **`GOST v3`** | Multi-protocol | Swiss-army knife tunnel (Relay, TLS, WSS, KCP, Multi-Hop forwarding). |
| **`WSTunnel`** | WebSocket | High-performance TCP/UDP tunneling over WebSockets. |
| **`Reverse TLS (RTT)`** | TLS Reverse | Establishes tunnel from Kharej into Iran without requiring open inbound ports on Iran VPS. |
| **`Chisel & Rathole`** | HTTP / Rust | Lightweight NAT traversal and fast reverse port forwarding. |
| **`Phantun & UDP2Raw`** | Fake TCP | Converts UDP packets into fake TCP SYN/ACK handshakes to bypass aggressive UDP blocking. |

### 📟 Automated MikroTik RouterOS Script Generator
For every configured tunnel, MH Panel instantly generates ready-to-run terminal scripts tailored for both **RouterOS v7** and **RouterOS v6**:
- Tunnel interface creation (`/interface/gre`, `ip6gre`, `ipip`, `wireguard`)
- Local and remote IP configuration (`/ip/address` and `/ipv6/address`)
- Static routing (`/ip/route`)
- Firewall NAT Masquerading and MSS Clamping rules

---

## 🔀 Port 443 SNI Multiplexer (HAProxy Dispatcher)

Host multiple SSL services on a single public IP address through Server Name Indication (SNI) routing:
- `panel.yourdomain.com` ⬅️ Routed to MH Panel Web UI
- `vpn.yourdomain.com` ⬅️ Routed to Cisco AnyConnect (OCServ)
- `ssh.yourdomain.com` ⬅️ Routed to SSH TLS / Stunnel
- `ovpn.yourdomain.com` ⬅️ Routed to OpenVPN TCP
- `sstp.yourdomain.com` ⬅️ Routed to Windows SSTP
- All services coexist seamlessly behind port 443, making traffic indistinguishable from typical HTTPS web traffic.

---

## 🔒 Security & Privacy

- **Zero Credentials Committed:** Sensitive files (`admin_credentials.txt`, `api_key.txt`, `session_secret.txt`), user accounts (`*_users.json`), and private keys are strictly ignored via [`.gitignore`](.gitignore).
- **Service Isolation:** All daemons are managed via dedicated Systemd unit files with automatic restart policies.
- **Firewall Hardening:** Automatic iptables and UFW port configuration for all active protocols.

---

## 📄 License

This software is released under the [MIT License](LICENSE).
