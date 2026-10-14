# 🚀 MH Panel - Enterprise Unified VPN, Anti-Censorship Tunnels & MikroTik RouterOS Management Hub

<p align="center">
  <a href="README.md"><b>🇬🇧 English</b></a> |
  <a href="README_FA.md"><b>🇮🇷 فارسی</b></a> |
  <a href="README_RU.md"><b>🇷🇺 Русский</b></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/MH--Panel-v1.0.0-6366f1.svg?style=for-the-badge&logo=shield&logoColor=white" alt="MHPanel Version">
  <img src="https://img.shields.io/badge/Linux-Ubuntu%20%7C%20Debian-orange.svg?style=for-the-badge&logo=linux&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-emerald.svg?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Languages-EN%20%7C%20FA%20%7C%20RU-purple.svg?style=for-the-badge" alt="Languages">
</p>

---

## 📖 Overview

**MH Panel** is an enterprise-grade, highly modular, all-in-one VPN orchestration and anti-censorship infrastructure designed specifically for Linux (Ubuntu 20.04/22.04/24.04 and Debian 11/12). 

It combines a modern, high-performance responsive **Web Dashboard** (Glassmorphism design, Dark/Light modes) and an interactive **Master CLI Management Console** (`mhpanel`), giving system administrators complete autonomy to deploy, monitor, and scale 11+ VPN and proxy protocols, layer-2/layer-3 site-to-site anti-censorship network tunnels, SNI-based port multiplexing on port 443, centralized FreeRADIUS user accounting, and automated MikroTik RouterOS bridge configuration scripts.

---

## ⚡ Quick Installation

Run the master automated installer with `root` privileges on any clean Ubuntu or Debian VPS:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/t-51/MHPanel/main/install.sh)
```

### Alternative Installation via Git Clone:

```bash
git clone https://github.com/t-51/MHPanel.git /www/wwwroot/mhpanel
cd /www/wwwroot/mhpanel
sudo bash install.sh
```

---

## 🧭 Master Interactive CLI Hub (`mhpanel`)

In addition to the Web UI, MH Panel installs a command-line tool accessible server-wide. Simply execute:

```bash
mhpanel
```

```text
  ======================================================================
     🚀 MH PANEL - UNIFIED MASTER CLI MANAGEMENT HUB (v1.0.0)
  ======================================================================
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

## 🌟 Key Architecture & Superpowers

```
                    ┌───────────────────────────────────────────────┐
                    │          Internet / Mobile Operators          │
                    │      (MCI, Irancell, Mokhaberat, Rightel)     │
                    └───────────────────────┬───────────────────────┘
                                            │
                                            ▼
                    ┌───────────────────────────────────────────────┐
                    │      Port 443 HAProxy SNI Multiplexer         │
                    │          (Single Public Port Entry)           │
                    └───┬─────────────┬─────────────┬───────────┬───┘
                        │             │             │           │
        ┌───────────────┘             │             │           └────────────────┐
        ▼                             ▼             ▼                            ▼
┌───────────────┐             ┌───────────────┐ ┌───────────────┐        ┌───────────────┐
│ MH Web Panel  │             │CiscoAnyConnect│ │ Windows SSTP  │        │ SSH TLS WSS   │
│  (:9090 SSL)  │             │ (OCServ 443)  │ │ (sstpd 4443)  │        │ (Stunnel 4444)│
└───────┬───────┘             └───────┬───────┘ └───────┬───────┘        └───────┬───────┘
        │                             │                 │                        │
        └─────────────────────────────┼─────────────────┴────────────────────────┘
                                      ▼
                    ┌───────────────────────────────────────────────┐
                    │           Centralized FreeRADIUS 3            │
                    │  (Unified Auth, Speed, Quota & Expiry Limits) │
                    └───────────────────────────────────────────────┘
```

### 1. 🔀 Port 443 SNI Multiplexing (HAProxy Dispatcher)
Run multiple SSL/TLS services simultaneously over a single public port (443):
- `panel.domain.com` ➔ Dispatched to MH Panel Web Console (Port 9090)
- `vpn.domain.com` ➔ Dispatched to Cisco AnyConnect / OCServ (Port 10443)
- `sstp.domain.com` ➔ Dispatched to Windows SSTP (Port 4443)
- `ssh.domain.com` ➔ Dispatched to SSH TLS Stunnel (Port 4444)
- `ovpn.domain.com` ➔ Dispatched to OpenVPN TCP (Port 1194)
- **Result:** To state-level DPI firewalls, your server behaves identical to an ordinary corporate HTTPS web server.

### 2. 👥 Centralized FreeRADIUS 3 & Mikrotik-Style User Manager
- **Single Account, Multiple Protocols:** One username and password grants access across OpenVPN, Cisco AnyConnect, L2TP, IKEv2, SSTP, SSH, and SOCKS5.
- **Traffic Quotas & Expiration:** Set total gigabyte limits (`Max-Octets`) and account expiration timestamps (`Expiration`).
- **Simultaneous Connection Enforcement:** Limit how many devices can log in concurrently per user (`Simultaneous-Use`).
- **Live Session Termination:** Real-time online user tracker with one-click Packet of Disconnect (PoD / Disconnect-Request) support.

### 3. 🛡️ Advanced Anti-DPI & Anti-Censorship Suite
- **AmneziaWG (AWG):** Obfuscated WireGuard protocol with randomized junk packets (`Jc`, `Jmin`, `Jmax`) and disguised handshakes (`S1`, `S2`, `H1..H4`).
- **OpenVPN Scramble (XOR):** Scrambles packet signatures to neutralize deep packet inspection.
- **UDPspeeder (FEC):** Injects Forward Error Correction packets to eliminate lag, jitter, and packet loss on congested international routes.
- **Rosenpass:** Quantum-resistant symmetric key exchange protocol to protect against future quantum computing decryption attacks.
- **SlowDNS / DNSTT Tunnels:** Bypasses total international internet blackouts using base32-encoded DNS query/TXT record encapsulation.

### 4. 🔗 Multi-Protocol Client Subscription Portal (`/sub/<token>`)
- Each client receives a unique, secret subscription link (`/sub/<token>`).
- Features interactive QR codes, direct one-click config import, `.ovpn` file downloads, and real-time usage meters (traffic used vs. allowed quota, expiry date).
- **JSON API Export:** Provides `/sub/<token>/json` ready for integration with custom Android, iOS, Windows, or macOS client apps.

### 5. 🌍 100% Trilingual Native Localization
- Instant one-click toggle between **English (🇬🇧)**, **Persian / فارسی (🇮🇷)**, and **Russian / Русский (🇷🇺)**.
- Every modal, chart label, notification, terminal output, and technical description is translated natively with zero unlocalized strings.

---

## 📚 Complete Protocols Breakdown

| Protocol | Transport Layer | Client Compatibility | Key Advantage & Use Case |
|---|---|---|---|
| **AmneziaWG (AWG)** | UDP | Windows, Android, iOS, macOS (AmneziaVPN) | **#1 Anti-DPI:** Scrambles handshakes and sends randomized junk packet bursts. Immune to WireGuard blocks. |
| **WireGuard Standard** | UDP (v4 & v6) | All platforms (Official WireGuard) | Highest kernel throughput, dual-stack IPv4/IPv6 address pools, automated MTU/MSS clamping. |
| **Cisco AnyConnect (OCServ)**| SSL/TLS + DTLS | Official Cisco AnyConnect, OpenConnect | Ultra-stable on mobile networks (MCI, Irancell, Rightel). Seamless port 443 multiplexing. |
| **Windows SSTP (sstpd)** | HTTPS / Port 443 | Built-in on Windows 7/10/11 (No app needed) | Standard HTTPS traffic footprint; works natively in Windows without installing third-party apps. |
| **IKEv2 StrongSwan** | IPSec / UDP 500, 4500 | iOS, macOS, Windows, Android (Native) | **Zero-app configuration.** Native OS settings support; instant reconnect during Wi-Fi ↔ 4G/5G handovers (MOBIKE). |
| **L2TP / IPsec** | UDP 1701, 500, 4500 | Legacy OS, MikroTik, Android, Windows | Proven interoperability for legacy routers, embedded systems, and enterprise site-to-site bridges. |
| **OpenVPN Dual-Stack** | Multi-Port TCP & UDP | Official OpenVPN Connect, Tunnelblick | Multi-port listening (443, 1194, 9443), XOR Scramble patch, UDPspeeder FEC, Rosenpass post-quantum encryption. |
| **SSH Direct & WebSocket** | TCP / WSS / Stunnel | PuTTY, Termius, NapsternetV, v2rayNG | Direct hardened SSH + HTTP/WebSocket upgrade tunneling for CDN fronting + BadVPN UDP-GW (Port 7300 for VoIP/Gaming). |
| **TUIC v5** | QUIC (HTTP/3) / UDP | Clash Meta, Sing-box, v2rayNG | 0-RTT handshake eliminates latency; advanced congestion control algorithms (BBR, Cubic). |
| **Shadowsocks (Rust 2022)**| TCP & UDP | Shadowsocks, Clash, Outline, Sing-box | High-speed AEAD ciphers (`2022-blake3-chacha20poly1305`, `2022-blake3-aes-256-gcm`). |
| **MTProto Proxy** | Fake-TLS / TCP | Official Telegram (Desktop, Mobile) | Native Telegram proxy with Fake-TLS domain impersonation (Google/Cloudflare) and `@MTProxybot` sponsor tag. |
| **DNS Tunnels (SlowDNS)** | UDP Port 53 | SlowDNS apps, DNSTT client | Operates over raw DNS requests during total internet shutdowns and strict firewall blackouts. |

---

## 🌐 Network Tunnels & Bridge Hub (Relay / Kharej ↔ Iran)

MH Panel includes a carrier-grade tunneling engine to interconnect domestic (Iran) relay VPS with international (Kharej) endpoints:

| Tunnel Type | Transport | Key Feature & Purpose |
|---|---|---|
| **`IP6GRE`** | Native IPv6 | **Top Censorship Resistance:** GRE tunnel encapsulated in IPv6. Circumvents domestic DPI filters that only inspect IPv4 traffic. |
| **`IP6TNL` (IPIP6)** | Native IPv6 | IPv4 over pure IPv6 transport. Minimal 20-byte header overhead for ultra-low latency. |
| **`SIT` (6in4)** | IPv4 | 6in4 encapsulation carrying IPv6 traffic across legacy IPv4 networks. |
| **`GRE` & `IPIP`** | IPv4 | Standard Linux layer-3 point-to-point tunnels with kernel acceleration. |
| **`WireGuard P2P`** | UDP (v4/v6) | Peer-to-peer encrypted tunnel with dual-stack masquerading. |
| **`GOST v3`** | Multi-Protocol | Versatile relay supporting TLS, WSS, KCP, HTTP2, and multi-hop forwarding chains. |
| **`WSTunnel`** | WebSocket | High-performance TCP/UDP tunneling over WebSockets (Cloudflare CDN friendly). |
| **`Reverse TLS (RTT)`**| TLS Reverse | Initiates connection from international server to domestic server without open inbound ports on the domestic node. |
| **`Chisel & Rathole`** | HTTP / Rust | Ultra-low memory NAT traversal and high-throughput port forwarding. |
| **`Phantun & UDP2Raw`**| Fake TCP | Converts UDP packets into fake TCP SYN/ACK handshakes to bypass aggressive UDP blocking. |

### 📟 Automated MikroTik RouterOS Configuration Generator
For any tunnel created, MH Panel dynamically generates tested, copy-paste-ready scripts for both **RouterOS v7** and **RouterOS v6**:
- Interface initialization (`/interface gre`, `/interface ip6gre`, `/interface wireguard`)
- IP addressing (`/ip address`, `/ipv6 address`)
- Routing tables & default gateways (`/ip route`)
- Firewall NAT Masquerade and MSS Clamping rules (`/ip firewall mangle`, `/ip firewall nat`)

---

## 📡 Live ISP Censorship Radar & Connectivity Analyzer

MH Panel features an integrated **Censorship Radar** that continuously tests live connectivity against major Iranian telecommunication providers:
- **Hamrah Aval (MCI)**
- **Irancell (MTN)**
- **Mokhaberat (TCI)**
- **Shatel**
- **Rightel**
- **System Verdict & Behavioral Analysis:** Evaluates packet loss, DNS tampering, TCP RST injection, and UDP dropping to provide actionable protocol optimization recommendations.

---

## 🔐 Security & Hardening

- **Two-Factor Authentication (2FA / TOTP):** Native RFC 6238 TOTP engine compatible with Google Authenticator and Microsoft Authenticator.
- **SSL Certificate Automation:** Built-in Let's Encrypt client with auto-renewal plus self-signed 10-year IP SAN certificates with downloadable Root CA (`.crt`) for client devices.
- **Zero Sensitive Data in Git:** Private keys, credentials, session secrets, and user databases are protected and excluded via `.gitignore`.
- **Systemd Supervision:** Every background daemon runs under an isolated, supervised systemd unit with automatic crash recovery.
- **Kernel-Level Tuning:** Automated activation of Google BBR congestion control, increased file descriptors (`nofile` 65535), and optimized TCP memory buffers.

---

## 📄 License

This project is licensed under the terms of the [MIT License](LICENSE).
