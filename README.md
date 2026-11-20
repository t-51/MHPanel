# 🚀 MH Panel - Enterprise Unified VPN, Anti-Censorship Tunnels, Sing-box Universal Suite & MikroTik Management Hub

<p align="center">
  <a href="README.md"><b>🇬🇧 English</b></a> |
  <a href="README_FA.md"><b>🇮🇷 فارسی</b></a> |
  <a href="README_RU.md"><b>🇷🇺 Русский</b></a> |
  <a href="README_AR.md"><b>🇸🇦 العربية</b></a> |
  <a href="README_IT.md"><b>🇮🇹 Italiano</b></a> |
  <a href="README_ES.md"><b>🇪🇸 Español</b></a> |
  <a href="README_ZH.md"><b>🇨🇳 简体中文</b></a> |
  <a href="README_DE.md"><b>🇩🇪 Deutsch</b></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/MH--Panel-v1.7.0-6366f1.svg?style=for-the-badge&logo=shield&logoColor=white" alt="MHPanel Version">
  <img src="https://img.shields.io/badge/Platform-Ubuntu%2020%2B%20%7C%20Debian%2011%2B-orange.svg?style=for-the-badge&logo=linux&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python Version">
  <img src="https://img.shields.io/badge/Core-Sing--box%20%2B%20Linux%20Kernel%20L2%2FL3-emerald.svg?style=for-the-badge" alt="Core">
  <img src="https://img.shields.io/badge/Theme-Light%20%26%20Dark%20Elegance-amber.svg?style=for-the-badge&logo=sparkles&logoColor=white" alt="Theme">
  <img src="https://img.shields.io/badge/Languages-8%20Native%20Locales-purple.svg?style=for-the-badge" alt="Languages">
  <img src="https://img.shields.io/badge/License-MIT-teal.svg?style=for-the-badge" alt="License">
</p>

---

## ⚡ Instant 1-Line Installation (Quick Start)

Deploy **MH Panel** in under 60 seconds with full automated dependency management, kernel module optimization, SSL provisioning, and systemd service orchestration:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/t-51/MHPanel/main/install.sh)
```

> [!TIP]
> **System Requirements:**
> - **Operating Systems:** Ubuntu 24.04 LTS, Ubuntu 22.04 LTS, Ubuntu 20.04 LTS, Debian 12 (Bookworm), Debian 11 (Bullseye)
> - **Hardware Specs:** Minimum 1 vCPU, 1 GB RAM, 10 GB Disk space
> - **Privileges:** Root user access (`sudo -i` or `su -`)

<details>
<summary><b>📦 Alternative: Manual Installation via Git</b></summary>

```bash
# Clone the repository
git clone https://github.com/t-51/MHPanel.git /www/wwwroot/mhpanel

# Enter directory and run installer
cd /www/wwwroot/mhpanel
sudo bash install.sh
```

Upon completion, your terminal displays your unique Web GUI URL, administrator credentials, API key, and port information.
</details>

---

## 📡 Universal Smart Subscription Engine (All 23 Configs in 1 Link)

MH Panel features an intelligent subscription engine capable of delivering all 23 Sing-box protocol configurations + SSH tunneling credentials inside a **single unified subscription link**:

### 🎯 Optimized For All Modern VPN Clients:
- **SlipNet** (Full auto-import, DoH scanner, Bridge QR parsing)
- **v2rayNG** / **v2rayN** (Base64 standard multi-config import)
- **Hiddify** / **NekoBox** (Sing-box native protocol support)
- **Streisand** / **Shadowrocket** / **Clash Meta**

### 🔗 Smart Subscription Formats & Endpoints:
| Link Type | URL Endpoint | Description |
|---|---|---|
| **Universal Base64** | `https://<DOMAIN>:<PORT>/sub/<TOKEN>/b64` | Standard Base64 delivering all 23 protocol inbounds + SSH configs for SlipNet, v2rayNG, and Hiddify. |
| **Sing-box Profile JSON** | `https://<DOMAIN>:<PORT>/sub/<TOKEN>/singbox.json` | Native JSON configuration profile with complete routing rules for official Sing-box clients. |
| **Fragment / Cloud IP** | `https://<DOMAIN>:<PORT>/sub/<TOKEN>/singbox-fragment.json` | Optimized configs with TLS SNI fragmentation to bypass aggressive SNI filtering. |
| **Client Web Portal** | `https://<DOMAIN>:<PORT>/sub/<TOKEN>` | Interactive web portal showing live traffic consumption, expiry date, raw URIs, and universal All-in-One QR code. |

> [!NOTE]
> In the panel's user table, simply click **`[📡 لینک ساب / Copy Sub]`** to copy the client's universal subscription link directly to your clipboard with 1 click.

---

## 📑 Table of Contents

- [⚡ Instant 1-Line Installation](#-instant-1-line-installation-quick-start)
- [📡 Universal Smart Subscription Engine](#-universal-smart-subscription-engine-all-23-configs-in-1-link)
- [🌟 What's New in Version 1.7.0](#-whats-new-in-version-170)
- [📸 Panel Visual Tour (Light Theme Gallery)](#-panel-visual-tour-light-theme-gallery)
- [📐 Visual Architecture & Traffic Flow Pipelines](#-visual-architecture--traffic-flow-pipelines)
  - [1. Universal Multi-Protocol Port 443 Sharing](#1-universal-multi-protocol-port-443-sharing-architecture)
  - [2. Google Apps Script Full-Tunnel Proxy](#2-google-apps-script-full-tunnel-proxy-pipeline)
  - [3. Anti-DPI WordPress Decoy Site](#3-anti-dpi-wordpress-decoy-site-vs-active-probers)
  - [4. Telegram Bot Alert Engine & Automated Backup Dispatch](#4-telegram-bot-alert-engine--automated-backup-dispatch)
  - [5. First-Connect Triggered Accounting Lifecycle](#5-sing-box-first-connect-triggered-accounting-lifecycle)
- [📚 Supported Protocols & Engines Matrix](#-supported-protocols--engines-matrix)
- [🧭 Interactive Master CLI (`mhpanel`)](#-interactive-master-cli-mhpanel)
- [🤝 Special Thanks, Acknowledgments & Upstream Projects](#-special-thanks-acknowledgments--upstream-projects)
- [📢 Official Community & Channel](#-official-community--channel)
- [📄 License & Disclaimer](#-license)

---

## 🌟 What's New in Version 1.7.0

Version **1.7.0** delivers superior anti-censorship resilience, Sing-box universal core integration, ergonomic UI/UX with dual theme support (Light & Dark), and one-click universal client subscriptions:

1. ⚡ **Sing-box 23-Mode Multi-Protocol Suite:**
   - Full automated deployment across modern transport layers:
     - **VLESS Reality** (Vision, TCP, gRPC, HTTPUpgrade)
     - **VLESS TLS** (WebSocket, gRPC, HTTPUpgrade, TCP)
     - **VMess** (WebSocket-TLS, gRPC-TLS, HTTPUpgrade-TLS, TCP)
     - **Trojan** (TCP-TLS, WebSocket-TLS, gRPC-TLS, HTTPUpgrade-TLS)
     - **Hysteria 2** (Salamander Obfuscation & Standard QUIC with Brutal Congestion Control)
     - **TUIC v5** (Pure UDP, QUIC HTTP/3, BBR Congestion Control, 0-RTT Handshake)
     - **Shadowsocks** (Modern 2022-Blake3 & Classic AEAD-AES256-GCM)
     - **NaiveProxy** (Chrome Network Stack Emulation over HTTP/2)
     - **ShadowTLS v3** & **Mixed/SOCKS5**

2. 📡 **Universal Smart Subscription Engine (SlipNet, V2Ray, Sing-box & Hiddify):**
   - 1-click **Base64 Smart Subscription** delivering all 23 active Sing-box configurations + SSH configs in a single unified link.
   - Automatic TLS SNI routing prioritizing active and valid server SSL domains to eliminate certificate mismatch and handshake errors.
   - 1-click direct clipboard copy button in the users table with immediate visual toast notification.

3. 🎛️ **Ergonomic Single-Line Inbounds UI & Interactive Management Modal:**
   - User table inbounds column transformed into a sleek, clean single line: `[ ⚙️ 23 Inbounds Active (Manage ⚙️) ]`.
   - **Interactive Inbound Management Modal**: Administrators can add, remove, or customize allowed protocols for any individual user with real-time checkbox synchronization, live counter badges, search filter, and 1-click presets (*Select All*, *Deselect All*, *Reality*, *QUIC / Hys2 & TUIC*, *TLS Standards*).
   - Modifications automatically update Sing-box core configurations with instant hot-reloading.

4. 🛡️ **Noise DNS (NoizDNS) & DoH Studio:**
   - Custom DNS obfuscation injecting random decoy query noise to defeat active DNS censorship and ISP DPI inspection.
   - Built-in DNS-over-HTTPS (DoH) engine with full SlipNet scanning support.

5. 🧅 **Tor Bridge & Snowflake Hub with Enhanced QR Codes:**
   - High-throughput Tor Snowflake & obfs4 Bridge deployment.
   - Automatic extraction and display of 40-character bridge fingerprints.
   - Enlarged 220px high-contrast QR codes across all tabs for rapid mobile camera scanning.

6. 🎨 **Modern Light & Dark Theme System:**
   - Complete redesign with a crisp, professional white/light theme alongside the sleek dark mode.
   - Unified typography using Vazirmatn and Inter, dynamic responsive charts, and instant theme switching.

---

## 📸 Panel Visual Tour (Light Theme Gallery)

Explore the clean, modern **White / Light Theme** interface of **MH Panel v1.7.0**:

### 1. 🖥️ Master Dashboard Overview
Real-time CPU/RAM/Disk metrics, active connections, total traffic counters, and quick system control center in pristine light theme.
![Master Dashboard](docs/screenshots/01_dashboard.png)

### 2. ⚡ Sing-box 23-Mode Protocol Studio
Central management of all 23 Sing-box inbounds (VLESS Reality, VMess, Trojan, Hysteria 2, TUIC v5, Shadowsocks 2022, NaiveProxy, ShadowTLS).
![Sing-box Studio](docs/screenshots/02_singbox_inbounds.png)

### 3. 👥 User Management & Smart Subscription Links
Ergonomic user table featuring single-line inbounds pills, 1-click direct sub link copy (`[📡 لینک ساب]`), quota monitoring, and live status badges.
![User Management](docs/screenshots/03_singbox_users.png)

### 4. 🎛️ Interactive User Inbound Management Modal
Instant addition or removal of allowed protocol inbounds for each user with live search, protocol badges, and 1-click preset filters.
![Inbound Management Modal](docs/screenshots/04_manage_inbounds_modal.png)

### 5. 🛡️ DNS Tunneling, Noise DNS & DoH Studio
Specialized anti-shutdown DNS tunnel engines (DNSTT, SlowDNS, Noise DNS obfuscation, and DoH).
![DNS Tunnels Studio](docs/screenshots/05_dns_tunnels.png)

### 6. 🧅 Tor Bridges & Snowflake Deployment
Automated Tor Snowflake relay, custom bridge generator with fingerprint verification and SlipNet QR scanner.
![Tor Bridges](docs/screenshots/06_tor_bridges.png)

### 7. 🌐 Core Tunnels & Anti-DPI Mesh Shield
Enterprise Layer-2/Layer-3 kernel tunnels (WireGuard, AmneziaWG, SIT, GRE, VXLAN, EoIP, Frp, Chisel, and Rathole).
![Core Tunnels](docs/screenshots/07_core_tunnels.png)

### 8. 🚀 AmneziaWG & WireGuard Multiport
Kernel-level obfuscated WireGuard with custom junk packet headers (`Jc`, `Jmin`, `Jmax`) and multiport listening.
![AmneziaWG Multiport](docs/screenshots/08_amneziawg.png)

### 9. 📱 Client Web Subscription Portal
User-facing portal showing traffic quota consumption, remaining validity days, raw client URIs, and universal All-In-One QR code in light elegance styling.
![Subscription Portal](docs/screenshots/09_subscription_portal.png)

---

## 📐 Visual Architecture & Traffic Flow Pipelines

### 1. Universal Multi-Protocol Port 443 Sharing Architecture

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                      📱 Global Clients & Operating Systems                             │
│         (v2rayNG, Streisand, Clash, AnyConnect, Windows SSTP, Chrome, iOS)             │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            │ Incoming Secure HTTPS Connection on Port 443
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│              🔀 Universal Port 443 Multiplexer & SNI Dispatcher Layer                  │
│               Intelligent TLS ClientHello, SNI Domain & ALPN Inspection                │
└───────┬─────────────────┬─────────────────┬─────────────────┬─────────────────┬────────┘
        │                 │                 │                 │                 │
  [sni: panel.*]    [sni: vless.*]    [sni: trojan.*]   [sni: cisco.*]    [sni: sstp.*]   [Untrusted / Scanner]
        │                 │                 │                 │                 │                 │
        ▼                 ▼                 ▼                 ▼                 ▼                 ▼
 ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
 │ Web Admin    │  │ VLESS        │  │ Trojan       │  │ Cisco        │  │ Windows      │  │ WordPress    │
 │ Panel GUI    │  │ Reality      │  │ TLS          │  │ AnyConnect   │  │ SSTP         │  │ Decoy Site   │
 │ (Port 9090)  │  │ (Sing-box)   │  │ (Sing-box)   │  │ (OCServ)     │  │ (sstpd)      │  │ (Anti-DPI)   │
 └──────────────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
                          │                 │                 │                 │                 │
                          └─────────────────┼─────────────────┼─────────────────┘                 │
                                            │                 │                                   │
                                            ▼                 ▼                                   ▼
                             ┌──────────────────────────────────────────────┐              ┌──────────────┐
                             │       🌐 Uncensored Global Internet          │              │ Scanner Safe │
                             │        (YouTube, Instagram, Telegram)        │              │  200 OK Page │
                             └──────────────────────────────────────────────┘              └──────────────┘
```

---

### 2. Google Apps Script Full-Tunnel Proxy Pipeline

```text
┌──────────────┐       AES-256-GCM Encrypted + HMAC Auth       ┌───────────────────────────────────┐
│  👤 User     │ ─────────────────────────────────────────────► │    ☁️ Google Cloud Edge CDN       │
│  Client      │                                                │     Google Apps Script V8 Engine  │
│ (Sing-box/V2)│ ◄───────────────────────────────────────────── │    Official IPs (172.217.x.x)     │
└──────────────┘       Fast Response via Official Google CDN    └─────────────────┬─────────────────┘
                                                                                  │
                                                                 Relays to VPS    │ (Google CDN IPs are
                                                                 Daemon over TLS  │  unblockable by DPI)
                                                                                  ▼
┌──────────────────────────────┐     Unrestricted Target Web    ┌───────────────────────────────────┐
│     🌍 Unfiltered Internet   │ ◄───────────────────────────── │    🖥️ MH Panel VPS (Foreign Server)│
│  (YouTube, Telegram, Google) │ ─────────────────────────────► │      Google Script Forwarder      │
└──────────────────────────────┘      Packets Returned to VPS   └───────────────────────────────────┘
```

---

### 3. Anti-DPI WordPress Decoy Site vs Active Probers

```text
                     ┌────────────────────────────────────────────────────────┐
                     │          Inbound Traffic on Public Port 443            │
                     └───────────────────────────┬────────────────────────────┘
                                                 │
                                                 ▼
                     ┌────────────────────────────────────────────────────────┐
                     │          Intelligent Handshake Pattern Analysis        │
                     └─────────────┬────────────────────────────┬─────────────┘
                                   │                            │
                     [Valid Key & Protocol SNI]      [Untrusted Scan / Generic HTTP]
                                   │                            │
                                   ▼                            ▼
                     ┌───────────────────────────┐┌───────────────────────────┐
                     │  ⚡ Core Proxy Engines    ││  🎭 WordPress Decoy Site  │
                     │  (Sing-box, Reality, ...) ││  (Anti-DPI CMS Template)  │
                     └─────────────┬─────────────┘└─────────────┬─────────────┘
                                   │                            │
                                   ▼                            ▼
                     ┌───────────────────────────┐┌───────────────────────────┐
                     │ 🌐 Unfiltered Global Web  ││ 📄 Returns Authentic Blog │
                     │    Full Speed Internet    ││ 🟢 "Standard site found"  │
                     └───────────────────────────┘└───────────────────────────┘
```

---

### 4. Telegram Bot Alert Engine & Automated Backup Dispatch

```text
┌──────────────────────────────────────────────┐
│           🖥️ MH Panel Telemetry Core         │
│  • Hardware Resource Probing (CPU, RAM, SWAP)│
│  • Tunnel Health, RTT & Packet Loss Tracking │
│  • DPI TCP RST Injection Attack Sensor       │
│  • Scheduled Cron Backup Engine (Daily/Weekly│
└──────────────────────┬───────────────────────┘
                       │
                       │ Direct HTTPS Dispatch to Telegram API
                       ▼
┌──────────────────────────────────────────────┐
│           🤖 Administrator Telegram Bot      │
│          MH Panel Alert & Backup Engine      │
└──────┬───────────────────────┬───────────────┘
       │                       │
       ▼ Instant Critical Push ▼ Direct Delivery of Archive
┌──────────────────────────────┐┌──────────────────────────────┐
│ 🚨 Emergency Security Alerts:││ 💾 Automated Backup File:    │
│ - Hardware Saturation Alert  ││ mhpanel-backup-*.tar.gz      │
│ - Tunnel Outage Detected     ││ Full Database & Configs      │
│ - Active DPI Attack Warning  ││ Instant 1-Click Download     │
└──────────────────────────────┘└──────────────────────────────┘
```

---

### 5. Sing-box First-Connect Triggered Accounting Lifecycle

```text
┌────────────────────────────────────────────────────────┐
│             👨‍💼 Administrator in Web GUI                │
│    Create User Account (Quota: 50 GB | Duration: 30 D) │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│      🟡 Initial Status: First-Connect Pending          │
│       * 30-Day validity countdown has NOT begun yet *  │
└───────────────────────────┬────────────────────────────┘
                            │
                            │ User imports config & initiates first handshake
                            ▼
┌────────────────────────────────────────────────────────┐
│     🟢 First Handshake Timestamp Automatically Stamped │
│       * 30-Day validity countdown starts right now *   │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│     📊 Real-Time Bandwidth Accounting (Upload+Download)│
└───────────────────────────┬────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              │ Did 50 GB quota deplete   │
              │  OR 30 days expire?       │
              └─────────────┬─────────────┘
                            │ Yes
                            ▼
┌────────────────────────────────────────────────────────┐
│     🔴 Automatic User Suspension Across All Inbounds   │
└────────────────────────────────────────────────────────┘
```

---

## 📚 Supported Protocols & Engines Matrix

| # | Protocol | Underlying Engine | Default Port | Security Architecture & Key Strength |
|:---:|---|---|:---:|---|
| 1 | **VLESS Reality** | Sing-box Core Suite | 443 | Modern standard; mimics foreign TLS websites, eliminates SSL cert setup, 100% stealth against DPI. |
| 2 | **Trojan TLS** | Sing-box Core Suite | 8443 (or 443 shared) | Masks traffic as authentic HTTPS browsing with valid TLS 1.3 certificates. |
| 3 | **Hysteria 2** | Sing-box Core Suite | 7443 (UDP) | Custom QUIC with Brutal congestion control; unthrottled performance across lossy networks. |
| 4 | **TUIC v5** | Sing-box Core Suite | 8448 (UDP) | QUIC HTTP/3 protocol with 0-RTT handshakes, low mobile battery consumption, and high resilience. |
| 5 | **Shadowsocks 2022** | Sing-box / Rust | 8388 | Modern AEAD 2022 ciphers; ultra-low latency with active probing protection. |
| 6 | **NaiveProxy** | Sing-box / Chromium | 8080 | Emulates Google Chrome's actual network stack; traffic is completely indistinguishable from web browsing. |
| 7 | **Google Apps Script Proxy** | Google V8 + Node.js | Google Webhook | Relays through Google Cloud edge network; immune to regional IP blocking. |
| 8 | **Anti-DPI WordPress Decoy** | Nginx + PHP/WP | 80, 443 fallback | Real WordPress blog serving realistic content to probing requests to prevent censor blacklisting. |
| 9 | **AmneziaWG (AWG)** | Linux Kernel Driver | 51820 (UDP) | Obfuscated WireGuard with header junk packet injection (`Jc`, `Jmin`, `Jmax`) and custom handshakes (`S1`, `S2`, `H1-H4`). |
| 10 | **Standard WireGuard** | Linux Kernel Driver | 51821 (UDP) | Ultra-lightweight kernel VPN with dual-stack IPv4 and IPv6 subnet assignment. |
| 11 | **Cisco AnyConnect** | OCServ | 10443 (or 443 shared) | Enterprise SSL VPN compatible with official Cisco clients across all desktop and mobile operating systems. |
| 12 | **Windows SSTP** | sstpd | 4443 (or 443 shared) | Native Windows support out of the box without requiring third-party software installation. |
| 13 | **IKEv2 / IPsec** | StrongSwan | 500, 4500 (UDP) | Native iOS, macOS, and Windows support with MOBIKE seamless network roaming. |
| 14 | **L2TP / IPsec** | xl2tpd + Libreswan | 1701, 500 (UDP) | Legacy protocol with hardware acceleration, compatible with routers and gaming consoles. |
| 15 | **OpenVPN (TCP / UDP)** | OpenVPN Community | 1194 | Supports OpenVPN 2.6, Scramble XOR patches, and UDPspeeder acceleration. |
| 16 | **SSH WebSocket (WSS)** | OpenSSH + Python WS | 22, 4444 | Direct SSH tunnel with WebSocket reverse proxy and BadVPN UDPGW (port 7300) for gaming. |
| 17 | **ShadowTLS v3** | Sing-box Core | 8444 | Wraps Shadowsocks traffic inside genuine TLS handshakes without needing private keys of target sites. |
| 18 | **SlowDNS / DNSTT** | DNSTT Suite | 53 (UDP) | Guaranteed tunnel during total international internet shutdowns via recursive DNS queries. |
| 19 | **VayDNS & Slipstream** | DNS Suite | 5353 (UDP) | Modern compressed and encrypted DNS tunneling protocol. |
| 20 | **Tor Bridges** | Tor Core | 9050, 9051 | Snowflake, obfs4, and WebTunnel bridges for hidden access to the Tor network. |
| 21 | **MTProto Proxy** | Python / Rust | 8445 | Official Telegram proxy with fake TLS secrets to bypass Telegram ISP blocking. |
| 22 | **WSTunnel** | WSTunnel Core | 8088 | Bidirectional WebSocket tunnel with full TLS encryption. |
| 23 | **Rathole** | Rathole Engine | 8089 | High-performance Rust tunnel with minimal CPU and memory footprint for site-to-site bridges. |
| 24 | **Chisel Tunnel** | Chisel Go | 8090 | HTTP/WebSocket based multiplexed tunnel. |
| 25 | **GOST v3 Relay** | GOST Multi-Node | 8091 | Multi-node mesh chaining relay for transit routing. |
| 26 | **Kernel L2/L3 Tunnels** | Linux Kernel Drivers | Variable | IPIP, SIT (6in4), GRE, GRETAP, IP6GRE, IP6GRETAP, VXLAN, and GENEVE. |

---

## 🧭 Interactive Master CLI (`mhpanel`)

MH Panel provides an enterprise-grade interactive command-line interface directly on your server terminal:

```bash
mhpanel
```

```text
  ========================================================================
     🚀 MH PANEL Enterprise Master CLI Console (Version 1.7.0)
  ========================================================================
  Web Panel Status: Online (IP:PORT/PATH) | Quick Command: mhpanel
  ------------------------------------------------------------------------
  [1]  Run Full Automated Installation (Setup All Missing Components)
  [2]  Run Step-by-Step Custom Installation Wizard
  [3]  Install Lightweight Web UI Only
  ------------------------------------------------------------------------
  [4]  View Panel Access URL & Login Info
  [5]  Change Admin Username & Password
  [6]  Change Panel Address, Port & Path
  [7]  Live System & Service Diagnostic Report
  [8]  Manage, Install, Uninstall & Reconfigure VPN Protocols
  [9]  Anti-Censorship Tunnels & MikroTik RouterOS Bridge Hub
  [10] Web Server Integration & WordPress Camouflage
  [11] Telegram Bot Notifications & Auto-Backup Hub
  [12] Web Dashboard Settings (Logs, Restart, 2FA & API Key)
  [13] SSL Certificate Management (Let's Encrypt & IP SAN)
  [14] Network & Kernel Optimization (BBR, IPv4/IPv6 Forwarding)
  [15] Backup & Restore Panel Configurations
  [16] Quick Terminal Commands Guide & Shortcuts
  [17] Update Script & Panel
  [18] Uninstall MH Panel from Server
  [0]  Exit
  ========================================================================
```

### ⚡ Quick Non-Interactive CLI Shortcuts:

Administrators can execute actions directly from bash without opening the interactive menu:

| Command | Action Description |
|---|---|
| `mhpanel` | Open the interactive master menu. |
| `mhpanel --status` | Run live diagnostic audit on all services, ports, and hardware. |
| `mhpanel --info` | Print the current Web GUI access URL, login credentials, and API key. |
| `mhpanel --user <new_username>` | Change the administrator username. |
| `mhpanel --pass <new_password>` | Change the administrator password. |
| `mhpanel --credentials <user> <pass>` | Change both username and password in a single command. |
| `mhpanel --port <port>` | Change the Web Panel listening port (e.g. `mhpanel --port 9443`). |
| `mhpanel --path <secret_path>` | Set a secret URL prefix for stealth access (e.g. `mhpanel --path /admin77`). |
| `mhpanel --address <port> <path>` | Change both port and custom secret path simultaneously. |
| `mhpanel --wp` | Open WordPress Decoy Camouflage setup wizard. |
| `mhpanel --tg` | Open Telegram Bot alert and automatic backup dispatcher. |
| `mhpanel --tunnels` | Open Anti-Censorship Tunnels & MikroTik Bridge Hub. |
| `mhpanel protocol <name> <cmd>` | Manage specific protocols (e.g. `mhpanel protocol singbox restart`). |
| `mhpanel restart` | Instantly hot-reload and restart the MH Panel systemd service. |
| `mhpanel start` / `mhpanel stop` | Start or stop the MH Panel background service. |
| `mhpanel update` | Fetch and apply the latest updates directly from GitHub. |
| `mhpanel --uninstall` | Completely purge MH Panel and auxiliary services from the server. |
| `mhpanel --help` | Display the built-in terminal CLI help guide. |

---

## 🤝 Special Thanks, Acknowledgments & Upstream Projects

MH Panel is built on the shoulders of giants. We express our deepest respect and gratitude to the open-source creators, protocol developers, and community maintainers whose innovative work, algorithms, and projects either directly empower or inspired MH Panel:

### 🛡️ Core VPN & Proxy Engines
- **[Sing-box (SagerNet)](https://github.com/SagerNet/sing-box)**: The universal proxy platform powering our multi-protocol core (VLESS, VMess, Trojan, ShadowTLS, Shadowsocks, TUIC, and Hysteria 2).
- **[Hysteria 2 (AperNet)](https://github.com/apernet/hysteria)**: Next-generation proxy protocol based on custom QUIC with Brutal congestion control and Salamander obfuscation.
- **[TUIC (EAimTY)](https://github.com/EAimTY/tuic)**: Delicately designed 0-RTT QUIC HTTP/3 proxy protocol.
- **[Shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)**: High-performance Rust implementation of Shadowsocks AEAD and modern 2022-blake3 ciphers.
- **[AmneziaWG](https://github.com/amnezia-vpn/amnezia-wg)** & **[wiresock/amneziawg-install](https://github.com/wiresock/amneziawg-install)**: Kernel-level obfuscated WireGuard implementation with junk packet initiation headers (`Jc`, `Jmin`, `Jmax`).
- **[WireGuard](https://www.wireguard.com/)** & **[angristan/wireguard-install](https://github.com/angristan/wireguard-install)**: Extremely simple yet fast and modern VPN tunnel.
- **[OpenVPN](https://openvpn.net/)** & **[Tunnelblick XOR Patches](https://github.com/Tunnelblick/Tunnelblick)**: OpenVPN 2.6 with Scramble XOR patches to bypass DPI packet signatures.
- **[OpenConnect (ocserv)](https://gitlab.com/openconnect/ocserv)**: High-performance SSL VPN server compatible with the Cisco AnyConnect client.
- **[SoftEther VPN](https://github.com/SoftEtherVPN/SoftEtherVPN_Stable)**: Powerful multi-protocol VPN software (L2TP/IPsec and SSTP).
- **[BadVPN (ambrop72)](https://github.com/ambrop72/badvpn)**: UDP gateway forwarding (`badvpn-udpgw`) for SSH tunneling and gaming traffic.
- **[MTProto Proxy (alexbers)](https://github.com/alexbers/mtprotoproxy)**: High-throughput async Telegram MTProto proxy with domain fronting fake TLS.
- **[Rosenpass](https://github.com/rosenpass/rosenpass)**: Post-quantum secure key exchange mechanism for WireGuard.

### 🌐 Anti-Censorship Mesh, Tunneling & Multiplexing
- **[Backhaul (Musixal)](https://github.com/Musixal/Backhaul)**: High-performance reverse tunneling tool written in Go with multi-connection web sockets and TCP multiplexing.
- **[Rathole (rapiz1)](https://github.com/rapiz1/rathole)**: Lightweight, high-performance reverse NAT proxy written in Rust with noise encryption.
- **[Chisel (jpillora)](https://github.com/jpillora/chisel)**: Fast TCP/UDP tunnel over HTTP/WebSockets with built-in SSH security.
- **[GOST (go-gost)](https://github.com/go-gost/gost)**: GO Simple Tunnel, versatile multi-node proxy chaining and relay engine.
- **[Wstunnel (erebe)](https://github.com/erebe/wstunnel)**: Tunneling arbitrary TCP and UDP traffic over WebSockets and HTTPS.
- **[ReverseTlsTunnel - RTT (radkesvat)](https://github.com/radkesvat/ReverseTlsTunnel)**: TLS tunnel designed specifically for bypassing aggressive regional filtering.
- **[frp (fatedier)](https://github.com/fatedier/frp)**: Fast Reverse Proxy to expose local servers behind NAT or firewalls.
- **[pingtunnel (esrrhs)](https://github.com/esrrhs/pingtunnel)**: ICMP echo traffic tunneling to bypass strict TCP/UDP port closures.
- **[UDPspeeder (wangyu-)](https://github.com/wangyu-/UDPspeeder)**: Network quality optimization via Reed-Solomon Forward Error Correction (FEC) over lossy connections.
- **[udp2raw (wangyu-)](https://github.com/wangyu-/udp2raw)**: Tunnel converting UDP traffic to FakeTCP raw packets to circumvent ISP UDP throttling and firewalls.
- **[Phantun (dndx)](https://github.com/dndx/phantun)**: Lightweight, obfuscated UDP-to-TCP tunnel written in Rust.
- **[tun2socks (xjasonlyu)](https://github.com/xjasonlyu/tun2socks)**: High-performance TUN interface redirection engine to SOCKS5/HTTP.
- **[DNSTT (utunnels / Bamsoftware)](https://github.com/utunnels/dnstt)**: Encrypted DNS tunnel over DoH (DNS over HTTPS), DoT, and plain UDP DNS.
- **[The Tor Project](https://gitlab.torproject.org/tpo/anti-censorship)**: Pluggable transports including Snowflake and obfs4 for circumventing censorship.

### 💡 Architectural Inspiration & Ecosystem Pioneers
- **[Marzban (Gozargah)](https://github.com/Gozargah/Marzban)**: Pioneer in Python-based modern subscription systems, user lifecycle accounting, and ergonomic multi-protocol proxy administration.
- **[3X-UI (MHSanaei)](https://github.com/MHSanaei/3x-ui)** & **[X-UI (vaxilu)](https://github.com/vaxilu/x-ui)**: Groundbreaking Web GUI paradigms for inbound configuration, traffic visualizers, and node management.
- **[Hiddify Manager (hiddify)](https://github.com/hiddify/hiddify-manager)**: Universal multi-protocol routing and smart client subscription ecosystem ideas.

---

## 📢 Official Community & Channel

Join our official community channel for latest updates, configuration guides, and architectural news:
- 📢 **Official Telegram Channel:** [@kigaping_fa](https://t.me/kigaping_fa)

---

## 📄 License

This project is licensed under the open-source [MIT License](LICENSE).  
Built with passion for digital freedom and resilient internet communications worldwide.
