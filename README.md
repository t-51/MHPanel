# 🚀 MH Panel - Enterprise Unified VPN, Anti-Censorship Tunnels, Sing-box Universal Suite & MikroTik Management Hub

<p align="center">
  <a href="README.md"><b>🇬🇧 English Documentation</b></a> |
  <a href="README_FA.md"><b>🇮🇷 مستندات فارسی (جامع)</b></a> |
  <a href="README_RU.md"><b>🇷🇺 Документация на русском</b></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/MH--Panel-v1.7.0-6366f1.svg?style=for-the-badge&logo=shield&logoColor=white" alt="MHPanel Version">
  <img src="https://img.shields.io/badge/Platform-Ubuntu%2020%2B%20%7C%20Debian%2011%2B-orange.svg?style=for-the-badge&logo=linux&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python Version">
  <img src="https://img.shields.io/badge/Core-Sing--box%20%2B%20Linux%20Kernel%20L2%2FL3-emerald.svg?style=for-the-badge" alt="Core">
  <img src="https://img.shields.io/badge/Languages-8%20Native%20Locales-purple.svg?style=for-the-badge" alt="Languages">
  <img src="https://img.shields.io/badge/License-MIT-teal.svg?style=for-the-badge" alt="License">
</p>

---

## 🌟 What's New in Version 1.7.0

Version **1.7.0** represents a massive leap forward in anti-censorship resilience, Sing-box integration, ergonomic UX design, and universal client compatibility:

1. ⚡ **Sing-box 23-Mode Multi-Protocol Suite:**
   - Full automated deployment of all modern protocol variants across all transports:
     - **VLESS Reality** (Vision, TCP, gRPC, HTTPUpgrade)
     - **VLESS TLS** (WebSocket, gRPC, HTTPUpgrade, TCP)
     - **VMess** (WebSocket-TLS, gRPC-TLS, HTTPUpgrade-TLS, TCP)
     - **Trojan** (TCP-TLS, WebSocket-TLS, gRPC-TLS, HTTPUpgrade-TLS)
     - **Hysteria 2** (Salamander Obfuscation & Standard QUIC)
     - **TUIC v5** (Pure UDP, QUIC HTTP/3, BBR Congestion Control, 0-RTT Handshake)
     - **Shadowsocks** (Modern 2022-Blake3 & Classic AEAD-AES256-GCM)
     - **NaiveProxy** (Chrome Network Stack Emulation over HTTP/2)
     - **ShadowTLS v3** & **Mixed/SOCKS5**

2. 📡 **Universal Smart Subscription Engine (SlipNet, V2Ray, Sing-box & Hiddify):**
   - 1-click **Base64 Smart Subscription** delivering all 23 active Sing-box configurations + SSH configs in a single unified link.
   - Fully optimized for **SlipNet**, **v2rayNG**, **NekoBox**, **Hiddify**, **v2rayN**, and **Streisand**.
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

6. 📖 **Integrated Protocol Guidance & Firewall Port Setup Hub:**
   - Comprehensive documentation integrated directly into modal views for NaiveProxy, TUIC, Tor, and DNS Tunnels.
   - Step-by-step guidance on hardware firewall port requirements and domain/NS delegations.

---

## 📸 Panel Visual Tour & Screenshots Gallery

Explore the modern, dark-themed, and responsive interface of **MH Panel v1.7.0**:

### 1. 🖥️ Master Dashboard Overview
Real-time CPU/RAM/Disk metrics, active connections, total traffic counters, and quick system control center.
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
User-facing portal showing traffic quota consumption, remaining validity days, raw client URIs, and universal All-In-One QR code.
![Subscription Portal](docs/screenshots/09_subscription_portal.png)

---

Version **1.6.0** is the most comprehensive and battle-tested release of **MH Panel**, introducing unbreakable censorship evasion mechanisms, cloud edge tunneling, active-probe deception, automated bot surveillance, and enterprise backup lifecycle management:

1. ☁️ **Google Apps Script Full-Tunnel Proxy Engine (V8 Edge Worker):**
   - Routes traffic through Google's indestructible global edge network (`172.217.x.x` and `142.250.x.x`).
   - Automated cloud deployment via Google Apps Script API or seamless copy-paste assistant.
   - High-throughput server-side forwarder daemon authenticated with HMAC-SHA256 tokens and AES-256-GCM cipher encryption.
   - Dedicated management studio in MH Panel with 1-click token issuance, client link generator, and real-time connectivity probing.

2. 🎭 **Anti-DPI WordPress Decoy Site (Active Probing Deception):**
   - Automated deployment of an authentic, fully functional WordPress blog/shop on a designated decoy domain or port 443 fallback.
   - Fools Deep Packet Inspection (DPI) scanners and active probers: unauthenticated scans or connection probes receive genuine WordPress HTML/CSS/JS with HTTP 200 OK responses, completely concealing proxy infrastructure.

3. 🤖 **Telegram Bot Management, Real-time Alerts & Automated Backup Delivery:**
   - Direct integration with administrator Telegram bots without requiring auxiliary external proxies.
   - Instant critical push notifications for server resource saturation (high CPU, RAM exhaustion, disk/swap alerts).
   - Real-time detection of DPI TCP RST packet injection attacks and tunnel interface drops.
   - Scheduled automatic delivery of compressed panel backups (`.tar.gz`) directly into the administrator's Telegram chat.

4. 💾 **1-Click Full Backup & Instant Restore Suite:**
   - Complete snapshot encompassing panel settings, Sing-box core inbound/outbound definitions, FreeRADIUS SQLite database, SSL certificates, and kernel tunnels.
   - Instant 1-click safe restore with automated integrity checks and service hot-reloading.

5. ⏱️ **First-Connect Triggered Traffic Accounting (Sing-box Core):**
   - User validity period (e.g., 30 days) begins counting down from the exact timestamp of the **first active handshake**, rather than the administrative creation date.

6. 🔀 **Universal Multi-Protocol Port 443 Multiplexer (Port Sharing):**
   - Co-existence of over 26 VPN and proxy protocols (VLESS Reality, Trojan, Hysteria 2, TUIC v5, NaiveProxy, Cisco AnyConnect, SSTP, and Web Panel) on shared port 443/8443 via intelligent SNI & ALPN routing with zero port conflicts.

7. 🌍 **Universal 8-Language Localization with Smart Scrollbar Mirroring:**
   - Full native translations for: **Persian (FA)**, **English (EN)**, **Russian (RU)**, **Arabic (AR)**, **Italian (IT)**, **Spanish (ES)**, **Simplified Chinese (ZH)**, and **German (DE)**.
   - Directional scrollbar inversion: In RTL mode, content scrollbar rests on the far left edge and sidebar scrollbar on the far right edge; mirrored in LTR mode.

8. 📱 **Mobile & Desktop Ergonomic UI 2.0:**
   - Real-time instant quick-search filter in the sidebar for rapid access to all 35+ protocol suites and tools.
   - Pinned top header, independently scrollable navigation container, and pinned language switcher footer (zero sticky scroll detachment).
   - Touch-optimized bottom navigation drawer on mobile with 38px squircle avatar containers.

---

## 📐 Visual Architecture & Traffic Flow Pipelines

### 1. Universal Multi-Protocol Port 443 Sharing Architecture

Allows running every modern protocol simultaneously over a single public HTTPS port (443) behind an intelligent Layer-4/Layer-7 SNI dispatcher with authentic decoy fallback:

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

Bypasses aggressive DPI filters by relaying traffic via official Google Cloud Edge workers (`script.google.com`):

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
└───────────────────────────┘
```

---

## 📚 Supported Protocols & Engines Matrix

| # | Protocol | Underlying Engine | Default Port | Security Architecture & Key Strength |
|:---:|---|---|:---:|---|
| 1 | **VLESS Reality** | Sing-box Core Suite | 443 | Modern standard; steals identity of foreign TLS websites, eliminates SSL cert setup, 100% stealth against DPI. |
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

## ⚡ Quick Installation

### System Requirements:
- **Operating Systems:**
  - Ubuntu 24.04 LTS (Noble Numbat)
  - Ubuntu 22.04 LTS (Jammy Jellyfish)
  - Ubuntu 20.04 LTS (Focal Fossa)
  - Debian 12 (Bookworm) / Debian 11 (Bullseye)
- **Minimum Specs:** 1 vCPU, 1 GB RAM, 10 GB SSD.
- **Privileges:** Root access (`root`).

### 1-Line Automated Installer (Recommended):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/t-51/MHPanel/main/install.sh)
```

### Manual Installation via Git:

```bash
git clone https://github.com/t-51/MHPanel.git /www/wwwroot/mhpanel
cd /www/wwwroot/mhpanel
sudo bash install.sh
```

Upon installation completion, panel credentials (Web URL, Port, Admin Username, Password, and API Key) will be displayed on your terminal.

---

## 🧭 Interactive Master CLI (`mhpanel`)

Access the complete server management console anytime directly from your terminal:

```bash
mhpanel
```

```text
  ======================================================================
     🚀 MH PANEL Enterprise Master CLI Console (Version 1.7.0)
  ======================================================================
  [1]  Execute Automated Full Suite Installation (All Protocols & Tools)
  [2]  Step-by-Step Custom Installation Wizard
  [3]  Lightweight Web Panel Only Installation
  ----------------------------------------------------------------------
  [4]  Live System Diagnostic Report & Service Status
  [5]  Manage, Install, Remove & Reconfigure VPN Protocols
  [6]  Anti-Censorship Tunnels Hub & MikroTik RouterOS Bridge
  [7]  Web Panel Settings (Credentials, Port, SSL, Restart)
  [8]  SSL Certificate Management (Let's Encrypt & 10-Year IP SAN)
  [9]  Network & Kernel Optimization (BBR, IPv4/IPv6 Forwarding)
  [10] Full Backup & Restore Suite (Create / Restore Archive)
  [11] Anti-DPI WordPress Decoy Site Studio
  [12] Telegram Bot Settings & Alert Testing
  [13] Check & Apply Official Updates from GitHub
  [0]  Exit
  ======================================================================
```

---

## 📢 Official Community & Channel

Join our official community channel for latest updates, configuration guides, and architectural news:
- 📢 **Official Telegram Channel:** [@kigaping_fa](https://t.me/kigaping_fa)

---

## 📄 License

This project is licensed under the open-source [MIT License](LICENSE).
Built with passion for digital freedom and resilient internet communications.
