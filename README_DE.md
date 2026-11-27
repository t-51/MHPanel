# 🚀 MH Panel - Enterprise Unified VPN, Zensurumgehungs-Tunnel, Sing-box Suite & MikroTik Management Hub

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
  <img src="https://img.shields.io/badge/MH--Panel-v1.8.0-6366f1.svg?style=for-the-badge&logo=shield&logoColor=white" alt="MHPanel Version">
  <img src="https://img.shields.io/badge/Plattform-Ubuntu%20%7C%20Debian-orange.svg?style=for-the-badge&logo=linux&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python Version">
  <img src="https://img.shields.io/badge/Core-Sing--box%20%2B%20Kernel%20L2%2FL3-emerald.svg?style=for-the-badge" alt="Core">
  <img src="https://img.shields.io/badge/Design-Helles%20und%20Dunkles%20Theme-amber.svg?style=for-the-badge&logo=sparkles&logoColor=white" alt="Theme">
  <img src="https://img.shields.io/badge/Sprachen-8%20Lokalisierungen-purple.svg?style=for-the-badge" alt="Languages">
  <a href="https://donito.me/ME_Script" target="_blank"><img src="https://img.shields.io/badge/💖%20Spenden-Donito.me-ff4757.svg?style=for-the-badge&logo=heart&logoColor=white" alt="Spenden via Donito"></a>
  <img src="https://img.shields.io/badge/Lizenz-MIT-teal.svg?style=for-the-badge" alt="License">
</p>

---

## ⚡ 1-Klick-Schnellinstallation (Quick Start)

Installieren Sie **MH Panel** in unter 60 Sekunden mit vollautomatischer Konfiguration aller Abhängigkeiten, Kernel-Module, SSL-Zertifikate und systemd-Dienste:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/t-51/MHPanel/main/install.sh)
```

> [!TIP]
> **Systemanforderungen:**
> - **Betriebssysteme:** Ubuntu 24.04 LTS, Ubuntu 22.04 LTS, Ubuntu 20.04 LTS, Debian 12 (Bookworm), Debian 11 (Bullseye)
> - **Minimale Hardware:** 1 vCPU, 1 GB RAM, 10 GB Festplattenspeicher
> - **Berechtigungen:** Root-Benutzerzugriff (`sudo -i` oder `su -`)

<details>
<summary><b>📦 Alternative: Manuelle Installation via Git Clone</b></summary>

```bash
# Repository klonen
git clone https://github.com/t-51/MHPanel.git /www/wwwroot/mhpanel

# Verzeichnis betreten und Installer ausführen
cd /www/wwwroot/mhpanel
sudo bash install.sh
```

Nach Abschluss der Installation werden die URL des Web-Panels, die Zugangsdaten, der Port und der API-Schlüssel im Terminal ausgegeben.
</details>

---

## 📡 Universelle Smart-Subscription-Engine (Alle 23 Konfigurationen in 1 Link)

MH Panel verfügt über eine intelligente Abonnement-Engine, die alle **23 Sing-box-Protokollkonfigurationen** sowie SSH-Tunnel in einem **einzigen, universellen Link** bereitstellt:

### 🎯 Perfekt optimiert für moderne VPN-Clients:
- **SlipNet** (Vollautomatischer Import, integrierter DoH-Scanner & Tor-Bridge-QR-Code-Erkennung)
- **v2rayNG** / **v2rayN** (Standard-Base64 mit periodischer automatischer Aktualisierung `profile-update-interval=24`)
- **Hiddify** / **NekoBox** (Nativer Sing-box-Support: Reality, QUIC & Fragment)
- **Streisand** / **Shadowrocket** / **Clash Meta**

### 🔗 Abonnement-Formate und Endpunkte:
| Link-Typ | URL-Endpunkt | Beschreibung |
|---|---|---|
| **Universelles Base64** | `https://<DOMAIN>:<PORT>/sub/<TOKEN>/b64` | Liefert alle 23 aktiven Inbound-Protokolle mit 1-Klick-Kopierfunktion in der Benutzerliste. |
| **Sing-box Profil-JSON** | `https://<DOMAIN>:<PORT>/sub/<TOKEN>/singbox.json` | Natives JSON-Profil für offizielle Sing-box-Clients mit intelligentem Routing. |
| **Fragment / Cloud-IP** | `https://<DOMAIN>:<PORT>/sub/<TOKEN>/singbox-fragment.json` | Konfiguration mit TLS-SNI-Fragmentierung zur Umgehung von harter DPI-Filterung. |
| **Benutzer-Webportal** | `https://<DOMAIN>:<PORT>/sub/<TOKEN>` | Interaktives Webportal mit hellem und dunklem Design, Datenvolumenanzeige und All-In-One-QR-Code. |

---

## 📑 Inhaltsverzeichnis

- [⚡ 1-Klick-Schnellinstallation](#-1-klick-schnellinstallation-quick-start)
- [📡 Universelle Smart-Subscription-Engine](#-universelle-smart-subscription-engine-alle-23-konfigurationen-in-1-link)
- [🌟 Neuerungen in Version 1.8.0](#-neuerungen-in-version-170)
- [📸 Visuelle Tour im hellen Design](#-visuelle-tour-im-hellen-design-light-theme-gallery)
- [📐 Netzwerkarchitektur & Datenfluss](#-netzwerkarchitektur--datenfluss)
- [📚 Matrix der unterstützten Protokolle](#-matrix-der-unterstützten-protokolle)
- [🧭 Interaktive Master-CLI (`mhpanel`)](#-interaktive-master-cli-mhpanel)
- [🤝 Danksagungen und Upstream-Projekte](#-danksagungen-und-upstream-projekte-upstream-projects)
- [📢 Offizieller Kanal & Community](#-offizieller-kanal--community)
- [📄 Lizenz](#-lizenz)

---

## 🌟 Neuerungen in Version 1.8.0

Version **1.8.0** ist ein Meilenstein in der Zensurresistenz, Sing-box-Integration, Benutzerfreundlichkeit mit hellem und dunklem Design sowie universellen Abonnements:

1. ⚡ **Sing-box 23-Protokoll-Suite:**
   - Vollautomatisches Deployment von: **VLESS Reality** (Vision, TCP, gRPC, HTTPUpgrade), **VLESS TLS**, **VMess**, **Trojan**, **Hysteria 2** (Salamander & Brutal QUIC), **TUIC v5** (0-RTT), **Shadowsocks 2022**, **NaiveProxy** (Chrome-Netzwerkstack) und **ShadowTLS v3**.
2. 📡 **Universelles Smart-Subscription-System (SlipNet, V2Ray, Sing-box & Hiddify):**
   - 1-Klick-Generierung von Base64-Links mit automatischer Bevorzugung valider SSL-Zertifikatsdomänen.
3. 🎛️ **Kompakte einzeilige Inbound-UI & interaktives Verwaltungs-Modal:**
   - Schlanke Darstellung `[ ⚙️ 23 Inbounds Active (Manage ⚙️) ]` mit Popup-Fenster zur gezielten Aktivierung von Protokollen pro Benutzer.
4. 🛡️ **Noise DNS und DoH-Studio:**
   - Abwehr von DPI-Erkennung durch Injektion von Zufallsrauschen in DNS-Pakete und integrierter DoH-Server.
5. 🧅 **Tor-Bridges & Snowflake:**
   - Einrichtung von Snowflake-Relays und obfs4-Bridges mit vergrößerten 220px-QR-Codes.
6. 🎨 **Modernes helles Theme (Light Elegance):**
   - Frisches, kontrastreiches helles Design neben dem bekannten Dark Mode.

---

## 📸 Visuelle Tour im hellen Design (Light Theme Gallery)

### 1. 🖥️ Haupt-Dashboard (Master Dashboard)
![Master Dashboard](docs/screenshots/01_dashboard.png)

### 2. ⚡ Sing-box Protokoll-Studio (23 Inbounds)
![Sing-box Studio](docs/screenshots/02_singbox_inbounds.png)

### 3. 👥 Benutzerverwaltung & Schnell-Kopier-Button
![User Management](docs/screenshots/03_singbox_users.png)

### 4. 🎛️ Interaktives Modal zur Benutzer-Protokollverwaltung
![Inbound Management Modal](docs/screenshots/04_manage_inbounds_modal.png)

### 5. 🛡️ DNS-Tunnel-Studio & Noise DNS
![DNS Tunnels Studio](docs/screenshots/05_dns_tunnels.png)

### 6. 🧅 Tor Bridges & Snowflake
![Tor Bridges](docs/screenshots/06_tor_bridges.png)

### 7. 🌐 Kernel L2/L3 Tunnel & Anti-DPI-Schutz
![Core Tunnels](docs/screenshots/07_core_tunnels.png)

### 8. 🚀 AmneziaWG & WireGuard Multiport
![AmneziaWG Multiport](docs/screenshots/08_amneziawg.png)

### 9. 📱 Benutzer-Webportal für Abonnements
![Subscription Portal](docs/screenshots/09_subscription_portal.png)

---

## 📐 Netzwerkarchitektur & Datenfluss

### Geteilter Port 443 für alle Protokolle (Port Multiplexer)

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        📱 Weltweite Clients (SlipNet, v2rayNG, Hiddify, AnyConnect)    │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ Eingehende sichere HTTPS-Verbindung auf Port 443
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│              🔀 Port 443 Multiplexer & SNI-Router (Universal Port Multiplexer)         │
└───────┬─────────────────┬─────────────────┬─────────────────┬─────────────────┬────────┘
        │                 │                 │                 │                 │
  [sni: panel.*]    [sni: vless.*]    [sni: trojan.*]   [sni: cisco.*]    [Unbekannt/DPI]
        │                 │                 │                 │                 │
        ▼                 ▼                 ▼                 ▼                 ▼
 ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
 │ Web-Panel    │  │ VLESS        │  │ Trojan       │  │ Cisco        │  │ WordPress    │
 │ Admin        │  │ Reality      │  │ TLS          │  │ AnyConnect   │  │ Tarnseite    │
 │ (Port 9090)  │  │ (Sing-box)   │  │ (Sing-box)   │  │ (OCServ)     │  │ (Anti-DPI)   │
 └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘
```

---

## 📚 Matrix der unterstützten Protokolle

| # | Protokoll | Core | Default-Port | Sicherheitsmerkmale & Anti-DPI |
|:---:|---|---|:---:|---|
| 1 | **VLESS Reality** | Sing-box | 443 | Identitätsübernahme ausländischer TLS-Websites ohne lokale Zertifikate, 100% DPI-resistent. |
| 2 | **Trojan TLS** | Sing-box | 8443 (443) | Maskiert Datenverkehr als echtes HTTPS-Surfen mit gültigem TLS 1.3-Zertifikat. |
| 3 | **Hysteria 2** | Sing-box | 7443 UDP | Basiert auf QUIC mit Brutal Congestion Control; maximale Durchsatzraten bei hohem Paketverlust. |
| 4 | **TUIC v5** | Sing-box | 8448 UDP | QUIC HTTP/3 mit 0-RTT-Handshakes und minimalem Smartphone-Akkubedarf. |
| 5 | **Shadowsocks 2022**| Sing-box / Rust | 8388 | Moderne AEAD 2022-Verschlüsselung mit Schutz gegen aktives Scanning. |
| 6 | **NaiveProxy** | Sing-box | 8080 | Emuliert den echten Google Chrome-Netzwerkstack; nicht von normalem Webtraffic unterscheidbar. |
| 7 | **Google Apps Script**| Node / V8 | Google Webhook | Weiterleitung über IP-Adressen der Google Edge CDN; immun gegen regionale Sperren. |
| 8 | **WordPress Tarnseite**| Nginx + WP | 80, 443 | Voll funktionsfähiger WordPress-Blog zur Täuschung von Zensur-Scannern mit 200 OK. |
| 9 | **AmneziaWG (AWG)** | Kernel-Treiber | 51820 UDP | Obfuskiertes WireGuard mit Zufalls-Junk-Paketen (`Jc`, `Jmin`, `Jmax`). |
| 10 | **Standard WireGuard**| Kernel-Treiber | 51821 UDP | Ultra-schneller Kernel-Tunnel mit IPv4- und IPv6-Dual-Stack-Unterstützung. |
| 11 | **Cisco AnyConnect**| OCServ | 10443 (443) | Kompatibel mit offiziellen Cisco-Clients auf Android, iOS und Desktop-Systemen. |
| 12 | **Windows SSTP** | sstpd | 4443 (443) | Nativ in Windows integriert ohne Installation zusätzlicher Software. |
| 13 | **SlowDNS / DNSTT**| DNSTT Suite | 53 UDP | Funktioniert bei totalem Netzausfall über rekursive DNS-Anfragen. |
| 14 | **Tor Bridges** | Tor Core | 9050, 9051 | Offizielle Snowflake- und obfs4-Bridges zur Zensurumgehung. |

---

## 🧭 Interaktive Master-CLI (`mhpanel`)

Starten Sie die Terminal-Management-Konsole jederzeit direkt auf Ihrem Server:

```bash
mhpanel
```

```text
  ========================================================================
     🚀 MH PANEL Enterprise Master-CLI-Konsole (Version 1.8.0)
  ========================================================================
  Web-Panel Status: Online (IP:PORT/PATH) | Schnellbefehl: mhpanel
  ------------------------------------------------------------------------
  [1]  Vollautomatische Komplettinstallation (Alle Komponenten & Protokolle)
  [2]  Schritt-für-Schritt-Installationsassistent (Custom Wizard)
  [3]  Installation nur der leichtgewichtigen Web-UI (Web UI Only)
  ------------------------------------------------------------------------
  [4]  Panel-Zugriffs-URL, Administrator-Zugangsdaten und API-Schlüssel
  [5]  Administrator-Benutzername und Passwort ändern
  [6]  Panel-Port, Serveradresse und geheimen Zugriffspfad ändern
  [7]  Live-Diagnosebericht zu Systemhardware und Diensten
  [8]  VPN-Protokolle verwalten, installieren, entfernen und Ports anpassen
  [9]  Anti-Zensur-Tunnel und MikroTik RouterOS Bridge Hub
  [10] Webserver-Integration & WordPress-Tarnseiten-Studio
  [11] Telegram-Bot-Benachrichtigungen und automatische Backup-Zentrale
  [12] Web-Panel-Einstellungen (Logs, Neustart, 2FA und API-Schlüssel)
  [13] SSL-Zertifikatsverwaltung (Let's Encrypt und 10-Jahres-IP-SAN)
  [14] Netzwerk- und Kernel-Optimierung (BBR, IPv4/IPv6 Forwarding)
  [15] Backup erstellen und Panel-Konfiguration wiederherstellen
  [16] Schnellbefehls-Übersicht und Terminal-Shortcuts
  [17] Offizielle Updates von GitHub abrufen und installieren
  [18] MH Panel vollständig vom Server deinstallieren (Uninstall)
  [0]  Beenden
  ========================================================================
```

### ⚡ Nicht-interaktive Terminal-Schnellbefehle (CLI Shortcuts):

| Befehl | Beschreibung |
|---|---|
| `mhpanel` | Öffnet das interaktive Hauptmenü. |
| `mhpanel --status` | Sofortiger System- und Dienstedaten-Diagnosebericht. |
| `mhpanel --info` | Zeigt Web-URL, Zugangsdaten und API-Token an. |
| `mhpanel --user <benutzer>` | Ändert den Administrator-Benutzernamen direkt. |
| `mhpanel --pass <passwort>` | Ändert das Administrator-Passwort direkt. |
| `mhpanel --credentials <user> <pass>` | Ändert Benutzer und Passwort in einem einzigen Befehl. |
| `mhpanel --port <port>` | Ändert den Web-Panel-Port (z.B. `mhpanel --port 9443`). |
| `mhpanel --path <pfad>` | Setzt einen geheimen URL-Pfad (z.B. `mhpanel --path /geheim`). |
| `mhpanel --address <port> <pfad>` | Ändert Port und Pfad gleichzeitig. |
| `mhpanel --wp` | Öffnet den Einrichtungsassistenten für die WordPress-Tarnseite. |
| `mhpanel --tg` | Konfiguriert Telegram-Benachrichtigungen und testet Alarme. |
| `mhpanel --tunnels` | Öffnet das Tunnel-Menü und MikroTik-Skripte. |
| `mhpanel protocol <name> <aktion>` | Steuert ein bestimmtes Protokoll (z.B. `mhpanel protocol singbox restart`). |
| `mhpanel restart` | Startet den Web-Panel-Dienst sofort neu (`systemctl restart mhpanel`). |
| `mhpanel start` / `mhpanel stop` | Startet oder stoppt den Hintergrunddienst. |
| `mhpanel update` | Lädt die neuesten Updates direkt von GitHub herunter. |
| `mhpanel --uninstall` | Entfernt MH Panel und alle Abhängigkeiten restlos vom Server. |
| `mhpanel --help` | Zeigt die integrierte CLI-Hilfe an. |

---

## 🤝 Danksagungen und Upstream-Projekte (Upstream Projects)

MH Panel basiert auf den hervorragenden Innovationen der weltweiten Open-Source-Community:
- **[Sing-box (SagerNet)](https://github.com/SagerNet/sing-box)**: Universelle Proxy-Plattform (VLESS Reality, VMess, Trojan, ShadowTLS, Shadowsocks, TUIC, Hysteria 2).
- **[Hysteria 2 (AperNet)](https://github.com/apernet/hysteria)**: Extrem schnelles QUIC-basiertes Protokoll mit Brutal CC.
- **[TUIC (EAimTY)](https://github.com/EAimTY/tuic)**: 0-RTT QUIC HTTP/3 Proxy-Protokoll.
- **[Shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)**: Rust-Implementierung von Shadowsocks mit AEAD 2022.
- **[AmneziaWG](https://github.com/amnezia-vpn/amnezia-wg)** & **[wiresock/amneziawg-install](https://github.com/wiresock/amneziawg-install)**: Obfuskiertes WireGuard.
- **[OpenConnect (ocserv)](https://gitlab.com/openconnect/ocserv)**: SSL-VPN-Server für Cisco-Clients.
- **[Backhaul](https://github.com/Musixal/Backhaul)**, **[Rathole](https://github.com/rapiz1/rathole)**, **[Chisel](https://github.com/jpillora/chisel)**: Hochperformante Reverse-Tunnel.
- **[Marzban (Gozargah)](https://github.com/Gozargah/Marzban)**, **[3X-UI (MHSanaei)](https://github.com/MHSanaei/3x-ui)**, **[Hiddify Manager](https://github.com/hiddify/hiddify-manager)**: Architektonische Ideen und universelle Abonnement-Paradigmen.

---

## 💖 Projektunterstützung & Spenden (Donate & Support)

Die kontinuierliche Wartung von **MH Panel**, Erforschung neuester DPI-Umgehungsverfahren und die Miete internationaler Testserver erfordert erhebliche Ressourcen. Wenn Ihnen dieses Projekt geholfen hat, freuen wir uns über Ihre Spende:

<p align="center">
  <a href="https://donito.me/ME_Script" target="_blank">
    <img src="https://img.shields.io/badge/💖%20Spenden%20via%20Donito-Donito.me%2FME__Script-ff4757?style=for-the-badge&logo=heart&logoColor=white" alt="Spenden" height="45">
  </a>
</p>

<p align="center">
  ☕ <b>Offizieller Spendenlink:</b> <a href="https://donito.me/ME_Script" target="_blank"><b>https://donito.me/ME_Script</b></a>
</p>

---

## 📢 Offizieller Kanal & Community

- 📢 **Offizieller Telegram-Kanal:** [@kigaping_fa](https://t.me/kigaping_fa)

---

## 📄 Lizenz

Dieses Projekt ist unter der [MIT License](LICENSE) lizenziert.
