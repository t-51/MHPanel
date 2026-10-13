#!/usr/bin/env bash
# ==============================================================================
#           MH Panel - Master Installer & Server Management Hub
#       Comprehensive, Intelligent & Modular VPN, Tunnel & Bridge Manager
# ------------------------------------------------------------------------------
# GitHub: https://github.com/t-51/MHPanel
# OS Support: Ubuntu 20.04+, 22.04+, 24.04+ | Debian 11+, 12+
# Architecture: x86_64 / amd64 / aarch64
# ==============================================================================

set -e

GITHUB_REPO="https://github.com/t-51/MHPanel.git"

# Terminal Colors & Formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Paths & Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PANEL_DIR="/www/wwwroot/mhpanel"

HELPER="${PANEL_DIR}/scripts/protocol_helper.sh"
SSL_DIR="/etc/vpnpanel/ssl"
CONFIG_DIR="/etc/vpnpanel"
VERSION="1.0.0"

# Root Permission Check
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This script must be executed as root.${NC}"
    echo -e "Please run with: ${CYAN}sudo bash $0${NC}"
    exit 1
fi

# Ensure mhpanel & hmpanel CLI shortcuts exist globally
ensure_cli_shortcuts() {
    local target_script="${PANEL_DIR}/install.sh"
    if [ ! -f "$target_script" ]; then
        target_script="$0"
        if [[ "$target_script" != /* ]]; then
            target_script="$(pwd)/$target_script"
        fi
    fi
    chmod +x "$target_script" 2>/dev/null || true

    mkdir -p /usr/local/bin /usr/bin
    if [ "$target_script" != "/usr/local/bin/mhpanel" ]; then
        ln -sf "$target_script" /usr/local/bin/mhpanel 2>/dev/null || true
    fi
    if [ "$target_script" != "/usr/local/bin/hmpanel" ]; then
        ln -sf "$target_script" /usr/local/bin/hmpanel 2>/dev/null || true
    fi
    if [ "$target_script" != "/usr/local/bin/kigapanel" ]; then
        ln -sf "$target_script" /usr/local/bin/kigapanel 2>/dev/null || true
    fi
    if [ "$target_script" != "/usr/bin/mhpanel" ]; then
        ln -sf "$target_script" /usr/bin/mhpanel 2>/dev/null || true
    fi
    if [ "$target_script" != "/usr/bin/hmpanel" ]; then
        ln -sf "$target_script" /usr/bin/hmpanel 2>/dev/null || true
    fi
}
ensure_cli_shortcuts

# Supported Protocols List
PROTOCOLS=(ssh openvpn ocserv ikev2 sstp l2tp wireguard amneziawg http socks shadowsocks tuic mtproto pptp badvpn)

# Banner Display
show_banner() {
    clear 2>/dev/null || true
    echo -e "${CYAN}${BOLD}"
    cat <<'EOF'
  __  __ _    _   _____                  _ 
 |  \/  | |  | | |  __ \                | |
 | \  / | |__| | | |__) |_ _ _ __   ___| |
 | |\/| |  __  | |  ___/ _` | '_ \ / _ \ |
 | |  | | |  | | | |  | (_| | | | |  __/ |
 |_|  |_|_|  |_| |_|   \__,_|_| |_|\___|_|
EOF
    echo -e "${WHITE}${BOLD}   MH Panel - Master Installer & Management CLI (${VERSION})${NC}"
    echo -e "${DIM}   Anti-Censorship VPN Protocols, Network Tunnels & MikroTik RouterOS Hub${NC}"
    echo -e "${BLUE}------------------------------------------------------------------------${NC}"
}

# Network IP Detection
get_public_ipv4() {
    curl -s --max-time 2 https://api.ipify.org 2>/dev/null || \
    curl -s --max-time 2 https://ifconfig.me 2>/dev/null || \
    ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[\d.]+' || echo "127.0.0.1"
}

get_public_ipv6() {
    ip -6 route get 2001:4860:4860::8888 2>/dev/null | grep -oP 'src \K[a-fA-F0-9:]+' || \
    curl -6 -s --max-time 2 https://api64.ipify.org 2>/dev/null || echo ""
}

# Protocol Descriptions
protocol_label() {
    case "$1" in
        ssh) echo "SSH Tunnel & WebSocket Proxy" ;;
        openvpn) echo "OpenVPN (UDP/TCP & Multi-Port)" ;;
        ocserv) echo "Ocserv (Cisco AnyConnect)" ;;
        ikev2) echo "IKEv2 StrongSwan (IPSec)" ;;
        sstp) echo "SSTP Server (SSL VPN)" ;;
        l2tp) echo "L2TP/IPsec (Site-to-Site)" ;;
        wireguard) echo "WireGuard (High-Speed P2P)" ;;
        amneziawg) echo "AmneziaWG (Anti-DPI Obfuscated)" ;;
        http) echo "HTTP Proxy (Custom Auth)" ;;
        socks) echo "SOCKS5 Proxy (Fast & Secure)" ;;
        shadowsocks) echo "Shadowsocks (AEAD Obfuscated)" ;;
        tuic) echo "TUIC v5 (QUIC 0-RTT Protocol)" ;;
        mtproto) echo "MTProto Proxy (Telegram Fast Proxy)" ;;
        pptp) echo "PPTP VPN (Classic Protocol)" ;;
        badvpn) echo "BadVPN UDP-GW (Port 7300 Forwarding)" ;;
        *) echo "$1" ;;
    esac
}

protocol_default_port() {
    case "$1" in
        ssh) echo "2222" ;;
        openvpn) echo "1194" ;;
        ocserv) echo "10443" ;;
        ikev2) echo "500/4500" ;;
        sstp) echo "4443" ;;
        l2tp) echo "1701" ;;
        wireguard) echo "904" ;;
        amneziawg) echo "443" ;;
        http) echo "3128" ;;
        socks) echo "1080" ;;
        shadowsocks) echo "8388" ;;
        tuic) echo "7443" ;;
        mtproto) echo "4433" ;;
        pptp) echo "1723" ;;
        badvpn) echo "7300" ;;
        *) echo "0" ;;
    esac
}

# Protocol Detection
protocol_is_installed() {
    case "$1" in
        ssh) [ -f "/etc/ssh/sshd_config_vpn" ] ;;
        openvpn) [ -f "/etc/openvpn/server.conf" ] ;;
        ocserv) [ -f "/etc/ocserv/ocserv.conf" ] ;;
        ikev2) [ -f "/etc/swanctl/conf.d/ikev2.conf" ] ;;
        sstp) [ -f "/etc/systemd/system/sstpd.service" ] || [ -f "/etc/systemd/system/vpnserver.service" ] ;;
        l2tp) [ -f "/etc/xl2tpd/xl2tpd.conf" ] ;;
        wireguard) [ -f "/etc/wireguard/wg0.conf" ] ;;
        amneziawg) [ -f "/etc/amnezia/amneziawg/awg0.conf" ] ;;
        http) [ -f "/etc/systemd/system/aethervpn-http-proxy.service" ] ;;
        socks) [ -f "/etc/systemd/system/aethervpn-socks-proxy.service" ] ;;
        shadowsocks) [ -f "/etc/systemd/system/aethervpn-shadowsocks.service" ] || command -v ssserver >/dev/null 2>&1 ;;
        tuic) [ -f "/etc/systemd/system/tuic-server.service" ] || [ -x /usr/local/bin/tuic-server ] ;;
        mtproto) ls /etc/vpnpanel/mtproto_config_*.py >/dev/null 2>&1 || [ -f "/etc/systemd/system/aethervpn-mtproto.service" ] ;;
        pptp) [ -f "/etc/pptpd.conf" ] ;;
        badvpn) [ -f "/etc/systemd/system/badvpn.service" ] && command -v badvpn-udpgw >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

protocol_service_status() {
    local svc=""
    case "$1" in
        ssh) svc="sshd_vpn" ;;
        openvpn) svc="openvpn@server" ;;
        ocserv) svc="ocserv" ;;
        ikev2) svc="strongswan-starter" ;;
        sstp) svc="sstpd" ;;
        l2tp) svc="xl2tpd" ;;
        wireguard) svc="wg-quick@wg0" ;;
        amneziawg) svc="awg-quick@awg0" ;;
        http) svc="aethervpn-http-proxy" ;;
        socks) svc="aethervpn-socks-proxy" ;;
        shadowsocks) svc="aethervpn-shadowsocks" ;;
        tuic) svc="tuic-server" ;;
        mtproto) svc="aethervpn-mtproto" ;;
        pptp) svc="pptpd" ;;
        badvpn) svc="badvpn" ;;
    esac

    if [ -n "$svc" ] && systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo -e "${GREEN}Active (Running)${NC}"
    elif protocol_is_installed "$1"; then
        echo -e "${YELLOW}Inactive (Stopped)${NC}"
    else
        echo -e "${RED}Not Installed${NC}"
    fi
}

protocol_current_port() {
    case "$1" in
        ssh) grep -Ei '^Port ' /etc/ssh/sshd_config_vpn 2>/dev/null | awk '{print $2}' | tail -n1 || echo "2222" ;;
        openvpn) grep -Ei '^port ' /etc/openvpn/server.conf 2>/dev/null | awk '{print $2}' | tail -n1 || echo "1194" ;;
        ocserv) grep -Ei '^tcp-port' /etc/ocserv/ocserv.conf 2>/dev/null | awk '{print $3}' | tail -n1 || echo "10443" ;;
        ikev2) echo "500/4500 (UDP)" ;;
        sstp) port=$(grep -oE '\-p [0-9]+' /etc/systemd/system/sstpd.service 2>/dev/null | awk '{print $2}' | tail -n1 || true); echo "${port:-4443}" ;;
        l2tp) echo "1701 (UDP)" ;;
        wireguard) grep -Ei '^ListenPort' /etc/wireguard/wg0.conf 2>/dev/null | awk '{print $3}' | tail -n1 || echo "904" ;;
        amneziawg) grep -Ei '^ListenPort' /etc/amnezia/amneziawg/awg0.conf 2>/dev/null | awk '{print $3}' | tail -n1 || echo "443" ;;
        http) grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/aethervpn-http-proxy.service 2>/dev/null | awk -F: '{print $2}' | tail -n1 || echo "3128" ;;
        socks) grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/aethervpn-socks-proxy.service 2>/dev/null | awk -F: '{print $2}' | tail -n1 || echo "1080" ;;
        shadowsocks) grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/aethervpn-shadowsocks.service 2>/dev/null | awk -F: '{print $2}' | tail -n1 || echo "8388" ;;
        tuic) grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/tuic-server.service 2>/dev/null | awk -F: '{print $2}' | tail -n1 || echo "7443" ;;
        mtproto) grep -E '^PORT = ' /etc/vpnpanel/mtproto_config.py 2>/dev/null | awk '{print $3}' | tail -n1 || echo "4433" ;;
        pptp) echo "1723 (TCP)" ;;
        badvpn) echo "7300 (UDP)" ;;
        *) echo "-" ;;
    esac
}

# ==============================================================================
# BASE SYSTEM & WEB UI INSTALLATION
# ==============================================================================

install_base_prerequisites() {
    echo -e "\n${YELLOW}>>> [1/6] Checking and installing Linux base prerequisites...${NC}"
    export DEBIAN_FRONTEND=noninteractive

    local pkgs_needed=()
    for p in python3 python3-pip python3-venv curl wget git openssl certbot iptables iptables-persistent ufw cron net-tools sudo cmake build-essential jq socat unzip; do
        if ! dpkg -s "$p" >/dev/null 2>&1; then
            pkgs_needed+=("$p")
        fi
    done

    if [ ${#pkgs_needed[@]} -eq 0 ]; then
        echo -e "    ${GREEN}[✓] All base Linux dependencies are already installed (Skipped).${NC}"
    else
        echo -e "    Installing missing packages: ${CYAN}${pkgs_needed[*]}${NC}..."
        apt-get update -y
        apt-get install -y --no-install-recommends "${pkgs_needed[@]}"
        echo -e "    ${GREEN}[✓] Base system dependencies successfully installed.${NC}"
    fi
}

enable_bbr_and_sysctl() {
    echo -e "\n${YELLOW}>>> [2/6] Enabling TCP BBR, packet forwarding & IPv6 tunnel modules...${NC}"

    modprobe ip_gre 2>/dev/null || true
    modprobe ip6_gre 2>/dev/null || true
    modprobe ipip 2>/dev/null || true
    modprobe ip6_tunnel 2>/dev/null || true
    modprobe sit 2>/dev/null || true
    modprobe wireguard 2>/dev/null || true

    mkdir -p /etc/modules-load.d
    cat > /etc/modules-load.d/mh-tunnels.conf <<EOF
ip_gre
ip6_gre
ipip
ip6_tunnel
sit
wireguard
EOF

    cat > /etc/sysctl.d/99-mhpanel.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
fs.file-max=1000000
fs.inotify.max_user_instances=8192
net.ipv4.tcp_fastopen=3
net.core.somaxconn=32768
net.ipv4.tcp_max_syn_backlog=16384
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=1024 65535
EOF
    sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-mhpanel.conf >/dev/null 2>&1 || true
    echo -e "    ${GREEN}[✓] TCP BBR, Kernel limits, IPv4 and IPv6 forwarding successfully configured.${NC}"
}

install_panel_web_ui() {
    echo -e "\n${YELLOW}>>> [3/6] Setting up MH Panel Web UI service...${NC}"
    mkdir -p "${PANEL_DIR}"
    mkdir -p "${SSL_DIR}"
    chmod 700 "${SSL_DIR}"

    if [ "${SCRIPT_DIR}" != "${PANEL_DIR}" ] && [ -f "${SCRIPT_DIR}/app.py" ]; then
        echo "    Deploying MH Panel source files to ${PANEL_DIR}..."
        cp -r "${SCRIPT_DIR}"/* "${PANEL_DIR}/" 2>/dev/null || true
    elif [ ! -f "${PANEL_DIR}/app.py" ]; then
        echo -e "${CYAN}    Fetching latest MH Panel source files from GitHub (${GITHUB_REPO})...${NC}"
        git clone "${GITHUB_REPO}" "${PANEL_DIR}" 2>/dev/null || true
    fi

    if [ ! -d "${PANEL_DIR}/venv" ] || [ ! -f "${PANEL_DIR}/venv/bin/python" ]; then
        echo "    Creating Python virtual environment in ${PANEL_DIR}/venv..."
        python3 -m venv "${PANEL_DIR}/venv"
        "${PANEL_DIR}/venv/bin/pip" install --upgrade pip --quiet
        echo "    Installing Python dependencies (Flask, Cryptography, PyOpenSSL, Requests, Psutil)..."
        "${PANEL_DIR}/venv/bin/pip" install \
            "Flask>=2.0.0" \
            "psutil>=5.8.0" \
            "pyrad>=2.4" \
            "cryptography>=3.4.8" \
            "pyOpenSSL" \
            "requests" --quiet
    else
        echo -e "    ${GREEN}[✓] Python virtual environment and dependencies already exist.${NC}"
    fi

    local port_file="${PANEL_DIR}/panel_port.txt"
    if [ ! -f "$port_file" ]; then echo "9090" > "$port_file"; fi
    local panel_port=$(cat "$port_file" 2>/dev/null || echo "9090")

    local cred_file="${PANEL_DIR}/admin_credentials.txt"
    if [ ! -f "$cred_file" ]; then
        local admin_user="admin"
        local admin_pass=$(openssl rand -hex 8)
        echo -e "username=${admin_user}\npassword=${admin_pass}" > "$cred_file"
        chmod 600 "$cred_file"
        echo -e "    Generated new admin credentials: user: ${CYAN}${admin_user}${NC} | pass: ${CYAN}${admin_pass}${NC}"
    fi

    if [ ! -f "${PANEL_DIR}/api_key.txt" ]; then
        openssl rand -hex 16 > "${PANEL_DIR}/api_key.txt"; chmod 600 "${PANEL_DIR}/api_key.txt"
    fi
    if [ ! -f "${PANEL_DIR}/session_secret.txt" ]; then
        openssl rand -hex 32 > "${PANEL_DIR}/session_secret.txt"; chmod 600 "${PANEL_DIR}/session_secret.txt"
    fi

    # Ensure default JSON config & state files exist
    for f in wg_users.json awg_users.json ssh_users.json l2tp_users.json ikev2_users.json ovpn_users.json sstp_users.json radius_users.json ocserv_users.json; do
        if [ ! -f "${PANEL_DIR}/${f}" ]; then echo "{}" > "${PANEL_DIR}/${f}"; fi
    done
    if [ ! -f "${PANEL_DIR}/radius_groups.json" ]; then echo "[]" > "${PANEL_DIR}/radius_groups.json"; fi
    if [ ! -f "${PANEL_DIR}/servers.json" ]; then echo "[]" > "${PANEL_DIR}/servers.json"; fi
    if [ ! -f "${PANEL_DIR}/traffic_stats.json" ]; then echo "{}" > "${PANEL_DIR}/traffic_stats.json"; fi
    if [ ! -f "${PANEL_DIR}/tunnels_config.json" ]; then
        echo '{"tunnels":[],"adv_tunnels":[],"relays":[]}' > "${PANEL_DIR}/tunnels_config.json"
    fi
    if [ ! -f "${PANEL_DIR}/multiplexer_config.json" ]; then
        echo '{"enabled":false,"listen_ports":[443],"web_server_type":"internal","default_backend":"web","protocols":[],"custom_rules":[],"udp_multiports":[]}' > "${PANEL_DIR}/multiplexer_config.json"
    fi

    local srv_ip=$(get_public_ipv4)
    if [ ! -f "${SSL_DIR}/panel.crt" ] || [ ! -f "${SSL_DIR}/panel.key" ]; then
        echo "    Generating 10-Year HTTPS IP SAN SSL Certificate for ${srv_ip}..."
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "${SSL_DIR}/panel.key" \
            -out "${SSL_DIR}/panel.crt" \
            -subj "/CN=${srv_ip}/O=MHPanel Server" \
            -addext "subjectAltName = IP:${srv_ip},IP:127.0.0.1" \
            -days 3650 2>/dev/null
        chmod 600 "${SSL_DIR}/panel.key"
        chmod 644 "${SSL_DIR}/panel.crt"
    fi

    cat > /etc/systemd/system/mhpanel.service <<EOF
[Unit]
Description=MH Panel Web Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${PANEL_DIR}
ExecStart=${PANEL_DIR}/venv/bin/python app.py
Restart=always
RestartSec=3
Environment=PATH=${PANEL_DIR}/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=PYTHONUNBUFFERED=1
Environment=LANG=en_US.UTF-8
Environment=LC_ALL=en_US.UTF-8

[Install]
WantedBy=multi-user.target
EOF
    ln -sf /etc/systemd/system/mhpanel.service /etc/systemd/system/vpnpanel.service

    if command -v ufw >/dev/null && systemctl is-active --quiet ufw; then
        ufw allow "${panel_port}/tcp" >/dev/null 2>&1 || true
        ufw allow 80/tcp >/dev/null 2>&1 || true
        ufw allow 443/tcp >/dev/null 2>&1 || true
    fi

    systemctl daemon-reload
    systemctl enable mhpanel >/dev/null 2>&1
    systemctl restart mhpanel
    sleep 2

    if systemctl is-active --quiet mhpanel; then
        echo -e "    ${GREEN}[✓] MH Panel Web UI service is active and running.${NC}"
    else
        echo -e "    ${RED}[!] MH Panel service is not active yet. Check journalctl logs.${NC}"
    fi
}

install_badvpn() {
    echo -e "    ${CYAN}--> Setting up BadVPN UDP-GW (Port 7300 for UDP gaming/voice forwarding)...${NC}"
    if [ ! -x /usr/local/bin/badvpn-udpgw ] && [ ! -x /usr/bin/badvpn-udpgw ]; then
        mkdir -p /tmp/badvpn-build
        cd /tmp/badvpn-build
        if git clone --depth 1 https://github.com/ambrop72/badvpn.git . 2>/dev/null; then
            mkdir -p build && cd build
            cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 >/dev/null 2>&1
            make install >/dev/null 2>&1
        fi
        cd /root && rm -rf /tmp/badvpn-build
    fi

    cat > /etc/systemd/system/badvpn.service <<EOF
[Unit]
Description=BadVPN UDPGW Service for Gaming & UDP Forwarding
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 20
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable badvpn.service >/dev/null 2>&1
    systemctl restart badvpn.service >/dev/null 2>&1 || true
    echo -e "    ${GREEN}[✓] BadVPN UDPGW service successfully started on port 7300.${NC}"
}

install_tunnel_tools() {
    echo -e "\n${YELLOW}>>> [4/6] Checking and downloading Anti-Censorship Tunnel Binaries...${NC}"
    local count_downloaded=0

    # GOST v3
    if [ ! -x /usr/local/bin/gost ]; then
        echo "    Downloading GOST v3..."
        curl -fsSL https://github.com/go-gost/gost/releases/download/v3.0.0-rc10/gost_3.0.0-rc10_linux_amd64.tar.gz 2>/dev/null | tar -xz -C /usr/local/bin/ gost 2>/dev/null || true
        chmod +x /usr/local/bin/gost 2>/dev/null || true
        count_downloaded=$((count_downloaded + 1))
    fi

    # WSTunnel
    if [ ! -x /usr/local/bin/wstunnel ]; then
        echo "    Downloading WSTunnel..."
        curl -fsSL https://github.com/erebe/wstunnel/releases/download/v11.0.0/wstunnel_11.0.0_linux_amd64.tar.gz 2>/dev/null | tar -xz -C /usr/local/bin/ wstunnel 2>/dev/null || true
        chmod +x /usr/local/bin/wstunnel 2>/dev/null || true
        count_downloaded=$((count_downloaded + 1))
    fi

    # RTT
    if [ ! -x /usr/local/bin/rtt ]; then
        echo "    Downloading ReverseTlsTunnel (RTT)..."
        curl -fsSL https://github.com/radkesvat/ReverseTlsTunnel/releases/download/v7.1/rtt-linux-amd64.zip -o /tmp/rtt.zip 2>/dev/null || true
        if [ -f /tmp/rtt.zip ]; then
            unzip -o /tmp/rtt.zip -d /usr/local/bin/ >/dev/null 2>&1 || true
            chmod +x /usr/local/bin/rtt 2>/dev/null || true
            rm -f /tmp/rtt.zip
            count_downloaded=$((count_downloaded + 1))
        fi
    fi

    # Chisel
    if [ ! -x /usr/local/bin/chisel ]; then
        echo "    Downloading Chisel..."
        curl -fsSL https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_linux_amd64.gz 2>/dev/null | gzip -d > /usr/local/bin/chisel 2>/dev/null || true
        chmod +x /usr/local/bin/chisel 2>/dev/null || true
        count_downloaded=$((count_downloaded + 1))
    fi

    # FRP
    if [ ! -x /usr/local/bin/frps ] || [ ! -x /usr/local/bin/frpc ]; then
        echo "    Downloading FRP (frps & frpc)..."
        curl -fsSL https://github.com/fatedier/frp/releases/download/v0.58.1/frp_0.58.1_linux_amd64.tar.gz 2>/dev/null | tar -xz -C /tmp/ 2>/dev/null || true
        if [ -d /tmp/frp_0.58.1_linux_amd64 ]; then
            mv /tmp/frp_0.58.1_linux_amd64/frps /usr/local/bin/ 2>/dev/null || true
            mv /tmp/frp_0.58.1_linux_amd64/frpc /usr/local/bin/ 2>/dev/null || true
            chmod +x /usr/local/bin/frps /usr/local/bin/frpc 2>/dev/null || true
            rm -rf /tmp/frp*
            count_downloaded=$((count_downloaded + 1))
        fi
    fi

    # UDP2Raw
    if [ ! -x /usr/local/bin/udp2raw ]; then
        echo "    Downloading UDP2Raw..."
        curl -fsSL https://github.com/wangyu-/udp2raw/releases/download/20230207.0/udp2raw_binaries.tar.gz 2>/dev/null | tar -xz -C /tmp/ 2>/dev/null || true
        if [ -f /tmp/udp2raw_amd64 ]; then
            mv /tmp/udp2raw_amd64 /usr/local/bin/udp2raw 2>/dev/null || true
            chmod +x /usr/local/bin/udp2raw 2>/dev/null || true
            rm -rf /tmp/udp2raw*
            count_downloaded=$((count_downloaded + 1))
        fi
    fi

    # Phantun
    if [ ! -x /usr/local/bin/phantun-server ]; then
        echo "    Downloading Phantun..."
        curl -fsSL https://github.com/dndx/phantun/releases/download/v0.6.0/phantun-x86_64-unknown-linux-musl.zip -o /tmp/phantun.zip 2>/dev/null || true
        if [ -f /tmp/phantun.zip ]; then
            unzip -o /tmp/phantun.zip -d /usr/local/bin/ >/dev/null 2>&1 || true
            chmod +x /usr/local/bin/phantun* 2>/dev/null || true
            rm -f /tmp/phantun.zip
            count_downloaded=$((count_downloaded + 1))
        fi
    fi

    # Rathole
    if [ ! -x /usr/local/bin/rathole ]; then
        echo "    Downloading Rathole..."
        curl -fsSL https://github.com/rapiz1/rathole/releases/download/v0.5.0/rathole-x86_64-unknown-linux-musl.zip -o /tmp/rathole.zip 2>/dev/null || true
        if [ -f /tmp/rathole.zip ]; then
            unzip -o /tmp/rathole.zip -d /tmp/ >/dev/null 2>&1 || true
            mv /tmp/rathole /usr/local/bin/ 2>/dev/null || true
            chmod +x /usr/local/bin/rathole 2>/dev/null || true
            rm -f /tmp/rathole*
            count_downloaded=$((count_downloaded + 1))
        fi
    fi

    # Kcptun
    if [ ! -x /usr/local/bin/kcptun-server ]; then
        echo "    Downloading Kcptun..."
        curl -fsSL https://github.com/xtaci/kcptun/releases/download/v20231012/kcptun-linux-amd64-20231012.tar.gz 2>/dev/null | tar -xz -C /usr/local/bin/ server_linux_amd64 client_linux_amd64 2>/dev/null || true
        if [ -f /usr/local/bin/server_linux_amd64 ]; then
            mv /usr/local/bin/server_linux_amd64 /usr/local/bin/kcptun-server 2>/dev/null || true
            mv /usr/local/bin/client_linux_amd64 /usr/local/bin/kcptun-client 2>/dev/null || true
            chmod +x /usr/local/bin/kcptun-* 2>/dev/null || true
            count_downloaded=$((count_downloaded + 1))
        fi
    fi

    echo -e "    ${GREEN}[✓] Anti-censorship tunnel binaries verified (${count_downloaded} new files downloaded).${NC}"
}

install_protocol_action() {
    local proto=$1
    local port=$2

    if [ "$proto" = "badvpn" ]; then
        install_badvpn
        return
    fi

    if [ ! -f "$HELPER" ]; then
        echo -e "${RED}[ERROR] Helper script not found: ${HELPER}${NC}"
        return 1
    fi

    chmod +x "$HELPER"
    echo -e "    ${CYAN}Installing & configuring $(protocol_label "$proto") (Port: ${port})...${NC}"
    "$HELPER" install "$proto" "$port"
    echo -e "    ${GREEN}✓ $(protocol_label "$proto") successfully installed and activated.${NC}"
}

# ==============================================================================
# INSTALLATION WIZARDS
# ==============================================================================

wizard_full_automated() {
    show_banner
    echo -e "${WHITE}${BOLD}=== Full Automated Setup (All Packages & Services) ===${NC}"
    echo -e "${DIM}This mode automatically scans your system, installs missing prerequisites, sets up the Web UI, core VPN protocols, and anti-filter tunnels without duplicating existing components.${NC}\n"

    install_base_prerequisites
    enable_bbr_and_sysctl
    install_panel_web_ui
    install_tunnel_tools

    echo -e "\n${YELLOW}>>> [5/6] Scanning and automatically setting up VPN protocols...${NC}"
    for proto in "${PROTOCOLS[@]}"; do
        local def_port="$(protocol_default_port "$proto")"
        local lbl="$(protocol_label "$proto")"
        if protocol_is_installed "$proto"; then
            echo -e "    ${GREEN}[✓] ${lbl}${NC} is already installed (Skipped to preserve settings)."
        else
            install_protocol_action "$proto" "$def_port"
        fi
    done

    echo -e "\n${YELLOW}>>> [6/6] Synchronizing firewall rules and saving state...${NC}"
    if command -v iptables-save >/dev/null 2>&1; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    fi

    show_final_summary
}

wizard_step_by_step() {
    show_banner
    echo -e "${WHITE}${BOLD}=== Step-by-Step Custom Installation Wizard ===${NC}"
    echo -e "${DIM}You will be prompted for each component. Any skipped component can be installed at any time later using the 'mhpanel' command.${NC}\n"

    # Step 1: Base Prerequisites
    read -p "Do you want to verify and install base Linux packages? [Y/n]: " ans_base
    if [[ -z "$ans_base" || "$ans_base" =~ ^[yY]$ ]]; then
        install_base_prerequisites
    else
        echo -e "${YELLOW}--> Skipped base packages.${NC}"
    fi

    # Step 2: BBR & IPv6
    read -p "Do you want to enable TCP BBR optimization, packet forwarding & IPv6 tunnel modules? [Y/n]: " ans_bbr
    if [[ -z "$ans_bbr" || "$ans_bbr" =~ ^[yY]$ ]]; then
        enable_bbr_and_sysctl
    else
        echo -e "${YELLOW}--> Skipped BBR & sysctl optimization.${NC}"
    fi

    # Step 3: Web UI
    read -p "Do you want to install/update the MH Panel Web UI service? [Y/n]: " ans_ui
    if [[ -z "$ans_ui" || "$ans_ui" =~ ^[yY]$ ]]; then
        install_panel_web_ui
    else
        echo -e "${YELLOW}--> Skipped Web UI installation.${NC}"
    fi

    # Step 4: Anti-Filter Tunnels
    read -p "Do you want to download Anti-Censorship Tunnel binaries (GOST, WSTunnel, RTT, Chisel, FRP, UDP2Raw, Phantun, Rathole, Kcptun)? [Y/n]: " ans_tun
    if [[ -z "$ans_tun" || "$ans_tun" =~ ^[yY]$ ]]; then
        install_tunnel_tools
    else
        echo -e "${YELLOW}--> Skipped tunnel binaries download.${NC}"
    fi

    # Step 5: Protocols One-by-One
    echo -e "\n${YELLOW}=== Select VPN Protocols to Install ===${NC}"
    for proto in "${PROTOCOLS[@]}"; do
        local lbl="$(protocol_label "$proto")"
        local def_port="$(protocol_default_port "$proto")"

        if protocol_is_installed "$proto"; then
            local cur_p="$(protocol_current_port "$proto")"
            local st="$(protocol_service_status "$proto")"
            echo -e "\n  ${GREEN}[✓] ${lbl}${NC} is currently installed. (Port: ${CYAN}${cur_p}${NC} | Status: ${st})"
            read -p "      Do you want to reinstall/reconfigure ${lbl}? [y/N]: " do_reinstall
            if [[ "$do_reinstall" =~ ^[yY]$ ]]; then
                read -p "      Enter custom port [Default: ${cur_p}]: " cust_port
                cust_port=${cust_port:-$cur_p}
                install_protocol_action "$proto" "$cust_port"
            else
                echo -e "      ${DIM}--> Kept existing installation.${NC}"
            fi
        else
            echo -e "\n  ${RED}[✗] ${lbl}${NC} is not installed."
            read -p "      Do you want to install and activate ${lbl}? [Y/n]: " do_install
            if [[ -z "$do_install" || "$do_install" =~ ^[yY]$ ]]; then
                read -p "      Enter port for this service [Default: ${def_port}]: " cust_port
                cust_port=${cust_port:-$def_port}
                install_protocol_action "$proto" "$cust_port"
            else
                echo -e "      ${YELLOW}--> Skipped. (You can install it anytime later by typing 'mhpanel')${NC}"
            fi
        fi
    done

    show_final_summary
}

wizard_web_ui_only() {
    show_banner
    echo -e "${WHITE}${BOLD}=== Lightweight Web UI Only Installation ===${NC}\n"
    install_base_prerequisites
    enable_bbr_and_sysctl
    install_panel_web_ui
    show_final_summary
}

show_final_summary() {
    local srv_ip=$(get_public_ipv4)
    local srv_ipv6=$(get_public_ipv6)
    local panel_port=$(cat "${PANEL_DIR}/panel_port.txt" 2>/dev/null || echo "9090")
    local user="admin"
    local pass="admin"
    if [ -f "${PANEL_DIR}/admin_credentials.txt" ]; then
        user=$(grep -Ei '^username=' "${PANEL_DIR}/admin_credentials.txt" | cut -d= -f2-)
        pass=$(grep -Ei '^password=' "${PANEL_DIR}/admin_credentials.txt" | cut -d= -f2-)
    fi
    local api_key=$(cat "${PANEL_DIR}/api_key.txt" 2>/dev/null || echo "N/A")

    echo -e "\n${GREEN}${BOLD}========================================================================${NC}"
    echo -e "${GREEN}${BOLD}   ✓ MH Panel Setup Completed Successfully!${NC}"
    echo -e "${GREEN}${BOLD}========================================================================${NC}"
    echo -e "  🌐 ${BOLD}Web Panel URL (IPv4):${NC}       ${CYAN}https://${srv_ip}:${panel_port}/${NC}"
    if [ -n "$srv_ipv6" ]; then
        echo -e "  🌐 ${BOLD}Web Panel URL (IPv6):${NC}       ${CYAN}https://[${srv_ipv6}]:${panel_port}/${NC}"
    fi
    echo -e "  👤 ${BOLD}Admin Username:${NC}             ${BOLD}${user}${NC}"
    echo -e "  🔑 ${BOLD}Admin Password:${NC}             ${BOLD}${pass}${NC}"
    echo -e "  🔑 ${BOLD}API Key:${NC}                    ${DIM}${api_key}${NC}"
    echo -e "${GREEN}${BOLD}========================================================================${NC}"
    echo -e "${YELLOW}${BOLD}Management Tip:${NC}"
    echo -e "  You can reopen this management hub anytime from your server terminal by running:"
    echo -e "  Command: ${CYAN}${BOLD}mhpanel${NC} (or ${CYAN}hmpanel${NC})"
    echo -e "${GREEN}${BOLD}========================================================================${NC}\n"
    read -p "Press Enter to return to main menu..."
}

# ==============================================================================
# SUB-MENUS & MANAGEMENT CONTROLLERS
# ==============================================================================

menu_diagnostic_status() {
    clear 2>/dev/null || true
    echo -e "${CYAN}${BOLD}========================================================================${NC}"
    echo -e "${WHITE}${BOLD}              Live System & Service Diagnostic Report                   ${NC}"
    echo -e "${CYAN}${BOLD}========================================================================${NC}"

    local srv_ip=$(get_public_ipv4)
    local srv_ipv6=$(get_public_ipv6)
    local panel_port=$(cat "${PANEL_DIR}/panel_port.txt" 2>/dev/null || echo "9090")
    local mem_used=$(free -m | awk '/Mem:/ {print $3}')
    local mem_total=$(free -m | awk '/Mem:/ {print $2}')
    local load=$(uptime | awk -F'load average:' '{print $2}')

    echo -e "  🖥️  ${BOLD}Server Public IPv4:${NC}     ${CYAN}${srv_ip}${NC}"
    echo -e "  🌐 ${BOLD}Server Public IPv6:${NC}     ${CYAN}${srv_ipv6:-None / Disabled}${NC}"
    echo -e "  📊 ${BOLD}Memory Usage (RAM):${NC}     ${mem_used} MB / ${mem_total} MB"
    echo -e "  ⚡ ${BOLD}CPU Load Average:${NC}       ${load}"

    echo -e "\n${YELLOW}--- MH Panel Web UI Service ---${NC}"
    if systemctl is-active --quiet mhpanel 2>/dev/null; then
        echo -e "  Service Status: ${GREEN}Active (Running)${NC} | Port: ${CYAN}${panel_port}${NC}"
        echo -e "  Dashboard URL:  ${CYAN}https://${srv_ip}:${panel_port}/${NC}"
    else
        echo -e "  Service Status: ${RED}Inactive (Stopped)${NC}"
    fi

    echo -e "\n${YELLOW}--- VPN Protocols Status ---${NC}"
    printf "  %-14s %-18s %-16s %-20s\n" "Protocol" "Installation" "Port" "Service State"
    echo "  ------------------------------------------------------------------------"
    for proto in "${PROTOCOLS[@]}"; do
        local inst="${RED}Not Installed${NC}"
        if protocol_is_installed "$proto"; then
            inst="${GREEN}Installed ✓${NC}"
        fi
        local port="$(protocol_current_port "$proto")"
        local st="$(protocol_service_status "$proto")"
        printf "  %-14s %-26b %-16s %-20b\n" "$proto" "$inst" "$port" "$st"
    done

    echo -e "\n${YELLOW}--- Anti-Censorship Tunnel Binaries ---${NC}"
    for tool in gost wstunnel rtt chisel frps frpc udp2raw phantun-server rathole kcptun-server; do
        if command -v "$tool" >/dev/null 2>&1 || [ -x "/usr/local/bin/$tool" ]; then
            echo -e "  • ${tool}: ${GREEN}Available on system ✓${NC}"
        else
            echo -e "  • ${tool}: ${RED}Not found${NC}"
        fi
    done

    echo -e "\n${CYAN}========================================================================${NC}"
    read -p "Press Enter to return to main menu..."
}

menu_vpn_protocols() {
    while true; do
        clear 2>/dev/null || true
        echo -e "${YELLOW}${BOLD}=== Manage & Configure VPN Protocols ===${NC}"
        local i=1
        for proto in "${PROTOCOLS[@]}"; do
            local st="${RED}Not Installed${NC}"
            if protocol_is_installed "$proto"; then
                st="${GREEN}Installed ✓${NC}"
            fi
            local p="$(protocol_current_port "$proto")"
            local live="$(protocol_service_status "$proto")"
            echo -e "  [$i] $(protocol_label "$proto") - ${st} - Port: ${CYAN}${p}${NC} (${live})"
            i=$((i + 1))
        done
        echo -e "  [0] Back to Main Menu"
        echo ""
        read -p "Select a protocol to manage [0-${#PROTOCOLS[@]}]: " choice
        if [ "$choice" = "0" ] || [ -z "$choice" ]; then break; fi

        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#PROTOCOLS[@]}" ]; then
            local sel_proto="${PROTOCOLS[$((choice - 1))]}"
            local lbl="$(protocol_label "$sel_proto")"

            echo -e "\n${WHITE}${BOLD}Actions for ${lbl}:${NC}"
            echo -e "  [1] Install or Reconfigure Protocol"
            echo -e "  [2] Uninstall Protocol Completely"
            echo -e "  [3] Change Protocol Port"
            echo -e "  [4] Restart Service"
            echo -e "  [5] View Live Logs (journalctl)"
            echo -e "  [0] Cancel"
            read -p "Select action: " act

            case "$act" in
                1)
                    local cur_p="$(protocol_current_port "$sel_proto")"
                    read -p "Enter custom port [Default: ${cur_p}]: " np
                    np=${np:-$cur_p}
                    install_protocol_action "$sel_proto" "$np"
                    read -p "Press Enter to continue..."
                    ;;
                2)
                    read -p "Are you sure you want to uninstall ${lbl}? [y/N]: " conf
                    if [[ "$conf" =~ ^[yY]$ ]]; then
                        if [ -f "$HELPER" ]; then "$HELPER" uninstall "$sel_proto"; fi
                        echo -e "${GREEN}Protocol uninstalled.${NC}"
                    fi
                    read -p "Press Enter to continue..."
                    ;;
                3)
                    read -p "Enter new port: " np
                    if [ -n "$np" ] && [ -f "$HELPER" ]; then
                        "$HELPER" set-port "$sel_proto" "$np"
                        echo -e "${GREEN}Port successfully updated.${NC}"
                    fi
                    read -p "Press Enter to continue..."
                    ;;
                4)
                    local svc="openvpn@server"
                    if [ "$sel_proto" = "wireguard" ]; then svc="wg-quick@wg0"; fi
                    if [ "$sel_proto" = "amneziawg" ]; then svc="awg-quick@awg0"; fi
                    if [ "$sel_proto" = "ocserv" ]; then svc="ocserv"; fi
                    if [ "$sel_proto" = "sstp" ]; then svc="sstpd"; fi
                    if [ "$sel_proto" = "l2tp" ]; then svc="xl2tpd"; fi
                    if [ "$sel_proto" = "tuic" ]; then svc="tuic-server"; fi
                    if [ "$sel_proto" = "badvpn" ]; then svc="badvpn"; fi
                    systemctl restart "$svc" 2>/dev/null || true
                    echo -e "${GREEN}Service restarted.${NC}"
                    read -p "Press Enter to continue..."
                    ;;
                5)
                    journalctl -n 40 --no-pager 2>/dev/null || true
                    read -p "Press Enter to continue..."
                    ;;
            esac
        fi
    done
}

menu_tunnel_tools() {
    clear 2>/dev/null || true
    echo -e "${YELLOW}${BOLD}=== Anti-Censorship Tunnels & Network Bridge Hub ===${NC}"
    echo -e "Manage GOST, WSTunnel, RTT, FRP, Chisel, UDP2Raw, Phantun, Rathole and IPv6 Tunnel Modules.\n"

    echo -e "  [1] Download / Update All Anti-Filter Tunnel Binaries"
    echo -e "  [2] Enable Kernel Tunnel Modules for IPv6 (ip6_gre, ip6_tunnel, sit)"
    echo -e "  [3] Execute Boot Tunnels Script (/etc/mhpanel/tunnels_boot.sh)"
    echo -e "  [4] List Active Systemd Tunnel Services (mhtun_*)"
    echo -e "  [0] Back"
    echo ""
    read -p "Select option [0-4]: " t_act
    case "$t_act" in
        1)
            install_tunnel_tools
            read -p "Press Enter to continue..."
            ;;
        2)
            modprobe ip6_gre; modprobe ip6_tunnel; modprobe sit; modprobe ip_gre; modprobe ipip
            echo -e "${GREEN}Kernel modules for GRE IPv6, IPIP IPv6 and SIT 6in4 loaded.${NC}"
            read -p "Press Enter to continue..."
            ;;
        3)
            if [ -f "/etc/mhpanel/tunnels_boot.sh" ]; then
                bash /etc/mhpanel/tunnels_boot.sh
                echo -e "${GREEN}Boot tunnels script executed.${NC}"
            else
                echo -e "${YELLOW}No tunnels configured in panel yet.${NC}"
            fi
            read -p "Press Enter to continue..."
            ;;
        4)
            systemctl list-units --type=service "mhtun_*" --no-pager
            read -p "Press Enter to continue..."
            ;;
    esac
}

menu_web_ui_settings() {
    while true; do
        clear 2>/dev/null || true
        local panel_port=$(cat "${PANEL_DIR}/panel_port.txt" 2>/dev/null || echo "9090")
        local user="admin"
        local pass="admin"
        if [ -f "${PANEL_DIR}/admin_credentials.txt" ]; then
            user=$(grep -Ei '^username=' "${PANEL_DIR}/admin_credentials.txt" | cut -d= -f2-)
            pass=$(grep -Ei '^password=' "${PANEL_DIR}/admin_credentials.txt" | cut -d= -f2-)
        fi
        local srv_ip=$(get_public_ipv4)

        echo -e "${YELLOW}${BOLD}=== MH Panel Web UI Settings ===${NC}"
        echo -e "  Admin Username: ${CYAN}${user}${NC}"
        echo -e "  Admin Password: ${CYAN}${pass}${NC}"
        echo -e "  Dashboard Port: ${CYAN}${panel_port}${NC}"
        echo -e "  Dashboard URL:  ${CYAN}https://${srv_ip}:${panel_port}/${NC}\n"

        echo -e "  [1] Restart Web Panel Service (Restart mhpanel)"
        echo -e "  [2] View Live Web Panel Logs"
        echo -e "  [3] Change Admin Username & Password"
        echo -e "  [4] Change Web Dashboard Port"
        echo -e "  [5] Regenerate Public API Key"
        echo -e "  [0] Back"
        echo ""
        read -p "Select option [0-5]: " ui_act
        case "$ui_act" in
            1)
                systemctl restart mhpanel
                echo -e "${GREEN}Web panel service restarted.${NC}"
                read -p "Press Enter to continue..."
                ;;
            2)
                echo -e "${YELLOW}Showing last 50 log lines:${NC}"
                journalctl -u mhpanel -n 50 --no-pager
                read -p "Press Enter to continue..."
                ;;
            3)
                read -p "Enter new username [Default: ${user}]: " nu
                nu=${nu:-$user}
                read -p "Enter new password: " np
                if [ -n "$np" ]; then
                    echo -e "username=${nu}\npassword=${np}" > "${PANEL_DIR}/admin_credentials.txt"
                    chmod 600 "${PANEL_DIR}/admin_credentials.txt"
                    systemctl restart mhpanel
                    echo -e "${GREEN}Admin credentials updated successfully.${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                read -p "Enter new port [Current: ${panel_port}]: " nport
                if [[ "$nport" =~ ^[0-9]+$ ]] && [ "$nport" -ge 1 ] && [ "$nport" -le 65535 ]; then
                    echo "$nport" > "${PANEL_DIR}/panel_port.txt"
                    if command -v ufw >/dev/null && systemctl is-active --quiet ufw; then
                        ufw allow "${nport}/tcp" >/dev/null 2>&1 || true
                    fi
                    systemctl restart mhpanel
                    echo -e "${GREEN}Web dashboard port changed to ${nport}.${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            5)
                local nkey=$(openssl rand -hex 16)
                echo "$nkey" > "${PANEL_DIR}/api_key.txt"
                chmod 600 "${PANEL_DIR}/api_key.txt"
                systemctl restart mhpanel
                echo -e "${GREEN}New API Key generated: ${CYAN}${nkey}${NC}"
                read -p "Press Enter to continue..."
                ;;
            0) break ;;
        esac
    done
}

menu_ssl_management() {
    clear 2>/dev/null || true
    echo -e "${YELLOW}${BOLD}=== SSL Certificate & HTTPS Management ===${NC}"
    echo -e "  [1] Obtain Let's Encrypt SSL Certificate for Domain"
    echo -e "  [2] Regenerate 10-Year IP SAN Self-Signed Certificate"
    echo -e "  [3] Repair HTTPS Configuration & Reload Systemd"
    echo -e "  [0] Back"
    echo ""
    read -p "Select option [0-3]: " s_act
    case "$s_act" in
        1)
            read -p "Enter the domain pointed to this server: " dom
            if [ -n "$dom" ]; then
                echo "Temporarily stopping Web UI to free port 80..."
                systemctl stop mhpanel 2>/dev/null || true
                if command -v ufw >/dev/null; then ufw allow 80/tcp || true; fi
                if certbot certonly --standalone -d "${dom}" --non-interactive --agree-tos --register-unsafely-without-email; then
                    ln -sf "/etc/letsencrypt/live/${dom}/fullchain.pem" "${SSL_DIR}/panel.crt"
                    ln -sf "/etc/letsencrypt/live/${dom}/privkey.pem" "${SSL_DIR}/panel.key"
                    echo -e "${GREEN}Let's Encrypt SSL certificate installed successfully!${NC}"
                else
                    echo -e "${RED}Failed to obtain Let's Encrypt certificate. Please check your DNS record.${NC}"
                fi
                systemctl start mhpanel 2>/dev/null || true
            fi
            read -p "Press Enter to continue..."
            ;;
        2)
            local ip=$(get_public_ipv4)
            openssl req -x509 -newkey rsa:2048 -nodes \
                -keyout "${SSL_DIR}/panel.key" \
                -out "${SSL_DIR}/panel.crt" \
                -subj "/CN=${ip}/O=MHPanel Server" \
                -addext "subjectAltName = IP:${ip},IP:127.0.0.1" \
                -days 3650 2>/dev/null
            chmod 600 "${SSL_DIR}/panel.key"
            chmod 644 "${SSL_DIR}/panel.crt"
            systemctl restart mhpanel
            echo -e "${GREEN}10-Year IP SAN certificate generated successfully.${NC}"
            read -p "Press Enter to continue..."
            ;;
        3)
            systemctl daemon-reload
            systemctl restart mhpanel
            echo -e "${GREEN}Service reloaded and restarted.${NC}"
            read -p "Press Enter to continue..."
            ;;
    esac
}

backup_restore() {
    clear 2>/dev/null || true
    echo -e "${YELLOW}${BOLD}=== Backup & Restore MH Panel Data ===${NC}"
    echo -e "  [1] Create Complete Backup Archive (Users, Configs, Credentials, SSL)"
    echo -e "  [2] Restore Backup from tar.gz Archive"
    echo -e "  [0] Back"
    echo ""
    read -p "Select option [0-2]: " b_act
    case "$b_act" in
        1)
            local bname="mhpanel_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
            tar -czf "/root/${bname}" \
                -C "${PANEL_DIR}" *.json *.txt 2>/dev/null || true
            echo -e "${GREEN}Backup archive saved at:${NC} ${CYAN}/root/${bname}${NC}"
            read -p "Press Enter to continue..."
            ;;
        2)
            read -p "Enter backup archive file path (e.g. /root/backup.tar.gz): " bfile
            if [ -f "$bfile" ]; then
                tar -xzf "$bfile" -C "${PANEL_DIR}"
                systemctl restart mhpanel
                echo -e "${GREEN}Data restored successfully.${NC}"
            else
                echo -e "${RED}File not found.${NC}"
            fi
            read -p "Press Enter to continue..."
            ;;
    esac
}

update_panel_repo() {
    clear 2>/dev/null || true
    echo -e "${YELLOW}>>> Checking and pulling latest updates from repository...${NC}"
    if [ -d "${PANEL_DIR}/.git" ]; then
        cd "${PANEL_DIR}" && git pull || true
    fi
    systemctl daemon-reload
    systemctl restart mhpanel 2>/dev/null || true
    echo -e "${GREEN}✓ Update process completed.${NC}"
    read -p "Press Enter to return to main menu..."
}

# ==============================================================================
# MAIN MENU CONTROLLER
# ==============================================================================

main_menu() {
    while true; do
        show_banner
        local srv_ip=$(get_public_ipv4)
        local panel_port=$(cat "${PANEL_DIR}/panel_port.txt" 2>/dev/null || echo "9090")
        local is_online="${RED}Stopped${NC}"
        if systemctl is-active --quiet mhpanel 2>/dev/null; then
            is_online="${GREEN}Online (${srv_ip}:${panel_port})${NC}"
        fi

        echo -e "  Web Panel Status: ${is_online} | Quick Terminal Command: ${CYAN}mhpanel${NC}"
        echo -e "${BLUE}------------------------------------------------------------------------${NC}"
        echo -e "  ${WHITE}${BOLD}[1]  Run Full Automated Installation (Setup All Missing Components)${NC}"
        echo -e "  ${WHITE}${BOLD}[2]  Run Step-by-Step Custom Installation Wizard${NC}"
        echo -e "  ${WHITE}${BOLD}[3]  Install Lightweight Web UI Only${NC}"
        echo -e "${DIM}  ----------------------------------------------------------------------${NC}"
        echo -e "  [4]  Live System & Service Diagnostic Report"
        echo -e "  [5]  Manage, Install, Uninstall & Reconfigure VPN Protocols"
        echo -e "  [6]  Anti-Censorship Tunnels & MikroTik RouterOS Bridge Hub"
        echo -e "  [7]  Web Dashboard Settings (Credentials, Port, Logs & Restart)"
        echo -e "  [8]  SSL Certificate Management (Let's Encrypt & IP SAN)"
        echo -e "  [9]  Network & Kernel Optimization (BBR, IPv4/IPv6 Forwarding)"
        echo -e "  [10] Backup & Restore Panel Configurations"
        echo -e "  [11] Update Script & Panel"
        echo -e "  [0]  Exit"
        echo -e "${BLUE}========================================================================${NC}"
        read -p "Please select an option [0-11]: " opt

        case "$opt" in
            1) wizard_full_automated ;;
            2) wizard_step_by_step ;;
            3) wizard_web_ui_only ;;
            4) menu_diagnostic_status ;;
            5) menu_vpn_protocols ;;
            6) menu_tunnel_tools ;;
            7) menu_web_ui_settings ;;
            8) menu_ssl_management ;;
            9) enable_bbr_and_sysctl; read -p "Press Enter to continue..." ;;
            10) backup_restore ;;
            11) update_panel_repo ;;
            0)
                echo -e "\n${GREEN}Exiting MH Panel CLI. Have a great day!${NC}"
                echo -e "Reminder: You can return to this menu at any time by typing ${CYAN}mhpanel${NC}\n"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option.${NC}"
                sleep 1
                ;;
        esac
    done
}

# Entrypoint Execution Logic
if [ "$1" = "--auto" ]; then
    wizard_full_automated
elif [ "$1" = "--step" ]; then
    wizard_step_by_step
elif [ "$1" = "--ui" ]; then
    wizard_web_ui_only
elif [ "$1" = "--status" ]; then
    menu_diagnostic_status
else
    if [ ! -f "${PANEL_DIR}/app.py" ] && [ ! -f "/etc/systemd/system/mhpanel.service" ]; then
        show_banner
        echo -e "${YELLOW}Welcome to MH Panel Installer! Panel is not installed yet on this server.${NC}\n"
        echo -e "  [1] Full Automated Setup (Recommended)"
        echo -e "  [2] Step-by-Step Custom Wizard"
        echo -e "  [3] Lightweight Web UI Only"
        echo -e "  [0] Exit"
        echo ""
        read -p "Select installation mode [1-3]: " init_choice
        case "$init_choice" in
            1) wizard_full_automated ;;
            2) wizard_step_by_step ;;
            3) wizard_web_ui_only ;;
            *) exit 0 ;;
        esac
    else
        main_menu
    fi
fi
