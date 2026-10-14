#!/usr/bin/env bash
# ==============================================================================
#           HM Panel - Master Installer & Server Management Hub
#       مرکز جامع، هوشمند و حرفه‌ای نصب و مدیریت سرور، پروتکل‌های VPN و تونل‌ها
# ------------------------------------------------------------------------------
# GitHub: https://github.com/
# Compatible with: Ubuntu 20.04+, 22.04+, 24.04+ | Debian 11+, 12+
# Architecture: x86_64 / amd64 / aarch64
# ==============================================================================

set -e

# Terminal Colors & Styles
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
if [ -f "${SCRIPT_DIR}/app.py" ]; then
    PANEL_DIR="${SCRIPT_DIR}"
elif [ -d "/www/wwwroot/mhpanel" ]; then
    PANEL_DIR="/www/wwwroot/mhpanel"
else
    PANEL_DIR="/www/wwwroot/mhpanel"
fi

HELPER="${PANEL_DIR}/scripts/protocol_helper.sh"
SSL_DIR="/etc/vpnpanel/ssl"
CONFIG_DIR="/etc/vpnpanel"
VERSION="3.2.0-Pro"

# Root Permission Check
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] این اسکریپت باید با دسترسی روت (root) اجرا شود.${NC}"
    echo -e "لطفاً با دستور زیر اجرا کنید: ${CYAN}sudo bash $0${NC}"
    exit 1
fi

# Ensure hmpanel & mhpanel shortcuts are created globally
ensure_cli_shortcuts() {
    local target_script="$0"
    if [[ "$target_script" != /* ]]; then
        target_script="$(pwd)/$target_script"
    fi
    chmod +x "$target_script" 2>/dev/null || true

    mkdir -p /usr/local/bin /usr/bin
    if [ "$target_script" != "/usr/local/bin/hmpanel" ]; then
        ln -sf "$target_script" /usr/local/bin/hmpanel 2>/dev/null || true
    fi
    if [ "$target_script" != "/usr/local/bin/mhpanel" ]; then
        ln -sf "$target_script" /usr/local/bin/mhpanel 2>/dev/null || true
    fi
    if [ "$target_script" != "/usr/local/bin/kigapanel" ]; then
        ln -sf "$target_script" /usr/local/bin/kigapanel 2>/dev/null || true
    fi
    if [ "$target_script" != "/usr/bin/hmpanel" ]; then
        ln -sf "$target_script" /usr/bin/hmpanel 2>/dev/null || true
    fi
    if [ "$target_script" != "/usr/bin/mhpanel" ]; then
        ln -sf "$target_script" /usr/bin/mhpanel 2>/dev/null || true
    fi
}
ensure_cli_shortcuts

# Supported Protocols List
PROTOCOLS=(ssh openvpn ocserv ikev2 sstp l2tp wireguard amneziawg http socks shadowsocks tuic mtproto pptp badvpn)

# Helper: Print Title Banner
show_banner() {
    clear 2>/dev/null || true
    echo -e "${CYAN}${BOLD}"
    cat <<'EOF'
  _    _ __  __   _____                  _ 
 | |  | |  \/  | |  __ \                | |
 | |__| | \  / | | |__) |_ _ _ __   ___| |
 |  __  | |\/| | |  ___/ _` | '_ \ / _ \ |
 | |  | | |  | | | |  | (_| | | | |  __/ |
 |_|  |_|_|  |_| |_|   \__,_|_| |_|\___|_|
EOF
    echo -e "${WHITE}${BOLD}   HM Panel - Master Installer & Management CLI (${VERSION})${NC}"
    echo -e "${DIM}   مدیریت هوشمند پروتکل‌های VPN، تونل‌های ضد فیلتر و روتربورد میکروتیک${NC}"
    echo -e "${BLUE}------------------------------------------------------------------------${NC}"
}

# Helper: Get Public IPv4 & IPv6
get_public_ipv4() {
    curl -s --max-time 2 https://api.ipify.org 2>/dev/null || \
    curl -s --max-time 2 https://ifconfig.me 2>/dev/null || \
    ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[\d.]+' || echo "127.0.0.1"
}

get_public_ipv6() {
    ip -6 route get 2001:4860:4860::8888 2>/dev/null | grep -oP 'src \K[a-fA-F0-9:]+' || \
    curl -6 -s --max-time 2 https://api64.ipify.org 2>/dev/null || echo ""
}

# Protocol Information Labels
protocol_label() {
    case "$1" in
        ssh) echo "SSH Tunnel & WebSocket Proxy" ;;
        openvpn) echo "OpenVPN (UDP/TCP & Multi-Port)" ;;
        ocserv) echo "Ocserv (Cisco AnyConnect)" ;;
        ikev2) echo "IKEv2 StrongSwan (IPSec)" ;;
        sstp) echo "SSTP Server (SSL VPN)" ;;
        l2tp) echo "L2TP/IPsec (Site-to-Site)" ;;
        wireguard) echo "WireGuard (High Speed P2P)" ;;
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

# Detection: Check if Protocol is Installed
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
        mtproto) ls /etc/vpnpanel/mtproto_config_*.py >/dev/null 2>&1 || [ -f /etc/systemd/system/aethervpn-mtproto.service ] ;;
        pptp) [ -f "/etc/pptpd.conf" ] ;;
        badvpn) [ -f "/etc/systemd/system/badvpn.service" ] && command -v badvpn-udpgw >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

# Detection: Service Live Status
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
        echo -e "${GREEN}فعال (Active)${NC}"
    elif protocol_is_installed "$1"; then
        echo -e "${YELLOW}متوقف (Inactive)${NC}"
    else
        echo -e "${RED}نصب نشده${NC}"
    fi
}

# Detection: Protocol Current Port
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
    echo -e "\n${YELLOW}>>> [1/6] در حال بررسی و نصب پیش‌نیازهای پایه لینوکس...${NC}"
    export DEBIAN_FRONTEND=noninteractive

    # Check if packages are already present
    local pkgs_needed=()
    for p in python3 python3-pip python3-venv curl wget git openssl certbot iptables iptables-persistent ufw cron net-tools sudo cmake build-essential jq socat unzip; do
        if ! dpkg -s "$p" >/dev/null 2>&1; then
            pkgs_needed+=("$p")
        fi
    done

    if [ ${#pkgs_needed[@]} -eq 0 ]; then
        echo -e "    ${GREEN}[✓] تمام بسته‌های پایه لینوکس از قبل نصب هستند (رد شد).${NC}"
    else
        echo -e "    در حال نصب بسته‌های کسری: ${CYAN}${pkgs_needed[*]}${NC}..."
        apt-get update -y
        apt-get install -y --no-install-recommends "${pkgs_needed[@]}"
        echo -e "    ${GREEN}[✓] پیش‌نیازهای پایه لینوکس با موفقیت نصب شدند.${NC}"
    fi
}

enable_bbr_and_sysctl() {
    echo -e "\n${YELLOW}>>> [2/6] در حال فعال‌سازی بهینه‌سازی TCP BBR، فورواردینگ IPv4 و تونل‌های IPv6...${NC}"
    
    # Enable Kernel tunnel modules
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
    echo -e "    ${GREEN}[✓] TCP BBR، هسته لینوکس و فورواردینگ پکت‌های IPv4/IPv6 با موفقیت بهینه‌سازی شدند.${NC}"
}

install_panel_web_ui() {
    echo -e "\n${YELLOW}>>> [3/6] بررسی و راه‌اندازی رابط کاربری وب پنل (HM Panel Web UI)...${NC}"
    mkdir -p "${PANEL_DIR}"
    mkdir -p "${SSL_DIR}"
    chmod 700 "${SSL_DIR}"

    # If app.py is missing in target but present in script dir, copy files
    if [ ! -f "${PANEL_DIR}/app.py" ] && [ -f "${SCRIPT_DIR}/app.py" ]; then
        echo "    در حال کپی فایل‌های پنل از مسیر فعلی..."
        cp -r "${SCRIPT_DIR}"/* "${PANEL_DIR}/" 2>/dev/null || true
    fi

    # Setup Python venv
    if [ ! -d "${PANEL_DIR}/venv" ] || [ ! -f "${PANEL_DIR}/venv/bin/python" ]; then
        echo "    در حال ایجاد محیط مجازی Python در ${PANEL_DIR}/venv..."
        python3 -m venv "${PANEL_DIR}/venv"
        "${PANEL_DIR}/venv/bin/pip" install --upgrade pip --quiet
        echo "    در حال نصب کتابخانه‌های پایتون (Flask, Cryptography, PyOpenSSL, Requests, Psutil)..."
        "${PANEL_DIR}/venv/bin/pip" install \
            "Flask>=2.0.0" \
            "psutil>=5.8.0" \
            "pyrad>=2.4" \
            "cryptography>=3.4.8" \
            "pyOpenSSL" \
            "requests" --quiet
    else
        echo -e "    ${GREEN}[✓] محیط مجازی پایتون و نیازمندی‌های پنل وب از قبل آماده است.${NC}"
    fi

    # Credentials
    local port_file="${PANEL_DIR}/panel_port.txt"
    if [ ! -f "$port_file" ]; then echo "9090" > "$port_file"; fi
    local panel_port=$(cat "$port_file" 2>/dev/null || echo "9090")

    local cred_file="${PANEL_DIR}/admin_credentials.txt"
    if [ ! -f "$cred_file" ]; then
        local admin_user="admin"
        local admin_pass=$(openssl rand -hex 8)
        echo -e "username=${admin_user}\npassword=${admin_pass}" > "$cred_file"
        chmod 600 "$cred_file"
        echo -e "    اطلاعات جدید مدیریت تولید شد: کاربر ${CYAN}${admin_user}${NC} | پسورد ${CYAN}${admin_pass}${NC}"
    fi

    if [ ! -f "${PANEL_DIR}/api_key.txt" ]; then
        openssl rand -hex 16 > "${PANEL_DIR}/api_key.txt"; chmod 600 "${PANEL_DIR}/api_key.txt"
    fi
    if [ ! -f "${PANEL_DIR}/session_secret.txt" ]; then
        openssl rand -hex 32 > "${PANEL_DIR}/session_secret.txt"; chmod 600 "${PANEL_DIR}/session_secret.txt"
    fi

    # SSL Certificate
    local srv_ip=$(get_public_ipv4)
    if [ ! -f "${SSL_DIR}/panel.crt" ] || [ ! -f "${SSL_DIR}/panel.key" ]; then
        echo "    تولید گواهی امنیتی HTTPS 10-Year IP SAN برای آی‌پی ${srv_ip}..."
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "${SSL_DIR}/panel.key" \
            -out "${SSL_DIR}/panel.crt" \
            -subj "/CN=${srv_ip}/O=HMPanel Server" \
            -addext "subjectAltName = IP:${srv_ip},IP:127.0.0.1" \
            -days 3650 2>/dev/null
        chmod 600 "${SSL_DIR}/panel.key"
        chmod 644 "${SSL_DIR}/panel.crt"
    fi

    # Systemd Service
    cat > /etc/systemd/system/mhpanel.service <<EOF
[Unit]
Description=HM Panel Web Service
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

    # Firewall
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
        echo -e "    ${GREEN}[✓] سرویس وب پنل HM Panel فعال و آنلاین شد.${NC}"
    else
        echo -e "    ${RED}[!] سرویس هنوز فعال نشده است. لاگ‌ها بررسی شوند.${NC}"
    fi
}

install_badvpn() {
    echo -e "    ${CYAN}--> راه‌اندازی سرویس BadVPN (UDPGW پورت 7300 جهت انتقال UDP گیمینگ/صدا)...${NC}"
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
    echo -e "    ${GREEN}[✓] BadVPN UDPGW با پورت 7300 فعال گردید.${NC}"
}

install_tunnel_tools() {
    echo -e "\n${YELLOW}>>> [4/6] بررسی و دانلود ابزارهای تونلینگ ضد فیلتر لینوکس...${NC}"
    local count_downloaded=0

    # GOST v3
    if [ ! -x /usr/local/bin/gost ]; then
        echo "    در حال دانلود GOST v3..."
        curl -fsSL https://github.com/go-gost/gost/releases/download/v3.0.0-rc10/gost_3.0.0-rc10_linux_amd64.tar.gz 2>/dev/null | tar -xz -C /usr/local/bin/ gost 2>/dev/null || true
        chmod +x /usr/local/bin/gost 2>/dev/null || true
        count_downloaded=$((count_downloaded + 1))
    fi

    # WSTunnel
    if [ ! -x /usr/local/bin/wstunnel ]; then
        echo "    در حال دانلود WSTunnel..."
        curl -fsSL https://github.com/erebe/wstunnel/releases/download/v11.1.0/wstunnel_11.1.0_linux_amd64.tar.gz 2>/dev/null | tar -xz -C /usr/local/bin/ wstunnel 2>/dev/null || true
        chmod +x /usr/local/bin/wstunnel 2>/dev/null || true
        count_downloaded=$((count_downloaded + 1))
    fi

    # RTT
    if [ ! -x /usr/local/bin/rtt ]; then
        echo "    در حال دانلود ReverseTlsTunnel (RTT)..."
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
        echo "    در حال دانلود Chisel..."
        curl -fsSL https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_linux_amd64.gz 2>/dev/null | gzip -d > /usr/local/bin/chisel 2>/dev/null || true
        chmod +x /usr/local/bin/chisel 2>/dev/null || true
        count_downloaded=$((count_downloaded + 1))
    fi

    # FRP
    if [ ! -x /usr/local/bin/frps ] || [ ! -x /usr/local/bin/frpc ]; then
        echo "    در حال دانلود FRP (frps & frpc)..."
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
        echo "    در حال دانلود UDP2Raw..."
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
        echo "    در حال دانلود Phantun..."
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
        echo "    در حال دانلود Rathole..."
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
        echo "    در حال دانلود Kcptun..."
        curl -fsSL https://github.com/xtaci/kcptun/releases/download/v20231012/kcptun-linux-amd64-20231012.tar.gz 2>/dev/null | tar -xz -C /usr/local/bin/ server_linux_amd64 client_linux_amd64 2>/dev/null || true
        if [ -f /usr/local/bin/server_linux_amd64 ]; then
            mv /usr/local/bin/server_linux_amd64 /usr/local/bin/kcptun-server 2>/dev/null || true
            mv /usr/local/bin/client_linux_amd64 /usr/local/bin/kcptun-client 2>/dev/null || true
            chmod +x /usr/local/bin/kcptun-* 2>/dev/null || true
            count_downloaded=$((count_downloaded + 1))
        fi
    fi

    echo -e "    ${GREEN}[✓] پکیج‌های تونلینگ ضد فیلتر لینوکس بررسی و همگام شدند (${count_downloaded} فایل جدید دریافت شد).${NC}"
}

# Install Single Protocol Action
install_protocol_action() {
    local proto=$1
    local port=$2

    if [ "$proto" = "badvpn" ]; then
        install_badvpn
        return
    fi

    if [ ! -f "$HELPER" ]; then
        echo -e "${RED}[ERROR] فایل protocol_helper.sh یافت نشد: ${HELPER}${NC}"
        return 1
    fi

    chmod +x "$HELPER"
    echo -e "    ${CYAN}در حال نصب و پیکربندی $(protocol_label "$proto") (پورت: ${port})...${NC}"
    "$HELPER" install "$proto" "$port"
    echo -e "    ${GREEN}✓ $(protocol_label "$proto") با موفقیت نصب و فعال شد.${NC}"
}

# ==============================================================================
# INSTALLATION WIZARDS (AUTOMATED & STEP-BY-STEP)
# ==============================================================================

wizard_full_automated() {
    show_banner
    echo -e "${WHITE}${BOLD}=== نصب خودکار و کامل تمام بخش‌های سرور (Full Automated Setup) ===${NC}"
    echo -e "${DIM}این حالت تمام پکیج‌های وب پنل، پروتکل‌های VPN، ابزارهای تونلینگ و بهینه‌سازی‌ها را بررسی کرده و بخش‌های کسری را نصب می‌کند.${NC}\n"

    install_base_prerequisites
    enable_bbr_and_sysctl
    install_panel_web_ui
    install_tunnel_tools

    echo -e "\n${YELLOW}>>> [5/6] بررسی و نصب هوشمند پروتکل‌های VPN...${NC}"
    for proto in "${PROTOCOLS[@]}"; do
        local def_port="$(protocol_default_port "$proto")"
        local lbl="$(protocol_label "$proto")"
        if protocol_is_installed "$proto"; then
            echo -e "    ${GREEN}[✓] ${lbl}${NC} از قبل نصب است (رد شد)."
        else
            install_protocol_action "$proto" "$def_port"
        fi
    done

    echo -e "\n${YELLOW}>>> [6/6] همگام‌سازی فایروال و ذخیره قوانین شبکه...${NC}"
    if command -v iptables-save >/dev/null 2>&1; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    fi

    show_final_summary
}

wizard_step_by_step() {
    show_banner
    echo -e "${WHITE}${BOLD}=== ویزارد نصب سفارشی و گام‌به‌گام (Step-by-Step Custom Setup) ===${NC}"
    echo -e "${DIM}در این حالت، برای هر بخش از شما سؤال پرسیده می‌شود. اگر بخشی را رد کنید، در هر زمان با دستور mhpanel می‌توانید آن را نصب نمایید.${NC}\n"

    # Step 1: Base Prerequisites
    read -p "آیا مایل به بررسی و نصب بسته‌های پایه لینوکس هستید؟ [Y/n]: " ans_base
    if [[ -z "$ans_base" || "$ans_base" =~ ^[yY]$ ]]; then
        install_base_prerequisites
    else
        echo -e "${YELLOW}--> بخش بسته‌های پایه رد شد.${NC}"
    fi

    # Step 2: BBR & IPv6
    read -p "آیا مایل به بهینه‌سازی TCP BBR، فورواردینگ پکت‌ها و ماژول‌های IPv6 هستید؟ [Y/n]: " ans_bbr
    if [[ -z "$ans_bbr" || "$ans_bbr" =~ ^[yY]$ ]]; then
        enable_bbr_and_sysctl
    else
        echo -e "${YELLOW}--> بهینه‌سازی BBR رد شد.${NC}"
    fi

    # Step 3: Web UI
    read -p "آیا مایل به نصب/بروزرسانی رابط وب MH Panel هستید؟ [Y/n]: " ans_ui
    if [[ -z "$ans_ui" || "$ans_ui" =~ ^[yY]$ ]]; then
        install_panel_web_ui
    else
        echo -e "${YELLOW}--> نصب رابط وب پنل رد شد.${NC}"
    fi

    # Step 4: Anti-Filter Tunnels
    read -p "آیا مایل به دریافت ابزارهای تونلینگ ضد فیلتر لینوکس (GOST, WSTunnel, RTT, Chisel, FRP, UDP2Raw, Phantun, Rathole, Kcptun) هستید؟ [Y/n]: " ans_tun
    if [[ -z "$ans_tun" || "$ans_tun" =~ ^[yY]$ ]]; then
        install_tunnel_tools
    else
        echo -e "${YELLOW}--> دریافت ابزارهای تونل رد شد.${NC}"
    fi

    # Step 5: Protocols One-by-One
    echo -e "\n${YELLOW}=== انتخاب پروتکل‌های VPN جهت نصب ===${NC}"
    for proto in "${PROTOCOLS[@]}"; do
        local lbl="$(protocol_label "$proto")"
        local def_port="$(protocol_default_port "$proto")"

        if protocol_is_installed "$proto"; then
            local cur_p="$(protocol_current_port "$proto")"
            local st="$(protocol_service_status "$proto")"
            echo -e "\n  ${GREEN}[✓] ${lbl}${NC} هم‌اکنون نصب است. (پورت: ${CYAN}${cur_p}${NC} | وضعیت: ${st})"
            read -p "      آیا مایل به نصب مجدد / بروزرسانی ${lbl} هستید؟ [y/N]: " do_reinstall
            if [[ "$do_reinstall" =~ ^[yY]$ ]]; then
                read -p "      پورت مورد نظر [پیش‌فرض: ${cur_p}]: " cust_port
                cust_port=${cust_port:-$cur_p}
                install_protocol_action "$proto" "$cust_port"
            else
                echo -e "      ${DIM}--> از نصب موجود استفاده می‌شود.${NC}"
            fi
        else
            echo -e "\n  ${RED}[✗] ${lbl}${NC} نصب نشده است."
            read -p "      آیا مایل به نصب و فعال‌سازی ${lbl} هستید؟ [Y/n]: " do_install
            if [[ -z "$do_install" || "$do_install" =~ ^[yY]$ ]]; then
                read -p "      پورت مورد نظر برای این سرویس [پیش‌فرض: ${def_port}]: " cust_port
                cust_port=${cust_port:-$def_port}
                install_protocol_action "$proto" "$cust_port"
            else
                echo -e "      ${YELLOW}--> این بخش رد شد. (می‌توانید بعداً با اجرای دستور mhpanel آن را نصب کنید)${NC}"
            fi
        fi
    done

    show_final_summary
}

wizard_web_ui_only() {
    show_banner
    echo -e "${WHITE}${BOLD}=== نصب سبک فقط رابط کاربری HM Panel (Web UI Only) ===${NC}\n"
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
    echo -e "${GREEN}${BOLD}   ✓ عملیات راه‌اندازی با موفقیت کامل انجام شد!${NC}"
    echo -e "${GREEN}${BOLD}========================================================================${NC}"
    echo -e "  🌐 ${BOLD}آدرس ورود به پنل تحت وب:${NC}   ${CYAN}https://${srv_ip}:${panel_port}/${NC}"
    if [ -n "$srv_ipv6" ]; then
        echo -e "  🌐 ${BOLD}آدرس ورود با IPv6:${NC}         ${CYAN}https://[${srv_ipv6}]:${panel_port}/${NC}"
    fi
    echo -e "  👤 ${BOLD}نام کاربری (Username):${NC}       ${BOLD}${user}${NC}"
    echo -e "  🔑 ${BOLD}رمز عبور (Password):${NC}         ${BOLD}${pass}${NC}"
    echo -e "  🔑 ${BOLD}کلید عمومی API Key:${NC}          ${DIM}${api_key}${NC}"
    echo -e "${GREEN}${BOLD}========================================================================${NC}"
    echo -e "${YELLOW}${BOLD}نکته کاربردی و فراخوانی مجدد:${NC}"
    echo -e "  در هر زمان، با وارد کردن دستور ${CYAN}${BOLD}mhpanel${NC} (یا ${CYAN}hmpanel${NC}) در ترمینال سرور، می‌توانید"
    echo -e "  مجدداً این منو را باز کرده، وضعیت سرویس‌ها را ببینید یا پکیج‌های رد شده را نصب کنید."
    echo -e "${GREEN}${BOLD}========================================================================${NC}\n"
    read -p "جهت بازگشت به منوی اصلی Enter بزنید..."
}

# ==============================================================================
# SUB-MENUS & MANAGEMENT OPTIONS
# ==============================================================================

menu_diagnostic_status() {
    clear 2>/dev/null || true
    echo -e "${CYAN}${BOLD}========================================================================${NC}"
    echo -e "${WHITE}${BOLD}              گزارش وضعیت جامع و زنده سیستم (System Diagnostic)          ${NC}"
    echo -e "${CYAN}${BOLD}========================================================================${NC}"

    local srv_ip=$(get_public_ipv4)
    local srv_ipv6=$(get_public_ipv6)
    local panel_port=$(cat "${PANEL_DIR}/panel_port.txt" 2>/dev/null || echo "9090")
    local mem_used=$(free -m | awk '/Mem:/ {print $3}')
    local mem_total=$(free -m | awk '/Mem:/ {print $2}')
    local load=$(uptime | awk -F'load average:' '{print $2}')

    echo -e "  🖥️  ${BOLD}آی‌پی سرور (IPv4):${NC}      ${CYAN}${srv_ip}${NC}"
    echo -e "  🌐 ${BOLD}آی‌پی سرور (IPv6):${NC}      ${CYAN}${srv_ipv6:-ندارد یا غیرفعال}${NC}"
    echo -e "  📊 ${BOLD}مصرف حافظه RAM:${NC}         ${mem_used} MB از ${mem_total} MB"
    echo -e "  ⚡ ${BOLD}لود پردازنده (Load):${NC}      ${load}"
    
    echo -e "\n${YELLOW}--- وضعیت وب پنل HM Panel ---${NC}"
    if systemctl is-active --quiet mhpanel 2>/dev/null; then
        echo -e "  وضعیت سرویس: ${GREEN}آنلاین و در حال اجرا (Active)${NC} | پورت: ${CYAN}${panel_port}${NC}"
        echo -e "  لینک ورود:   ${CYAN}https://${srv_ip}:${panel_port}/${NC}"
    else
        echo -e "  وضعیت سرویس: ${RED}متوقف (Stopped)${NC}"
    fi

    echo -e "\n${YELLOW}--- وضعیت پروتکل‌های VPN سرور ---${NC}"
    printf "  %-12s %-16s %-15s %-20s\n" "پروتکل" "وضعیت نصب" "پورت" "وضعیت سرویس"
    echo "  ----------------------------------------------------------------------"
    for proto in "${PROTOCOLS[@]}"; do
        local inst="${RED}نصب نشده${NC}"
        if protocol_is_installed "$proto"; then
            inst="${GREEN}نصب شده ✓${NC}"
        fi
        local port="$(protocol_current_port "$proto")"
        local st="$(protocol_service_status "$proto")"
        printf "  %-12s %-24b %-15s %-20b\n" "$proto" "$inst" "$port" "$st"
    done

    echo -e "\n${YELLOW}--- وضعیت ابزارهای تونلینگ ضد فیلتر ---${NC}"
    for tool in gost wstunnel rtt chisel frps frpc udp2raw phantun-server rathole kcptun-server; do
        if command -v "$tool" >/dev/null 2>&1 || [ -x "/usr/local/bin/$tool" ]; then
            echo -e "  • ${tool}: ${GREEN}موجود در سیستم ✓${NC}"
        else
            echo -e "  • ${tool}: ${RED}دانلود نشده${NC}"
        fi
    done

    echo -e "\n${CYAN}========================================================================${NC}"
    read -p "جهت بازگشت به منو کلید Enter را فشار دهید..."
}

menu_vpn_protocols() {
    while true; do
        clear 2>/dev/null || true
        echo -e "${YELLOW}${BOLD}=== مدیریت و پیکربندی پروتکل‌های VPN ===${NC}"
        local i=1
        for proto in "${PROTOCOLS[@]}"; do
            local st="${RED}نصب نشده${NC}"
            if protocol_is_installed "$proto"; then
                st="${GREEN}نصب شده ✓${NC}"
            fi
            local p="$(protocol_current_port "$proto")"
            local live="$(protocol_service_status "$proto")"
            echo -e "  [$i] $(protocol_label "$proto") - ${st} - پورت: ${CYAN}${p}${NC} (${live})"
            i=$((i + 1))
        done
        echo -e "  [0] بازگشت به منوی اصلی"
        echo ""
        read -p "پروتکل مورد نظر را انتخاب نمایید [0-${#PROTOCOLS[@]}]: " choice
        if [ "$choice" = "0" ] || [ -z "$choice" ]; then break; fi

        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#PROTOCOLS[@]}" ]; then
            local sel_proto="${PROTOCOLS[$((choice - 1))]}"
            local lbl="$(protocol_label "$sel_proto")"
            
            echo -e "\n${WHITE}${BOLD}عملیات برای ${lbl}:${NC}"
            echo -e "  [1] نصب یا بروزرسانی پروتکل"
            echo -e "  [2] حذف کامل پروتکل"
            echo -e "  [3] تغییر پورت پروتکل"
            echo -e "  [4] راه‌اندازی مجدد سرویس (Restart)"
            echo -e "  [5] مشاهده لاگ‌ها (journalctl)"
            echo -e "  [0] انصراف"
            read -p "انتخاب عملیات: " act

            case "$act" in
                1)
                    local cur_p="$(protocol_current_port "$sel_proto")"
                    read -p "پورت مورد نظر [پیش‌فرض: ${cur_p}]: " np
                    np=${np:-$cur_p}
                    install_protocol_action "$sel_proto" "$np"
                    read -p "جهت ادامه Enter بزنید..."
                    ;;
                2)
                    read -p "آیا از حذف ${lbl} مطمئن هستید؟ [y/N]: " conf
                    if [[ "$conf" =~ ^[yY]$ ]]; then
                        if [ -f "$HELPER" ]; then "$HELPER" uninstall "$sel_proto"; fi
                        echo -e "${GREEN}پروتکل حذف شد.${NC}"
                    fi
                    read -p "جهت ادامه Enter بزنید..."
                    ;;
                3)
                    read -p "پورت جدید را وارد کنید: " np
                    if [ -n "$np" ] && [ -f "$HELPER" ]; then
                        "$HELPER" set-port "$sel_proto" "$np"
                        echo -e "${GREEN}پورت با موفقیت تغییر کرد.${NC}"
                    fi
                    read -p "جهت ادامه Enter بزنید..."
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
                    echo -e "${GREEN}سرویس بازنشانی شد.${NC}"
                    read -p "جهت ادامه Enter بزنید..."
                    ;;
                5)
                    journalctl -n 40 --no-pager 2>/dev/null || true
                    read -p "جهت ادامه Enter بزنید..."
                    ;;
            esac
        fi
    done
}

menu_tunnel_tools() {
    clear 2>/dev/null || true
    echo -e "${YELLOW}${BOLD}=== مدیریت ابزارهای تونلینگ ضد فیلتر و میکروتیک ===${NC}"
    echo -e "این بخش ابزارهای پیشرفته مانند GOST، WSTunnel، RTT، FRP، Chisel، UDP2Raw و ماژول‌های IPv6 را مدیریت می‌کند.\n"

    echo -e "  [1] دانلود / بروزرسانی تمامی ابزارهای تونلینگ ضد فیلتر"
    echo -e "  [2] فعال‌سازی ماژول‌های هسته لینوکس برای تونل‌های IPv6 (ip6_gre, ip6_tunnel, sit)"
    echo -e "  [3] اجرای اسکریپت راه‌اندازی مجدد تونل‌های بوت (/etc/mhpanel/tunnels_boot.sh)"
    echo -e "  [4] مشاهده لیست سرویس‌های فعال Systemd تونل (mhtun_*)"
    echo -e "  [0] بازگشت"
    echo ""
    read -p "انتخاب گزینه [0-4]: " t_act
    case "$t_act" in
        1)
            install_tunnel_tools
            read -p "جهت بازگشت Enter بزنید..."
            ;;
        2)
            modprobe ip6_gre; modprobe ip6_tunnel; modprobe sit; modprobe ip_gre; modprobe ipip
            echo -e "${GREEN}ماژول‌های GRE IPv6، IPIP IPv6 و SIT 6in4 بارگذاری شدند.${NC}"
            read -p "جهت بازگشت Enter بزنید..."
            ;;
        3)
            if [ -f "/etc/mhpanel/tunnels_boot.sh" ]; then
                bash /etc/mhpanel/tunnels_boot.sh
                echo -e "${GREEN}اسکریپت تونل‌ها اجرا شد.${NC}"
            else
                echo -e "${YELLOW}هنوز هیچ تونلی در پنل ثبت نشده است.${NC}"
            fi
            read -p "جهت بازگشت Enter بزنید..."
            ;;
        4)
            systemctl list-units --type=service "mhtun_*" --no-pager
            read -p "جهت بازگشت Enter بزنید..."
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

        echo -e "${YELLOW}${BOLD}=== تنظیمات و مدیریت HM Panel Web UI ===${NC}"
        echo -e "  نام کاربری ادمین: ${CYAN}${user}${NC}"
        echo -e "  رمز عبور ادمین:   ${CYAN}${pass}${NC}"
        echo -e "  پورت پنل تحت وب:  ${CYAN}${panel_port}${NC}"
        echo -e "  آدرس ورود:        ${CYAN}https://${srv_ip}:${panel_port}/${NC}\n"

        echo -e "  [1] راه‌اندازی مجدد سرویس پنل (Restart mhpanel)"
        echo -e "  [2] مشاهده لاگ‌های زنده پنل (Logs)"
        echo -e "  [3] تغییر نام کاربری و رمز عبور ادمین"
        echo -e "  [4] تغییر پورت پنل تحت وب"
        echo -e "  [5] تولید مجدد کلید API Key"
        echo -e "  [0] بازگشت"
        echo ""
        read -p "انتخاب گزینه [0-5]: " ui_act
        case "$ui_act" in
            1)
                systemctl restart mhpanel
                echo -e "${GREEN}سرویس وب پنل ری‌استارت شد.${NC}"
                read -p "جهت بازگشت Enter بزنید..."
                ;;
            2)
                echo -e "${YELLOW}مشاهده آخرین ۵۰ خط لاگ پنل:${NC}"
                journalctl -u mhpanel -n 50 --no-pager
                read -p "جهت بازگشت Enter بزنید..."
                ;;
            3)
                read -p "نام کاربری جدید [پیش‌فرض: ${user}]: " nu
                nu=${nu:-$user}
                read -p "رمز عبور جدید: " np
                if [ -n "$np" ]; then
                    echo -e "username=${nu}\npassword=${np}" > "${PANEL_DIR}/admin_credentials.txt"
                    chmod 600 "${PANEL_DIR}/admin_credentials.txt"
                    systemctl restart mhpanel
                    echo -e "${GREEN}اطلاعات ورود ادمین با موفقیت به‌روزرسانی شد.${NC}"
                fi
                read -p "جهت بازگشت Enter بزنید..."
                ;;
            4)
                read -p "پورت جدید پنل وب [فعلی: ${panel_port}]: " nport
                if [[ "$nport" =~ ^[0-9]+$ ]] && [ "$nport" -ge 1 ] && [ "$nport" -le 65535 ]; then
                    echo "$nport" > "${PANEL_DIR}/panel_port.txt"
                    if command -v ufw >/dev/null && systemctl is-active --quiet ufw; then
                        ufw allow "${nport}/tcp" >/dev/null 2>&1 || true
                    fi
                    systemctl restart mhpanel
                    echo -e "${GREEN}پورت وب پنل به ${nport} تغییر یافت.${NC}"
                fi
                read -p "جهت بازگشت Enter بزنید..."
                ;;
            5)
                local nkey=$(openssl rand -hex 16)
                echo "$nkey" > "${PANEL_DIR}/api_key.txt"
                chmod 600 "${PANEL_DIR}/api_key.txt"
                systemctl restart mhpanel
                echo -e "${GREEN}کلید جدید API تولید شد: ${CYAN}${nkey}${NC}"
                read -p "جهت بازگشت Enter بزنید..."
                ;;
            0) break ;;
        esac
    done
}

menu_ssl_management() {
    clear 2>/dev/null || true
    echo -e "${YELLOW}${BOLD}=== مدیریت گواهی‌های امنیتی SSL & HTTPS ===${NC}"
    echo -e "  [1] تنظیم گواهی رایگان Let's Encrypt برای دامنه سرور"
    echo -e "  [2] بازتولید گواهی ۱۰ ساله IP SAN برای آی‌پی سرور"
    echo -e "  [3] تعمیر و بازنشانی خودکار HTTPS پنل"
    echo -e "  [0] بازگشت"
    echo ""
    read -p "انتخاب گزینه [0-3]: " s_act
    case "$s_act" in
        1)
            read -p "نام دامنه‌ای که به این سرور پوینت شده است را وارد کنید: " dom
            if [ -n "$dom" ]; then
                echo "توقف موقت پنل جهت آزادسازی پورت 80..."
                systemctl stop mhpanel 2>/dev/null || true
                if command -v ufw >/dev/null; then ufw allow 80/tcp || true; fi
                if certbot certonly --standalone -d "${dom}" --non-interactive --agree-tos --register-unsafely-without-email; then
                    ln -sf "/etc/letsencrypt/live/${dom}/fullchain.pem" "${SSL_DIR}/panel.crt"
                    ln -sf "/etc/letsencrypt/live/${dom}/privkey.pem" "${SSL_DIR}/panel.key"
                    echo -e "${GREEN}گواهی Let's Encrypt با موفقیت نصب شد!${NC}"
                else
                    echo -e "${RED}خطا در دریافت سرتیفیکیت Let's Encrypt. لطفاً DNS را بررسی نمایید.${NC}"
                fi
                systemctl start mhpanel 2>/dev/null || true
            fi
            read -p "جهت بازگشت Enter بزنید..."
            ;;
        2)
            local ip=$(get_public_ipv4)
            openssl req -x509 -newkey rsa:2048 -nodes \
                -keyout "${SSL_DIR}/panel.key" \
                -out "${SSL_DIR}/panel.crt" \
                -subj "/CN=${ip}/O=HMPanel Server" \
                -addext "subjectAltName = IP:${ip},IP:127.0.0.1" \
                -days 3650 2>/dev/null
            chmod 600 "${SSL_DIR}/panel.key"
            chmod 644 "${SSL_DIR}/panel.crt"
            systemctl restart mhpanel
            echo -e "${GREEN}گواهی ۱۰ ساله IP SAN با موفقیت بازتولید گردید.${NC}"
            read -p "جهت بازگشت Enter بزنید..."
            ;;
        3)
            systemctl daemon-reload
            systemctl restart mhpanel
            echo -e "${GREEN}سرویس بازنشانی شد.${NC}"
            read -p "جهت بازگشت Enter بزنید..."
            ;;
    esac
}

backup_restore() {
    clear 2>/dev/null || true
    echo -e "${YELLOW}${BOLD}=== پشتیبان‌گیری و بازیابی داده‌های HM Panel ===${NC}"
    echo -e "  [1] تهیه فایل بکاپ کامل (Users, Configs, Credentials, SSL)"
    echo -e "  [2] بازگردانی بکاپ از فایل tar.gz"
    echo -e "  [0] بازگشت"
    echo ""
    read -p "انتخاب گزینه [0-2]: " b_act
    case "$b_act" in
        1)
            local bname="hmpanel_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
            tar -czf "/root/${bname}" \
                -C "${PANEL_DIR}" *.json *.txt 2>/dev/null || true
            echo -e "${GREEN}فایل پشتیبان در مسیر زیر ذخیره شد:${NC} ${CYAN}/root/${bname}${NC}"
            read -p "جهت ادامه Enter بزنید..."
            ;;
        2)
            read -p "مسیر فایل بکاپ را وارد نمایید (مثال: /root/backup.tar.gz): " bfile
            if [ -f "$bfile" ]; then
                tar -xzf "$bfile" -C "${PANEL_DIR}"
                systemctl restart mhpanel
                echo -e "${GREEN}داده‌ها با موفقیت بازیابی شدند.${NC}"
            else
                echo -e "${RED}فایل یافت نشد.${NC}"
            fi
            read -p "جهت ادامه Enter بزنید..."
            ;;
    esac
}

update_panel_repo() {
    clear 2>/dev/null || true
    echo -e "${YELLOW}>>> در حال بررسی و دریافت آخرین تغییرات پنل و اسکریپت...${NC}"
    if [ -d "${PANEL_DIR}/.git" ]; then
        cd "${PANEL_DIR}" && git pull || true
    fi
    systemctl daemon-reload
    systemctl restart mhpanel 2>/dev/null || true
    echo -e "${GREEN}✓ بروزرسانی با موفقیت انجام شد.${NC}"
    read -p "جهت بازگشت Enter بزنید..."
}

# ==============================================================================
# MAIN MENU CONTROLLER
# ==============================================================================

main_menu() {
    while true; do
        show_banner
        local srv_ip=$(get_public_ipv4)
        local panel_port=$(cat "${PANEL_DIR}/panel_port.txt" 2>/dev/null || echo "9090")
        local is_online="${RED}متوقف${NC}"
        if systemctl is-active --quiet mhpanel 2>/dev/null; then
            is_online="${GREEN}آنلاین (${srv_ip}:${panel_port})${NC}"
        fi

        echo -e "  وضعیت وب پنل: ${is_online} | دستور دسترسی سریع: ${CYAN}mhpanel${NC} (یا hmpanel)"
        echo -e "${BLUE}------------------------------------------------------------------------${NC}"
        echo -e "  ${WHITE}${BOLD}[1]  اجرای ویزارد نصب خودکار و کامل تمام پکیج‌ها (Full Automated Setup)${NC}"
        echo -e "  ${WHITE}${BOLD}[2]  اجرای ویزارد نصب مرحله‌به‌مرحله و انتخابی (Step-by-Step Custom Setup)${NC}"
        echo -e "  ${WHITE}${BOLD}[3]  نصب سریع فقط رابط کاربری وب پنل (Lightweight Web UI Only)${NC}"
        echo -e "${DIM}  ----------------------------------------------------------------------${NC}"
        echo -e "  [4]  گزارش وضعیت کامل سیستم، پکیج‌ها و ترافیک (System Diagnostic Report)"
        echo -e "  [5]  مدیریت، نصب، حذف و تغییر پورت پروتکل‌های VPN"
        echo -e "  [6]  نصب و مدیریت ابزارهای تونلینگ ضد فیلتر و روتربورد میکروتیک"
        echo -e "  [7]  تنظیمات وب پنل (تغییر پورت، پسورد، بازنشانی سرویس و لاگ‌ها)"
        echo -e "  [8]  مدیریت گواهی‌های امنیتی SSL (Let's Encrypt و IP SAN 10-Year)"
        echo -e "  [9]  بهینه‌سازی TCP BBR، فورواردینگ پکت‌ها و هسته لینوکس"
        echo -e "  [10] پشتیبان‌گیری و بازیابی اطلاعات پنل (Backup & Restore)"
        echo -e "  [11] بروزرسانی اسکریپت و پنل"
        echo -e "  [0]  خروج از برنامه"
        echo -e "${BLUE}========================================================================${NC}"
        read -p "لطفاً یک گزینه را انتخاب نمایید [0-11]: " opt

        case "$opt" in
            1) wizard_full_automated ;;
            2) wizard_step_by_step ;;
            3) wizard_web_ui_only ;;
            4) menu_diagnostic_status ;;
            5) menu_vpn_protocols ;;
            6) menu_tunnel_tools ;;
            7) menu_web_ui_settings ;;
            8) menu_ssl_management ;;
            9) enable_bbr_and_sysctl; read -p "جهت ادامه Enter بزنید..." ;;
            10) backup_restore ;;
            11) update_panel_repo ;;
            0)
                echo -e "\n${GREEN}خروج از MH Panel. روز خوبی داشته باشید!${NC}"
                echo -e "یادآوری: با تایپ دستور ${CYAN}mhpanel${NC} همیشه می‌توانید به این منو برگردید.\n"
                exit 0
                ;;
            *)
                echo -e "${RED}گزینه نامعتبر است.${NC}"
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
    # If not installed at all, prompt initial wizard directly or launch menu
    if [ ! -f "${PANEL_DIR}/app.py" ] && [ ! -f "/etc/systemd/system/mhpanel.service" ]; then
        show_banner
        echo -e "${YELLOW}به نصاب هوشمند HM Panel خوش آمدید! پنل هنوز بر روی سرور نصب نشده است.${NC}\n"
        echo -e "  [1] نصب خودکار و کامل تمام پکیج‌ها (پیشنهادی)"
        echo -e "  [2] نصب سفارشی و گام‌به‌گام (سؤال برای هر بخش)"
        echo -e "  [3] فقط نصب پنل وب (سبک)"
        echo -e "  [0] خروج"
        echo ""
        read -p "انتخاب روش نصب [1-3]: " init_choice
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
