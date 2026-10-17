#!/usr/bin/env bash
# ==============================================================================
#           MH Panel - Master Installer & Server Management Hub
#       Comprehensive, Intelligent & Modular VPN, Tunnel & Bridge Manager
# ------------------------------------------------------------------------------
# GitHub: https://github.com/t-51/MHPanel
# OS Support: Ubuntu 20.04+, 22.04+, 24.04+ | Debian 11+, 12+
# Architecture: x86_64 / amd64 / aarch64
# ==============================================================================

# Noninteractive environment variables to prevent installer interruption
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1

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
VERSION="1.5.0"

# Root Permission Check
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This script must be executed as root.${NC}"
    echo -e "Please run with: ${CYAN}sudo bash $0${NC}"
    exit 1
fi

# Ensure mhpanel & hmpanel CLI shortcuts exist globally
ensure_cli_shortcuts() {
    mkdir -p /usr/local/bin /usr/bin "${PANEL_DIR}"

    local running_src=""
    if [ -f "$0" ] && [[ "$0" != /dev/* ]]; then
        running_src="$0"
    elif [ -f "${BASH_SOURCE[0]}" ] && [[ "${BASH_SOURCE[0]}" != /dev/* ]]; then
        running_src="${BASH_SOURCE[0]}"
    fi

    if [ -n "$running_src" ] && [ ! -f "${PANEL_DIR}/install.sh" ]; then
        cp -f "$running_src" "${PANEL_DIR}/install.sh" 2>/dev/null || true
        chmod +x "${PANEL_DIR}/install.sh" 2>/dev/null || true
    fi

    rm -f /usr/local/bin/mhpanel /usr/bin/mhpanel 2>/dev/null || true
    cat > /usr/local/bin/mhpanel <<'EOF'
#!/usr/bin/env bash
PANEL_DIR="/www/wwwroot/mhpanel"
if [ -f "${PANEL_DIR}/install.sh" ]; then
    exec bash "${PANEL_DIR}/install.sh" "$@"
elif [ -f /root/mhpanel-repo/install.sh ]; then
    exec bash /root/mhpanel-repo/install.sh "$@"
else
    echo "MH Panel script not found. Fetching latest installer..."
    bash <(curl -sSL https://raw.githubusercontent.com/t-51/MHPanel/main/install.sh) "$@"
fi
EOF
    chmod +x /usr/local/bin/mhpanel 2>/dev/null || true
    ln -sf /usr/local/bin/mhpanel /usr/local/bin/hmpanel 2>/dev/null || true
    ln -sf /usr/local/bin/mhpanel /usr/local/bin/kigapanel 2>/dev/null || true
    ln -sf /usr/local/bin/mhpanel /usr/bin/mhpanel 2>/dev/null || true
    ln -sf /usr/local/bin/mhpanel /usr/bin/hmpanel 2>/dev/null || true
}
ensure_cli_shortcuts

# Supported Protocols List
PROTOCOLS=(ssh openvpn ocserv ikev2 sstp l2tp wireguard amneziawg http socks shadowsocks tuic mtproto pptp badvpn dnstt vaydns slipstream hysteria2 trojan naiveproxy stuntls noizdns masterdnsvpn tor)

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
    echo -e "${WHITE}${BOLD}   MH Panel - Master Installer & Management CLI (v${VERSION})${NC}"
    echo -e "${DIM}   Anti-Censorship VPN Protocols, Network Tunnels & MikroTik RouterOS Hub${NC}"
    echo -e "${GREEN}   [v${VERSION}] Mobile UX Overhaul | Dual-Stack IPv6 Tunnels | AmneziaWG Fix | SlowDNS Studio${NC}" 
    echo -e "${BLUE}------------------------------------------------------------------------${NC}"
}

# Network IP Detection
get_public_ipv4() {
    local ip=""
    for url in "https://api.ipify.org" "https://ipv4.icanhazip.com" "https://ifconfig.me/ip" "https://checkip.amazonaws.com"; do
        ip=$(curl -fsSL --max-time 2 "$url" 2>/dev/null | tr -d '[:space:]')
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[\d.]+' | head -n1)
    if [ -n "$ip" ]; then echo "$ip"; return 0; fi
    hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1"
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
        dnstt) echo "DNSTT (SlowDNS Crypto Tunnel)" ;;
        vaydns) echo "VayDNS (High-Speed DNS Tunnel)" ;;
        slipstream) echo "Slipstream (Covert DNS Channel)" ;;
        hysteria2) echo "Hysteria 2 (High-Speed QUIC & Salamander)" ;;
        trojan) echo "Trojan TLS (HTTPS Camouflage Proxy)" ;;
        naiveproxy) echo "NaiveProxy (Chromium Network Stack)" ;;
        stuntls) echo "StunTLS (WebRTC STUN Obfuscation)" ;;
        noizdns) echo "NoizDNS (Noise-Padded Anti-DPI DNS)" ;;
        masterdnsvpn) echo "MasterdnsVPN (High-Speed Chunked DNS)" ;;
        tor) echo "Tor Bridge (obfs4 / Pluggable Transports)" ;;
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
        wireguard) echo "51820" ;;
        amneziawg) echo "51821" ;;
        http) echo "8080" ;;
        socks) echo "1080" ;;
        shadowsocks) echo "8388" ;;
        tuic) echo "7443" ;;
        mtproto) echo "4433" ;;
        pptp) echo "1723" ;;
        badvpn) echo "7300" ;;
        dnstt) echo "5300" ;;
        vaydns) echo "5353" ;;
        slipstream) echo "5354" ;;
        hysteria2) echo "11443" ;;
        trojan) echo "12443" ;;
        naiveproxy) echo "13443" ;;
        stuntls) echo "3478" ;;
        noizdns) echo "5355" ;;
        masterdnsvpn) echo "5356" ;;
        tor) echo "9001" ;;
        *) echo "0" ;;
    esac
}

# Web Server (Apache / Nginx) Coexistence & Port Conflict Protection
detect_and_configure_webserver_compatibility() {
    local has_apache=0
    local has_nginx=0
    local ws_info=()

    if [ -x "/www/server/apache/bin/httpd" ] || [ -f "/etc/init.d/httpd" ] || systemctl is-active --quiet httpd 2>/dev/null || systemctl is-active --quiet apache2 2>/dev/null || [ -x "/usr/sbin/apache2" ]; then
        has_apache=1
        ws_info+=("Apache")
    fi

    if [ -x "/www/server/nginx/sbin/nginx" ] || [ -f "/etc/init.d/nginx" ] || systemctl is-active --quiet nginx 2>/dev/null || [ -x "/usr/sbin/nginx" ]; then
        has_nginx=1
        ws_info+=("Nginx")
    fi

    local p80_proc=$(ss -tlnp 2>/dev/null | grep -E ':80\b' | grep -oP 'users:\(\("\K[^"]+' | head -n1 || true)
    local p443_proc=$(ss -tlnp 2>/dev/null | grep -E ':443\b' | grep -oP 'users:\(\("\K[^"]+' | head -n1 || true)

    if [ ${#ws_info[@]} -gt 0 ] || [ -n "$p80_proc" ] || [ -n "$p443_proc" ]; then
        echo -e "${CYAN}------------------------------------------------------------------------${NC}"
        echo -e "${YELLOW}${BOLD}  🌐 Active Web Server Detected (Apache / Nginx / Web Daemon)${NC}"
        echo -e "${CYAN}------------------------------------------------------------------------${NC}"
        [ -n "$p80_proc" ] && echo -e "  • Service listening on Port 80: ${GREEN}${p80_proc}${NC}"
        [ -n "$p443_proc" ] && echo -e "  • Service listening on Port 443: ${GREEN}${p443_proc}${NC}"
        echo -e "  ${GREEN}✓ Ports 80 and 443 are protected and reserved for your web server & hosted websites.${NC}"
        echo -e "  ${GREEN}✓ All VPN protocols are routed to dedicated ports to avoid web server conflicts.${NC}"
        
        # Prevent conflict between distro apache2 and aaPanel httpd / nginx on port 80
        if systemctl is-active --quiet httpd 2>/dev/null || systemctl is-active --quiet nginx 2>/dev/null || [ -x "/www/server/apache/bin/httpd" ]; then
            if systemctl is-enabled apache2 2>/dev/null || systemctl is-failed apache2 2>/dev/null || systemctl is-active apache2 2>/dev/null; then
                echo -e "  ${GREEN}✓ Disabling conflicting default apache2 service in favor of the active web server daemon...${NC}"
                systemctl stop apache2 2>/dev/null || true
                systemctl disable apache2 2>/dev/null || true
                systemctl reset-failed apache2 2>/dev/null || true
            fi
        fi
        echo -e "${CYAN}------------------------------------------------------------------------${NC}\n"
    fi
}

# Helper: Validate and avoid port collisions with Apache, Nginx, or existing daemons
resolve_clean_port() {
    local proto=$1
    local req_port=$2

    if [ -z "$req_port" ] || [ "$req_port" = "0" ]; then
        req_port=$(protocol_default_port "$proto")
    fi

    local final_port="$req_port"

    # Port 80 and 443 special protection for Apache/Nginx
    if [ "$final_port" = "80" ] || [ "$final_port" = "443" ]; then
        if ss -tlnp 2>/dev/null | grep -qE "(:${final_port}\b)" || ss -ulnp 2>/dev/null | grep -qE "(:${final_port}\b)"; then
            case "$proto" in
                ocserv) final_port=10443 ;;
                amneziawg) final_port=51821 ;;
                trojan) final_port=12443 ;;
                naiveproxy) final_port=13443 ;;
                hysteria2) final_port=11443 ;;
                http) final_port=8080 ;;
                *) final_port=$((req_port + 10000)) ;;
            esac
        fi
    else
        # For any other port, verify it is not already in use by another service
        local is_busy=0
        if ss -tlnp 2>/dev/null | grep -qE "(:${final_port}\b)" || ss -ulnp 2>/dev/null | grep -qE "(:${final_port}\b)"; then
            is_busy=1
        fi

        if [ "$is_busy" -eq 1 ]; then
            case "$proto" in
                hysteria2) final_port=11443 ;;
                tuic) final_port=7443 ;;
                trojan) final_port=12443 ;;
                naiveproxy) final_port=13443 ;;
                stuntls) final_port=3478 ;;
                wireguard) final_port=51820 ;;
                amneziawg) final_port=51821 ;;
                ocserv) final_port=10443 ;;
                *)
                    local p=$final_port
                    while ss -tlnp 2>/dev/null | grep -qE "(:${p}\b)" || ss -ulnp 2>/dev/null | grep -qE "(:${p}\b)"; do
                        p=$((p + 1))
                    done
                    final_port=$p
                    ;;
            esac
        fi
    fi

    echo "$final_port"
}

# Protocol Detection
protocol_is_installed() {
    case "$1" in
        ssh) [ -f "/etc/ssh/sshd_config_vpn" ] || [ -f "/etc/ssh/sshd_config" ] ;;
        openvpn) [ -f "/etc/openvpn/server.conf" ] || [ -f "/etc/openvpn/server/server.conf" ] || [ -f "/etc/openvpn/server-tcp.conf" ] ;;
        ocserv) [ -f "/etc/ocserv/ocserv.conf" ] ;;
        ikev2) [ -f "/etc/swanctl/conf.d/ikev2.conf" ] || ([ -f "/etc/ipsec.conf" ] && grep -q "conn ikev2" /etc/ipsec.conf 2>/dev/null) ;;
        sstp) [ -f "/etc/systemd/system/sstpd.service" ] || [ -f "/etc/systemd/system/vpnserver.service" ] || [ -f "/etc/accel-ppp.conf" ] ;;
        l2tp) [ -f "/etc/xl2tpd/xl2tpd.conf" ] ;;
        wireguard) [ -f "/etc/wireguard/wg0.conf" ] ;;
        amneziawg) [ -f "/etc/amnezia/amneziawg/awg0.conf" ] ;;
        http) [ -f "/etc/systemd/system/mhpanel-http-proxy.service" ] ;;
        socks) [ -f "/etc/systemd/system/mhpanel-socks-proxy.service" ] ;;
        shadowsocks) [ -f "/etc/systemd/system/mhpanel-shadowsocks.service" ] && [ -x /usr/local/bin/ssserver ] ;;
        tuic) [ -f "/etc/systemd/system/mhpanel-tuic.service" ] && [ -x /usr/local/bin/tuic-server ] ;;
        mtproto) ls /etc/vpnpanel/mtproto_config_*.py >/dev/null 2>&1 || [ -f "/etc/systemd/system/mhpanel-mtproto.service" ] ;;
        pptp) [ -f "/etc/pptpd.conf" ] && (command -v pptpd >/dev/null 2>&1 || [ -x /usr/sbin/pptpd ]) ;;
        badvpn) [ -x /usr/local/bin/badvpn-udpgw ] || [ -x /usr/bin/badvpn-udpgw ] || [ -f "/etc/systemd/system/badvpn.service" ] || [ -f "/etc/systemd/system/videocall.service" ] ;;
        dnstt) [ -f "/etc/systemd/system/mhpanel-dnstt.service" ] && [ -x /usr/local/bin/dnstt-server ] ;;
        vaydns) [ -f "/etc/systemd/system/mhpanel-vaydns.service" ] && [ -x /usr/local/bin/vaydns-server ] ;;
        slipstream) [ -f "/etc/systemd/system/mhpanel-slipstream.service" ] && [ -x /usr/local/bin/slipstream-server ] ;;
        hysteria2) [ -f "/etc/vpnpanel/hysteria2.yaml" ] && [ -f "/etc/systemd/system/mhpanel-hysteria2.service" ] && [ -x /usr/local/bin/hysteria ] ;;
        trojan) [ -f "/etc/vpnpanel/trojan.json" ] && [ -f "/etc/systemd/system/mhpanel-trojan.service" ] && [ -x /usr/local/bin/sing-box ] ;;
        naiveproxy) [ -f "/etc/vpnpanel/naiveproxy.json" ] && [ -f "/etc/systemd/system/mhpanel-naiveproxy.service" ] && [ -x /usr/local/bin/sing-box ] ;;
        stuntls) [ -f "/etc/vpnpanel/stuntls.json" ] && [ -f "/etc/systemd/system/mhpanel-stuntls.service" ] && [ -x /usr/local/bin/stuntls-server ] ;;
        noizdns) [ -f "/etc/vpnpanel/noizdns.json" ] && [ -f "/etc/systemd/system/mhpanel-noizdns.service" ] && [ -x /usr/local/bin/noizdns-server ] ;;
        masterdnsvpn) [ -f "/etc/vpnpanel/masterdnsvpn.json" ] && [ -f "/etc/systemd/system/mhpanel-masterdnsvpn.service" ] && [ -x /usr/local/bin/masterdnsvpn-server ] ;;
        tor) [ -f "/etc/tor/torrc" ] && [ -f "/etc/systemd/system/mhpanel-tor.service" ] && (command -v tor >/dev/null 2>&1 || [ -x /usr/bin/tor ]) ;;
        *) return 1 ;;
    esac
}

protocol_service_status() {
    local svc=""
    case "$1" in
        ssh)
            for s in mhpanel-ssh ssh-ws sshd_vpn sshd ssh; do
                if systemctl is-active --quiet "$s" 2>/dev/null; then
                    svc="$s"
                    break
                fi
            done
            [ -z "$svc" ] && svc="mhpanel-ssh"
            ;;
        openvpn)
            for s in openvpn-server@server openvpn-server@server-tcp openvpn@server openvpn; do
                if systemctl is-active --quiet "$s" 2>/dev/null; then
                    svc="$s"
                    break
                fi
            done
            [ -z "$svc" ] && svc="openvpn-server@server"
            ;;
        ocserv) svc="ocserv" ;;
        ikev2)
            for s in strongswan-starter strongswan strongswan-swanctl; do
                if systemctl is-active --quiet "$s" 2>/dev/null; then
                    svc="$s"
                    break
                fi
            done
            [ -z "$svc" ] && svc="strongswan-starter"
            ;;
        sstp)
            for s in sstpd accel-ppp vpnserver; do
                if systemctl is-active --quiet "$s" 2>/dev/null; then
                    svc="$s"
                    break
                fi
            done
            [ -z "$svc" ] && svc="sstpd"
            ;;
        l2tp) svc="xl2tpd" ;;
        wireguard) svc="wg-quick@wg0" ;;
        amneziawg) svc="awg-quick@awg0" ;;
        http) svc="mhpanel-http-proxy" ;;
        socks) svc="mhpanel-socks-proxy" ;;
        shadowsocks) svc="mhpanel-shadowsocks" ;;
        tuic) svc="mhpanel-tuic"; systemctl is-active --quiet "$svc" 2>/dev/null || svc="tuic-server" ;;
        mtproto) svc="mhpanel-mtproto" ;;
        pptp)
            for s in pptpd mhpanel-pptp; do
                if systemctl is-active --quiet "$s" 2>/dev/null; then
                    svc="$s"
                    break
                fi
            done
            [ -z "$svc" ] && svc="pptpd"
            ;;
        badvpn)
            for s in videocall badvpn; do
                if systemctl is-active --quiet "$s" 2>/dev/null; then
                    svc="$s"
                    break
                fi
            done
            [ -z "$svc" ] && svc="videocall"
            ;;
        dnstt) svc="mhpanel-dnstt" ;;
        vaydns) svc="mhpanel-vaydns" ;;
        slipstream) svc="mhpanel-slipstream" ;;
        hysteria2) svc="mhpanel-hysteria2" ;;
        trojan) svc="mhpanel-trojan" ;;
        naiveproxy) svc="mhpanel-naiveproxy" ;;
        stuntls) svc="mhpanel-stuntls" ;;
        noizdns) svc="mhpanel-noizdns" ;;
        masterdnsvpn) svc="mhpanel-masterdnsvpn" ;;
        tor) svc="mhpanel-tor" ;;
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
    local port=""
    case "$1" in
        ssh) port=$(grep -Ei '^Port ' /etc/ssh/sshd_config_vpn 2>/dev/null | awk '{print $2}' | tail -n1) ;;
        openvpn) port=$(grep -Ei '^port ' /etc/openvpn/server.conf 2>/dev/null | awk '{print $2}' | tail -n1) ;;
        ocserv) port=$(grep -Ei '^tcp-port' /etc/ocserv/ocserv.conf 2>/dev/null | awk '{print $3}' | tail -n1) ;;
        ikev2) echo "500/4500 (UDP)"; return ;;
        sstp) port=$(grep -oE '\-p [0-9]+' /etc/systemd/system/sstpd.service 2>/dev/null | awk '{print $2}' | tail -n1) ;;
        l2tp) echo "1701 (UDP)"; return ;;
        wireguard) port=$(grep -Ei '^ListenPort' /etc/wireguard/wg0.conf 2>/dev/null | awk '{print $3}' | tail -n1) ;;
        amneziawg) port=$(grep -Ei '^ListenPort' /etc/amnezia/amneziawg/awg0.conf 2>/dev/null | awk '{print $3}' | tail -n1) ;;
        http) port=$(grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/mhpanel-http-proxy.service 2>/dev/null | awk -F: '{print $2}' | tail -n1) ;;
        socks) port=$(grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/mhpanel-socks-proxy.service 2>/dev/null | awk -F: '{print $2}' | tail -n1) ;;
        shadowsocks) port=$(grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/mhpanel-shadowsocks.service 2>/dev/null | awk -F: '{print $2}' | tail -n1) ;;
        tuic) port=$(grep -oE '0\.0\.0\.0:[0-9]+' /etc/vpnpanel/tuic.json /etc/systemd/system/mhpanel-tuic.service 2>/dev/null | awk -F: '{print $NF}' | tr -d '"' | tail -n1) ;;
        mtproto) port=$(grep -E '^PORT = ' /etc/vpnpanel/mtproto_config_*.py /etc/vpnpanel/mtproto_config.py 2>/dev/null | awk '{print $NF}' | tail -n1) ;;
        pptp) echo "1723 (TCP)"; return ;;
        badvpn) echo "7300 (UDP)"; return ;;
        dnstt) port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/dnstt.json 2>/dev/null | awk '{print $2}' | tail -n1) ;;
        vaydns) port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/vaydns.json 2>/dev/null | awk '{print $2}' | tail -n1) ;;
        slipstream) port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/slipstream.json 2>/dev/null | awk '{print $2}' | tail -n1) ;;
        hysteria2) port=$(grep -oE 'listen: :[0-9]+' /etc/vpnpanel/hysteria2.yaml 2>/dev/null | awk -F: '{print $3}' | tail -n1) ;;
        trojan) port=$(grep -oE '"listen_port":\s*[0-9]+' /etc/vpnpanel/trojan.json 2>/dev/null | awk '{print $2}' | tail -n1) ;;
        naiveproxy) port=$(grep -oE '"listen_port":\s*[0-9]+' /etc/vpnpanel/naiveproxy.json 2>/dev/null | awk '{print $2}' | tail -n1) ;;
        stuntls) port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/stuntls.json 2>/dev/null | awk '{print $2}' | tail -n1) ;;
        noizdns) port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/noizdns.json 2>/dev/null | awk '{print $2}' | tail -n1) ;;
        masterdnsvpn) port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/masterdnsvpn.json 2>/dev/null | awk '{print $2}' | tail -n1) ;;
        tor) port=$(grep -E '^ORPort ' /etc/tor/torrc 2>/dev/null | awk '{print $2}' | tail -n1) ;;
    esac
    if [ -n "$port" ]; then
        echo "$port"
    else
        protocol_default_port "$1"
    fi
}

# ==============================================================================
# BASE SYSTEM & WEB UI INSTALLATION
# ==============================================================================

install_base_prerequisites() {
    echo -e "\n${YELLOW}>>> [1/6] Checking and installing Linux base prerequisites...${NC}"
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    export NEEDRESTART_SUSPEND=1

    # Safeguard current SSH session port early to prevent accidental disconnection
    local ssh_p=$(ss -tlnp 2>/dev/null | grep -E '\b(sshd|systemd-ssh)' | awk '{print $4}' | awk -F: '{print $NF}' | head -n1 || true)
    ssh_p=${ssh_p:-22}
    if command -v ufw >/dev/null 2>&1 && systemctl is-active --quiet ufw 2>/dev/null; then
        ufw allow "${ssh_p}/tcp" >/dev/null 2>&1 || true
        ufw allow 22/tcp >/dev/null 2>&1 || true
    fi
    iptables -I INPUT -p tcp --dport "${ssh_p}" -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true

    # Preseed debconf selections for iptables-persistent to avoid interactive dialog prompts
    if command -v debconf-set-selections >/dev/null 2>&1; then
        echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections 2>/dev/null || true
        echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections 2>/dev/null || true
    fi

    # Configure needrestart to avoid restarting sshd or prompting during upgrades
    if [ -d /etc/needrestart/conf.d ]; then
        cat > /etc/needrestart/conf.d/99mhpanel.conf 2>/dev/null <<'EOF' || true
$nrconf{restart} = 'a';
$nrconf{override_rc} = {
    qr(^sshd?(\.service)?) => 0,
    qr(^systemd-networkd) => 0,
    qr(^systemd-resolved) => 0,
};
EOF
    fi

    # Safeguard Apache / Nginx / Web server coexistence early
    detect_and_configure_webserver_compatibility

    local pkgs_needed=()
    local firewall_pkg="ufw"
    if dpkg -s iptables-persistent >/dev/null 2>&1; then
        firewall_pkg="iptables-persistent"
    fi

    for p in python3 python3-pip python3-venv curl wget git openssl certbot iptables "$firewall_pkg" cron net-tools sudo cmake build-essential jq socat unzip; do
        if ! dpkg -s "$p" >/dev/null 2>&1; then
            pkgs_needed+=("$p")
        fi
    done

    if [ ${#pkgs_needed[@]} -eq 0 ]; then
        echo -e "    ${GREEN}[✓] All base Linux dependencies are already installed (Skipped).${NC}"
    else
        echo -e "    Installing missing packages: ${CYAN}${pkgs_needed[*]}${NC}..."
        apt-get update -y 2>/dev/null || true
        if ! apt-get install -y --no-install-recommends \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            "${pkgs_needed[@]}" 2>/dev/null; then
            echo -e "    ${YELLOW}Batch package installation encountered issues; installing required packages individually...${NC}"
            for pkg in "${pkgs_needed[@]}"; do
                apt-get install -y --no-install-recommends \
                    -o Dpkg::Options::="--force-confdef" \
                    -o Dpkg::Options::="--force-confold" \
                    "$pkg" 2>/dev/null || apt-get install -y "$pkg" 2>/dev/null || true
            done
        fi
        echo -e "    ${GREEN}[✓] Base system dependencies successfully installed.${NC}"
    fi

    # Fix Ubuntu PAM radius auth sample issue (failed bind to vrf-blue)
    if [ -f /etc/pam_radius_auth.conf ]; then
        sed -i -E 's/\s+vrf=[^\s]+//g' /etc/pam_radius_auth.conf 2>/dev/null || true
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
    touch /etc/sysctl.conf 2>/dev/null || true
    grep -qxF 'net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf 2>/dev/null || true
    grep -qxF 'net.ipv6.conf.all.forwarding=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf 2>/dev/null || true
    sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-mhpanel.conf >/dev/null 2>&1 || true
    echo -e "    ${GREEN}[✓] TCP BBR, Kernel limits, IPv4 and IPv6 forwarding successfully configured.${NC}"
}

install_panel_web_ui() {
    echo -e "\n${YELLOW}>>> [3/6] Setting up MH Panel Web UI service...${NC}"
    mkdir -p "${PANEL_DIR}"
    mkdir -p "${SSL_DIR}"
    chmod 700 "${SSL_DIR}"

    # Ensure git is available
    if ! command -v git >/dev/null 2>&1; then
        apt-get update -y 2>/dev/null || true
        apt-get install -y git 2>/dev/null || true
    fi

    if [ "${SCRIPT_DIR}" != "${PANEL_DIR}" ] && [ -f "${SCRIPT_DIR}/app.py" ]; then
        echo "    Deploying MH Panel source files to ${PANEL_DIR}..."
        cp -r "${SCRIPT_DIR}"/* "${PANEL_DIR}/" 2>/dev/null || true
    elif [ ! -f "${PANEL_DIR}/app.py" ]; then
        echo -e "${CYAN}    Fetching latest MH Panel source files from GitHub (${GITHUB_REPO})...${NC}"
        rm -rf /tmp/mhpanel_clone
        if git clone --depth=1 "${GITHUB_REPO}" /tmp/mhpanel_clone 2>/dev/null || git clone "${GITHUB_REPO}" /tmp/mhpanel_clone 2>/dev/null; then
            cp -r /tmp/mhpanel_clone/* "${PANEL_DIR}/" 2>/dev/null || true
            cp -r /tmp/mhpanel_clone/.* "${PANEL_DIR}/" 2>/dev/null || true
            rm -rf /tmp/mhpanel_clone
        else
            echo -e "${YELLOW}    Git clone encountered issues; attempting direct archive download from GitHub...${NC}"
            curl -sSL "https://github.com/t-51/MHPanel/archive/refs/heads/main.tar.gz" -o /tmp/mhpanel.tar.gz 2>/dev/null || wget -qO /tmp/mhpanel.tar.gz "https://github.com/t-51/MHPanel/archive/refs/heads/main.tar.gz" 2>/dev/null || true
            if [ -f /tmp/mhpanel.tar.gz ]; then
                tar -xzf /tmp/mhpanel.tar.gz -C /tmp/ 2>/dev/null || true
                if [ -d /tmp/MHPanel-main ]; then
                    cp -r /tmp/MHPanel-main/* "${PANEL_DIR}/" 2>/dev/null || true
                    rm -rf /tmp/MHPanel-main /tmp/mhpanel.tar.gz
                fi
            fi
        fi
    else
        echo -e "${CYAN}    Syncing and updating existing MH Panel files to latest GitHub version...${NC}"
        cd "${PANEL_DIR}"
        if [ ! -d .git ]; then
            git init -b main 2>/dev/null || git init 2>/dev/null || true
            git remote add origin "${GITHUB_REPO}" 2>/dev/null || git remote set-url origin "${GITHUB_REPO}" 2>/dev/null || true
        fi
        git remote set-url origin "${GITHUB_REPO}" 2>/dev/null || true
        if git fetch origin main --depth=1 2>/dev/null || git fetch origin main 2>/dev/null; then
            git reset --hard origin/main 2>/dev/null || true
        fi
    fi

    chmod +x "${PANEL_DIR}/install.sh" 2>/dev/null || true

    # Install repository bundled binaries
    if [ -d "${PANEL_DIR}/bin" ]; then
        echo "    Installing bundled binaries from ${PANEL_DIR}/bin/ to /usr/local/bin/..."
        cp -f "${PANEL_DIR}/bin/"* /usr/local/bin/ 2>/dev/null || true
        chmod +x /usr/local/bin/*dns* /usr/local/bin/*slip* /usr/local/bin/tuic* /usr/local/bin/badvpn* /usr/local/bin/stuntls* /usr/local/bin/ssh-ws* 2>/dev/null || true
    fi

    # Ensure python3-venv and python3-pip are installed
    if ! dpkg -s python3-venv >/dev/null 2>&1 || ! dpkg -s python3-pip >/dev/null 2>&1; then
        apt-get install -y python3-venv python3-pip 2>/dev/null || true
    fi

    if [ ! -d "${PANEL_DIR}/venv" ] || [ ! -f "${PANEL_DIR}/venv/bin/python" ] || [ ! -f "${PANEL_DIR}/venv/bin/pip" ]; then
        echo "    Creating Python virtual environment in ${PANEL_DIR}/venv..."
        rm -rf "${PANEL_DIR}/venv"
        python3 -m venv "${PANEL_DIR}/venv" 2>/dev/null || true
        if [ ! -f "${PANEL_DIR}/venv/bin/pip" ]; then
            apt-get install -y python3-venv python3-pip 2>/dev/null || true
            rm -rf "${PANEL_DIR}/venv"
            python3 -m venv "${PANEL_DIR}/venv"
        fi
        "${PANEL_DIR}/venv/bin/pip" install --upgrade pip --quiet 2>/dev/null || true
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

    # Install daemon microservices scripts
    if [ -d "${PANEL_DIR}/scripts/daemons" ]; then
        cp -f "${PANEL_DIR}/scripts/daemons/"* /usr/local/bin/ 2>/dev/null || true
        chmod +x /usr/local/bin/masterdnsvpn-server /usr/local/bin/noizdns-server /usr/local/bin/stuntls-server /usr/local/bin/ssh-ws-proxy.py /usr/local/bin/badvpn-udpgw 2>/dev/null || true
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
    if systemctl is-active --quiet videocall.service 2>/dev/null; then
        echo -e "    ${GREEN}[✓] BadVPN UDPGW is already running via videocall.service on port 7300.${NC}"
        return 0
    fi

    if [ ! -x /usr/local/bin/badvpn-udpgw ] && [ ! -x /usr/bin/badvpn-udpgw ]; then
        for bdir in "${PANEL_DIR}/bin" "${PANEL_DIR}/scripts/daemons" "${SCRIPT_DIR}/bin" "/root/mhpanel-repo/bin"; do
            if [ -f "${bdir}/badvpn-udpgw" ]; then
                cp -f "${bdir}/badvpn-udpgw" /usr/local/bin/badvpn-udpgw 2>/dev/null || true
                chmod +x /usr/local/bin/badvpn-udpgw 2>/dev/null || true
                break
            fi
        done
    fi

    if [ ! -x /usr/local/bin/badvpn-udpgw ] && [ ! -x /usr/bin/badvpn-udpgw ]; then
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/badvpn-udpgw -o /usr/local/bin/badvpn-udpgw 2>/dev/null || true
        chmod +x /usr/local/bin/badvpn-udpgw 2>/dev/null || true
    fi

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

    if [ ! -x /usr/local/bin/badvpn-udpgw ] && [ ! -x /usr/bin/badvpn-udpgw ]; then
        echo -e "    ${YELLOW}[!] BadVPN UDPGW binary could not be prepared. Skipping badvpn service.${NC}"
        systemctl stop badvpn.service 2>/dev/null || true
        systemctl disable badvpn.service 2>/dev/null || true
        rm -f /etc/systemd/system/badvpn.service
        systemctl daemon-reload
        return 0
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
    echo -e "\n${YELLOW}>>> [4/6] Checking and verifying Anti-Censorship Tunnel Binaries...${NC}"
    local count_downloaded=0

    # First: install repository bundled binaries if available
    for bdir in "${PANEL_DIR}/bin" "${PANEL_DIR}/scripts/daemons" "${SCRIPT_DIR}/bin" "${SCRIPT_DIR}/scripts/daemons" "/root/mhpanel-repo/bin"; do
        if [ -d "$bdir" ]; then
            echo "    Installing bundled binaries from ${bdir} to /usr/local/bin/..."
            cp -f "$bdir"/* /usr/local/bin/ 2>/dev/null || true
            chmod +x /usr/local/bin/* 2>/dev/null || true
        fi
    done

    # DNSTT
    if [ ! -x /usr/local/bin/dnstt-server ]; then
        echo "    Downloading DNSTT (dnstt-server & dnstt-client)..."
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/dnstt-server -o /usr/local/bin/dnstt-server 2>/dev/null || true
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/dnstt-client -o /usr/local/bin/dnstt-client 2>/dev/null || true
        chmod +x /usr/local/bin/dnstt-* 2>/dev/null || true
        if [ -x /usr/local/bin/dnstt-server ]; then
            count_downloaded=$((count_downloaded + 1))
        else
            echo -e "    ${RED}[!] Warning: Failed to download dnstt-server. Check server internet access.${NC}"
        fi
    fi

    # VayDNS
    if [ ! -x /usr/local/bin/vaydns-server ]; then
        echo "    Downloading VayDNS (vaydns-server & vaydns-client)..."
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/vaydns-server -o /usr/local/bin/vaydns-server 2>/dev/null || true
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/vaydns-client -o /usr/local/bin/vaydns-client 2>/dev/null || true
        chmod +x /usr/local/bin/vaydns-* 2>/dev/null || true
        if [ -x /usr/local/bin/vaydns-server ]; then
            count_downloaded=$((count_downloaded + 1))
        else
            echo -e "    ${RED}[!] Warning: Failed to download vaydns-server. Check server internet access.${NC}"
        fi
    fi

    # Slipstream
    if [ ! -x /usr/local/bin/slipstream-server ]; then
        echo "    Downloading Slipstream (slipstream-server & slipstream-client)..."
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/slipstream-server -o /usr/local/bin/slipstream-server 2>/dev/null || true
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/slipstream-client -o /usr/local/bin/slipstream-client 2>/dev/null || true
        chmod +x /usr/local/bin/slipstream-* 2>/dev/null || true
        if [ -x /usr/local/bin/slipstream-server ]; then
            count_downloaded=$((count_downloaded + 1))
        else
            echo -e "    ${RED}[!] Warning: Failed to download slipstream-server. Check server internet access.${NC}"
        fi
    fi

    # TUIC
    if [ ! -x /usr/local/bin/tuic-server ]; then
        echo "    Downloading TUIC Server..."
        local arch="$(uname -m)"
        local tuic_arch="x86_64"
        [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ] && tuic_arch="aarch64"
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/tuic-server -o /usr/local/bin/tuic-server 2>/dev/null || \
        curl -fsSL --connect-timeout 10 --max-time 60 "https://github.com/EAimTY/tuic/releases/download/tuic-server-1.0.0/tuic-server-1.0.0-${tuic_arch}-unknown-linux-musl" -o /usr/local/bin/tuic-server 2>/dev/null || true
        chmod +x /usr/local/bin/tuic-server 2>/dev/null || true
        if [ -x /usr/local/bin/tuic-server ]; then
            count_downloaded=$((count_downloaded + 1))
        else
            echo -e "    ${RED}[!] Warning: Failed to download tuic-server. Check server internet access.${NC}"
        fi
    fi

    # Hysteria 2
    if [ ! -x /usr/local/bin/hysteria ]; then
        echo "    Downloading Hysteria 2..."
        local arch="$(uname -m)"
        local hy_arch="amd64"
        [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ] && hy_arch="arm64"
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/hysteria -o /usr/local/bin/hysteria 2>/dev/null || \
        curl -fsSL --connect-timeout 10 --max-time 60 "https://github.com/apernet/hysteria/releases/download/app%2Fv2.5.2/hysteria-linux-${hy_arch}" -o /usr/local/bin/hysteria 2>/dev/null || true
        chmod +x /usr/local/bin/hysteria 2>/dev/null || true
        if [ -x /usr/local/bin/hysteria ]; then
            count_downloaded=$((count_downloaded + 1))
        else
            echo -e "    ${RED}[!] Warning: Failed to download hysteria. Check server internet access.${NC}"
        fi
    fi

    # Sing-box (Trojan & NaiveProxy)
    if [ ! -x /usr/local/bin/sing-box ]; then
        echo "    Downloading Sing-box (Trojan & NaiveProxy)..."
        local arch="$(uname -m)"
        local sb_arch="amd64"
        [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ] && sb_arch="arm64"
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/sing-box -o /usr/local/bin/sing-box 2>/dev/null || \
        (curl -fsSL --connect-timeout 10 --max-time 60 "https://github.com/SagerNet/sing-box/releases/download/v1.9.3/sing-box-1.9.3-linux-${sb_arch}.tar.gz" 2>/dev/null | tar -xz -C /tmp/ 2>/dev/null && mv /tmp/sing-box-*/sing-box /usr/local/bin/sing-box 2>/dev/null && rm -rf /tmp/sing-box* || true)
        chmod +x /usr/local/bin/sing-box 2>/dev/null || true
        if [ -x /usr/local/bin/sing-box ]; then
            count_downloaded=$((count_downloaded + 1))
        else
            echo -e "    ${RED}[!] Warning: Failed to download sing-box. Check server internet access.${NC}"
        fi
    fi
    mkdir -p /etc/sing-box

    # Shadowsocks-rust (ssserver)
    if [ ! -x /usr/local/bin/ssserver ]; then
        echo "    Downloading Shadowsocks-rust (ssserver)..."
        local arch="$(uname -m)"
        local ss_arch="x86_64"
        [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ] && ss_arch="aarch64"
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/ssserver -o /usr/local/bin/ssserver 2>/dev/null || \
        curl -fsSL --connect-timeout 10 --max-time 60 "https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.22.0/shadowsocks-v1.22.0.${ss_arch}-unknown-linux-gnu.tar.xz" 2>/dev/null | tar -xJ -C /usr/local/bin/ ssserver 2>/dev/null || true
        chmod +x /usr/local/bin/ssserver 2>/dev/null || true
        if [ -x /usr/local/bin/ssserver ]; then
            count_downloaded=$((count_downloaded + 1))
        else
            echo -e "    ${RED}[!] Warning: Failed to download ssserver. Check server internet access.${NC}"
        fi
    fi

    # StunTLS Server
    if [ ! -x /usr/local/bin/stuntls-server ]; then
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/stuntls-server -o /usr/local/bin/stuntls-server 2>/dev/null || true
        chmod +x /usr/local/bin/stuntls-server 2>/dev/null || true
        [ -x /usr/local/bin/stuntls-server ] && count_downloaded=$((count_downloaded + 1))
    fi

    # NoizDNS Server
    if [ ! -x /usr/local/bin/noizdns-server ]; then
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/noizdns-server -o /usr/local/bin/noizdns-server 2>/dev/null || true
        chmod +x /usr/local/bin/noizdns-server 2>/dev/null || true
        [ -x /usr/local/bin/noizdns-server ] && count_downloaded=$((count_downloaded + 1))
    fi

    # MasterdnsVPN Server
    if [ ! -x /usr/local/bin/masterdnsvpn-server ]; then
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/masterdnsvpn-server -o /usr/local/bin/masterdnsvpn-server 2>/dev/null || true
        chmod +x /usr/local/bin/masterdnsvpn-server 2>/dev/null || true
        [ -x /usr/local/bin/masterdnsvpn-server ] && count_downloaded=$((count_downloaded + 1))
    fi

    # SSH-WS Proxy Daemon
    if [ ! -f /usr/local/bin/ssh-ws-proxy.py ]; then
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/ssh-ws-proxy.py -o /usr/local/bin/ssh-ws-proxy.py 2>/dev/null || true
        chmod +x /usr/local/bin/ssh-ws-proxy.py 2>/dev/null || true
    fi

    # BadVPN UDPGW
    if [ ! -x /usr/local/bin/badvpn-udpgw ] && [ ! -x /usr/bin/badvpn-udpgw ]; then
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/badvpn-udpgw -o /usr/local/bin/badvpn-udpgw 2>/dev/null || true
        chmod +x /usr/local/bin/badvpn-udpgw 2>/dev/null || true
        [ -x /usr/local/bin/badvpn-udpgw ] && count_downloaded=$((count_downloaded + 1))
    fi

    # Tor & Pluggable Transports
    if ! command -v tor >/dev/null 2>&1; then
        echo "    Installing Tor & obfs4proxy/lyrebird..."
        export DEBIAN_FRONTEND=noninteractive
        apt-get install -y --no-install-recommends tor obfs4proxy >/dev/null 2>&1 || apt-get install -y --no-install-recommends tor lyrebird >/dev/null 2>&1 || true
        systemctl stop tor tor@default 2>/dev/null || true
        systemctl disable tor tor@default 2>/dev/null || true
    fi

    # GOST v3
    if [ ! -x /usr/local/bin/gost ]; then
        echo "    Downloading GOST v3..."
        curl -fsSL https://github.com/go-gost/gost/releases/download/v3.0.0-rc10/gost_3.0.0-rc10_linux_amd64.tar.gz 2>/dev/null | tar -xz -C /usr/local/bin/ gost 2>/dev/null || true
        chmod +x /usr/local/bin/gost 2>/dev/null || true
        if [ -x /usr/local/bin/gost ]; then
            count_downloaded=$((count_downloaded + 1))
        else
            echo -e "    ${RED}[!] Warning: Failed to download GOST. Check server internet access.${NC}"
        fi
    fi

    # WSTunnel
    if [ ! -x /usr/local/bin/wstunnel ]; then
        echo "    Downloading WSTunnel..."
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/wstunnel -o /usr/local/bin/wstunnel 2>/dev/null || \
        (curl -fsSL https://github.com/erebe/wstunnel/releases/download/v11.0.0/wstunnel_11.0.0_linux_amd64.tar.gz 2>/dev/null | tar -xz -C /usr/local/bin/ wstunnel 2>/dev/null || true)
        chmod +x /usr/local/bin/wstunnel 2>/dev/null || true
        if [ -x /usr/local/bin/wstunnel ]; then
            count_downloaded=$((count_downloaded + 1))
        else
            echo -e "    ${RED}[!] Warning: Failed to download WSTunnel. Check server internet access.${NC}"
        fi
    fi

    # RTT
    if [ ! -x /usr/local/bin/rtt ]; then
        echo "    Downloading ReverseTlsTunnel (RTT)..."
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/rtt -o /usr/local/bin/rtt 2>/dev/null || \
        curl -fsSL https://github.com/radkesvat/ReverseTlsTunnel/releases/download/v7.1/rtt-linux-amd64.zip -o /tmp/rtt.zip 2>/dev/null || true
        if [ -f /tmp/rtt.zip ]; then
            unzip -o /tmp/rtt.zip -d /usr/local/bin/ >/dev/null 2>&1 || true
            chmod +x /usr/local/bin/rtt 2>/dev/null || true
            rm -f /tmp/rtt.zip
        fi
        chmod +x /usr/local/bin/rtt 2>/dev/null || true
        if [ -x /usr/local/bin/rtt ]; then
            count_downloaded=$((count_downloaded + 1))
        else
            echo -e "    ${RED}[!] Warning: Failed to download RTT. Check server internet access.${NC}"
        fi
    fi

    # Chisel
    if [ ! -x /usr/local/bin/chisel ]; then
        echo "    Downloading Chisel..."
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/chisel -o /usr/local/bin/chisel 2>/dev/null || \
        (curl -fsSL https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_linux_amd64.gz 2>/dev/null | gzip -d > /usr/local/bin/chisel 2>/dev/null || true)
        chmod +x /usr/local/bin/chisel 2>/dev/null || true
        if [ -x /usr/local/bin/chisel ]; then
            count_downloaded=$((count_downloaded + 1))
        else
            echo -e "    ${RED}[!] Warning: Failed to download Chisel. Check server internet access.${NC}"
        fi
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
        else
            echo -e "    ${RED}[!] Warning: Failed to download FRP. Check server internet access.${NC}"
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
        else
            echo -e "    ${RED}[!] Warning: Failed to download UDP2Raw. Check server internet access.${NC}"
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
        else
            echo -e "    ${RED}[!] Warning: Failed to download Phantun. Check server internet access.${NC}"
        fi
    fi

    # Rathole
    if [ ! -x /usr/local/bin/rathole ]; then
        echo "    Downloading Rathole..."
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/rathole -o /usr/local/bin/rathole 2>/dev/null || \
        curl -fsSL https://github.com/rapiz1/rathole/releases/download/v0.5.0/rathole-x86_64-unknown-linux-musl.zip -o /tmp/rathole.zip 2>/dev/null || true
        if [ -f /tmp/rathole.zip ]; then
            unzip -o /tmp/rathole.zip -d /tmp/ >/dev/null 2>&1 || true
            mv /tmp/rathole /usr/local/bin/ 2>/dev/null || true
            chmod +x /usr/local/bin/rathole 2>/dev/null || true
            rm -f /tmp/rathole*
        fi
        chmod +x /usr/local/bin/rathole 2>/dev/null || true
        if [ -x /usr/local/bin/rathole ]; then
            count_downloaded=$((count_downloaded + 1))
        else
            echo -e "    ${RED}[!] Warning: Failed to download Rathole. Check server internet access.${NC}"
        fi
    fi

    # Tun2Socks
    if [ ! -x /usr/local/bin/tun2socks ]; then
        echo "    Downloading Tun2Socks..."
        local arch="$(uname -m)"
        local t2s_arch="linux-amd64"
        [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ] && t2s_arch="linux-arm64"
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/tun2socks -o /usr/local/bin/tun2socks 2>/dev/null || \
        (curl -fsSL --connect-timeout 10 --max-time 60 "https://github.com/xjasonlyu/tun2socks/releases/download/v2.5.2/tun2socks-${t2s_arch}.zip" -o /tmp/t2s.zip 2>/dev/null && unzip -o /tmp/t2s.zip -d /tmp/ >/dev/null 2>&1 && mv /tmp/tun2socks-* /usr/local/bin/tun2socks 2>/dev/null && rm -f /tmp/t2s.zip || true)
        chmod +x /usr/local/bin/tun2socks 2>/dev/null || true
        if [ -x /usr/local/bin/tun2socks ]; then
            count_downloaded=$((count_downloaded + 1))
        else
            echo -e "    ${RED}[!] Warning: Failed to download Tun2Socks. Check server internet access.${NC}"
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
        else
            echo -e "    ${RED}[!] Warning: Failed to download Kcptun. Check server internet access.${NC}"
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

    local clean_port="$(resolve_clean_port "$proto" "$port")"
    if [ "$clean_port" != "$port" ] && [ -n "$port" ] && [ "$port" != "0" ]; then
        echo -e "    ${YELLOW}[!] Port conflict (${port}) detected. Reassigned ${proto} to clean port ${clean_port}.${NC}"
    fi
    port="$clean_port"

    echo -e "    ${CYAN}Installing & configuring $(protocol_label "$proto") (Port: ${port})...${NC}"
    mkdir -p /var/log/mhpanel
    local log_file="/var/log/mhpanel/install_${proto}.log"
    echo "=== Installation of ${proto} started at $(date) ===" > "$log_file"
    if "$HELPER" install "$proto" "$port" >> "$log_file" 2>&1; then
        echo -e "    ${GREEN}✓ $(protocol_label "$proto") successfully installed and activated on port ${port}.${NC}"
    else
        echo -e "    ${YELLOW}[!] Setup for $(protocol_label "$proto") completed (Log: ${log_file}).${NC}"
    fi
    cat "$log_file" >> /var/log/mhpanel_install.log 2>/dev/null || true
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

    # Step 5: Protocols Setup
    echo -e "\n${YELLOW}=== VPN Protocols Setup ===${NC}"
    read -p "Do you want to automatically setup all missing VPN protocols? [Y/n]: " ans_all_proto
    if [[ -z "$ans_all_proto" || "$ans_all_proto" =~ ^[yY]$ ]]; then
        echo -e "    ${CYAN}Automatically configuring missing protocols with optimized default ports...${NC}"
        for proto in "${PROTOCOLS[@]}"; do
            local def_port="$(protocol_default_port "$proto")"
            local lbl="$(protocol_label "$proto")"
            if protocol_is_installed "$proto"; then
                echo -e "    ${GREEN}[✓] ${lbl}${NC} is already installed (Skipped to preserve settings)."
            else
                install_protocol_action "$proto" "$def_port"
            fi
        done
    else
        echo -e "    ${DIM}--> Skipped protocol bulk install. You can manage individual protocols anytime via 'mhpanel'.${NC}"
    fi

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

show_panel_access_info() {
    clear 2>/dev/null || true
    local srv_ip=$(get_public_ipv4)
    local srv_ipv6=$(get_public_ipv6)
    local panel_port=$(cat "${PANEL_DIR}/panel_port.txt" 2>/dev/null || echo "9090")
    local domain=""
    if [ -f "${PANEL_DIR}/system_domain.txt" ]; then
        domain=$(cat "${PANEL_DIR}/system_domain.txt" 2>/dev/null | tr -d '[:space:]')
    fi
    local user="admin"
    local pass="admin"
    if [ -f "${PANEL_DIR}/admin_credentials.txt" ]; then
        user=$(grep -Ei '^username=' "${PANEL_DIR}/admin_credentials.txt" | cut -d= -f2-)
        pass=$(grep -Ei '^password=' "${PANEL_DIR}/admin_credentials.txt" | cut -d= -f2-)
    fi
    local api_key=$(cat "${PANEL_DIR}/api_key.txt" 2>/dev/null || echo "N/A")
    local is_active=""
    if systemctl is-active --quiet mhpanel 2>/dev/null; then
        is_active="${GREEN}Active / Running${NC}"
    else
        is_active="${RED}Stopped / Inactive${NC}"
    fi

    echo -e "${CYAN}${BOLD}========================================================================${NC}"
    echo -e "${WHITE}${BOLD}              MH Panel - Panel Access & Login Credentials               ${NC}"
    echo -e "${CYAN}${BOLD}========================================================================${NC}"
    echo -e "  ⚡ ${BOLD}Service Status:${NC}         ${is_active}"
    echo -e "  🌐 ${BOLD}Web Panel URL (IPv4):${NC}   ${CYAN}${BOLD}https://${srv_ip}:${panel_port}/${NC}"
    if [ -n "$srv_ipv6" ]; then
        echo -e "  🌐 ${BOLD}Web Panel URL (IPv6):${NC}   ${CYAN}${BOLD}https://[${srv_ipv6}]:${panel_port}/${NC}"
    fi
    if [ -n "$domain" ]; then
        echo -e "  🌐 ${BOLD}Custom Domain URL:${NC}      ${CYAN}${BOLD}https://${domain}:${panel_port}/${NC}"
    fi
    echo -e "  🔌 ${BOLD}Web Panel Port:${NC}        ${YELLOW}${BOLD}${panel_port}${NC}"
    echo -e "  👤 ${BOLD}Admin Username:${NC}        ${GREEN}${BOLD}${user}${NC}"
    echo -e "  🔑 ${BOLD}Admin Password:${NC}        ${GREEN}${BOLD}${pass}${NC}"
    echo -e "  🛡️  ${BOLD}Public API Key:${NC}         ${DIM}${api_key}${NC}"
    echo -e "${CYAN}${BOLD}========================================================================${NC}"
    echo -e "  💡 ${YELLOW}${BOLD}Connection Note:${NC} Default SSL certificate is Self-Signed (IP SAN)."
    echo -e "     When accessing the URL in your browser, if an SSL warning appears:"
    echo -e "     Click ${BOLD}Advanced${NC} and select ${BOLD}Proceed to ... (unsafe)${NC}."
    echo -e "     You can configure a free Let's Encrypt SSL certificate anytime from the menu."
    echo -e "${CYAN}${BOLD}========================================================================${NC}\n"
    read -p "Press Enter to return to main menu..."
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
            echo -e "  [5] View Live Logs (journalctl -u service)"
            echo -e "  [6] View Installation & Setup Log (/var/log/mhpanel/...)"
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
                    case "$sel_proto" in
                        ssh) svc="mhpanel-ssh" ;;
                        openvpn) svc="openvpn@server" ;;
                        wireguard) svc="wg-quick@wg0" ;;
                        amneziawg) svc="awg-quick@awg0" ;;
                        ocserv) svc="ocserv" ;;
                        ikev2)
                            for s in strongswan strongswan-swanctl strongswan-starter; do
                                if systemctl is-active --quiet "$s" 2>/dev/null; then svc="$s"; break; fi
                            done
                            [ -z "$svc" ] && svc="strongswan"
                            ;;
                        sstp) svc="sstpd" ;;
                        l2tp) svc="xl2tpd" ;;
                        shadowsocks) svc="mhpanel-shadowsocks" ;;
                        tuic) svc="mhpanel-tuic" ;;
                        badvpn) svc="badvpn" ;;
                        http) svc="mhpanel-http-proxy" ;;
                        socks) svc="mhpanel-socks-proxy" ;;
                        mtproto)
                            local p="$(protocol_current_port "$sel_proto")"
                            svc="mhpanel-mtproto@${p}"
                            ;;
                        pptp) svc="mhpanel-pptp"; systemctl is-active --quiet "$svc" 2>/dev/null || svc="pptpd" ;;
                        dnstt) svc="mhpanel-dnstt" ;;
                        vaydns) svc="mhpanel-vaydns" ;;
                        slipstream) svc="mhpanel-slipstream" ;;
                        hysteria2) svc="mhpanel-hysteria2" ;;
                        trojan) svc="mhpanel-trojan" ;;
                        naiveproxy) svc="mhpanel-naiveproxy" ;;
                        stuntls) svc="mhpanel-stuntls" ;;
                        noizdns) svc="mhpanel-noizdns" ;;
                        masterdnsvpn) svc="mhpanel-masterdnsvpn" ;;
                        tor) svc="mhpanel-tor" ;;
                    esac
                    systemctl restart "$svc" 2>/dev/null || true
                    echo -e "${GREEN}Service ${svc} restarted.${NC}"
                    read -p "Press Enter to continue..."
                    ;;
                5)
                    local svc="openvpn@server"
                    case "$sel_proto" in
                        ssh) svc="mhpanel-ssh" ;;
                        openvpn) svc="openvpn@server" ;;
                        wireguard) svc="wg-quick@wg0" ;;
                        amneziawg) svc="awg-quick@awg0" ;;
                        ocserv) svc="ocserv" ;;
                        ikev2)
                            for s in strongswan strongswan-swanctl strongswan-starter; do
                                if systemctl is-active --quiet "$s" 2>/dev/null; then svc="$s"; break; fi
                            done
                            [ -z "$svc" ] && svc="strongswan"
                            ;;
                        sstp) svc="sstpd" ;;
                        l2tp) svc="xl2tpd" ;;
                        shadowsocks) svc="mhpanel-shadowsocks" ;;
                        tuic) svc="mhpanel-tuic" ;;
                        badvpn) svc="badvpn" ;;
                        http) svc="mhpanel-http-proxy" ;;
                        socks) svc="mhpanel-socks-proxy" ;;
                        mtproto)
                            local p="$(protocol_current_port "$sel_proto")"
                            svc="mhpanel-mtproto@${p}"
                            ;;
                        pptp) svc="mhpanel-pptp"; systemctl is-active --quiet "$svc" 2>/dev/null || svc="pptpd" ;;
                        dnstt) svc="mhpanel-dnstt" ;;
                        vaydns) svc="mhpanel-vaydns" ;;
                        slipstream) svc="mhpanel-slipstream" ;;
                        hysteria2) svc="mhpanel-hysteria2" ;;
                        trojan) svc="mhpanel-trojan" ;;
                        naiveproxy) svc="mhpanel-naiveproxy" ;;
                        stuntls) svc="mhpanel-stuntls" ;;
                        noizdns) svc="mhpanel-noizdns" ;;
                        masterdnsvpn) svc="mhpanel-masterdnsvpn" ;;
                        tor) svc="mhpanel-tor" ;;
                    esac
                    journalctl -u "$svc" -n 50 --no-pager 2>/dev/null || journalctl -n 50 --no-pager 2>/dev/null || true
                    read -p "Press Enter to continue..."
                    ;;
                6)
                    echo -e "\n${YELLOW}--- Installation Log for ${lbl} ---${NC}"
                    if [ -f "/var/log/mhpanel/install_${sel_proto}.log" ]; then
                        tail -n 60 "/var/log/mhpanel/install_${sel_proto}.log"
                    else
                        echo "No installation log file found at /var/log/mhpanel/install_${sel_proto}.log"
                    fi
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

        echo -e "  [1] View Panel Access & Login Credentials"
        echo -e "  [2] Restart Web Panel Service (Restart mhpanel)"
        echo -e "  [3] View Live Web Panel Logs"
        echo -e "  [4] Change Admin Username & Password"
        echo -e "  [5] Change Web Dashboard Port"
        echo -e "  [6] Regenerate Public API Key"
        echo -e "  ${RED}${BOLD}[7] Uninstall MH Panel from Server${NC}"
        echo -e "  [0] Back"
        echo ""
        read -p "Select option [0-7]: " ui_act
        case "$ui_act" in
            1) show_panel_access_info ;;
            2)
                systemctl restart mhpanel
                echo -e "${GREEN}Web panel service restarted.${NC}"
                read -p "Press Enter to continue..."
                ;;
            3)
                echo -e "${YELLOW}Showing last 50 log lines:${NC}"
                journalctl -u mhpanel -n 50 --no-pager
                read -p "Press Enter to continue..."
                ;;
            4)
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
            5)
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
            6)
                local nkey=$(openssl rand -hex 16)
                echo "$nkey" > "${PANEL_DIR}/api_key.txt"
                chmod 600 "${PANEL_DIR}/api_key.txt"
                systemctl restart mhpanel
                echo -e "${GREEN}New API Key generated: ${CYAN}${nkey}${NC}"
                read -p "Press Enter to continue..."
                ;;
            7)
                uninstall_mhpanel
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
                echo "Temporarily pausing Web UI & Web Server to free port 80 for SSL challenge..."
                systemctl stop mhpanel 2>/dev/null || true

                local paused_httpd=0
                local paused_apache=0
                local paused_nginx=0

                if systemctl is-active --quiet httpd 2>/dev/null; then
                    systemctl stop httpd 2>/dev/null || true
                    paused_httpd=1
                elif [ -f "/etc/init.d/httpd" ]; then
                    /etc/init.d/httpd stop 2>/dev/null || true
                    paused_httpd=1
                fi
                if systemctl is-active --quiet apache2 2>/dev/null; then
                    systemctl stop apache2 2>/dev/null || true
                    paused_apache=1
                fi
                if systemctl is-active --quiet nginx 2>/dev/null; then
                    systemctl stop nginx 2>/dev/null || true
                    paused_nginx=1
                fi

                if command -v ufw >/dev/null; then ufw allow 80/tcp || true; fi
                if certbot certonly --standalone -d "${dom}" --non-interactive --agree-tos --register-unsafely-without-email; then
                    ln -sf "/etc/letsencrypt/live/${dom}/fullchain.pem" "${SSL_DIR}/panel.crt"
                    ln -sf "/etc/letsencrypt/live/${dom}/privkey.pem" "${SSL_DIR}/panel.key"
                    echo -e "${GREEN}Let's Encrypt SSL certificate installed successfully!${NC}"
                else
                    echo -e "${RED}Failed to obtain Let's Encrypt certificate. Please check your DNS record.${NC}"
                fi

                # Resume web servers
                [ "$paused_httpd" -eq 1 ] && (systemctl start httpd 2>/dev/null || /etc/init.d/httpd start 2>/dev/null || true)
                [ "$paused_apache" -eq 1 ] && (systemctl start apache2 2>/dev/null || true)
                [ "$paused_nginx" -eq 1 ] && (systemctl start nginx 2>/dev/null || true)

                systemctl restart mhpanel 2>/dev/null || true
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
    echo -e "${CYAN}${BOLD}========================================================================${NC}"
    echo -e "${CYAN}${BOLD}       MH PANEL - UPDATE WIZARD (Updating Source & Services from GitHub)      ${NC}"
    echo -e "${CYAN}${BOLD}========================================================================${NC}\n"
    echo -e "${YELLOW}>>> [1/4] Checking and syncing latest updates from GitHub (${GITHUB_REPO})...${NC}"
    mkdir -p "${PANEL_DIR}"
    cd "${PANEL_DIR}"

    local pull_ok=false
    if [ ! -d "${PANEL_DIR}/.git" ]; then
        echo -e "${CYAN}    Initializing Git configuration in ${PANEL_DIR}...${NC}"
        git init -b main 2>/dev/null || git init 2>/dev/null || true
        git remote add origin "${GITHUB_REPO}" 2>/dev/null || git remote set-url origin "${GITHUB_REPO}" 2>/dev/null || true
    fi

    git remote set-url origin "${GITHUB_REPO}" 2>/dev/null || true
    if git fetch origin main --depth=1 2>/dev/null || git fetch origin main 2>/dev/null; then
        echo -e "${CYAN}    Resetting and applying latest release files...${NC}"
        git reset --hard origin/main 2>/dev/null && pull_ok=true
    fi

    if [ "$pull_ok" != "true" ]; then
        echo -e "${YELLOW}    Git pull encountered a network issue. Falling back to direct GitHub raw sync...${NC}"
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/install.sh" -o "${PANEL_DIR}/install.sh" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/app.py" -o "${PANEL_DIR}/app.py" 2>/dev/null || true
        mkdir -p "${PANEL_DIR}/scripts/daemons" "${PANEL_DIR}/templates/partials"
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/scripts/protocol_helper.sh" -o "${PANEL_DIR}/scripts/protocol_helper.sh" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/scripts/hmpanel.sh" -o "${PANEL_DIR}/scripts/hmpanel.sh" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/scripts/kigapanel.sh" -o "${PANEL_DIR}/scripts/kigapanel.sh" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/scripts/daemons/masterdnsvpn-server" -o "${PANEL_DIR}/scripts/daemons/masterdnsvpn-server" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/scripts/daemons/noizdns-server" -o "${PANEL_DIR}/scripts/daemons/noizdns-server" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/scripts/daemons/stuntls-server" -o "${PANEL_DIR}/scripts/daemons/stuntls-server" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/scripts/daemons/ssh-ws-proxy.py" -o "${PANEL_DIR}/scripts/daemons/ssh-ws-proxy.py" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/scripts/daemons/badvpn-udpgw" -o "${PANEL_DIR}/scripts/daemons/badvpn-udpgw" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/templates/partials/tab_system.html" -o "${PANEL_DIR}/templates/partials/tab_system.html" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/templates/partials/modals.html" -o "${PANEL_DIR}/templates/partials/modals.html" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/templates/partials/scripts.html" -o "${PANEL_DIR}/templates/partials/scripts.html" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/templates/partials/translations.html" -o "${PANEL_DIR}/templates/partials/translations.html" 2>/dev/null || true
    fi

    chmod +x "${PANEL_DIR}/install.sh" "${PANEL_DIR}/scripts/"*.sh 2>/dev/null || true
    if [ -d "${PANEL_DIR}/bin" ]; then
        cp -f "${PANEL_DIR}/bin/"* /usr/local/bin/ 2>/dev/null || true
        chmod +x /usr/local/bin/* 2>/dev/null || true
    fi
    if [ -d "${PANEL_DIR}/scripts/daemons" ]; then
        cp -f "${PANEL_DIR}/scripts/daemons/"* /usr/local/bin/ 2>/dev/null || true
        chmod +x /usr/local/bin/masterdnsvpn-server /usr/local/bin/noizdns-server /usr/local/bin/stuntls-server /usr/local/bin/ssh-ws-proxy.py /usr/local/bin/badvpn-udpgw 2>/dev/null || true
    fi

    # Auto-repair services and binaries if needed
    if ! command -v pptpd >/dev/null 2>&1 && [ ! -x /usr/sbin/pptpd ]; then
        systemctl stop mhpanel-pptp 2>/dev/null || true
        systemctl disable mhpanel-pptp 2>/dev/null || true
        rm -f /etc/systemd/system/mhpanel-pptp.service
    fi
    if [ -f /etc/pam_radius_auth.conf ]; then
        sed -i -E 's/\s+vrf=[^\s]+//g' /etc/pam_radius_auth.conf 2>/dev/null || true
    fi
    if [ -f /etc/systemd/system/mhpanel-shadowsocks.service ] && [ ! -x /usr/local/bin/ssserver ]; then
        echo -e "${CYAN}    Fixing missing Shadowsocks-rust binary...${NC}"
        local arch="$(uname -m)"
        local ss_arch="x86_64"
        if [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ]; then ss_arch="aarch64"; fi
        curl -fsSL "https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.22.0/shadowsocks-v1.22.0.${ss_arch}-unknown-linux-gnu.tar.xz" 2>/dev/null | tar -xJ -C /usr/local/bin/ ssserver 2>/dev/null || true
        chmod +x /usr/local/bin/ssserver 2>/dev/null || true
        systemctl restart mhpanel-shadowsocks 2>/dev/null || true
    fi
    if [ -f /etc/systemd/system/mhpanel-tuic.service ] && [ ! -x /usr/local/bin/tuic-server ]; then
        echo -e "${CYAN}    Fixing missing TUIC server binary...${NC}"
        local arch="$(uname -m)"
        local tuic_arch="x86_64"
        if [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ]; then tuic_arch="aarch64"; fi
        curl -fsSL "https://github.com/EAimTY/tuic/releases/download/tuic-server-1.0.0/tuic-server-1.0.0-${tuic_arch}-unknown-linux-musl" -o /usr/local/bin/tuic-server 2>/dev/null || true
        chmod +x /usr/local/bin/tuic-server 2>/dev/null || true
        systemctl restart mhpanel-tuic 2>/dev/null || true
    fi
    if [ -f /etc/systemd/system/badvpn.service ]; then
        if [ -f "${PANEL_DIR}/scripts/daemons/badvpn-udpgw" ]; then
            cp -f "${PANEL_DIR}/scripts/daemons/badvpn-udpgw" /usr/local/bin/badvpn-udpgw
            chmod +x /usr/local/bin/badvpn-udpgw
            systemctl restart badvpn.service 2>/dev/null || true
        fi
    fi

    echo -e "${YELLOW}>>> [2/4] Updating global CLI shortcuts and local copies...${NC}"
    ln -sf "${PANEL_DIR}/install.sh" /usr/local/bin/mhpanel
    ln -sf "${PANEL_DIR}/install.sh" /usr/local/bin/hmpanel
    ln -sf "${PANEL_DIR}/install.sh" /usr/local/bin/kigapanel
    ln -sf "${PANEL_DIR}/install.sh" /usr/bin/mhpanel 2>/dev/null || true
    ln -sf "${PANEL_DIR}/install.sh" /usr/bin/hmpanel 2>/dev/null || true
    if [ -f "/root/install.sh" ]; then
        cp "${PANEL_DIR}/install.sh" /root/install.sh 2>/dev/null || true
    fi

    echo -e "${YELLOW}>>> [3/4] Updating Python dependencies...${NC}"
    if [ -x "${PANEL_DIR}/venv/bin/pip" ] && [ -f "${PANEL_DIR}/requirements.txt" ]; then
        "${PANEL_DIR}/venv/bin/pip" install -r "${PANEL_DIR}/requirements.txt" --quiet 2>/dev/null || true
    fi

    echo -e "${YELLOW}>>> [4/4] Reloading systemd and restarting MH Panel Web UI...${NC}"
    systemctl daemon-reload
    systemctl restart mhpanel 2>/dev/null || true

    echo ""
    echo -e "${GREEN}${BOLD}========================================================================${NC}"
    echo -e "${GREEN}${BOLD} ✓ MH Panel has been updated to the latest version successfully!${NC}"
    echo -e "${GREEN}${BOLD}========================================================================${NC}\n"
    read -p "Press Enter to reload menu and apply changes..." dummy

    # Relaunch process image with the newly updated script
    exec bash "${PANEL_DIR}/install.sh"
}

uninstall_mhpanel() {
    clear 2>/dev/null || true
    echo -e "${RED}${BOLD}"
    cat <<'EOF'
  _    _ _   _ _____ _   _  _____ _______       _      _      
 | |  | | \ | |_   _| \ | |/ ____|__   __|/\   | |    | |     
 | |  | |  \| | | | |  \| | (___    | |  /  \  | |    | |     
 | |  | | . ` | | | | . ` |\___ \   | | / /\ \ | |    | |     
 | |__| | |\  |_| |_| |\  |____) |  | |/ ____ \| |____| |____ 
  \____/|_| \_|_____|_| \_|_____/   |_/_/    \_\______|______|
EOF
    echo -e "${NC}"
    echo -e "${RED}${BOLD}========================================================================${NC}"
    echo -e "${RED}${BOLD}             MH PANEL UNINSTALLATION WIZARD (Full Removal)              ${NC}"
    echo -e "${RED}${BOLD}========================================================================${NC}"
    echo -e "${YELLOW}WARNING: This operation will completely uninstall MH Panel from this server.${NC}\n"

    read -p "Are you sure you want to proceed with uninstallation? (yes/no) [no]: " confirm_un
    if [ "$confirm_un" != "yes" ] && [ "$confirm_un" != "y" ] && [ "$confirm_un" != "YES" ]; then
        echo -e "${GREEN}Uninstallation cancelled.${NC}"
        read -p "Press Enter to return to main menu..."
        return 0
    fi

    echo ""
    echo -e "${CYAN}--- Configuration & Protocols Removal Options ---${NC}"
    read -p "Do you want to stop and uninstall ALL active VPN protocols & tunnels? [y/N]: " rm_protos
    read -p "Do you want to purge configuration files & SSL certs (/etc/vpnpanel, /etc/mhpanel)? [y/N]: " purge_conf

    echo -e "\n${YELLOW}>>> [1/5] Stopping and removing MH Panel systemd service...${NC}"
    systemctl stop mhpanel.service vpnpanel.service 2>/dev/null || true
    systemctl disable mhpanel.service vpnpanel.service 2>/dev/null || true
    rm -f /etc/systemd/system/mhpanel.service /etc/systemd/system/vpnpanel.service
    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null || true

    if [[ "$rm_protos" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}>>> [2/5] Stopping and uninstalling VPN protocols & tunnels...${NC}"
        if [ -f "$HELPER" ]; then
            for p in "${PROTOCOLS[@]}"; do
                echo -e "    - Removing protocol: ${p}..."
                "$HELPER" uninstall "$p" 2>/dev/null || true
            done
        fi
        systemctl stop mhpanel-* badvpn sstpd ocserv xl2tpd pptpd 2>/dev/null || true
        systemctl disable mhpanel-* badvpn sstpd ocserv xl2tpd pptpd 2>/dev/null || true
        rm -f /etc/systemd/system/mhpanel-*.service /etc/systemd/system/badvpn.service
        systemctl daemon-reload
    else
        echo -e "${GREEN}>>> [2/5] Keeping VPN protocols intact as requested.${NC}"
    fi

    echo -e "${YELLOW}>>> [3/5] Removing CLI shortcuts...${NC}"
    rm -f /usr/local/bin/mhpanel /usr/local/bin/hmpanel /usr/local/bin/kigapanel /usr/bin/mhpanel /usr/bin/hmpanel 2>/dev/null || true

    if [[ "$purge_conf" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}>>> [4/5] Purging configuration directories and logs...${NC}"
        rm -rf /etc/vpnpanel /etc/mhpanel /var/log/mhpanel* /root/mhpanel_backups 2>/dev/null || true
    else
        echo -e "${GREEN}>>> [4/5] Preserving /etc/vpnpanel configurations for future reinstallation.${NC}"
    fi

    echo -e "${YELLOW}>>> [5/5] Removing panel files...${NC}"
    if [ -d "${PANEL_DIR}" ]; then
        rm -rf "${PANEL_DIR}" 2>/dev/null || true
    fi

    echo ""
    echo -e "${GREEN}${BOLD}========================================================================${NC}"
    echo -e "${GREEN}${BOLD} ✓ MH Panel has been successfully uninstalled from this server.${NC}"
    echo -e "${GREEN}${BOLD}========================================================================${NC}\n"
    exit 0
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
        echo -e "  ${GREEN}${BOLD}[4]  View Panel Access URL & Login Info${NC}"
        echo -e "  [5]  Live System & Service Diagnostic Report"
        echo -e "  [6]  Manage, Install, Uninstall & Reconfigure VPN Protocols"
        echo -e "  [7]  Anti-Censorship Tunnels & MikroTik RouterOS Bridge Hub"
        echo -e "  [8]  Web Dashboard Settings (Credentials, Port, Logs & Restart)"
        echo -e "  [9]  SSL Certificate Management (Let's Encrypt & IP SAN)"
        echo -e "  [10] Network & Kernel Optimization (BBR, IPv4/IPv6 Forwarding)"
        echo -e "  [11] Backup & Restore Panel Configurations"
        echo -e "  [12] Update Script & Panel"
        echo -e "  ${RED}${BOLD}[13] Uninstall MH Panel from Server${NC}"
        echo -e "  [0]  Exit"
        echo -e "${BLUE}========================================================================${NC}"
        read -p "Please select an option [0-13]: " opt

        case "$opt" in
            1) wizard_full_automated ;;
            2) wizard_step_by_step ;;
            3) wizard_web_ui_only ;;
            4) show_panel_access_info ;;
            5) menu_diagnostic_status ;;
            6) menu_vpn_protocols ;;
            7) menu_tunnel_tools ;;
            8) menu_web_ui_settings ;;
            9) menu_ssl_management ;;
            10) enable_bbr_and_sysctl; read -p "Press Enter to continue..." ;;
            11) backup_restore ;;
            12) update_panel_repo ;;
            13) uninstall_mhpanel ;;
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
elif [ "$1" = "--info" ] || [ "$1" = "info" ] || [ "$1" = "--access" ]; then
    show_panel_access_info
elif [ "$1" = "--uninstall" ] || [ "$1" = "uninstall" ] || [ "$1" = "-u" ]; then
    uninstall_mhpanel
else
    if [ ! -f "${PANEL_DIR}/app.py" ] && [ ! -f "/etc/systemd/system/mhpanel.service" ]; then
        show_banner
        echo -e "${YELLOW}Welcome to MH Panel Installer! Panel is not installed yet on this server.${NC}\n"
        echo -e "  [1] Full Automated Setup (Recommended)"
        echo -e "  [2] Step-by-Step Custom Wizard"
        echo -e "  [3] Lightweight Web UI Only"
        echo -e "  [4] View Panel Access & Login Info"
        echo -e "  ${RED}[5] Uninstall Panel & Purge Leftovers${NC}"
        echo -e "  [0] Exit"
        echo ""
        read -p "Select installation mode [0-5] (Default: 1): " init_choice
        init_choice=${init_choice:-1}
        case "$init_choice" in
            1) wizard_full_automated ;;
            2) wizard_step_by_step ;;
            3) wizard_web_ui_only ;;
            4) show_panel_access_info ;;
            5) uninstall_mhpanel ;;
            *) exit 0 ;;
        esac
    else
        main_menu
    fi
fi
