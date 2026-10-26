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
export UCF_FORCE_CONFFOLD=1

ensure_apt_noninteractive() {
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    export NEEDRESTART_SUSPEND=1
    export UCF_FORCE_CONFFOLD=1
    if [ ! -f /etc/apt/apt.conf.d/99mhpanel-noninteractive ]; then
        mkdir -p /etc/apt/apt.conf.d 2>/dev/null || true
        cat > /etc/apt/apt.conf.d/99mhpanel-noninteractive <<'EOF'
Dpkg::Options {
   "--force-confdef";
   "--force-confold";
};
DPkg::Lock::Timeout "60";
EOF
    fi
}
ensure_apt_noninteractive 2>/dev/null || true

run_apt() {
    ensure_apt_noninteractive 2>/dev/null || true
    local count=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
        sleep 2
        count=$((count + 1))
        if [ "$count" -ge 15 ]; then
            fuser -k -9 /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock 2>/dev/null || true
            rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock
            dpkg --configure -a --force-confdef --force-confold 2>/dev/null || true
            break
        fi
    done
    apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" "$@"
}

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
VERSION="1.6.0"

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
PROTOCOLS=(ssh openvpn ocserv ikev2 sstp l2tp wireguard amneziawg http socks shadowsocks tuic mtproto pptp badvpn dnstt vaydns slipstream hysteria2 trojan naiveproxy stuntls noizdns masterdnsvpn tor singbox google_script)

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
    echo -e "${DIM}   Universal Anti-Censorship VPN Suite, Port Multiplexer & MikroTik Hub${NC}"
    echo -e "${GREEN}   [v${VERSION}] Google Apps Script Proxy | WordPress Decoy | Telegram Alerts | Sing-box Suite | Port 443 Mux${NC}" 
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
        singbox) echo "Sing-box Universal Suite (VLESS/Reality/Trojan/Hysteria2)" ;;
        google_script) echo "Google Apps Script Full Tunnel (GAS Relay)" ;;
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
        amneziawg) echo "443" ;;
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
        singbox) echo "20443" ;;
        google_script) echo "8448" ;;
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
                amneziawg) final_port=443 ;;
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
                amneziawg) final_port=443 ;;
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
        singbox) ([ -x /usr/local/bin/sing-box ] && [ -f "/etc/sing-box/config.json" ]) || [ -f "/etc/systemd/system/mhpanel-singbox.service" ] ;;
        google_script) ([ -f "/etc/vpnpanel/google_script.json" ] && [ -x /usr/local/bin/mhpanel-gas-server ]) || [ -f "/etc/systemd/system/mhpanel-gas-tunnel.service" ] ;;
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
        tuic)
            for s in mhpanel-tuic tuic-server tuic; do
                if systemctl is-active --quiet "$s" 2>/dev/null; then
                    svc="$s"
                    break
                fi
            done
            [ -z "$svc" ] && svc="mhpanel-tuic"
            ;;
        mtproto)
            local mt_active=$(systemctl list-units --type=service --state=running 'mhpanel-mtproto@*' 2>/dev/null | grep -oE 'mhpanel-mtproto@[0-9]+' | head -n1)
            if [ -n "$mt_active" ]; then
                svc="$mt_active"
            else
                local mt_port=$(protocol_current_port mtproto 2>/dev/null)
                [ -z "$mt_port" ] && mt_port="4433"
                svc="mhpanel-mtproto@${mt_port}"
            fi
            ;;
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
            for s in badvpn videocall badvpn-udpgw; do
                if systemctl is-active --quiet "$s" 2>/dev/null; then
                    svc="$s"
                    break
                fi
            done
            [ -z "$svc" ] && svc="badvpn"
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
        singbox) svc="mhpanel-singbox" ;;
        google_script) svc="mhpanel-gas-tunnel" ;;
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
        singbox) port=$(grep -oE '"listen_port":\s*[0-9]+' /etc/sing-box/config.json 2>/dev/null | head -n1 | awk '{print $2}') ;;
        google_script) port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/google_script.json 2>/dev/null | awk '{print $2}' || echo "8448") ;;
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

    # Remove broken third-party repos that can break apt-get update
    rm -f /etc/apt/sources.list.d/tor.list 2>/dev/null || true

    for p in python3 python3-pip python3-venv curl wget git openssl certbot iptables "$firewall_pkg" cron net-tools sudo cmake build-essential jq socat unzip kmod procps freeradius freeradius-utils libpam-radius-auth; do
        if ! dpkg -s "$p" >/dev/null 2>&1; then
            pkgs_needed+=("$p")
        fi
    done

    if [ ${#pkgs_needed[@]} -eq 0 ]; then
        echo -e "    ${GREEN}[✓] All base Linux dependencies are already installed (Skipped).${NC}"
    else
        echo -e "    Installing missing packages: ${CYAN}${pkgs_needed[*]}${NC}..."
        run_apt update 2>/dev/null || true
        if ! run_apt install --no-install-recommends "${pkgs_needed[@]}" 2>/dev/null; then
            echo -e "    ${YELLOW}Batch package installation encountered issues; installing required packages individually...${NC}"
            for pkg in "${pkgs_needed[@]}"; do
                run_apt install --no-install-recommends "$pkg" 2>/dev/null || run_apt install "$pkg" 2>/dev/null || true
            done
        fi
        echo -e "    ${GREEN}[✓] Base system dependencies successfully installed.${NC}"
    fi

    # Fix Ubuntu PAM radius auth sample issue (failed bind to vrf-blue)
    if [ -f /etc/pam_radius_auth.conf ]; then
        sed -i -E 's/\s+vrf=[^\s]+//g' /etc/pam_radius_auth.conf 2>/dev/null || true
    fi
}

is_container_env() {
    if [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then
        return 0
    fi
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        local virt
        virt=$(systemd-detect-virt --container 2>/dev/null || true)
        if [ -n "$virt" ] && [ "$virt" != "none" ]; then
            return 0
        fi
    fi
    if [ -f /proc/1/environ ] && grep -qaE 'container=(lxc|docker|podman|containerd)' /proc/1/environ 2>/dev/null; then
        return 0
    fi
    if [ -f /proc/1/cgroup ] && grep -qE '(lxc|docker|kubepods|containerd)' /proc/1/cgroup 2>/dev/null; then
        return 0
    fi
    if [ -d /proc/vz ] && [ ! -d /proc/vz/vzaquota ]; then
        return 0
    fi
    return 1
}

enable_bbr_and_sysctl() {
    echo -e "\n${YELLOW}>>> [2/6] Enabling TCP BBR, packet forwarding & IPv6 tunnel modules...${NC}"

    mkdir -p /etc/sysctl.d /etc/modules-load.d

    local in_container=0
    if is_container_env; then
        in_container=1
    fi

    # Kernel Modules Loading (only on VM / Bare Metal or if modprobe is operational)
    local available_modules=()
    local tunnel_modules=("ip_gre" "ip6_gre" "ipip" "ip6_tunnel" "sit" "wireguard")

    if [ "$in_container" -eq 0 ] && command -v modprobe >/dev/null 2>&1; then
        for mod in "${tunnel_modules[@]}"; do
            if [ -d "/sys/module/${mod//-/_}" ]; then
                available_modules+=("$mod")
            elif modprobe "$mod" >/dev/null 2>&1; then
                available_modules+=("$mod")
            fi
        done

        if [ ${#available_modules[@]} -gt 0 ]; then
            printf "%s\n" "${available_modules[@]}" > /etc/modules-load.d/mh-tunnels.conf 2>/dev/null || true
        else
            rm -f /etc/modules-load.d/mh-tunnels.conf 2>/dev/null || true
        fi
    else
        # In containers, do not maintain mh-tunnels.conf to avoid systemd-modules-load failures
        rm -f /etc/modules-load.d/mh-tunnels.conf 2>/dev/null || true
    fi

    # Test BBR support
    if command -v modprobe >/dev/null 2>&1; then
        modprobe tcp_bbr >/dev/null 2>&1 || true
    fi

    local bbr_supported=0
    local avail_cc=""
    if [ -f /proc/sys/net/ipv4/tcp_available_congestion_control ]; then
        avail_cc=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || true)
    elif command -v sysctl >/dev/null 2>&1; then
        avail_cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
    fi

    if echo "$avail_cc" | grep -qw "bbr"; then
        bbr_supported=1
    fi

    # Test IPv6 support
    local ipv6_supported=0
    if [ -d /proc/sys/net/ipv6 ] && [ -f /proc/sys/net/ipv6/conf/all/forwarding ]; then
        ipv6_supported=1
    fi

    # Construct /etc/sysctl.d/99-mhpanel.conf tailored to environment capabilities
    cat > /etc/sysctl.d/99-mhpanel.conf <<EOF
# MH Panel Kernel & Network Optimization
net.ipv4.ip_forward=1
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=1024 65535
EOF

    if [ "$bbr_supported" -eq 1 ]; then
        cat >> /etc/sysctl.d/99-mhpanel.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    fi

    if [ "$ipv6_supported" -eq 1 ]; then
        cat >> /etc/sysctl.d/99-mhpanel.conf <<EOF
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
EOF
    fi

    if [ "$in_container" -eq 0 ]; then
        cat >> /etc/sysctl.d/99-mhpanel.conf <<EOF
fs.file-max=1000000
fs.inotify.max_user_instances=8192
net.core.somaxconn=32768
net.ipv4.tcp_max_syn_backlog=16384
EOF
    fi

    # Apply sysctl settings safely without fatal errors
    if [ -f /etc/sysctl.d/99-mhpanel.conf ]; then
        while IFS='=' read -r key val; do
            [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
            key=$(echo "$key" | tr -d '[:space:]')
            val=$(echo "$val" | tr -d '[:space:]')
            [ -n "$key" ] && sysctl -w "${key}=${val}" >/dev/null 2>&1 || true
        done < /etc/sysctl.d/99-mhpanel.conf
    fi

    touch /etc/sysctl.conf 2>/dev/null || true
    grep -qxF 'net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf 2>/dev/null || true
    if [ "$ipv6_supported" -eq 1 ]; then
        grep -qxF 'net.ipv6.conf.all.forwarding=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf 2>/dev/null || true
    fi

    sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-mhpanel.conf >/dev/null 2>&1 || true

    # Informative output for user
    if [ "$bbr_supported" -eq 1 ]; then
        echo -e "    ${GREEN}[✓] TCP BBR congestion control successfully enabled.${NC}"
    else
        local current_cc
        current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "cubic")
        echo -e "    ${YELLOW}[i] TCP BBR is not supported by current kernel/environment (using: ${current_cc}).${NC}"
    fi

    if [ "$ipv6_supported" -eq 1 ]; then
        echo -e "    ${GREEN}[✓] IPv4 and IPv6 packet forwarding successfully enabled.${NC}"
    else
        echo -e "    ${GREEN}[✓] IPv4 packet forwarding enabled (IPv6 disabled or not present on host).${NC}"
    fi

    if [ ${#available_modules[@]} -gt 0 ]; then
        echo -e "    ${GREEN}[✓] Network tunnel kernel modules loaded: ${available_modules[*]}${NC}"
    elif [ "$in_container" -eq 1 ]; then
        echo -e "    ${CYAN}[i] Container environment detected (modules managed by container host).${NC}"
    fi
}

install_panel_web_ui() {
    echo -e "\n${YELLOW}>>> [3/6] Setting up MH Panel Web UI service...${NC}"
    mkdir -p "${PANEL_DIR}"
    mkdir -p "${SSL_DIR}"
    chmod 700 "${SSL_DIR}"

    # Ensure git is available
    if ! command -v git >/dev/null 2>&1; then
        run_apt update 2>/dev/null || true
        run_apt install git 2>/dev/null || true
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
        run_apt install python3-venv python3-pip 2>/dev/null || true
    fi

    if [ ! -d "${PANEL_DIR}/venv" ] || [ ! -f "${PANEL_DIR}/venv/bin/python" ] || [ ! -f "${PANEL_DIR}/venv/bin/pip" ]; then
        echo "    Creating Python virtual environment in ${PANEL_DIR}/venv..."
        rm -rf "${PANEL_DIR}/venv"
        python3 -m venv "${PANEL_DIR}/venv" 2>/dev/null || true
        if [ ! -f "${PANEL_DIR}/venv/bin/pip" ]; then
            run_apt install python3-venv python3-pip 2>/dev/null || true
            rm -rf "${PANEL_DIR}/venv"
            python3 -m venv "${PANEL_DIR}/venv"
        fi
    fi

    echo "    Ensuring and updating Python dependencies in virtual environment..."
    "${PANEL_DIR}/venv/bin/pip" install --upgrade pip setuptools wheel --quiet 2>/dev/null || true
    if [ -f "${PANEL_DIR}/requirements.txt" ]; then
        "${PANEL_DIR}/venv/bin/pip" install -r "${PANEL_DIR}/requirements.txt" --quiet 2>/dev/null || \
        "${PANEL_DIR}/venv/bin/pip" install -r "${PANEL_DIR}/requirements.txt"
    fi
    "${PANEL_DIR}/venv/bin/pip" install \
        "Flask>=2.0.0" \
        "psutil>=5.8.0" \
        "pyrad>=2.4" \
        "cryptography>=3.4.8" \
        "pyOpenSSL" \
        "requests" \
        "flask-compress>=1.14,<1.15" \
        "brotli" --quiet 2>/dev/null || true

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
    for f in wg_users.json awg_users.json ssh_users.json l2tp_users.json ikev2_users.json ovpn_users.json sstp_users.json radius_users.json ocserv_users.json singbox_users.json; do
        if [ ! -f "${PANEL_DIR}/${f}" ]; then echo "{}" > "${PANEL_DIR}/${f}"; fi
    done
    if [ ! -f "${PANEL_DIR}/radius_groups.json" ] || [ "$(cat "${PANEL_DIR}/radius_groups.json" 2>/dev/null)" = "[]" ]; then
        cat > "${PANEL_DIR}/radius_groups.json" <<'EOF'
{
  "default": {
    "id": "default",
    "name": "پکیج استاندارد (Standard)",
    "traffic_gb": 0,
    "validity_days": 30,
    "simultaneous_use": 2,
    "allowed_days": "all",
    "custom_days": [],
    "start_time": "00:00",
    "end_time": "24:00",
    "description": "پکیج استاندارد با ۲ کاربر همزمان و ترافیک نامحدود"
  },
  "vip": {
    "id": "vip",
    "name": "پکیج ویژه (VIP)",
    "traffic_gb": 100,
    "validity_days": 30,
    "simultaneous_use": 5,
    "allowed_days": "all",
    "custom_days": [],
    "start_time": "00:00",
    "end_time": "24:00",
    "description": "پکیج حرفه‌ای با ۵ اتصال همزمان و ۱۰۰ گیگابایت حجم"
  },
  "night": {
    "id": "night",
    "name": "بسته شبانه (Nightly)",
    "traffic_gb": 50,
    "validity_days": 30,
    "simultaneous_use": 2,
    "allowed_days": "all",
    "custom_days": [],
    "start_time": "01:00",
    "end_time": "08:00",
    "description": "فعال فقط از ۱ بامداد تا ۸ صبح"
  }
}
EOF
    fi
    if [ ! -f "${PANEL_DIR}/servers.json" ]; then echo "[]" > "${PANEL_DIR}/servers.json"; fi
    if [ ! -f "${PANEL_DIR}/traffic_stats.json" ]; then echo "{}" > "${PANEL_DIR}/traffic_stats.json"; fi
    if [ ! -f "${PANEL_DIR}/sub_settings.json" ]; then echo "{}" > "${PANEL_DIR}/sub_settings.json"; fi
    if [ ! -f "${PANEL_DIR}/tunnel_alerts.json" ]; then echo '{"alerts":[]}' > "${PANEL_DIR}/tunnel_alerts.json"; fi
    if [ ! -f "${PANEL_DIR}/tunnels_config.json" ]; then
        echo '{"tunnels":[],"adv_tunnels":[],"relays":[]}' > "${PANEL_DIR}/tunnels_config.json"
    fi
    if [ ! -f "${PANEL_DIR}/multiplexer_config.json" ]; then
        echo '{"enabled":false,"listen_ports":[443],"web_server_type":"internal","default_backend":"web","protocols":[],"custom_rules":[],"udp_multiports":[]}' > "${PANEL_DIR}/multiplexer_config.json"
    fi
    if [ ! -f "${PANEL_DIR}/sstp_config.json" ]; then
        cat > "${PANEL_DIR}/sstp_config.json" <<'EOF'
{
  "engine": "sstpd",
  "port": 4443,
  "sni": "sstp.example.com",
  "haproxy_443": true,
  "stunnel_multiport": true,
  "stunnel_ports": [9443, 2087],
  "local_ip": "10.20.20.1",
  "remote_subnet": "10.20.20.0/24",
  "ip_range": "10.20.20.10-250",
  "dns1": "8.8.8.8",
  "dns2": "1.1.1.1",
  "mtu": 1400,
  "mru": 1400,
  "cipher_preset": "all_aes_sha",
  "ciphers": "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:HIGH:!aNULL:!MD5:!RC4",
  "mppe_mode": "require-mppe-128",
  "auth_mode": "radius_and_chap"
}
EOF
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
LimitNOFILE=1048576
LimitNPROC=512000
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

    # Setup Google Apps Script (GAS) Full Tunnel Exit Server (mhrv-tunnel-node)
    for bdir in "${PANEL_DIR}/bin" "${SCRIPT_DIR}/bin" "/root/mhpanel-repo/bin"; do
        if [ -f "${bdir}/mhrv-tunnel-node" ]; then
            cp -f "${bdir}/mhrv-tunnel-node" /usr/local/bin/mhrv-tunnel-node 2>/dev/null || true
            chmod +x /usr/local/bin/mhrv-tunnel-node 2>/dev/null || true
            break
        fi
    done
    for sdir in "${PANEL_DIR}/scripts/daemons" "${SCRIPT_DIR}/scripts/daemons" "/root/mhpanel-repo/scripts/daemons"; do
        if [ -f "${sdir}/mhpanel-gas-server" ]; then
            cp -f "${sdir}/mhpanel-gas-server" /usr/local/bin/mhpanel-gas-server 2>/dev/null || true
            chmod +x /usr/local/bin/mhpanel-gas-server 2>/dev/null || true
            break
        fi
    done
    mkdir -p /etc/vpnpanel
    if [ ! -f /etc/vpnpanel/google_script.json ]; then
        local rand_gas_sec
        rand_gas_sec=$(openssl rand -hex 16 2>/dev/null || echo "mhpanel_gas_$(date +%s)")
        cat > /etc/vpnpanel/google_script.json <<GEO
{
  "enabled": true,
  "port": 8448,
  "secret": "${rand_gas_sec}",
  "mode": "full_tunnel",
  "singbox_target": "127.0.0.1:20443",
  "default_upstream": "127.0.0.1:20443",
  "session_timeout": 60,
  "read_timeout": 1.2,
  "google_project_title": "MHPanel-GAS-FullTunnel",
  "google_script_id": "",
  "google_deployment_id": "",
  "google_webapp_url": "",
  "last_deploy_time": ""
}
GEO
    fi
    cat > /etc/systemd/system/mhpanel-gas-tunnel.service <<GEO
[Unit]
Description=MHPanel Google Apps Script (GAS) Full Tunnel Exit Server (mhrv-tunnel-node)
After=network.target sing-box.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/mhpanel-gas-server
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
GEO
    systemctl daemon-reload
    systemctl enable mhpanel-gas-tunnel >/dev/null 2>&1
    systemctl restart mhpanel-gas-tunnel >/dev/null 2>&1

    if systemctl is-active --quiet mhpanel; then
        echo -e "    ${GREEN}[✓] MH Panel Web UI service is active and running.${NC}"
    else
        echo -e "    ${RED}[!] MH Panel service is not active yet. Check journalctl logs.${NC}"
    fi

    setup_freeradius
}

setup_freeradius() {
    echo -e "    ${CYAN}--> Setting up FreeRADIUS Authentication & Multi-Protocol Accounting Server...${NC}"

    local rad_conf_dir="/etc/freeradius/3.0"
    local rad_service="freeradius"
    local rad_user="freerad"
    local rad_group="freerad"
    local auth_file="${rad_conf_dir}/mods-config/files/authorize"

    if [ -f /etc/debian_version ] || command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        rm -f /etc/apt/sources.list.d/tor.list 2>/dev/null || true
        if ! command -v freeradius >/dev/null 2>&1 || [ ! -d "${rad_conf_dir}" ]; then
            run_apt update >/dev/null 2>&1 || true
            run_apt install --no-install-recommends freeradius freeradius-utils freeradius-config libpam-radius-auth libradcli4 >/dev/null 2>&1 || \
            run_apt install freeradius freeradius-utils libpam-radius-auth >/dev/null 2>&1 || true
        fi
        rad_conf_dir="/etc/freeradius/3.0"
        rad_service="freeradius"
        rad_user="freerad"
        rad_group="freerad"
        auth_file="${rad_conf_dir}/mods-config/files/authorize"
    elif [ -f /etc/redhat-release ] || command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
        local pkg_mgr="yum"
        command -v dnf >/dev/null 2>&1 && pkg_mgr="dnf"
        $pkg_mgr install -y epel-release >/dev/null 2>&1 || true
        $pkg_mgr install -y freeradius freeradius-utils pam_radius radcli >/dev/null 2>&1 || true
        rad_conf_dir="/etc/raddb"
        rad_service="radiusd"
        rad_user="radiusd"
        rad_group="radiusd"
        auth_file="${rad_conf_dir}/mods-config/files/authorize"
        [ ! -f "$auth_file" ] && auth_file="${rad_conf_dir}/users"
    fi

    # Ensure reciprocal directory symlinks for full cross-distro compatibility
    if [ -d "/etc/freeradius/3.0" ] && [ ! -d "/etc/raddb" ] && [ ! -L "/etc/raddb" ]; then
        ln -sf /etc/freeradius/3.0 /etc/raddb 2>/dev/null || true
    elif [ -d "/etc/raddb" ] && [ ! -d "/etc/freeradius/3.0" ] && [ ! -L "/etc/freeradius/3.0" ]; then
        mkdir -p /etc/freeradius 2>/dev/null || true
        ln -sf /etc/raddb /etc/freeradius/3.0 2>/dev/null || true
    fi

    mkdir -p "${rad_conf_dir}" /etc/radcli

    local mh_users="${rad_conf_dir}/mhpanel_users"
    if [ ! -f "$mh_users" ]; then
        echo "# MH Panel Unified RADIUS Database" > "$mh_users"
    fi

    if [ -f "$auth_file" ]; then
        if ! grep -q "mhpanel_users" "$auth_file" 2>/dev/null; then
            sed -i "1s|^|\$INCLUDE ${mh_users}\n|" "$auth_file" 2>/dev/null || true
        fi
    fi

    local clients_conf="${rad_conf_dir}/clients.conf"
    if [ -f "$clients_conf" ]; then
        if ! grep -q "vpn_network" "$clients_conf" 2>/dev/null; then
            cat >> "$clients_conf" <<'EOF'

client localhost_ipv6 {
	ipv6addr	= ::1
	secret		= testing123
}

client vpn_network {
    ipaddr = 0.0.0.0/0
    secret = testing123
    require_message_authenticator = no
}
EOF
        fi
        sed -i 's/require_message_authenticator = yes/require_message_authenticator = no/g' "$clients_conf" 2>/dev/null || true
    fi

    cat > /etc/radcli/radiusclient.conf <<'EOF'
authserver 127.0.0.1:1812
acctserver 127.0.0.1:1813
servers /etc/radcli/servers
dictionary /etc/radcli/dictionary
default_realm
radius_timeout 3
radius_retries 3
bindaddr *
seqfile /var/run/radius.seq
mapfile /etc/radcli/port-id-map
nologin /etc/nologin
EOF
    echo "127.0.0.1 testing123" > /etc/radcli/servers
    chmod 600 /etc/radcli/servers /etc/radcli/radiusclient.conf 2>/dev/null || true
    [ ! -L "/etc/radiusclient" ] && [ ! -d "/etc/radiusclient" ] && ln -sf /etc/radcli /etc/radiusclient 2>/dev/null || true

    cat > /etc/pam_radius_auth.conf <<'EOF'
# RADIUS Server configuration generated by MH Panel
127.0.0.1:1812 testing123 3
EOF
    chmod 600 /etc/pam_radius_auth.conf 2>/dev/null || true

    if id "$rad_user" >/dev/null 2>&1; then
        chown -R "${rad_user}:${rad_group}" "${rad_conf_dir}" 2>/dev/null || true
    fi
    chmod 640 "$mh_users" 2>/dev/null || true

    if command -v ufw >/dev/null && systemctl is-active --quiet ufw; then
        ufw allow 1812/udp >/dev/null 2>&1 || true
        ufw allow 1813/udp >/dev/null 2>&1 || true
    fi

    systemctl unmask "$rad_service" 2>/dev/null || true
    systemctl enable "$rad_service" 2>/dev/null || true
    systemctl restart "$rad_service" 2>/dev/null || true

    # Synchronize users from MH Panel database
    if [ -f "${PANEL_DIR}/app.py" ] && [ -x "${PANEL_DIR}/venv/bin/python" ]; then
        ${PANEL_DIR}/venv/bin/python -c "
import sys; sys.path.insert(0, '${PANEL_DIR}')
try:
    from app import sync_freeradius_users
    sync_freeradius_users()
except Exception:
    pass
" 2>/dev/null || true
    fi

    if systemctl is-active --quiet "$rad_service"; then
        echo -e "    ${GREEN}[✓] FreeRADIUS authentication service is active on UDP 1812/1813.${NC}"
    else
        echo -e "    ${YELLOW}[!] FreeRADIUS service not active yet. Check systemctl status ${rad_service}.${NC}"
    fi
}

install_badvpn() {
    echo -e "    ${CYAN}--> Setting up BadVPN UDP-GW (Port 7300 for UDP gaming/voice forwarding)...${NC}"
    if systemctl is-active --quiet videocall.service 2>/dev/null; then
        echo -e "    ${GREEN}[✓] BadVPN UDPGW is already running via videocall.service on port 7300.${NC}"
        return 0
    fi

    if [ -x /usr/local/bin/badvpn-udpgw ] && ! /usr/local/bin/badvpn-udpgw --help >/dev/null 2>&1; then
        rm -f /usr/local/bin/badvpn-udpgw
    fi

    if [ ! -x /usr/local/bin/badvpn-udpgw ] && [ ! -x /usr/bin/badvpn-udpgw ]; then
        for bdir in "${PANEL_DIR}/bin" "${PANEL_DIR}/scripts/daemons" "${SCRIPT_DIR}/bin" "/root/mhpanel-repo/bin"; do
            if [ -f "${bdir}/badvpn-udpgw" ]; then
                cp -f "${bdir}/badvpn-udpgw" /usr/local/bin/badvpn-udpgw 2>/dev/null || true
                chmod +x /usr/local/bin/badvpn-udpgw 2>/dev/null || true
                if /usr/local/bin/badvpn-udpgw --help >/dev/null 2>&1; then
                    break
                else
                    rm -f /usr/local/bin/badvpn-udpgw
                fi
            fi
        done
    fi

    if [ ! -x /usr/local/bin/badvpn-udpgw ] && [ ! -x /usr/bin/badvpn-udpgw ]; then
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/badvpn-udpgw -o /usr/local/bin/badvpn-udpgw 2>/dev/null || true
        chmod +x /usr/local/bin/badvpn-udpgw 2>/dev/null || true
        if ! /usr/local/bin/badvpn-udpgw --help >/dev/null 2>&1; then
            rm -f /usr/local/bin/badvpn-udpgw
        fi
    fi

    if [ ! -x /usr/local/bin/badvpn-udpgw ] && [ ! -x /usr/bin/badvpn-udpgw ]; then
        echo -e "    ${CYAN}Building BadVPN UDP-GW from source for native OS compatibility...${NC}"
        run_apt install cmake build-essential gcc git >/dev/null 2>&1 || true
        mkdir -p /tmp/badvpn-build
        cd /tmp/badvpn-build
        if git clone --depth 1 https://github.com/ambrop72/badvpn.git . 2>/dev/null; then
            mkdir -p build && cd build
            cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 >/dev/null 2>&1
            make -j$(nproc) >/dev/null 2>&1
            cp -f udpgw/badvpn-udpgw /usr/local/bin/badvpn-udpgw 2>/dev/null || make install >/dev/null 2>&1 || true
            chmod +x /usr/local/bin/badvpn-udpgw 2>/dev/null || true
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

# Cloudflare WARP and AmneziaWG Outbound Gateway
install_cloudflare_warp() {
    echo -e "    Checking Cloudflare WARP & AmneziaWG Gateway..."
    export DEBIAN_FRONTEND=noninteractive

    # Install cloudflare-warp if missing
    if ! command -v warp-cli >/dev/null 2>&1; then
        echo "    Adding Cloudflare WARP repository..."
        curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null || true
        local codename=$(lsb_release -cs 2>/dev/null || echo "focal")
        echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ ${codename} main" > /etc/apt/sources.list.d/cloudflare-client.list 2>/dev/null || true
        run_apt update 2>/dev/null || true
        run_apt install --no-install-recommends cloudflare-warp 2>/dev/null || apt-get install -y --no-install-recommends cloudflare-warp 2>/dev/null || true
    fi

    if command -v warp-cli >/dev/null 2>&1; then
        systemctl enable --now warp-svc >/dev/null 2>&1 || true
        if warp-cli --accept-tos status 2>/dev/null | grep -qi "Registration missing"; then
            warp-cli --accept-tos registration new >/dev/null 2>&1 || true
        fi
        warp-cli --accept-tos mode proxy >/dev/null 2>&1 || true
        warp-cli --accept-tos connect >/dev/null 2>&1 || true
    fi

    # Install tun2socks binary
    for bdir in "${PANEL_DIR}/bin" "${SCRIPT_DIR}/bin" "/root/mhpanel-repo/bin"; do
        if [ -f "${bdir}/tun2socks" ]; then
            cp -f "${bdir}/tun2socks" /usr/local/bin/tun2socks 2>/dev/null || true
            chmod +x /usr/local/bin/tun2socks 2>/dev/null || true
            break
        fi
    done

    # Install amnezia-warp scripts
    for sdir in "${PANEL_DIR}/scripts" "${SCRIPT_DIR}/scripts" "/root/mhpanel-repo/scripts"; do
        if [ -f "${sdir}/amnezia-warp-up.sh" ]; then
            cp -f "${sdir}/amnezia-warp-up.sh" /usr/local/bin/amnezia-warp-up.sh 2>/dev/null || true
            cp -f "${sdir}/amnezia-warp-down.sh" /usr/local/bin/amnezia-warp-down.sh 2>/dev/null || true
            chmod +x /usr/local/bin/amnezia-warp-up.sh /usr/local/bin/amnezia-warp-down.sh 2>/dev/null || true
            break
        fi
    done

    # Create systemd service for mhpanel-amnezia-warp
    cat > /etc/systemd/system/mhpanel-amnezia-warp.service <<'WARPEOF'
[Unit]
Description=MHPanel AmneziaWG Cloudflare WARP Outbound Gateway
After=network.target warp-svc.service
Wants=warp-svc.service

[Service]
Type=simple
ExecStartPre=-/sbin/ip link delete awg-warp
ExecStart=/usr/local/bin/tun2socks --device awg-warp --proxy socks5://127.0.0.1:40000 --tun-post-up /usr/local/bin/amnezia-warp-up.sh --loglevel warn
ExecStopPost=/usr/local/bin/amnezia-warp-down.sh
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
WARPEOF
    systemctl daemon-reload 2>/dev/null || true
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

    # Sing-box Universal Suite
    if [ ! -x /usr/local/bin/sing-box ]; then
        echo "    Checking / Downloading Sing-box Universal Suite..."
        for bdir in "${PANEL_DIR}/bin" "${SCRIPT_DIR}/bin" "/root/mhpanel-repo/bin"; do
            if [ -f "${bdir}/sing-box" ]; then
                cp -f "${bdir}/sing-box" /usr/local/bin/sing-box 2>/dev/null || true
                chmod +x /usr/local/bin/sing-box 2>/dev/null || true
                break
            fi
        done
        if [ ! -x /usr/local/bin/sing-box ]; then
            local arch="$(uname -m)"
            local sb_arch="amd64"
            [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ] && sb_arch="arm64"
            curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/sing-box -o /usr/local/bin/sing-box 2>/dev/null || \
            (curl -fsSL --connect-timeout 10 --max-time 60 "https://github.com/SagerNet/sing-box/releases/download/v1.9.3/sing-box-1.9.3-linux-${sb_arch}.tar.gz" 2>/dev/null | tar -xz -C /tmp/ 2>/dev/null && mv /tmp/sing-box-*/sing-box /usr/local/bin/sing-box 2>/dev/null && rm -rf /tmp/sing-box* || true)
            chmod +x /usr/local/bin/sing-box 2>/dev/null || true
        fi
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
        run_apt install --no-install-recommends tor obfs4proxy >/dev/null 2>&1 || run_apt install --no-install-recommends tor lyrebird >/dev/null 2>&1 || true
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
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/frps -o /usr/local/bin/frps 2>/dev/null || true
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/frpc -o /usr/local/bin/frpc 2>/dev/null || true
        if [ ! -x /usr/local/bin/frps ] || [ ! -x /usr/local/bin/frpc ]; then
            curl -fsSL --connect-timeout 10 --max-time 60 https://github.com/fatedier/frp/releases/download/v0.58.1/frp_0.58.1_linux_amd64.tar.gz 2>/dev/null | tar -xz -C /tmp/ 2>/dev/null || true
            if [ -d /tmp/frp_0.58.1_linux_amd64 ]; then
                mv /tmp/frp_0.58.1_linux_amd64/frps /usr/local/bin/ 2>/dev/null || true
                mv /tmp/frp_0.58.1_linux_amd64/frpc /usr/local/bin/ 2>/dev/null || true
                rm -rf /tmp/frp*
            fi
        fi
        chmod +x /usr/local/bin/frps /usr/local/bin/frpc 2>/dev/null || true
        if [ -x /usr/local/bin/frps ] && [ -x /usr/local/bin/frpc ]; then
            count_downloaded=$((count_downloaded + 1))
        else
            echo -e "    ${RED}[!] Warning: Failed to download FRP. Check server internet access.${NC}"
        fi
    fi

    # UDP2Raw
    if [ ! -x /usr/local/bin/udp2raw ]; then
        echo "    Downloading UDP2Raw..."
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/udp2raw -o /usr/local/bin/udp2raw 2>/dev/null || \
        (curl -fsSL --connect-timeout 10 --max-time 60 https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz 2>/dev/null | tar -xz -C /tmp/ 2>/dev/null && mv /tmp/udp2raw_amd64 /usr/local/bin/udp2raw 2>/dev/null && rm -rf /tmp/udp2raw* || true)
        chmod +x /usr/local/bin/udp2raw 2>/dev/null || true
        if [ -x /usr/local/bin/udp2raw ]; then
            count_downloaded=$((count_downloaded + 1))
        else
            echo -e "    ${RED}[!] Warning: Failed to download UDP2Raw. Check server internet access.${NC}"
        fi
    fi

    # Phantun
    if [ ! -x /usr/local/bin/phantun-server ]; then
        echo "    Downloading Phantun..."
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/phantun-server -o /usr/local/bin/phantun-server 2>/dev/null || true
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/phantun-client -o /usr/local/bin/phantun-client 2>/dev/null || true
        if [ ! -x /usr/local/bin/phantun-server ]; then
            curl -fsSL --connect-timeout 10 --max-time 60 https://github.com/dndx/phantun/releases/download/v0.8.1/phantun_x86_64-unknown-linux-musl.zip -o /tmp/phantun.zip 2>/dev/null || true
            if [ -f /tmp/phantun.zip ]; then
                unzip -o /tmp/phantun.zip -d /usr/local/bin/ >/dev/null 2>&1 || true
                rm -f /tmp/phantun.zip
            fi
        fi
        chmod +x /usr/local/bin/phantun* 2>/dev/null || true
        if [ -x /usr/local/bin/phantun-server ]; then
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
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/kcptun-server -o /usr/local/bin/kcptun-server 2>/dev/null || true
        curl -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/t-51/MHPanel/main/bin/kcptun-client -o /usr/local/bin/kcptun-client 2>/dev/null || true
        chmod +x /usr/local/bin/kcptun-* 2>/dev/null || true
        if [ -x /usr/local/bin/kcptun-server ]; then
            count_downloaded=$((count_downloaded + 1))
        else
            echo -e "    ${RED}[!] Warning: Failed to download Kcptun. Check server internet access.${NC}"
        fi
    fi

    # MHRV Tunnel Node & Google Apps Script Daemon
    for bdir in "${PANEL_DIR}/bin" "${SCRIPT_DIR}/bin" "/root/mhpanel-repo/bin"; do
        if [ -f "${bdir}/mhrv-tunnel-node" ] && [ ! -x /usr/local/bin/mhrv-tunnel-node ]; then
            cp -f "${bdir}/mhrv-tunnel-node" /usr/local/bin/mhrv-tunnel-node 2>/dev/null || true
            chmod +x /usr/local/bin/mhrv-tunnel-node 2>/dev/null || true
            break
        fi
    done
    for sdir in "${PANEL_DIR}/scripts/daemons" "${SCRIPT_DIR}/scripts/daemons" "/root/mhpanel-repo/scripts/daemons"; do
        if [ -f "${sdir}/mhpanel-gas-server" ] && [ ! -x /usr/local/bin/mhpanel-gas-server ]; then
            cp -f "${sdir}/mhpanel-gas-server" /usr/local/bin/mhpanel-gas-server 2>/dev/null || true
            chmod +x /usr/local/bin/mhpanel-gas-server 2>/dev/null || true
            break
        fi
    done

    # AmneziaWG tools & userspace binary
    for bdir in "${PANEL_DIR}/bin" "${SCRIPT_DIR}/bin" "/root/mhpanel-repo/bin"; do
        for b in awg awg-quick amneziawg-go; do
            if [ -f "${bdir}/${b}" ] && [ ! -x "/usr/bin/${b}" ]; then
                cp -f "${bdir}/${b}" "/usr/bin/${b}" 2>/dev/null || true
                cp -f "${bdir}/${b}" "/usr/local/bin/${b}" 2>/dev/null || true
                chmod +x "/usr/bin/${b}" "/usr/local/bin/${b}" 2>/dev/null || true
            fi
        done
    done

    install_cloudflare_warp
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

protocol_ensure_active() {
    local proto="$1"
    local def_port="$(protocol_default_port "$proto")"
    case "$proto" in
        ssh) systemctl restart ssh sshd 2>/dev/null || true ;;
        openvpn) systemctl restart openvpn openvpn@server openvpn@server-tcp 2>/dev/null || true ;;
        ocserv) systemctl restart ocserv 2>/dev/null || true ;;
        ikev2) systemctl restart strongswan-starter strongswan ipsec 2>/dev/null || true ;;
        sstp)
            if [ -f /etc/systemd/system/sstpd.service ]; then
                systemctl daemon-reload
                systemctl restart sstpd 2>/dev/null || true
            else
                install_protocol_action "sstp" "${def_port}"
            fi
            ;;
        pptp) systemctl restart pptpd 2>/dev/null || true ;;
        l2tp) systemctl restart strongswan-starter strongswan xl2tpd 2>/dev/null || true ;;
        wireguard) systemctl restart wg-quick@wg0 2>/dev/null || true ;;
        amneziawg)
            if [ -f /etc/amnezia/amneziawg/awg0.conf ]; then
                systemctl restart awg-quick@awg0 2>/dev/null || true
            else
                install_protocol_action "amneziawg" "${def_port}"
            fi
            ;;
        http) systemctl restart mhpanel-http-proxy 2>/dev/null || true ;;
        socks) systemctl restart mhpanel-socks-proxy 2>/dev/null || true ;;
        shadowsocks) systemctl restart mhpanel-shadowsocks 2>/dev/null || true ;;
        tuic) systemctl restart mhpanel-tuic 2>/dev/null || true ;;
        mtproto) systemctl restart mhpanel-mtproto@4433 2>/dev/null || true ;;
        badvpn)
            if [ -f /etc/systemd/system/badvpn.service ]; then
                systemctl restart badvpn 2>/dev/null || true
            else
                install_badvpn
            fi
            ;;
        dnstt) systemctl restart mhpanel-dnstt 2>/dev/null || true ;;
        vaydns) systemctl restart mhpanel-vaydns 2>/dev/null || true ;;
        slipstream) systemctl restart mhpanel-slipstream 2>/dev/null || true ;;
        hysteria2) systemctl restart mhpanel-hysteria2 2>/dev/null || true ;;
        trojan) systemctl restart mhpanel-trojan 2>/dev/null || true ;;
        naiveproxy) systemctl restart mhpanel-naiveproxy 2>/dev/null || true ;;
        stuntls) systemctl restart mhpanel-stuntls 2>/dev/null || true ;;
        noizdns) systemctl restart mhpanel-noizdns 2>/dev/null || true ;;
        masterdnsvpn) systemctl restart mhpanel-masterdnsvpn 2>/dev/null || true ;;
        tor) systemctl restart mhpanel-tor 2>/dev/null || true ;;
        singbox)
            if [ -f /etc/sing-box/config.json ] && [ -s /etc/sing-box/config.json ]; then
                systemctl restart mhpanel-singbox 2>/dev/null || true
            else
                install_protocol_action "singbox" "${def_port}"
            fi
            ;;
        google_script) systemctl restart mhpanel-gas-tunnel 2>/dev/null || true ;;
    esac
}

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
            echo -e "    ${GREEN}[✓] ${lbl}${NC} is already installed (Preserving settings & ensuring service is active)."
            protocol_ensure_active "$proto"
        else
            install_protocol_action "$proto" "$def_port"
        fi
    done

    echo -e "\n${YELLOW}>>> [6/6] Synchronizing firewall rules, TCP MSS clamping, and routing state...${NC}"
    if [ -x "/www/wwwroot/mhpanel/scripts/protocol_helper.sh" ]; then
        /www/wwwroot/mhpanel/scripts/protocol_helper.sh setup-nat 2>/dev/null || true
    fi
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

    local custom_path=$(cat /etc/vpnpanel/panel_path.txt 2>/dev/null || cat "${PANEL_DIR}/panel_path.txt" 2>/dev/null || echo "")
    [ -n "$custom_path" ] && [ "${custom_path:0:1}" != "/" ] && custom_path="/${custom_path}"

    echo -e "${CYAN}${BOLD}========================================================================${NC}"
    echo -e "${WHITE}${BOLD}              MH Panel - Panel Access & Login Credentials               ${NC}"
    echo -e "${CYAN}${BOLD}========================================================================${NC}"
    echo -e "  ⚡ ${BOLD}Service Status:${NC}         ${is_active}"
    echo -e "  🌐 ${BOLD}Web Panel URL (IPv4):${NC}   ${CYAN}${BOLD}https://${srv_ip}:${panel_port}${custom_path}/${NC}"
    if [ -n "$srv_ipv6" ]; then
        echo -e "  🌐 ${BOLD}Web Panel URL (IPv6):${NC}   ${CYAN}${BOLD}https://[${srv_ipv6}]:${panel_port}${custom_path}/${NC}"
    fi
    if [ -n "$domain" ]; then
        echo -e "  🌐 ${BOLD}Custom Domain URL:${NC}      ${CYAN}${BOLD}https://${domain}:${panel_port}${custom_path}/${NC}"
    fi
    echo -e "  🔌 ${BOLD}Web Panel Port:${NC}        ${YELLOW}${BOLD}${panel_port}${NC}"
    if [ -n "$custom_path" ]; then
        echo -e "  🔒 ${BOLD}Secret URL Path:${NC}       ${CYAN}${BOLD}${custom_path}${NC}"
    fi
    echo -e "  👤 ${BOLD}Admin Username:${NC}        ${GREEN}${BOLD}${user}${NC}"
    echo -e "  🔑 ${BOLD}Admin Password:${NC}        ${GREEN}${BOLD}${pass}${NC}"
    echo -e "  🛡️  ${BOLD}Public API Key:${NC}         ${DIM}${api_key}${NC}"
    echo -e "${CYAN}${BOLD}========================================================================${NC}"
    echo -e "  💡 ${YELLOW}${BOLD}Connection Note:${NC} Default SSL certificate is Self-Signed (IP SAN)."
    echo -e "     When accessing the URL in your browser, if an SSL warning appears:"
    echo -e "     Click ${BOLD}Advanced${NC} and select ${BOLD}Proceed to ... (unsafe)${NC}."
    echo -e "     You can configure a free Let's Encrypt SSL certificate anytime from the menu."
    echo -e "${CYAN}${BOLD}========================================================================${NC}\n"
    if [ -t 0 ]; then
        read -p "Press Enter to return to main menu..." || true
    fi
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
    local custom_path=$(cat /etc/vpnpanel/panel_path.txt 2>/dev/null || cat "${PANEL_DIR}/panel_path.txt" 2>/dev/null || echo "")
    [ -n "$custom_path" ] && [ "${custom_path:0:1}" != "/" ] && custom_path="/${custom_path}"

    echo -e "\n${GREEN}${BOLD}========================================================================${NC}"
    echo -e "${GREEN}${BOLD}   ✓ MH Panel Setup Completed Successfully!${NC}"
    echo -e "${GREEN}${BOLD}========================================================================${NC}"
    echo -e "  🌐 ${BOLD}Web Panel URL (IPv4):${NC}       ${CYAN}https://${srv_ip}:${panel_port}${custom_path}/${NC}"
    if [ -n "$srv_ipv6" ]; then
        echo -e "  🌐 ${BOLD}Web Panel URL (IPv6):${NC}       ${CYAN}https://[${srv_ipv6}]:${panel_port}${custom_path}/${NC}"
    fi
    if [ -n "$custom_path" ]; then
        echo -e "  🔒 ${BOLD}Secret URL Path:${NC}            ${CYAN}${custom_path}${NC}"
    fi
    echo -e "  👤 ${BOLD}Admin Username:${NC}             ${BOLD}${user}${NC}"
    echo -e "  🔑 ${BOLD}Admin Password:${NC}             ${BOLD}${pass}${NC}"
    echo -e "  🔑 ${BOLD}API Key:${NC}                    ${DIM}${api_key}${NC}"
    echo -e "${GREEN}${BOLD}========================================================================${NC}"
    echo -e "${YELLOW}${BOLD}Management Tip:${NC}"
    echo -e "  You can reopen this management hub anytime from your server terminal by running:"
    echo -e "  Command: ${CYAN}${BOLD}mhpanel${NC} (or ${CYAN}hmpanel${NC})"
    echo -e "${GREEN}${BOLD}========================================================================${NC}\n"
    if [ -t 0 ]; then
        read -p "Press Enter to return to main menu..." || true
    fi
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
    if [ -t 0 ]; then
        read -p "Press Enter to return to main menu..." || true
    fi
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
                        singbox) svc="mhpanel-singbox" ;;
                        google_script) svc="mhpanel-gas-tunnel" ;;
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
                        singbox) svc="mhpanel-singbox" ;;
                        google_script) svc="mhpanel-gas-tunnel" ;;
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
    while true; do
        clear 2>/dev/null || true
        echo -e "${YELLOW}${BOLD}=== Anti-Censorship Tunnels & Network Bridge Hub (مدیریت تانل‌ها) ===${NC}"
        echo -e "${DIM}Tranziting, reverse tunnels, fake-TCP and server-to-server obfuscation${NC}\n"

        echo -e "  ${WHITE}${BOLD}Live Tunnel Binaries Status:${NC}"
        local tools=(
            "gost:GOST v3 (WSS/TLS Relay):/usr/local/bin/gost"
            "wstunnel:WSTunnel (WebSocket Tunnel):/usr/local/bin/wstunnel"
            "chisel:Chisel (TCP/UDP over HTTP):/usr/local/bin/chisel"
            "frps:FRP Server:/usr/local/bin/frps"
            "frpc:FRP Client:/usr/local/bin/frpc"
            "rathole:Rathole (Secure Reverse Proxy):/usr/local/bin/rathole"
            "udp2raw:UDP2Raw (Fake-TCP Tunnel):/usr/local/bin/udp2raw"
            "phantun-server:Phantun Server (Obfuscated UDP):/usr/local/bin/phantun-server"
            "phantun-client:Phantun Client:/usr/local/bin/phantun-client"
            "rtt:RTT (Reverse TLS Tunnel):/usr/local/bin/rtt"
            "kcptun-server:KCPTun Server (KCP/UDP FEC):/usr/local/bin/kcptun-server"
            "tun2socks:Tun2Socks (TUN to SOCKS5):/usr/local/bin/tun2socks"
            "mhrv-tunnel-node:MHRV Tunnel Node (GAS / Rust Relay):/usr/local/bin/mhrv-tunnel-node"
        )
        for item in "${tools[@]}"; do
            local key="${item%%:*}"
            local rest="${item#*:}"
            local label="${rest%%:*}"
            local bpath="${rest#*:}"
            local st="${RED}Missing (نصب نشده)${NC}"
            if [ -x "$bpath" ]; then
                st="${GREEN}Installed ✓ (نصب شده)${NC}"
            fi
            echo -e "    • ${label}: ${st}"
        done
        echo ""

        echo -e "  ${CYAN}[1] Download & Install / Update ALL Tunnel Binaries (نصب همه ابزارهای تانل)${NC}"
        echo -e "  [2] Install / Reinstall a Specific Missing Binary (نصب تکی ابزار دلخواه)"
        echo -e "  [3] Execute / Start Local Configured Tunnels (/etc/mhpanel/tunnels_boot.sh)"
        echo -e "  [4] List Active Systemd Tunnel Services (mhtun_*) & Live Status"
        echo -e "  [5] View Live Journal Logs of Tunnel Services"
        echo -e "  [6] Enable Kernel Modules for GRE / IPIP / IPv6 Tunnels"
        echo -e "  ${YELLOW}[7] Generate / View Setup Commands for Iran / Remote Server (دستورات سرور مقابل)${NC}"
        echo -e "  ${GREEN}[8] Step-by-Step Tunnel Architecture Guide (راهنمای جامع راه‌اندازی تانل‌های اسکریپتی)${NC}"
        echo -e "  [0] Back to Main Menu"
        echo ""
        read -p "Select option [0-8]: " t_act
        case "$t_act" in
            1)
                install_tunnel_tools
                read -p "Press Enter to continue..."
                ;;
            2)
                echo -e "\n${WHITE}Select binary to install:${NC}"
                echo "1) gost  2) wstunnel  3) chisel  4) frp  5) rathole  6) udp2raw  7) phantun  8) rtt  9) kcptun  10) tun2socks  11) mhrv-tunnel-node"
                read -p "Choice [1-11]: " b_choice
                case "$b_choice" in
                    1) curl -fsSL https://github.com/go-gost/gost/releases/download/v3.0.0-rc10/gost_3.0.0-rc10_linux_amd64.tar.gz 2>/dev/null | tar -xz -C /usr/local/bin/ gost 2>/dev/null && chmod +x /usr/local/bin/gost ;;
                    2) curl -fsSL https://github.com/erebe/wstunnel/releases/download/v11.0.0/wstunnel_11.0.0_linux_amd64.tar.gz 2>/dev/null | tar -xz -C /usr/local/bin/ wstunnel 2>/dev/null && chmod +x /usr/local/bin/wstunnel ;;
                    3) curl -fsSL https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_linux_amd64.gz 2>/dev/null | gzip -d > /usr/local/bin/chisel && chmod +x /usr/local/bin/chisel ;;
                    4) curl -fsSL https://github.com/fatedier/frp/releases/download/v0.58.1/frp_0.58.1_linux_amd64.tar.gz 2>/dev/null | tar -xz -C /tmp/ 2>/dev/null && mv /tmp/frp_0.58.1_linux_amd64/frp* /usr/local/bin/ 2>/dev/null && chmod +x /usr/local/bin/frp* ;;
                    5) curl -fsSL https://github.com/rapiz1/rathole/releases/download/v0.5.0/rathole-x86_64-unknown-linux-musl.zip -o /tmp/r.zip 2>/dev/null && unzip -o /tmp/r.zip -d /usr/local/bin/ 2>/dev/null && chmod +x /usr/local/bin/rathole && rm -f /tmp/r.zip ;;
                    6) curl -fsSL https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz 2>/dev/null | tar -xz -C /tmp/ 2>/dev/null && mv /tmp/udp2raw_amd64 /usr/local/bin/udp2raw 2>/dev/null && chmod +x /usr/local/bin/udp2raw ;;
                    7) curl -fsSL https://github.com/dndx/phantun/releases/download/v0.8.1/phantun_x86_64-unknown-linux-musl.zip -o /tmp/p.zip 2>/dev/null && unzip -o /tmp/p.zip -d /usr/local/bin/ 2>/dev/null && chmod +x /usr/local/bin/phantun* && rm -f /tmp/p.zip ;;
                    8) curl -fsSL https://github.com/radkesvat/ReverseTlsTunnel/releases/download/v7.1/rtt-linux-amd64.zip -o /tmp/rtt.zip 2>/dev/null && unzip -o /tmp/rtt.zip -d /usr/local/bin/ 2>/dev/null && chmod +x /usr/local/bin/rtt && rm -f /tmp/rtt.zip ;;
                    9) curl -fsSL https://raw.githubusercontent.com/t-51/MHPanel/main/bin/kcptun-server -o /usr/local/bin/kcptun-server 2>/dev/null && curl -fsSL https://raw.githubusercontent.com/t-51/MHPanel/main/bin/kcptun-client -o /usr/local/bin/kcptun-client 2>/dev/null && chmod +x /usr/local/bin/kcptun-* ;;
                    10) curl -fsSL "https://github.com/xjasonlyu/tun2socks/releases/download/v2.5.2/tun2socks-linux-amd64.zip" -o /tmp/t.zip 2>/dev/null && unzip -o /tmp/t.zip -d /tmp/ 2>/dev/null && mv /tmp/tun2socks-* /usr/local/bin/tun2socks 2>/dev/null && chmod +x /usr/local/bin/tun2socks && rm -f /tmp/t.zip ;;
                    11)
                        for bdir in "${PANEL_DIR}/bin" "/root/mhpanel-repo/bin"; do
                            [ -f "${bdir}/mhrv-tunnel-node" ] && cp -f "${bdir}/mhrv-tunnel-node" /usr/local/bin/mhrv-tunnel-node && chmod +x /usr/local/bin/mhrv-tunnel-node && break
                        done
                        ;;
                esac
                echo -e "${GREEN}Operation completed.${NC}"
                read -p "Press Enter to continue..."
                ;;
            3)
                if [ -f "/etc/mhpanel/tunnels_boot.sh" ]; then
                    bash /etc/mhpanel/tunnels_boot.sh
                    echo -e "${GREEN}Boot tunnels script executed successfully.${NC}"
                else
                    echo -e "${YELLOW}No configured tunnels found in /etc/mhpanel/tunnels_boot.sh yet.${NC}"
                    echo -e "You can create and manage tunnels from the Web UI under 'Tunnels & MikroTik Hub'."
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                echo -e "\n${WHITE}${BOLD}Active Systemd Tunnel Units (mhtun_*):${NC}"
                systemctl list-units --type=service "mhtun_*" --no-pager
                read -p "Press Enter to continue..."
                ;;
            5)
                echo -e "\n${WHITE}Select tunnel service name (e.g. mhtun_1 or leave empty for all mhtun):${NC}"
                read -p "Service name [mhtun_*]: " tun_svc_name
                tun_svc_name=${tun_svc_name:-"mhtun_*"}
                journalctl -u "$tun_svc_name" -n 60 --no-pager
                read -p "Press Enter to continue..."
                ;;
            6)
                modprobe ip6_gre 2>/dev/null || true
                modprobe ip6_tunnel 2>/dev/null || true
                modprobe sit 2>/dev/null || true
                modprobe ip_gre 2>/dev/null || true
                modprobe ipip 2>/dev/null || true
                echo -e "${GREEN}Kernel modules for GRE IPv6, IPIP IPv6 and SIT 6in4 loaded.${NC}"
                read -p "Press Enter to continue..."
                ;;
            7)
                echo -e "\n${YELLOW}${BOLD}=== دستورات و اسکریپت نصب روی سرور مقابل (سرور ایران یا کلاینت) ===${NC}"
                local srv_ip=$(get_public_ipv4)
                echo -e "برای راه‌اندازی تانل در سرور مقابل (ایران)، می‌توانید از اسکریپت‌های هوشمند زیر استفاده کنید:"
                echo -e "\n${CYAN}1) نصب باینری‌های تانل در سرور ایران با یک دستور:${NC}"
                echo -e "   curl -fsSL https://raw.githubusercontent.com/t-51/MHPanel/main/install.sh | bash -s -- --ui"
                echo -e "\n${CYAN}2) دریافت دستور دقیق سرویس هر تانل ساخت‌شده:${NC}"
                echo -e "   در پنل وب -> تب «مرکز تونل‌ها» -> جدول تونل‌های ضد فیلتر -> روی دکمه «اسکریپت و دستورات» کلیک کنید."
                echo -e "   اسکریپت به همراه تمام کلیدها، ساب‌نت‌ها و پورتی که به سرور خارج (${srv_ip}) متصل می‌شود کپی خواهد شد."
                read -p "Press Enter to continue..."
                ;;
            8)
                echo -e "\n${GREEN}${BOLD}=== راهنمای جامع راه‌اندازی و معماری تانل‌های اسکریپتی ===${NC}"
                echo -e "1. ${BOLD}مفهوم تانل اسکریپتی چیست؟${NC}"
                echo -e "   تانل‌های اسکریپتی (مثل GOST, WSTunnel, Chisel, RTT, Rathole) ترافیک را به شکل"
                echo -e "   وب‌سوکت امن (WSS) یا TLS استاندارد شبیه وب‌سایت‌های عادی تغییر می‌دهند."
                echo -e "2. ${BOLD}کجا نصب می‌شوند؟${NC}"
                echo -e "   یک طرف تانل (معمولاً نقش Server) روی همین سرور خارج با پنل مدیریت ساخته می‌شود."
                echo -e "   طرف دیگر (نقش Client) روی سرور ایران شما اجرا می‌شود."
                echo -e "3. ${BOLD}چگونه اجرا کنیم؟${NC}"
                echo -e "   در تب مرکز تونل‌ها دکمه «اسکریپت سرور مقابل» را بزنید و متن آن را در SSH سرور ایران"
                echo -e "   Paste کنید. اسکریپت به صورت خودکار سرویس دائمی systemd را در سرور ایران می‌سازد."
                echo -e "4. ${BOLD}در صورت نبود ابزارها در همین سرور خارج چه کنیم؟${NC}"
                echo -e "   گزینه [1] را در همین منوی ترمینال بزنید تا تمامی ابزارها با یک کلیک نصب و آماده شوند."
                read -p "Press Enter to continue..."
                ;;
            0|"")
                break
                ;;
        esac
    done
}

menu_wordpress_camouflage() {
    while true; do
        clear 2>/dev/null || true
        echo -e "${YELLOW}${BOLD}=== Web Server Integration & WordPress Anti-DPI Camouflage ===${NC}"
        echo -e "${DIM}هماهنگی خودکار با آپاچی/انجین‌یکس و استتار ترافیک فیلترشکن پشت سایت وردپرس${NC}\n"

        local ws_type="None"
        local ws_active="${RED}Not Running${NC}"
        local ws_port="80"
        local ws_ssl_port="8444"

        if systemctl is-active --quiet httpd 2>/dev/null || [ -x "/www/server/apache/bin/httpd" ]; then
            ws_type="Apache (aaPanel / httpd)"
            systemctl is-active --quiet httpd 2>/dev/null && ws_active="${GREEN}Running (Port 80/8444) ✓${NC}"
        elif systemctl is-active --quiet apache2 2>/dev/null; then
            ws_type="Apache2 (Debian/Ubuntu)"
            ws_active="${GREEN}Running ✓${NC}"
        elif systemctl is-active --quiet nginx 2>/dev/null || [ -x "/www/server/nginx/sbin/nginx" ]; then
            ws_type="Nginx"
            ws_active="${GREEN}Running ✓${NC}"
            ws_ssl_port="8443"
        fi

        local wp_sites=()
        for cand in /www/wwwroot/* /var/www/html /var/www/*; do
            if [ -f "${cand}/wp-config.php" ] || [ -f "${cand}/wp-load.php" ] || [ -d "${cand}/wp-content" ]; then
                [ -d "$cand" ] && wp_sites+=("$cand")
            fi
        done

        local decoy_status="${RED}Not Installed${NC}"
        if [ -f "/www/wwwroot/decoy-wp/index.html" ] || [ -f "/etc/mhpanel/decoy_wp.json" ]; then
            decoy_status="${GREEN}Deployed & Active ✓${NC}"
        fi

        local mux_status="${RED}Disabled${NC}"
        if systemctl is-active --quiet haproxy 2>/dev/null; then
            mux_status="${GREEN}Active on Port 443 (HAProxy Mux) ✓${NC}"
        fi

        echo -e "  Detected Web Server:   ${CYAN}${ws_type}${NC} (${ws_active})"
        echo -e "  Port 443 Multiplexer:  ${mux_status}"
        echo -e "  Decoy WordPress Site:  ${decoy_status} (/www/wwwroot/decoy-wp)"
        if [ ${#wp_sites[@]} -gt 0 ]; then
            echo -e "  Found WordPress Sites: ${GREEN}${#wp_sites[@]} site(s) detected:${NC}"
            for w in "${wp_sites[@]}"; do
                echo -e "    • ${w}"
            done
        else
            echo -e "  Found WordPress Sites: ${YELLOW}None (Decoy WordPress available)${NC}"
        fi
        echo -e "${BLUE}------------------------------------------------------------------------${NC}"
        echo -e "  ${WHITE}${BOLD}[1] Auto-Match Web Server & Enable Port 443 WordPress Camouflage${NC}"
        echo -e "      (تنظیم خودکار اتصال ترافیک به وب‌سرور و نمایش وردپرس در صورت ورود عادی)"
        echo -e "  ${WHITE}${BOLD}[2] Deploy / Update Realistic Decoy WordPress Site (/www/wwwroot/decoy-wp)${NC}"
        echo -e "      (نصب و فعال‌سازی سایت فریب بلاگ فناوری وردپرس برای آپاچی و انجین‌یکس)"
        echo -e "  [3] Configure Sing-box Reality Camouflage Target to WordPress Site"
        echo -e "  [4] Send Live HTTP & HTTPS Camouflage Probe (تست زنده پاسخ وردپرس در پورت ۸۰ و ۴۴۳)"
        echo -e "  [5] Remove / Unlink Decoy WordPress Virtual Host"
        echo -e "  [0] Back to Main Menu"
        echo -e "${BLUE}========================================================================${NC}"
        read -p "Select option [0-5]: " wp_opt

        case "$wp_opt" in
            1)
                echo -e "\n${CYAN}Configuring HAProxy Port Multiplexer for Web Server & WordPress Fallback...${NC}"
                if [ -x /www/wwwroot/mhpanel/venv/bin/python ]; then
                    /www/wwwroot/mhpanel/venv/bin/python -c "
import sys; sys.path.insert(0, '/www/wwwroot/mhpanel')
from app import get_multiplexer_config, save_multiplexer_config, apply_multiplexer_config
cfg = get_multiplexer_config()
cfg['enabled'] = True
cfg['listen_ports'] = [443]
cfg['default_backend'] = 'web'
web_p = ${ws_ssl_port}
for p in cfg.get('protocols', []):
    if p.get('id') == 'web':
        p['enabled'] = True
        p['backend_port'] = web_p
        p['is_default'] = True
save_multiplexer_config(cfg)
ok, msg = apply_multiplexer_config(cfg)
print('Result:', ok, msg)
" 2>/dev/null || true
                fi
                echo -e "${GREEN}✓ HAProxy multiplexer configured to route all non-VPN and normal browser traffic directly to your WordPress web server on port ${ws_ssl_port}.${NC}"
                read -p "Press Enter to continue..."
                ;;
            2)
                echo -e "\n${CYAN}Deploying Decoy WordPress Anti-DPI Site...${NC}"
                local srv_ip=$(get_public_ipv4)
                read -p "Enter camouflage domain name (Default: blog.${srv_ip}.nip.io or press Enter): " c_domain
                c_domain=${c_domain:-"blog.${srv_ip}.nip.io"}
                if [ -x /www/wwwroot/mhpanel/venv/bin/python ]; then
                    /www/wwwroot/mhpanel/venv/bin/python -c "
import sys; sys.path.insert(0, '/www/wwwroot/mhpanel')
from app import deploy_decoy_wordpress
cfg = deploy_decoy_wordpress('${c_domain}', site_title='Modern DevOps & Cloud Infrastructure', theme='twentytwentythree')
print('Deployed to:', cfg.get('path'))
" 2>/dev/null || true
                fi
                echo -e "${GREEN}✓ Decoy WordPress site installed at /www/wwwroot/decoy-wp with virtual hosts for Apache and Nginx.${NC}"
                read -p "Press Enter to continue..."
                ;;
            3)
                echo -e "\n${CYAN}Configuring Sing-box Reality handshake camouflage target...${NC}"
                read -p "Enter camouflage domain for Reality (Default: dl.google.com): " r_domain
                r_domain=${r_domain:-"dl.google.com"}
                if [ -f /etc/sing-box/config.json ]; then
                    sed -i -E "s/\"server\": \"[^\"]+\"/\"server\": \"${r_domain}\"/g" /etc/sing-box/config.json 2>/dev/null || true
                    sed -i -E "s/\"server_name\": \"[^\"]+\"/\"server_name\": \"${r_domain}\"/g" /etc/sing-box/config.json 2>/dev/null || true
                    systemctl restart mhpanel-singbox 2>/dev/null || true
                    echo -e "${GREEN}✓ Sing-box Reality camouflage target set to ${r_domain}.${NC}"
                else
                    echo -e "${YELLOW}Sing-box config not found at /etc/sing-box/config.json.${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                echo -e "\n${CYAN}Testing Web Server & WordPress Camouflage Live Probe...${NC}"
                echo "1. Testing HTTP Port 80:"
                curl -Is --connect-timeout 3 http://127.0.0.1:80/ | head -n 6 || echo "Port 80 probe failed."
                echo -e "\n2. Testing HTTPS Port 8444 / 8443 (Web Server SSL Backend):"
                curl -Iks --connect-timeout 3 https://127.0.0.1:${ws_ssl_port}/ | head -n 6 || echo "SSL Backend probe failed."
                echo -e "\n3. Testing Port 443 Multiplexer (Direct Browser visit):"
                curl -Iks --connect-timeout 3 https://127.0.0.1:443/ | head -n 6 || echo "Port 443 probe failed."
                read -p "Press Enter to continue..."
                ;;
            5)
                if [ -x /www/wwwroot/mhpanel/venv/bin/python ]; then
                    /www/wwwroot/mhpanel/venv/bin/python -c "
import sys; sys.path.insert(0, '/www/wwwroot/mhpanel')
from app import remove_decoy_wordpress
remove_decoy_wordpress()
" 2>/dev/null || true
                fi
                echo -e "${GREEN}✓ Decoy WordPress virtual host removed.${NC}"
                read -p "Press Enter to continue..."
                ;;
            0|"")
                break
                ;;
        esac
    done
}

menu_telegram_bot() {
    while true; do
        clear 2>/dev/null || true
        echo -e "${YELLOW}${BOLD}=== Telegram Bot Notification & Auto-Backup Hub ===${NC}"
        echo -e "${DIM}مدیریت ربات تلگرام، اعلان‌های مصرف منابع، ورود مدیر و ارسال خودکار بکاپ${NC}\n"

        local tg_cfg="/etc/mhpanel/telegram_bot.json"
        local b_token="Not Set"
        local c_id="Not Set"
        local is_en="${RED}Disabled${NC}"
        local auto_bk="${RED}Disabled${NC}"
        local bk_sched="daily"
        local cpu_th="90"
        local ram_th="90"
        local disk_th="90"

        if [ -f "$tg_cfg" ]; then
            local raw_tok=$(grep -oE '"bot_token":\s*"[^"]+"' "$tg_cfg" | cut -d'"' -f4)
            if [ -n "$raw_tok" ] && [ "$raw_tok" != "" ]; then
                if [ ${#raw_tok} -gt 10 ]; then
                    b_token="${raw_tok:0:4}****${raw_tok: -4}"
                else
                    b_token="Set (${raw_tok})"
                fi
            fi
            local raw_cid=$(grep -oE '"chat_id":\s*"[^"]+"' "$tg_cfg" | cut -d'"' -f4)
            [ -n "$raw_cid" ] && [ "$raw_cid" != "" ] && c_id="$raw_cid"
            if grep -q '"enabled":\s*true' "$tg_cfg"; then
                is_en="${GREEN}Enabled (Active) ✓${NC}"
            fi
            if grep -q '"auto_backup":\s*true' "$tg_cfg"; then
                auto_bk="${GREEN}Enabled ✓${NC}"
            fi
            local raw_sched=$(grep -oE '"auto_backup_schedule":\s*"[^"]+"' "$tg_cfg" | cut -d'"' -f4)
            [ -n "$raw_sched" ] && bk_sched="$raw_sched"
            local raw_cpu=$(grep -oE '"alert_cpu_percent":\s*[0-9]+' "$tg_cfg" | awk '{print $2}')
            [ -n "$raw_cpu" ] && cpu_th="$raw_cpu"
            local raw_ram=$(grep -oE '"alert_ram_percent":\s*[0-9]+' "$tg_cfg" | awk '{print $2}')
            [ -n "$raw_ram" ] && ram_th="$raw_ram"
            local raw_disk=$(grep -oE '"alert_disk_percent":\s*[0-9]+' "$tg_cfg" | awk '{print $2}')
            [ -n "$raw_disk" ] && disk_th="$raw_disk"
        fi

        echo -e "  Telegram Bot Token:   ${CYAN}${b_token}${NC}"
        echo -e "  Admin Chat ID:        ${CYAN}${c_id}${NC}"
        echo -e "  Notification Engine:  ${is_en}"
        echo -e "  Auto-Backup to Chat:  ${auto_bk} (Schedule: ${bk_sched})"
        echo -e "  Resource Thresholds:  CPU: ${cpu_th}% | RAM: ${ram_th}% | Disk: ${disk_th}%"
        echo -e "${BLUE}------------------------------------------------------------------------${NC}"
        echo -e "  ${WHITE}${BOLD}[1] Set / Change Telegram Bot Token (ثبت یا ویرایش توکن ربات)${NC}"
        echo -e "  ${WHITE}${BOLD}[2] Set / Change Admin Telegram Chat ID (ثبت یا ویرایش شناسه چت ادمین)${NC}"
        echo -e "  [3] Toggle Notification Service (فعال / غیرفعال‌سازی سراسری اعلان‌ها)"
        echo -e "  [4] Configure Resource Alert Thresholds (تنظیم سقف مجاز CPU, RAM, Disk)"
        echo -e "  [5] Configure Automated Backup to Telegram (زمان‌بندی ارسال خودکار بکاپ)"
        echo -e "  ${GREEN}${BOLD}[6] Send Live Test Message to Telegram (تست ارسال اعلان تلگرام)${NC}"
        echo -e "  ${YELLOW}${BOLD}[7] Send Instant Full Panel Backup to Telegram Now (ارسال آنی بکاپ)${NC}"
        echo -e "  [8] Restart Telegram Alert Monitoring Daemon (راه‌اندازی مجدد پایشگر)"
        echo -e "  [0] Back to Main Menu"
        echo -e "${BLUE}========================================================================${NC}"
        read -p "Select option [0-8]: " tg_opt

        case "$tg_opt" in
            1)
                echo -e "\n${CYAN}Enter your Telegram Bot Token from @BotFather (e.g. 123456789:AAH...):${NC}"
                read -p "Bot Token: " input_tok
                input_tok=$(echo "$input_tok" | tr -d '[:space:]')
                if [ -n "$input_tok" ]; then
                    if [ -x /www/wwwroot/mhpanel/venv/bin/python ]; then
                        /www/wwwroot/mhpanel/venv/bin/python -c "
import sys; sys.path.insert(0, '/www/wwwroot/mhpanel')
from app import load_telegram_config, save_telegram_config
c = load_telegram_config()
c['bot_token'] = '${input_tok}'
c['enabled'] = True
save_telegram_config(c)
print('Token saved successfully.')
" 2>/dev/null || true
                    fi
                    echo -e "${GREEN}✓ Telegram bot token registered.${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            2)
                echo -e "\n${CYAN}Enter your Telegram numeric Chat ID (from @userinfobot or @raw_data_bot):${NC}"
                read -p "Admin Chat ID: " input_cid
                input_cid=$(echo "$input_cid" | tr -d '[:space:]')
                if [ -n "$input_cid" ]; then
                    if [ -x /www/wwwroot/mhpanel/venv/bin/python ]; then
                        /www/wwwroot/mhpanel/venv/bin/python -c "
import sys; sys.path.insert(0, '/www/wwwroot/mhpanel')
from app import load_telegram_config, save_telegram_config
c = load_telegram_config()
c['chat_id'] = '${input_cid}'
c['enabled'] = True
save_telegram_config(c)
print('Chat ID saved successfully.')
" 2>/dev/null || true
                    fi
                    echo -e "${GREEN}✓ Admin chat ID registered.${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                if [ -x /www/wwwroot/mhpanel/venv/bin/python ]; then
                    /www/wwwroot/mhpanel/venv/bin/python -c "
import sys; sys.path.insert(0, '/www/wwwroot/mhpanel')
from app import load_telegram_config, save_telegram_config
c = load_telegram_config()
c['enabled'] = not c.get('enabled', False)
save_telegram_config(c)
print('Notifications now:', 'Enabled' if c['enabled'] else 'Disabled')
" 2>/dev/null || true
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                echo -e "\n${CYAN}Configure Resource Thresholds (Percentages 1-100):${NC}"
                read -p "CPU Alert Threshold % (Default: 90): " new_cpu
                read -p "RAM Alert Threshold % (Default: 90): " new_ram
                read -p "Disk Alert Threshold % (Default: 90): " new_disk
                new_cpu=${new_cpu:-90}
                new_ram=${new_ram:-90}
                new_disk=${new_disk:-90}
                if [ -x /www/wwwroot/mhpanel/venv/bin/python ]; then
                    /www/wwwroot/mhpanel/venv/bin/python -c "
import sys; sys.path.insert(0, '/www/wwwroot/mhpanel')
from app import load_telegram_config, save_telegram_config
c = load_telegram_config()
c['alert_cpu_percent'] = int('${new_cpu}')
c['alert_ram_percent'] = int('${new_ram}')
c['alert_disk_percent'] = int('${new_disk}')
save_telegram_config(c)
" 2>/dev/null || true
                fi
                echo -e "${GREEN}✓ Thresholds updated: CPU: ${new_cpu}%, RAM: ${new_ram}%, Disk: ${new_disk}%.${NC}"
                read -p "Press Enter to continue..."
                ;;
            5)
                echo -e "\n${CYAN}Automated Backup Schedule to Telegram:${NC}"
                echo "1) Disabled  2) Every 12 Hours  3) Daily (24h)  4) Weekly (7 Days)"
                read -p "Select schedule [1-4] (Default: 3): " s_choice
                s_choice=${s_choice:-3}
                local s_val="daily"
                local s_en="True"
                case "$s_choice" in
                    1) s_en="False" ;;
                    2) s_val="every_12h" ;;
                    3) s_val="daily" ;;
                    4) s_val="weekly" ;;
                esac
                if [ -x /www/wwwroot/mhpanel/venv/bin/python ]; then
                    /www/wwwroot/mhpanel/venv/bin/python -c "
import sys; sys.path.insert(0, '/www/wwwroot/mhpanel')
from app import load_telegram_config, save_telegram_config
c = load_telegram_config()
c['auto_backup'] = ${s_en}
c['auto_backup_schedule'] = '${s_val}'
save_telegram_config(c)
" 2>/dev/null || true
                fi
                echo -e "${GREEN}✓ Automated backup settings updated.${NC}"
                read -p "Press Enter to continue..."
                ;;
            6)
                echo -e "\n${CYAN}Sending Live Test Notification Message to Telegram...${NC}"
                if [ -x /www/wwwroot/mhpanel/venv/bin/python ]; then
                    /www/wwwroot/mhpanel/venv/bin/python -c "
import sys; sys.path.insert(0, '/www/wwwroot/mhpanel')
import psutil, time
from app import load_telegram_config, send_telegram_msg, get_server_public_ip
cfg = load_telegram_config()
srv_ip = get_server_public_ip()
cpu = psutil.cpu_percent(0.2)
ram = psutil.virtual_memory().percent
disk = psutil.disk_usage('/').percent
msg = f'''🤖 <b>MHPanel Telegram Notification Bot</b>\n\n✅ <b>ارتباط ربات تلگرام با سرور با موفقیت برقرار شد!</b>\n🌐 آی‌پی سرور: <code>{srv_ip}</code>\n⏰ زمان سرور: <code>{time.strftime('%Y-%m-%d %H:%M:%S')}</code>\n📊 مصرف منابع: CPU: {cpu}% | RAM: {ram}% | Disk: {disk}%\n🛡️ هسته سینگ‌باکس و پروتکل‌های امنیتی: فعال و آماده سرویس‌دهی\n\n<i>ارسال شده از طریق دستورات ترمینال MHPanel CLI</i>'''
ok, res = send_telegram_msg(msg, cfg)
if ok:
    print('SUCCESS: Notification delivered successfully to your Telegram!')
else:
    print('ERROR:', res)
"
                else
                    echo -e "${RED}Python venv not found.${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            7)
                echo -e "\n${CYAN}Creating and dispatching full panel backup to Telegram...${NC}"
                if [ -x /www/wwwroot/mhpanel/venv/bin/python ]; then
                    /www/wwwroot/mhpanel/venv/bin/python -c "
import sys; sys.path.insert(0, '/www/wwwroot/mhpanel')
import time
from app import load_telegram_config, create_system_backup, send_telegram_doc, get_server_public_ip, save_telegram_config
cfg = load_telegram_config()
if not cfg.get('bot_token') or not cfg.get('chat_id'):
    print('ERROR: Please set bot token and chat ID first.')
    sys.exit(1)
b_res = create_system_backup(backup_type='full', note='ارسال مستقیم از منوی ترمینال')
fp = b_res['filepath']
srv_ip = get_server_public_ip()
caption = f'''📦 <b>پشتیبان خودکار کامل MHPanel (Full Backup)</b>\n\n🌐 سرور: <code>{srv_ip}</code>\n📅 تاریخ: <code>{b_res['created_at']}</code>\n💾 حجم: <code>{b_res['size_formatted']}</code>\n⚡ شامل تمامی کانفیگ‌ها، پروتکل‌ها، کاربران و تنظیمات سیستم.'''
ok, res = send_telegram_doc(fp, caption, cfg)
if ok:
    cfg['last_backup_sent'] = time.strftime('%Y-%m-%d %H:%M:%S')
    save_telegram_config(cfg)
    print('SUCCESS: Backup archive sent directly to your Telegram chat!')
else:
    print('ERROR:', res)
"
                fi
                read -p "Press Enter to continue..."
                ;;
            8)
                systemctl restart mhpanel
                echo -e "${GREEN}✓ MHPanel service restarted to reload telegram monitoring thread.${NC}"
                read -p "Press Enter to continue..."
                ;;
            0|"")
                break
                ;;
        esac
    done
}

# ==============================================================================
# CREDENTIALS & PANEL ADDRESS CONTROLLERS
# ==============================================================================

change_admin_username() {
    local user="admin"
    local pass=""
    if [ -f "${PANEL_DIR}/admin_credentials.txt" ]; then
        user=$(grep -Ei '^username=' "${PANEL_DIR}/admin_credentials.txt" | cut -d= -f2-)
        pass=$(grep -Ei '^password=' "${PANEL_DIR}/admin_credentials.txt" | cut -d= -f2-)
    fi
    local nu="$1"
    if [ -z "$nu" ]; then
        echo -e "\n${YELLOW}${BOLD}=== Change Admin Username ===${NC}"
        echo -e "Current Username: ${CYAN}${user}${NC}"
        read -p "Enter new admin username: " nu
    fi
    nu=$(echo "$nu" | tr -d '[:space:]')
    if [ -z "$nu" ]; then
        echo -e "${RED}Error: Username cannot be empty.${NC}"
        [ -z "$1" ] && read -p "Press Enter to continue..."
        return 1
    fi
    if ! [[ "$nu" =~ ^[a-zA-Z0-9_.-]+$ ]]; then
        echo -e "${RED}Error: Username can only contain letters, numbers, dots, hyphens, and underscores.${NC}"
        [ -z "$1" ] && read -p "Press Enter to continue..."
        return 1
    fi
    echo -e "username=${nu}\npassword=${pass}" > "${PANEL_DIR}/admin_credentials.txt"
    chmod 600 "${PANEL_DIR}/admin_credentials.txt"
    mkdir -p /etc/vpnpanel
    echo -e "username=${nu}\npassword=${pass}" > "/etc/vpnpanel/admin_credentials.txt"
    chmod 600 "/etc/vpnpanel/admin_credentials.txt"
    systemctl restart mhpanel 2>/dev/null || true
    echo -e "\n${GREEN}${BOLD}✓ Admin username updated to: ${CYAN}${nu}${NC}"
    [ -z "$1" ] && read -p "Press Enter to continue..."
}

change_admin_password() {
    local user="admin"
    if [ -f "${PANEL_DIR}/admin_credentials.txt" ]; then
        user=$(grep -Ei '^username=' "${PANEL_DIR}/admin_credentials.txt" | cut -d= -f2-)
    fi
    local np="$1"
    if [ -z "$np" ]; then
        echo -e "\n${YELLOW}${BOLD}=== Change Admin Password ===${NC}"
        echo -e "Admin Username: ${CYAN}${user}${NC}"
        echo -e "Options: Type a new password, or type ${BOLD}'g'${NC} to generate a strong random password."
        read -p "Enter new admin password [or 'g']: " np
    fi
    if [ "$np" = "g" ] || [ "$np" = "G" ]; then
        np=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)
        echo -e "Generated secure password: ${GREEN}${BOLD}${np}${NC}"
    fi
    np=$(echo "$np" | tr -d '[:space:]')
    if [ -z "$np" ]; then
        echo -e "${RED}Error: Password cannot be empty.${NC}"
        [ -z "$1" ] && read -p "Press Enter to continue..."
        return 1
    fi
    if [ ${#np} -lt 4 ]; then
        echo -e "${RED}Error: Password must be at least 4 characters.${NC}"
        [ -z "$1" ] && read -p "Press Enter to continue..."
        return 1
    fi
    echo -e "username=${user}\npassword=${np}" > "${PANEL_DIR}/admin_credentials.txt"
    chmod 600 "${PANEL_DIR}/admin_credentials.txt"
    mkdir -p /etc/vpnpanel
    echo -e "username=${user}\npassword=${np}" > "/etc/vpnpanel/admin_credentials.txt"
    chmod 600 "/etc/vpnpanel/admin_credentials.txt"
    systemctl restart mhpanel 2>/dev/null || true
    echo -e "\n${GREEN}${BOLD}✓ Admin password updated successfully!${NC}"
    echo -e "Username: ${CYAN}${user}${NC}"
    echo -e "Password: ${GREEN}${BOLD}${np}${NC}"
    [ -z "$1" ] && read -p "Press Enter to continue..."
}

change_admin_credentials() {
    local cur_u="admin"
    local cur_p=""
    if [ -f "${PANEL_DIR}/admin_credentials.txt" ]; then
        cur_u=$(grep -Ei '^username=' "${PANEL_DIR}/admin_credentials.txt" | cut -d= -f2-)
        cur_p=$(grep -Ei '^password=' "${PANEL_DIR}/admin_credentials.txt" | cut -d= -f2-)
    fi
    local nu="$1"
    local np="$2"
    if [ -z "$nu" ] || [ -z "$np" ]; then
        echo -e "\n${YELLOW}${BOLD}=== Change Admin Username & Password ===${NC}"
        echo -e "Current Username: ${CYAN}${cur_u}${NC}"
        read -p "Enter new username [Default: ${cur_u}]: " input_u
        nu=${input_u:-$cur_u}
        echo -e "Type a new password, or type ${BOLD}'g'${NC} to generate a strong random password."
        read -p "Enter new password: " input_p
        np="$input_p"
    fi
    if [ "$np" = "g" ] || [ "$np" = "G" ]; then
        np=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)
        echo -e "Generated secure password: ${GREEN}${BOLD}${np}${NC}"
    fi
    nu=$(echo "$nu" | tr -d '[:space:]')
    np=$(echo "$np" | tr -d '[:space:]')
    if [ -z "$nu" ] || [ -z "$np" ]; then
        echo -e "${RED}Error: Username and Password cannot be empty.${NC}"
        [ -z "$1" ] && read -p "Press Enter to continue..."
        return 1
    fi
    echo -e "username=${nu}\npassword=${np}" > "${PANEL_DIR}/admin_credentials.txt"
    chmod 600 "${PANEL_DIR}/admin_credentials.txt"
    mkdir -p /etc/vpnpanel
    echo -e "username=${nu}\npassword=${np}" > "/etc/vpnpanel/admin_credentials.txt"
    chmod 600 "/etc/vpnpanel/admin_credentials.txt"
    systemctl restart mhpanel 2>/dev/null || true
    echo -e "\n${GREEN}${BOLD}✓ Admin credentials updated successfully!${NC}"
    echo -e "  Username: ${CYAN}${BOLD}${nu}${NC}"
    echo -e "  Password: ${GREEN}${BOLD}${np}${NC}"
    [ -z "$1" ] && read -p "Press Enter to continue..."
}

change_panel_port() {
    local cur_port=$(cat "${PANEL_DIR}/panel_port.txt" 2>/dev/null || cat "/etc/vpnpanel/panel_port.txt" 2>/dev/null || echo "9090")
    local nport="$1"
    if [ -z "$nport" ]; then
        echo -e "\n${YELLOW}${BOLD}=== Change Web Panel Port ===${NC}"
        echo -e "Current Web Port: ${CYAN}${cur_port}${NC}"
        read -p "Enter new port (1-65535) [Current: ${cur_port}]: " nport
    fi
    nport=$(echo "$nport" | tr -d '[:space:]')
    if ! [[ "$nport" =~ ^[0-9]+$ ]] || [ "$nport" -lt 1 ] || [ "$nport" -gt 65535 ]; then
        echo -e "${RED}Error: Invalid port number. Must be between 1 and 65535.${NC}"
        [ -z "$1" ] && read -p "Press Enter to continue..."
        return 1
    fi
    echo "$nport" > "${PANEL_DIR}/panel_port.txt"
    mkdir -p /etc/vpnpanel
    echo "$nport" > "/etc/vpnpanel/panel_port.txt"
    if command -v ufw >/dev/null && systemctl is-active --quiet ufw; then
        ufw allow "${nport}/tcp" >/dev/null 2>&1 || true
    fi
    if command -v iptables >/dev/null; then
        iptables -I INPUT -p tcp --dport "$nport" -j ACCEPT 2>/dev/null || true
    fi
    systemctl restart mhpanel 2>/dev/null || true
    local srv_ip=$(get_public_ipv4)
    local custom_path=$(cat /etc/vpnpanel/panel_path.txt 2>/dev/null || cat "${PANEL_DIR}/panel_path.txt" 2>/dev/null || echo "")
    [ -n "$custom_path" ] && [ "${custom_path:0:1}" != "/" ] && custom_path="/${custom_path}"
    echo -e "\n${GREEN}${BOLD}✓ Web Panel port changed to: ${YELLOW}${BOLD}${nport}${NC}"
    echo -e "New Panel URL: ${CYAN}https://${srv_ip}:${nport}${custom_path}/${NC}"
    [ -z "$1" ] && read -p "Press Enter to continue..."
}

change_panel_path() {
    local cur_path=$(cat /etc/vpnpanel/panel_path.txt 2>/dev/null || cat "${PANEL_DIR}/panel_path.txt" 2>/dev/null || echo "")
    [ -n "$cur_path" ] && [ "${cur_path:0:1}" != "/" ] && custom_path="/${cur_path}"
    local npath="$1"
    if [ -z "$npath" ]; then
        echo -e "\n${YELLOW}${BOLD}=== Change Panel Secret Path (Address URL) ===${NC}"
        echo -e "Current Secret Path: ${CYAN}${cur_path:-/(default root)}${NC}"
        echo -e "Enter a secret path (e.g. ${BOLD}/myadmin${NC} or ${BOLD}/secret_portal${NC})."
        echo -e "To reset to default root (/), type ${BOLD}'none'${NC} or leave blank."
        read -p "Enter new path: " npath
    fi
    npath=$(echo "$npath" | tr -d '[:space:]')
    if [ "$npath" = "none" ] || [ "$npath" = "root" ] || [ "$npath" = "/" ] || [ -z "$npath" ]; then
        rm -f /etc/vpnpanel/panel_path.txt "${PANEL_DIR}/panel_path.txt" 2>/dev/null || true
        npath=""
        echo -e "${GREEN}Panel path reset to default root (/).${NC}"
    else
        [ "${npath:0:1}" != "/" ] && npath="/${npath}"
        npath="${npath%/}"
        mkdir -p /etc/vpnpanel
        echo "$npath" > /etc/vpnpanel/panel_path.txt
        echo "$npath" > "${PANEL_DIR}/panel_path.txt"
        echo -e "${GREEN}Panel secret path set to: ${CYAN}${npath}${NC}"
    fi
    systemctl restart mhpanel 2>/dev/null || true
    local srv_ip=$(get_public_ipv4)
    local panel_port=$(cat "${PANEL_DIR}/panel_port.txt" 2>/dev/null || cat "/etc/vpnpanel/panel_port.txt" 2>/dev/null || echo "9090")
    echo -e "\n${GREEN}${BOLD}✓ Web Panel Address updated!${NC}"
    echo -e "New URL: ${CYAN}https://${srv_ip}:${panel_port}${npath}/${NC}"
    [ -z "$1" ] && read -p "Press Enter to continue..."
}

change_panel_address() {
    echo -e "\n${YELLOW}${BOLD}=== Configure Panel Address (Port & Secret Path) ===${NC}"
    local cur_port=$(cat "${PANEL_DIR}/panel_port.txt" 2>/dev/null || cat "/etc/vpnpanel/panel_port.txt" 2>/dev/null || echo "9090")
    local cur_path=$(cat /etc/vpnpanel/panel_path.txt 2>/dev/null || cat "${PANEL_DIR}/panel_path.txt" 2>/dev/null || echo "")
    [ -n "$cur_path" ] && [ "${cur_path:0:1}" != "/" ] && cur_path="/${cur_path}"
    local srv_ip=$(get_public_ipv4)
    echo -e "Current Access URL: ${CYAN}https://${srv_ip}:${cur_port}${cur_path}/${NC}\n"

    local p_in="$1"
    local path_in="$2"
    if [ -z "$p_in" ]; then
        read -p "Enter new port (1-65535) [Current: ${cur_port}]: " p_in
        p_in=${p_in:-$cur_port}
    fi
    if [ -z "$path_in" ]; then
        echo -e "Enter new secret path (e.g. /secure_panel, or press Enter to keep '${cur_path:-/}'):"
        read -p "Path: " path_in
        path_in=${path_in:-$cur_path}
    fi

    # Update port
    p_in=$(echo "$p_in" | tr -d '[:space:]')
    if [[ "$p_in" =~ ^[0-9]+$ ]] && [ "$p_in" -ge 1 ] && [ "$p_in" -le 65535 ]; then
        echo "$p_in" > "${PANEL_DIR}/panel_port.txt"
        mkdir -p /etc/vpnpanel
        echo "$p_in" > "/etc/vpnpanel/panel_port.txt"
        if command -v ufw >/dev/null && systemctl is-active --quiet ufw; then
            ufw allow "${p_in}/tcp" >/dev/null 2>&1 || true
        fi
        if command -v iptables >/dev/null; then
            iptables -I INPUT -p tcp --dport "$p_in" -j ACCEPT 2>/dev/null || true
        fi
    fi

    # Update path
    path_in=$(echo "$path_in" | tr -d '[:space:]')
    if [ "$path_in" = "none" ] || [ "$path_in" = "/" ] || [ -z "$path_in" ]; then
        rm -f /etc/vpnpanel/panel_path.txt "${PANEL_DIR}/panel_path.txt" 2>/dev/null || true
        path_in=""
    else
        [ "${path_in:0:1}" != "/" ] && path_in="/${path_in}"
        path_in="${path_in%/}"
        mkdir -p /etc/vpnpanel
        echo "$path_in" > /etc/vpnpanel/panel_path.txt
        echo "$path_in" > "${PANEL_DIR}/panel_path.txt"
    fi

    systemctl restart mhpanel 2>/dev/null || true
    echo -e "\n${GREEN}${BOLD}✓ Panel Address & Port updated successfully!${NC}"
    echo -e "  Port: ${YELLOW}${BOLD}${p_in}${NC}"
    echo -e "  Path: ${CYAN}${BOLD}${path_in:-/(root)}${NC}"
    echo -e "  New Access URL: ${CYAN}${BOLD}https://${srv_ip}:${p_in}${path_in}/${NC}"
    [ -z "$1" ] && read -p "Press Enter to continue..."
}

menu_web_ui_settings() {
    while true; do
        clear 2>/dev/null || true
        local panel_port=$(cat "${PANEL_DIR}/panel_port.txt" 2>/dev/null || cat "/etc/vpnpanel/panel_port.txt" 2>/dev/null || echo "9090")
        local custom_path=$(cat /etc/vpnpanel/panel_path.txt 2>/dev/null || cat "${PANEL_DIR}/panel_path.txt" 2>/dev/null || echo "")
        [ -n "$custom_path" ] && [ "${custom_path:0:1}" != "/" ] && custom_path="/${custom_path}"
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
        echo -e "  Custom Path:    ${CYAN}${custom_path:-/(root)}${NC}"
        echo -e "  Dashboard URL:  ${CYAN}https://${srv_ip}:${panel_port}${custom_path}/${NC}\n"

        echo -e "  [1] View Panel Access & Login Credentials"
        echo -e "  [2] Change Admin Username"
        echo -e "  [3] Change Admin Password"
        echo -e "  [4] Change Both Username & Password"
        echo -e "  [5] Change Web Dashboard Port"
        echo -e "  [6] Change Panel URL Secret Path (Address)"
        echo -e "  [7] Change Full Panel Address (Port & Path)"
        echo -e "  [8] Restart Web Panel Service (Restart mhpanel)"
        echo -e "  [9] View Live Web Panel Logs"
        echo -e "  [10] Regenerate Public API Key"
        echo -e "  ${RED}${BOLD}[11] Uninstall MH Panel from Server${NC}"
        echo -e "  [0] Back"
        echo ""
        read -p "Select option [0-11]: " ui_act
        case "$ui_act" in
            1) show_panel_access_info ;;
            2) change_admin_username ;;
            3) change_admin_password ;;
            4) change_admin_credentials ;;
            5) change_panel_port ;;
            6) change_panel_path ;;
            7) change_panel_address ;;
            8)
                systemctl restart mhpanel
                echo -e "${GREEN}Web panel service restarted.${NC}"
                read -p "Press Enter to continue..."
                ;;
            9)
                echo -e "${YELLOW}Showing last 50 log lines:${NC}"
                journalctl -u mhpanel -n 50 --no-pager
                read -p "Press Enter to continue..."
                ;;
            10)
                local nkey=$(openssl rand -hex 16)
                echo "$nkey" > "${PANEL_DIR}/api_key.txt"
                chmod 600 "${PANEL_DIR}/api_key.txt"
                systemctl restart mhpanel
                echo -e "${GREEN}New API Key generated: ${CYAN}${nkey}${NC}"
                read -p "Press Enter to continue..."
                ;;
            11)
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
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/scripts/daemons/mhpanel-gas-server" -o "${PANEL_DIR}/scripts/daemons/mhpanel-gas-server" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/templates/dashboard.html" -o "${PANEL_DIR}/templates/dashboard.html" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/templates/subscription.html" -o "${PANEL_DIR}/templates/subscription.html" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/templates/partials/header.html" -o "${PANEL_DIR}/templates/partials/header.html" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/templates/partials/sidebar.html" -o "${PANEL_DIR}/templates/partials/sidebar.html" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/templates/partials/styles.html" -o "${PANEL_DIR}/templates/partials/styles.html" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/templates/partials/tab_system.html" -o "${PANEL_DIR}/templates/partials/tab_system.html" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/templates/partials/tab_terminal.html" -o "${PANEL_DIR}/templates/partials/tab_terminal.html" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/templates/partials/tab_wireguard.html" -o "${PANEL_DIR}/templates/partials/tab_wireguard.html" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/templates/partials/tab_amneziawg.html" -o "${PANEL_DIR}/templates/partials/tab_amneziawg.html" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/templates/partials/tab_singbox.html" -o "${PANEL_DIR}/templates/partials/tab_singbox.html" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/templates/partials/tab_multiplexer.html" -o "${PANEL_DIR}/templates/partials/tab_multiplexer.html" 2>/dev/null || true
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/templates/partials/tab_google_script.html" -o "${PANEL_DIR}/templates/partials/tab_google_script.html" 2>/dev/null || true
        mkdir -p "${PANEL_DIR}/templates/gas"
        curl -fsSL "https://raw.githubusercontent.com/t-51/MHPanel/main/templates/gas/CodeFull.gs" -o "${PANEL_DIR}/templates/gas/CodeFull.gs" 2>/dev/null || true
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

    echo -e "${YELLOW}>>> [4/4] Reloading systemd and restarting MH Panel Web UI & Services...${NC}"
    systemctl daemon-reload
    systemctl restart mhpanel 2>/dev/null || true
    systemctl restart mhpanel-gas-tunnel 2>/dev/null || true

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

    local confirm_un="no"
    local rm_protos="n"
    local purge_conf="n"

    if [ "$1" = "--force" ] || [ "$1" = "-f" ] || [ "$2" = "--force" ] || [ "$2" = "-f" ]; then
        confirm_un="yes"
        rm_protos="y"
        purge_conf="y"
    else
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
    fi

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
        systemctl stop mhpanel-* badvpn sstpd ocserv xl2tpd pptpd strongswan strongswan-starter ipsec openvpn openvpn@* wg-quick@* awg-quick@* 2>/dev/null || true
        systemctl disable mhpanel-* badvpn sstpd ocserv xl2tpd pptpd strongswan strongswan-starter openvpn wg-quick@* awg-quick@* 2>/dev/null || true
        rm -f /etc/systemd/system/mhpanel-*.service /etc/systemd/system/badvpn.service /etc/systemd/system/sstpd.service /etc/systemd/system/awg-quick@*.service
        systemctl daemon-reload
    else
        echo -e "${GREEN}>>> [2/5] Keeping VPN protocols intact as requested.${NC}"
    fi

    echo -e "${YELLOW}>>> [3/5] Removing CLI shortcuts...${NC}"
    rm -f /usr/local/bin/mhpanel /usr/local/bin/hmpanel /usr/local/bin/kigapanel /usr/bin/mhpanel /usr/bin/hmpanel 2>/dev/null || true

    if [[ "$purge_conf" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}>>> [4/5] Purging configuration directories and logs...${NC}"
        rm -rf /etc/vpnpanel /etc/mhpanel /var/log/mhpanel* /root/mhpanel_backups /etc/sing-box /etc/amnezia /etc/accel-ppp.conf /etc/ppp/options.sstpd /etc/pptpd.conf /etc/xl2tpd /etc/ocserv /etc/tor/torrc 2>/dev/null || true
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

show_cli_commands_guide() {
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
    echo -e "${WHITE}${BOLD}   راهنمای جامع دستورات ترمینال و میانبرهای خط فرمان MH Panel${NC}"
    echo -e "${DIM}   Quick Terminal Commands & CLI Shortcuts Reference Manual${NC}"
    echo -e "${BLUE}========================================================================${NC}\n"

    echo -e "${GREEN}${BOLD}1. دستورات منو و دسترسی سریع (Quick Navigation):${NC}"
    echo -e "  ${CYAN}mhpanel${NC}                    باز کردن منوی تعاملی و مدیریت کامل پنل"
    echo -e "  ${CYAN}mhpanel --help${NC} (یا ${CYAN}help${NC})   نمایش همین راهنمای کامل دستورات"
    echo -e "  ${CYAN}mhpanel --status${NC}           مشاهده گزارش وضعیت زنده تمام سرویس‌ها، پورت‌ها و تانل‌ها"
    echo -e "  ${CYAN}mhpanel --info${NC}             نمایش آدرس وب پنل، پورت و مشخصات ورود مدیر"
    echo -e "  ${CYAN}mhpanel --tg${NC}               ورود مستقیم به مدیریت ربات تلگرام و اعلان‌ها"
    echo -e "  ${CYAN}mhpanel --wp${NC}               ورود مستقیم به هماهنگی با آپاچی/انجین‌یکس و استتار وردپرس"
    echo -e "  ${CYAN}mhpanel --tunnels${NC}          ورود مستقیم به مرکز ابزارها و تانل‌های اسکریپتی"
    echo ""

    echo -e "${YELLOW}${BOLD}2. دستورات مدیریت امنیت و مشخصات دسترسی (Security & Credentials):${NC}"
    echo -e "  ${CYAN}mhpanel --user <نام_جدید>${NC}       تغییر مستقیم نام کاربری مدیر"
    echo -e "  ${CYAN}mhpanel --pass <رمز_جدید>${NC}       تغییر مستقیم رمز عبور مدیر"
    echo -e "  ${CYAN}mhpanel --port <شماره_پورت>${NC}     تغییر پورت پنل مدیریت وب (پیش‌فرض: 9090)"
    echo -e "  ${CYAN}mhpanel --path <مسیر_امن>${NC}      تغییر مسیر امن دسترسی پنل (مثلاً secret_panel)"
    echo -e "  ${CYAN}mhpanel --address <ip> <port>${NC}  تغییر آدرس IP و پورت اتصال پنل"
    echo ""

    echo -e "${MAGENTA}${BOLD}3. دستورات خط فرمان مدیریت مستقیم پروتکل‌ها (Protocol Control):${NC}"
    echo -e "  ${CYAN}mhpanel protocol status <نام>${NC}         مشاهده وضعیت پروتکل (active / inactive)"
    echo -e "  ${CYAN}mhpanel protocol install <نام> [پورت]${NC}  نصب و راه‌اندازی مستقیم پروتکل"
    echo -e "  ${CYAN}mhpanel protocol uninstall <نام>${NC}       حذف و توقف کامل پروتکل"
    echo -e "  ${CYAN}mhpanel protocol set-port <نام> <پورت>${NC} تغییر پورت شنود پروتکل"
    echo -e "  ${CYAN}mhpanel protocol logs <نام>${NC}           مشاهده لاگ‌های زنده با journalctl"
    echo -e "  ${DIM}نام‌های معتبر: singbox, google_script, amneziawg, ssh, openvpn, ocserv, hysteria2, trojan, etc.${NC}"
    echo ""

    echo -e "${WHITE}${BOLD}4. دستورات مدیریت سرویس و بروزرسانی (Service Control & Maintenance):${NC}"
    echo -e "  ${CYAN}mhpanel restart${NC}            راه‌اندازی مجدد سرویس پنل"
    echo -e "  ${CYAN}mhpanel update${NC}             بروزرسانی مستقیم پنل از گیت‌هاب"
    echo -e "  ${CYAN}mhpanel start / stop${NC}       روشن یا خاموش کردن سرویس پنل"
    echo -e "  ${CYAN}mhpanel --auto${NC}             نصب خودکار تمام پیش‌نیازها و پروتکل‌های بدون کانفلیکت"
    echo -e "  ${CYAN}mhpanel --step${NC}             نصب گام‌به‌گام و سفارشی با انتخاب کاربر"
    echo -e "  ${CYAN}mhpanel --ui${NC}               نصب فوق سبک فقط وب پنل (مناسب سرور کلاینت/ایران)"
    echo -e "  ${CYAN}mhpanel --uninstall${NC}        حذف کامل پنل، سرویس‌ها و پاکسازی سرور"
    echo ""
    echo -e "${BLUE}========================================================================${NC}"
}

# ==============================================================================
# MAIN MENU CONTROLLER
# ==============================================================================

main_menu() {
    while true; do
        show_banner
        local srv_ip=$(get_public_ipv4)
        local panel_port=$(cat "${PANEL_DIR}/panel_port.txt" 2>/dev/null || cat "/etc/vpnpanel/panel_port.txt" 2>/dev/null || echo "9090")
        local custom_path=$(cat /etc/vpnpanel/panel_path.txt 2>/dev/null || cat "${PANEL_DIR}/panel_path.txt" 2>/dev/null || echo "")
        [ -n "$custom_path" ] && [ "${custom_path:0:1}" != "/" ] && custom_path="/${custom_path}"
        local is_online="${RED}Stopped${NC}"
        if systemctl is-active --quiet mhpanel 2>/dev/null; then
            is_online="${GREEN}Online (${srv_ip}:${panel_port}${custom_path}/)${NC}"
        fi

        echo -e "  Web Panel Status: ${is_online} | Quick Terminal Command: ${CYAN}mhpanel${NC}"
        echo -e "${BLUE}------------------------------------------------------------------------${NC}"
        echo -e "  ${WHITE}${BOLD}[1]  Run Full Automated Installation (Setup All Missing Components)${NC}"
        echo -e "  ${WHITE}${BOLD}[2]  Run Step-by-Step Custom Installation Wizard${NC}"
        echo -e "  ${WHITE}${BOLD}[3]  Install Lightweight Web UI Only${NC}"
        echo -e "${DIM}  ----------------------------------------------------------------------${NC}"
        echo -e "  ${GREEN}${BOLD}[4]  View Panel Access URL & Login Info${NC}"
        echo -e "  ${YELLOW}${BOLD}[5]  Change Admin Username & Password (تغییر نام کاربری و رمز عبور)${NC}"
        echo -e "  ${YELLOW}${BOLD}[6]  Change Panel Address, Port & Path (تغییر پورت و آدرس پنل)${NC}"
        echo -e "  [7]  Live System & Service Diagnostic Report"
        echo -e "  [8]  Manage, Install, Uninstall & Reconfigure VPN Protocols"
        echo -e "  [9]  Anti-Censorship Tunnels & MikroTik RouterOS Bridge Hub (مدیریت تانل‌ها)"
        echo -e "  ${CYAN}[10] Web Server Integration & WordPress Camouflage (هماهنگی آپاچی/انجین‌یکس و استتار وردپرس)${NC}"
        echo -e "  ${YELLOW}[11] Telegram Bot Notifications & Auto-Backup Hub (مدیریت ربات تلگرام و اعلان‌ها)${NC}"
        echo -e "  [12] Web Dashboard Settings (Logs, Restart, 2FA & API Key)"
        echo -e "  [13] SSL Certificate Management (Let's Encrypt & IP SAN)"
        echo -e "  [14] Network & Kernel Optimization (BBR, IPv4/IPv6 Forwarding)"
        echo -e "  [15] Backup & Restore Panel Configurations"
        echo -e "  ${GREEN}${BOLD}[16] Quick Terminal Commands Guide & Shortcuts (راهنمای جامع دستورات ترمینال و میانبرها)${NC}"
        echo -e "  [17] Update Script & Panel"
        echo -e "  ${RED}${BOLD}[18] Uninstall MH Panel from Server${NC}"
        echo -e "  [0]  Exit"
        echo -e "${BLUE}========================================================================${NC}"
        read -p "Please select an option [0-18]: " opt

        case "$opt" in
            1) wizard_full_automated ;;
            2) wizard_step_by_step ;;
            3) wizard_web_ui_only ;;
            4) show_panel_access_info ;;
            5) change_admin_credentials ;;
            6) change_panel_address ;;
            7) menu_diagnostic_status ;;
            8) menu_vpn_protocols ;;
            9) menu_tunnel_tools ;;
            10) menu_wordpress_camouflage ;;
            11) menu_telegram_bot ;;
            12) menu_web_ui_settings ;;
            13) menu_ssl_management ;;
            14) enable_bbr_and_sysctl; read -p "Press Enter to continue..." ;;
            15) backup_restore ;;
            16) show_cli_commands_guide; read -p "Press Enter to continue..." ;;
            17) update_panel_repo ;;
            18) uninstall_mhpanel ;;
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
elif [ "$1" = "--help" ] || [ "$1" = "-h" ] || [ "$1" = "help" ] || [ "$1" = "--commands" ] || [ "$1" = "commands" ] || [ "$1" = "دستورات" ]; then
    show_cli_commands_guide
    exit 0
elif [ "$1" = "protocol" ] || [ "$1" = "--protocol" ] || [ "$1" = "-p" ]; then
    shift
    if [ -x "$HELPER" ]; then
        exec "$HELPER" "$@"
    else
        exec "${PANEL_DIR}/scripts/protocol_helper.sh" "$@"
    fi
elif [ "$1" = "--user" ] || [ "$1" = "user" ] || [ "$1" = "--username" ]; then
    change_admin_username "$2"
elif [ "$1" = "--pass" ] || [ "$1" = "pass" ] || [ "$1" = "--password" ]; then
    change_admin_password "$2"
elif [ "$1" = "--credentials" ] || [ "$1" = "credentials" ]; then
    change_admin_credentials "$2" "$3"
elif [ "$1" = "--port" ] || [ "$1" = "port" ]; then
    change_panel_port "$2"
elif [ "$1" = "--path" ] || [ "$1" = "path" ]; then
    change_panel_path "$2"
elif [ "$1" = "--address" ] || [ "$1" = "address" ]; then
    change_panel_address "$2" "$3"
elif [ "$1" = "--wp" ] || [ "$1" = "wordpress" ] || [ "$1" = "--wordpress" ]; then
    menu_wordpress_camouflage
elif [ "$1" = "--tg" ] || [ "$1" = "telegram" ] || [ "$1" = "--telegram" ]; then
    menu_telegram_bot
elif [ "$1" = "--tunnels" ] || [ "$1" = "tunnels" ]; then
    menu_tunnel_tools
elif [ "$1" = "--uninstall" ] || [ "$1" = "uninstall" ] || [ "$1" = "-u" ]; then
    uninstall_mhpanel "$2" "$3"
elif [ "$1" = "restart" ] || [ "$1" = "--restart" ]; then
    systemctl restart mhpanel
    echo -e "${GREEN}MH Panel service restarted successfully.${NC}"
elif [ "$1" = "start" ] || [ "$1" = "--start" ]; then
    systemctl start mhpanel
    echo -e "${GREEN}MH Panel service started.${NC}"
elif [ "$1" = "stop" ] || [ "$1" = "--stop" ]; then
    systemctl stop mhpanel
    echo -e "${YELLOW}MH Panel service stopped.${NC}"
elif [ "$1" = "update" ] || [ "$1" = "--update" ]; then
    update_panel_repo
else
    if [ ! -f "${PANEL_DIR}/app.py" ] && [ ! -f "/etc/systemd/system/mhpanel.service" ]; then
        show_banner
        echo -e "${YELLOW}Welcome to MH Panel Installer! Panel is not installed yet on this server.${NC}\n"
        echo -e "  [1] Full Automated Setup (Recommended)"
        echo -e "  [2] Step-by-Step Custom Wizard"
        echo -e "  [3] Lightweight Web UI Only"
        echo -e "  [4] View Panel Access & Login Info"
        echo -e "  [5] Change Panel Admin Credentials (Username & Password)"
        echo -e "  [6] Change Panel Address & Port"
        echo -e "  ${RED}[7] Uninstall Panel & Purge Leftovers${NC}"
        echo -e "  [0] Exit"
        echo ""
        read -p "Select installation mode [0-7] (Default: 1): " init_choice
        init_choice=${init_choice:-1}
        case "$init_choice" in
            1) wizard_full_automated ;;
            2) wizard_step_by_step ;;
            3) wizard_web_ui_only ;;
            4) show_panel_access_info ;;
            5) change_admin_credentials ;;
            6) change_panel_address ;;
            7) uninstall_mhpanel ;;
            *) exit 0 ;;
        esac
    else
        main_menu
    fi
fi
