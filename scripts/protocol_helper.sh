#!/usr/bin/env bash
# MH Panel Protocol Helper Script
# Must be executed as root.

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1

ACTION=$1
PROTOCOL=$2
ARG3=$3 # Port for install/set-port
ARG4=$4 # Optional MTProto advertising tag

# Config directories
CA_DIR="/etc/vpn-ca"
WEB_CERT_DIR="/etc/vpnpanel/ssl"
SERVER_CERT="${CA_DIR}/vpn-server.crt"
SERVER_KEY="${CA_DIR}/vpn-server.key"
CA_CERT="${CA_DIR}/ca.crt"
PANEL_CERT="${WEB_CERT_DIR}/panel.crt"
PANEL_KEY="${WEB_CERT_DIR}/panel.key"

PANEL_DIR="/www/wwwroot/mhpanel"
if [ ! -d "$PANEL_DIR" ]; then
    PANEL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
PANEL_VENV="${PANEL_DIR}/venv"
PANEL_PYTHON="${PANEL_VENV}/bin/python"
if [ ! -x "$PANEL_PYTHON" ]; then
    PANEL_PYTHON="python3"
fi

get_setting() {
    local key=$1
    local default=$2
    if [ -f "/etc/vpnpanel/protocol_settings.json" ]; then
        ${PANEL_PYTHON} -c "import json; d=json.load(open('/etc/vpnpanel/protocol_settings.json')); print(d.get('$key', '$default'))" 2>/dev/null || echo "$default"
    else
        echo "$default"
    fi
}

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

get_server_ip() {
    get_public_ipv4 "$@"
}

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

# Helper: UFW Port Management
allow_port() {
    local port=$1
    local proto=$2
    if command -v ufw >/dev/null; then
        ufw allow "${port}/${proto}" || true
    else
        iptables -I INPUT -p "${proto}" -m "${proto}" --dport "${port}" -j ACCEPT || true
        if [ -d /etc/iptables ]; then iptables-save > /etc/iptables/rules.v4; fi
    fi
}

deny_port() {
    local port=$1
    local proto=$2
    if command -v ufw >/dev/null; then
        ufw delete allow "${port}/${proto}" || true
    else
        iptables -D INPUT -p "${proto}" -m "${proto}" --dport "${port}" -j ACCEPT || true
        if [ -d /etc/iptables ]; then iptables-save > /etc/iptables/rules.v4; fi
    fi
}

ensure_binary() {
    local bin_name="$1"
    local fallback_url="${2:-}"
    local alt_url="${3:-}"

    # Verify if binary exists and is a valid ELF executable (not an HTML error page or tar.gz)
    if [ -x "/usr/local/bin/${bin_name}" ]; then
        if file -b "/usr/local/bin/${bin_name}" 2>/dev/null | grep -qiE "ELF|script|text"; then
            return 0
        fi
        rm -f "/usr/local/bin/${bin_name}"
    fi

    # Check panel repo bin/ and daemons directories
    for dir in "${PANEL_DIR}/bin" "${PANEL_DIR}/scripts/daemons" "${SCRIPT_DIR}/../bin" "${SCRIPT_DIR}/daemons" "/root/mhpanel-repo/bin" "/root/mhpanel-repo/scripts/daemons" "/www/wwwroot/mhpanel/bin" "/www/wwwroot/mhpanel/scripts/daemons"; do
        if [ -f "${dir}/${bin_name}" ]; then
            cp -f "${dir}/${bin_name}" "/usr/local/bin/${bin_name}" 2>/dev/null || true
            chmod +x "/usr/local/bin/${bin_name}" 2>/dev/null || true
            if file -b "/usr/local/bin/${bin_name}" 2>/dev/null | grep -qiE "ELF|script|text"; then
                return 0
            fi
        fi
    done

    # Attempt download from fallback_url
    if [ -n "${fallback_url}" ]; then
        echo "Binary ${bin_name} not found locally. Downloading from: ${fallback_url} ..."
        if curl -fsSL --connect-timeout 10 --max-time 60 "${fallback_url}" -o "/usr/local/bin/${bin_name}" 2>/dev/null; then
            chmod +x "/usr/local/bin/${bin_name}" 2>/dev/null || true
            if file -b "/usr/local/bin/${bin_name}" 2>/dev/null | grep -qiE "ELF|script|text"; then
                return 0
            fi
            rm -f "/usr/local/bin/${bin_name}"
        fi
    fi

    # Attempt download from alt_url if provided
    if [ -n "${alt_url}" ]; then
        echo "Retrying download of ${bin_name} from: ${alt_url} ..."
        if [[ "${alt_url}" =~ \.tar\.gz$ ]]; then
            local tmp_d="/tmp/bin_extract_$$"
            mkdir -p "${tmp_d}"
            if curl -fsSL --connect-timeout 10 --max-time 60 "${alt_url}" 2>/dev/null | tar -xz -C "${tmp_d}" 2>/dev/null; then
                local found_bin="$(find "${tmp_d}" -type f -name "${bin_name}" | head -n1)"
                if [ -n "${found_bin}" ] && [ -f "${found_bin}" ]; then
                    mv -f "${found_bin}" "/usr/local/bin/${bin_name}"
                    chmod +x "/usr/local/bin/${bin_name}" 2>/dev/null || true
                    rm -rf "${tmp_d}"
                    return 0
                fi
            fi
            rm -rf "${tmp_d}"
        elif [[ "${alt_url}" =~ \.tar\.xz$ ]]; then
            local tmp_d="/tmp/bin_extract_$$"
            mkdir -p "${tmp_d}"
            if curl -fsSL --connect-timeout 10 --max-time 60 "${alt_url}" 2>/dev/null | tar -xJ -C "${tmp_d}" 2>/dev/null; then
                local found_bin="$(find "${tmp_d}" -type f -name "${bin_name}" | head -n1)"
                if [ -n "${found_bin}" ] && [ -f "${found_bin}" ]; then
                    mv -f "${found_bin}" "/usr/local/bin/${bin_name}"
                    chmod +x "/usr/local/bin/${bin_name}" 2>/dev/null || true
                    rm -rf "${tmp_d}"
                    return 0
                fi
            fi
            rm -rf "${tmp_d}"
        elif [[ "${alt_url}" =~ \.zip$ ]]; then
            local tmp_z="/tmp/bin_extract_$$.zip"
            local tmp_d="/tmp/bin_extract_$$"
            mkdir -p "${tmp_d}"
            if curl -fsSL --connect-timeout 10 --max-time 60 "${alt_url}" -o "${tmp_z}" 2>/dev/null; then
                unzip -q -o "${tmp_z}" -d "${tmp_d}" 2>/dev/null || true
                local found_bin="$(find "${tmp_d}" -type f -name "${bin_name}" | head -n1)"
                if [ -n "${found_bin}" ] && [ -f "${found_bin}" ]; then
                    mv -f "${found_bin}" "/usr/local/bin/${bin_name}"
                    chmod +x "/usr/local/bin/${bin_name}" 2>/dev/null || true
                    rm -rf "${tmp_d}" "${tmp_z}"
                    return 0
                fi
            fi
            rm -rf "${tmp_d}" "${tmp_z}"
        else
            if curl -fsSL --connect-timeout 10 --max-time 60 "${alt_url}" -o "/usr/local/bin/${bin_name}" 2>/dev/null; then
                chmod +x "/usr/local/bin/${bin_name}" 2>/dev/null || true
                if file -b "/usr/local/bin/${bin_name}" 2>/dev/null | grep -qiE "ELF|script|text"; then
                    return 0
                fi
                rm -f "/usr/local/bin/${bin_name}"
            fi
        fi
    fi

    echo "ERROR: Network connectivity failed. Unable to obtain ${bin_name}. Please check internet/GitHub access." >&2
    return 1
}

# Helper: Find public interface for NAT
get_public_interface() {
    ip route show default | awk '/default/ {print $5}' | head -n1
}

generate_certs() {
    mkdir -p "${CA_DIR}" "${WEB_CERT_DIR}"
    chmod 700 "${CA_DIR}" "${WEB_CERT_DIR}"

    # Generate a private VPN CA for OpenVPN client profiles and default VPN certs.
    if [ ! -f "${CA_DIR}/ca.key" ] || [ ! -f "${CA_CERT}" ]; then
        openssl genrsa -out "${CA_DIR}/ca.key" 2048
        openssl req -x509 -new -nodes -key "${CA_DIR}/ca.key" -subj "/CN=MHPanel Root CA" -days 3650 -out "${CA_CERT}"
        chmod 600 "${CA_DIR}/ca.key"
        chmod 644 "${CA_CERT}"
    fi

    if [ ! -f "${SERVER_KEY}" ] || [ ! -f "${SERVER_CERT}" ]; then
        openssl genrsa -out "${SERVER_KEY}" 2048
        openssl req -new -key "${SERVER_KEY}" -subj "/CN=vpn-server" -out "${CA_DIR}/vpn-server.csr"
        openssl x509 -req -in "${CA_DIR}/vpn-server.csr" -CA "${CA_CERT}" -CAkey "${CA_DIR}/ca.key" -CAcreateserial -out "${SERVER_CERT}" -days 3650
        chmod 600 "${SERVER_KEY}"
        chmod 644 "${SERVER_CERT}"
    fi

    # Keep legacy paths available for old configs without making them canonical.
    ln -sf "${SERVER_CERT}" /root/vpn-server.crt
    ln -sf "${SERVER_KEY}" /root/vpn-server.key

    if [ ! -f "${PANEL_CERT}" ] || [ ! -f "${PANEL_KEY}" ]; then
        openssl req -x509 -newkey rsa:2048 -nodes -keyout "${PANEL_KEY}" -out "${PANEL_CERT}" -subj "/CN=MHPanel Panel" -days 3650
        chmod 600 "${PANEL_KEY}"
        chmod 644 "${PANEL_CERT}"
    fi
}

# Helper: Setup Firewall & NAT Routing globally
setup_global_nat() {
    # 1. Enable IP Forwarding
    touch /etc/sysctl.conf
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
    sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf 2>/dev/null || true
    grep -qxF 'net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    grep -qxF 'net.ipv6.conf.all.forwarding=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf
    mkdir -p /etc/sysctl.d
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-ipforward.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-ipforward.conf
    
    # 2. Add masquerade rules for our VPN subnets (10.8.0.0/12 covers 10.8.x.x through 10.13.x.x)
    local ext_if=$(get_public_interface)
    if [ -n "${ext_if}" ]; then
        # Add to iptables if not exists
        if ! iptables -t nat -C POSTROUTING -s 10.8.0.0/12 -o "${ext_if}" -j MASQUERADE 2>/dev/null; then
            iptables -t nat -A POSTROUTING -s 10.8.0.0/12 -o "${ext_if}" -j MASQUERADE
        fi
        
        # Save iptables rules so they persist
        if command -v iptables-save >/dev/null; then
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4
        fi
    fi
}

is_protocol_installed() {
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
        dnstt) [ -f "/etc/systemd/system/mhpanel-dnstt.service" ] && [ -x /usr/local/bin/dnstt-server ] ;;
        vaydns) [ -f "/etc/systemd/system/mhpanel-vaydns.service" ] && [ -x /usr/local/bin/vaydns-server ] ;;
        slipstream) [ -f "/etc/systemd/system/mhpanel-slipstream.service" ] && [ -x /usr/local/bin/slipstream-server ] ;;
        mtproto) ls /etc/vpnpanel/mtproto_config_*.py >/dev/null 2>&1 ;;
        pptp) [ -f "/etc/pptpd.conf" ] && (command -v pptpd >/dev/null 2>&1 || [ -x /usr/sbin/pptpd ]) ;;
        badvpn) [ -x /usr/local/bin/badvpn-udpgw ] || [ -x /usr/bin/badvpn-udpgw ] || [ -f "/etc/systemd/system/badvpn.service" ] || [ -f "/etc/systemd/system/videocall.service" ] ;;
        l2tpv3) [ -f "/etc/vpnpanel/l2tpv3_config.json" ] ;;
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

# ----------------- SSH PROTOCOL -----------------
install_ssh() {
    local port=${1:-2222}

    # ──────────────────────────────────────────────────────────────────────
    # SAFETY CHECK: Make sure we NEVER touch system SSH on port 22.
    # The VPN SSH daemon runs as a completely separate process.
    # ──────────────────────────────────────────────────────────────────────
    if [ "${port}" = "22" ]; then
        echo "ERROR: Port 22 is reserved for system SSH. Use a different port (default: 2222)." >&2
        exit 1
    fi

    run_apt update && run_apt install openssh-server libpam-radius-auth

    # Copy sshd binary — PAM uses the binary name to pick the right PAM file.
    # /usr/sbin/sshd-vpn  →  /etc/pam.d/sshd-vpn
    cp -f /usr/sbin/sshd /usr/sbin/sshd-vpn
    chmod 755 /usr/sbin/sshd-vpn

    local max_sessions=$(get_setting "ssh_max_sessions" "100")
    local grace_time=$(get_setting "ssh_grace_time" "30")
    local max_auth_tries=$(get_setting "ssh_max_auth_tries" "5")
    local keepalive=$(get_setting "ssh_keepalive" "60")
    local gateway_ports=$(get_setting "ssh_gateway_ports" "clientspecified")
    local compression=$(get_setting "ssh_compression" "yes")
    local permit_root=$(get_setting "ssh_permit_root" "yes")

    # ── SSH VPN-dedicated configuration (COMPLETELY SEPARATE from /etc/ssh/sshd_config) ──
    cat > /etc/ssh/sshd_config_vpn <<EOF
# ============================================================
# MHPanel — Dedicated SSH Tunnel Daemon
# Port: ${port}   System SSH remains on: 22
# ============================================================
Port ${port}
Protocol 2
ListenAddress 0.0.0.0

# Host keys (shared read-only — does NOT affect system sshd)
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# ── Authentication ──
UsePAM yes
PasswordAuthentication yes
PubkeyAuthentication yes
ChallengeResponseAuthentication yes
KerberosAuthentication no
GSSAPIAuthentication no

# ── Security Hardening ──
PermitRootLogin ${permit_root}
MaxAuthTries ${max_auth_tries}
MaxSessions ${max_sessions}
LoginGraceTime ${grace_time}
StrictModes yes

# ── Tunnel & Forwarding ──
AllowTcpForwarding yes
GatewayPorts ${gateway_ports}
X11Forwarding no
PermitTunnel yes
AllowAgentForwarding yes
StreamLocalBindUnlink yes

# ── Performance ──
ClientAliveInterval ${keepalive}
ClientAliveCountMax 3
TCPKeepAlive yes
Compression ${compression}

# ── Logging ──
SyslogFacility AUTH
LogLevel INFO

# ── SFTP Subsystem ──
Subsystem sftp /usr/lib/openssh/sftp-server

# ── Banner ──
Banner /etc/ssh/mhpanel_banner
EOF
    chmod 600 /etc/ssh/sshd_config_vpn

    # ── Login Banner ──
    cat > /etc/ssh/mhpanel_banner <<'BANNER'
╔═══════════════════════════════════════════════╗
║          MHPanel — SSH Tunnel Server        ║
║     Unauthorized access is strictly banned    ║
╚═══════════════════════════════════════════════╝
BANNER

    # ── PAM config (isolated — standard unix auth by default) ──
    cat > /etc/pam.d/sshd-vpn <<'EOF'
# PAM for MHPanel SSH Tunnel
@include common-auth
@include common-account
@include common-session
@include common-password
EOF

    # ── systemd service ──
    cat > /etc/systemd/system/mhpanel-ssh.service <<EOF
[Unit]
Description=MHPanel SSH Tunnel Daemon (Port ${port})
Documentation=https://github.com/mhpanel
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStartPre=/bin/mkdir -p /run/sshd
ExecStartPre=/usr/sbin/sshd-vpn -t -f /etc/ssh/sshd_config_vpn
ExecStart=/usr/sbin/sshd-vpn -D -f /etc/ssh/sshd_config_vpn
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl enable mhpanel-ssh
    systemctl restart mhpanel-ssh

    echo "✓ MHPanel SSH installed on port ${port}"
    echo "✓ System SSH on port 22 is UNCHANGED"
}

uninstall_ssh() {
    systemctl stop mhpanel-ssh || true
    systemctl disable mhpanel-ssh || true
    
    port=$(grep -Ei '^Port ' /etc/ssh/sshd_config_vpn | awk '{print $2}' 2>/dev/null || echo "2222")
    [ -n "${port}" ] && deny_port "${port}" "tcp"
    
    rm -f /etc/ssh/sshd_config_vpn /etc/pam.d/sshd-vpn /etc/systemd/system/mhpanel-ssh.service /usr/sbin/sshd-vpn
    systemctl daemon-reload
}

set_port_ssh() {
    local port=$1
    local old_port=$(grep -Ei '^Port ' /etc/ssh/sshd_config_vpn | awk '{print $2}' 2>/dev/null || echo "2222")
    if [ -n "${old_port}" ] && [ "${old_port}" != "${port}" ]; then
        deny_port "${old_port}" "tcp"
    fi
    sed -i "s/^Port .*/Port ${port}/g" /etc/ssh/sshd_config_vpn
    allow_port "${port}" "tcp"
    systemctl restart mhpanel-ssh
}

# ----------------- OPENVPN PROTOCOL -----------------
install_openvpn() {
    local port=${1:-1194}
    local proto=$(get_setting "openvpn_proto" "udp")
    local cipher=$(get_setting "openvpn_cipher" "AES-256-GCM")
    local subnet=$(get_setting "openvpn_subnet" "10.8.0.0")
    local dns1=$(get_setting "openvpn_dns1" "8.8.8.8")
    local dns2=$(get_setting "openvpn_dns2" "8.8.4.4")

    run_apt update && run_apt install openvpn libpam-radius-auth
    generate_certs

    if [ ! -f /etc/openvpn/tls-crypt.key ]; then
        openvpn --genkey --secret /etc/openvpn/tls-crypt.key
        chmod 600 /etc/openvpn/tls-crypt.key
    fi
    
    local pam_plugin=""
    for p in /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so \
             /usr/lib/aarch64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so \
             /usr/lib64/openvpn/plugins/openvpn-plugin-auth-pam.so \
             /usr/lib/openvpn/plugins/openvpn-plugin-auth-pam.so; do
        if [ -f "$p" ]; then pam_plugin="$p"; break; fi
    done
    [ -z "$pam_plugin" ] && pam_plugin="openvpn-plugin-auth-pam.so"

    # Write Server Configuration
    cat > /etc/openvpn/server.conf <<EOF
port ${port}
proto ${proto}
dev tun
ca ${CA_CERT}
cert ${SERVER_CERT}
key ${SERVER_KEY}
dh none
tls-crypt /etc/openvpn/tls-crypt.key
server ${subnet} 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS ${dns1}"
push "dhcp-option DNS ${dns2}"
keepalive 10 120
cipher ${cipher}
ncp-ciphers ${cipher}:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn-status.log
verb 3
explicit-exit-notify 1
plugin ${pam_plugin} openvpn
username-as-common-name
verify-client-cert none
EOF

    if [ -f /etc/pam_radius_auth.conf ]; then
        sed -i -E 's/\s+vrf=[^\s]+//g' /etc/pam_radius_auth.conf 2>/dev/null || true
    fi

    cat > /etc/pam.d/openvpn <<EOF
auth [success=done default=ignore] pam_radius_auth.so
auth [success=done default=die] pam_unix.so try_first_pass
account [success=done default=ignore] pam_radius_auth.so
account [success=done default=die] pam_unix.so
session sufficient pam_permit.so
session required pam_unix.so
EOF

    allow_port "${port}" "${proto}"
    systemctl enable openvpn@server
    systemctl restart openvpn@server
}

uninstall_openvpn() {
    systemctl stop openvpn@server || true
    systemctl disable openvpn@server || true
    port=$(grep -Ei '^port ' /etc/openvpn/server.conf 2>/dev/null | awk '{print $2}' || echo "1194")
    proto=$(grep -Ei '^proto ' /etc/openvpn/server.conf 2>/dev/null | awk '{print $2}' || echo "udp")
    deny_port "${port}" "${proto}"
    rm -f /etc/openvpn/server.conf /etc/openvpn/tls-crypt.key /etc/pam.d/openvpn
}

set_port_openvpn() {
    local port=$1
    local old_port=$(grep -Ei '^port ' /etc/openvpn/server.conf 2>/dev/null | awk '{print $2}' || echo "1194")
    proto=$(grep -Ei '^proto ' /etc/openvpn/server.conf 2>/dev/null | awk '{print $2}' || echo "udp")
    if [ -n "${old_port}" ] && [ "${old_port}" != "${port}" ]; then
        deny_port "${old_port}" "${proto}"
    fi
    sed -i "s/^port .*/port ${port}/g" /etc/openvpn/server.conf
    allow_port "${port}" "${proto}"
    systemctl restart openvpn@server
}

# ----------------- OCSERV PROTOCOL -----------------
install_ocserv() {
    local port=${1:-10443}
    if [ -z "$port" ] || [ "$port" = "0" ] || [ "$port" = "443" ]; then
        port=10443
    fi
    local subnet=$(get_setting "ocserv_subnet" "10.9.0.0")
    local dns1=$(get_setting "ocserv_dns1" "8.8.8.8")
    local dns2=$(get_setting "ocserv_dns2" "8.8.4.4")

    run_apt update && run_apt install ocserv libradcli4
    generate_certs

    # Ensure ocserv system user and directory exist
    getent group ocserv >/dev/null || groupadd -r ocserv
    getent passwd ocserv >/dev/null || useradd -r -g ocserv -d /var/lib/ocserv -s /usr/sbin/nologin ocserv
    mkdir -p /var/lib/ocserv/run /var/lib/ocserv
    chown -R ocserv:ocserv /var/lib/ocserv
    
    # Write Default Configuration
    cat > /etc/ocserv/ocserv.conf <<EOF
run-as-user = ocserv
run-as-group = ocserv
socket-file = /run/ocserv.socket
chroot-dir = /var/lib/ocserv
tcp-port = ${port}
udp-port = ${port}
server-cert = ${SERVER_CERT}
server-key = ${SERVER_KEY}
ca-cert = ${CA_CERT}
max-clients = 128
max-same-clients = 4
keepalive = 32400
dpd = 240
mobile-dpd = 1800
tunnel-all-dns = true
dns = ${dns1}
dns = ${dns2}
device = vpns
ipv4-network = ${subnet}
ipv4-netmask = 255.255.255.0
route = default
auth = "pam[gid-min=1000]"
EOF

    allow_port "${port}" "tcp"
    allow_port "${port}" "udp"
    systemctl enable ocserv
    systemctl restart ocserv
}

uninstall_ocserv() {
    systemctl stop ocserv || true
    systemctl disable ocserv || true
    port=$(grep -Ei '^tcp-port ' /etc/ocserv/ocserv.conf | awk '{print $3}' 2>/dev/null || echo "443")
    deny_port "${port}" "tcp"
    deny_port "${port}" "udp"
    rm -f /etc/ocserv/ocserv.conf
}

set_port_ocserv() {
    local port=$1
    local old_port=$(grep -Ei '^tcp-port ' /etc/ocserv/ocserv.conf | awk '{print $3}' 2>/dev/null || echo "443")
    if [ -n "${old_port}" ] && [ "${old_port}" != "${port}" ]; then
        deny_port "${old_port}" "tcp"
        deny_port "${old_port}" "udp"
    fi
    sed -i "s/^tcp-port = .*/tcp-port = ${port}/g" /etc/ocserv/ocserv.conf
    sed -i "s/^udp-port = .*/udp-port = ${port}/g" /etc/ocserv/ocserv.conf
    allow_port "${port}" "tcp"
    allow_port "${port}" "udp"
    systemctl restart ocserv
}

# ----------------- IKEv2 PROTOCOL -----------------
install_ikev2() {
    local subnet=$(get_setting "ikev2_subnet" "10.10.0.0")
    local dns1=$(get_setting "ikev2_dns1" "8.8.8.8")
    local dns2=$(get_setting "ikev2_dns2" "8.8.4.4")

    export DEBIAN_FRONTEND=noninteractive
    run_apt update >/dev/null 2>&1 || true
    run_apt install strongswan strongswan-pki libcharon-extra-plugins libstrongswan-extra-plugins strongswan-swanctl >/dev/null 2>&1 || true
    generate_certs
    
    local server_ip=$(get_server_ip)

    # Copy Certs for strongSwan ipsec.d (classical starter) and swanctl (VICI)
    mkdir -p /etc/ipsec.d/cacerts /etc/ipsec.d/certs /etc/ipsec.d/private /etc/swanctl/x509ca /etc/swanctl/x509 /etc/swanctl/private /etc/swanctl/conf.d
    cp -f "${CA_CERT}" /etc/ipsec.d/cacerts/ca-cert.pem
    cp -f "${SERVER_CERT}" /etc/ipsec.d/certs/server-cert.pem
    cp -f "${SERVER_KEY}" /etc/ipsec.d/private/server-key.pem
    if [ -f "${CA_KEY}" ]; then cp -f "${CA_KEY}" /etc/ipsec.d/private/ca-key.pem; fi
    chmod 644 /etc/ipsec.d/cacerts/ca-cert.pem /etc/ipsec.d/certs/server-cert.pem
    chmod 600 /etc/ipsec.d/private/server-key.pem

    cp -f "${CA_CERT}" /etc/swanctl/x509ca/ca.crt
    cp -f "${SERVER_CERT}" /etc/swanctl/x509/vpn-server.crt
    cp -f "${SERVER_KEY}" /etc/swanctl/private/vpn-server.key
    chmod 644 /etc/swanctl/x509ca/ca.crt /etc/swanctl/x509/vpn-server.crt
    chmod 600 /etc/swanctl/private/vpn-server.key
    
    # Preserve existing L2TP-PSK in /etc/ipsec.conf if present
    local existing_l2tp=""
    if [ -f /etc/ipsec.conf ] && grep -q "conn L2TP-PSK" /etc/ipsec.conf 2>/dev/null; then
        existing_l2tp=$(sed -n '/conn L2TP-PSK/,$p' /etc/ipsec.conf)
    else
        existing_l2tp="conn L2TP-PSK
    auto=add
    keyexchange=ikev1
    type=transport
    authby=secret
    left=%any
    leftid=%any
    leftprotoport=17/1701
    right=%any
    rightid=%any
    rightprotoport=17/%any
    rekey=no
    dpdaction=clear
    dpddelay=30s
    ike=aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha256-modp2048,aes128-sha1-modp2048,aes256-sha256-modp1024,aes256-sha1-modp1024,3des-sha1-modp1024!
    esp=aes256-sha256,aes256-sha1,aes128-sha256,aes128-sha1,3des-sha1!"
    fi

    cat > /etc/ipsec.conf <<EOF
config setup
    charondebug="ike 2, knl 1, cfg 1, enc 1"
    uniqueids=no

conn %default
    ikelifetime=60m
    keylife=20m
    rekeymargin=3m
    keyingtries=1

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=${server_ip}
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    leftauth=pubkey
    right=%any
    rightid=%any
    rightauth=eap-radius
    rightsourceip=10.10.10.10-10.10.10.250
    rightdns=${dns1},${dns2}
    rightsendcert=never
    eap_identity=%identity
    ike=aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha256-modp2048,aes128-sha1-modp2048,aes256-sha256-modp1024,aes256-sha1-modp1024,aes128-sha256-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024,aes256-sha256-ecp256,aes128-sha256-ecp256!
    esp=aes256-sha256,aes256-sha1,aes128-sha256,aes128-sha1,3des-sha1,aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048,aes256gcm128,aes256gcm16!

${existing_l2tp}
EOF

    # Configure /etc/ipsec.secrets for strongSwan
    if [ ! -f /etc/ipsec.secrets ] || ! grep -q "RSA server-key.pem" /etc/ipsec.secrets 2>/dev/null; then
        echo ": RSA server-key.pem" >> /etc/ipsec.secrets
    fi
    if ! grep -q "PSK " /etc/ipsec.secrets 2>/dev/null; then
        echo ': PSK "123456789"' >> /etc/ipsec.secrets
        echo '%any %any : PSK "123456789"' >> /etc/ipsec.secrets
    fi
    chmod 600 /etc/ipsec.secrets

    # Configure FreeRADIUS EAP plugin for charon
    mkdir -p /etc/strongswan.d/charon
    cat > /etc/strongswan.d/charon/eap-radius.conf <<EOF
eap-radius {
    load = yes
    servers {
        primary {
            address = 127.0.0.1
            secret = testing123
            auth_port = 1812
            acct_port = 1813
        }
    }
}
EOF

    # Create IKEv2 Config for swanctl (VICI)
    cat > /etc/swanctl/conf.d/ikev2.conf <<EOF
connections {
    ikev2-vpn {
        version = 2
        send_cert = always
        encap = yes
        pools = ikev2-pool
        local {
            auth = pubkey
            certs = vpn-server.crt
            id = @vpn-server
        }
        remote-local {
            auth = eap-radius
        }
        children {
            net {
                local_ts = 0.0.0.0/0
                updown = /etc/swanctl/ikev2-logging.sh
            }
        }
    }
}
pools {
    ikev2-pool {
        addrs = ${subnet}/24
        dns = ${dns1}, ${dns2}
    }
}
EOF

    # Create IKEv2 Logging Script
    cat > /etc/swanctl/ikev2-logging.sh <<'EOF'
#!/usr/bin/env bash
LOG_FILE="/var/log/mhpanel-connections.log"
touch $LOG_FILE && chmod 666 $LOG_FILE
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

if [ "$PLUTO_VERB" = "up-client" ]; then
    echo "[$TIMESTAMP] CONNECT    | PROTO: IKEv2 | USER: ${PLUTO_PEER_ID} | CLIENT_IP: ${PLUTO_PEER} | VPN_IP: ${PLUTO_PEER_CLIENT%%/*}" >> $LOG_FILE
elif [ "$PLUTO_VERB" = "down-client" ]; then
    echo "[$TIMESTAMP] DISCONNECT | PROTO: IKEv2 | USER: ${PLUTO_PEER_ID} | CLIENT_IP: ${PLUTO_PEER} | VPN_IP: ${PLUTO_PEER_CLIENT%%/*}" >> $LOG_FILE
fi
exit 0
EOF
    chmod +x /etc/swanctl/ikev2-logging.sh

    # Open standard IPsec/IKEv2 ports
    allow_port "500" "udp"
    allow_port "4500" "udp"
    
    # Determine the actual strongswan service
    local svc_name="strongswan-starter"
    for s in strongswan-starter strongswan-swanctl strongswan; do
        if [ -f "/usr/lib/systemd/system/${s}.service" ] || [ -f "/lib/systemd/system/${s}.service" ] || [ -f "/etc/systemd/system/${s}.service" ]; then
            svc_name="$s"
            break
        fi
    done

    # Create systemd alias so systemctl restart strongswan works reliably
    if [ "$svc_name" != "strongswan" ] && [ ! -f /etc/systemd/system/strongswan.service ]; then
        local src_unit="/lib/systemd/system/${svc_name}.service"
        [ -f "/usr/lib/systemd/system/${svc_name}.service" ] && src_unit="/usr/lib/systemd/system/${svc_name}.service"
        ln -sf "${src_unit}" /etc/systemd/system/strongswan.service 2>/dev/null || true
    fi

    echo "Enabling and starting strongSwan service: ${svc_name}"
    systemctl daemon-reload
    systemctl enable "${svc_name}" 2>/dev/null || true
    systemctl restart "${svc_name}" 2>/dev/null || true
    systemctl enable strongswan 2>/dev/null || true
    systemctl restart strongswan 2>/dev/null || true
    
    # Wait a few seconds to let charon initialize
    sleep 2
    if command -v ipsec >/dev/null 2>&1; then
        ipsec update 2>/dev/null || true
        ipsec reload 2>/dev/null || true
    fi
    if command -v swanctl >/dev/null 2>&1; then
        swanctl --load-all 2>/dev/null || true
    fi
    echo "IKEv2 successfully installed and activated."
}

uninstall_ikev2() {
    for s in strongswan strongswan-swanctl strongswan-starter; do
        systemctl stop "$s" 2>/dev/null || true
        systemctl disable "$s" 2>/dev/null || true
    done
    deny_port "500" "udp"
    deny_port "4500" "udp"
    rm -f /etc/swanctl/conf.d/ikev2.conf
    if [ -f /etc/ipsec.conf ]; then
        sed -i '/conn ikev2-vpn/,/^conn / { /^conn ikev2-vpn/d; /^conn /!d; }' /etc/ipsec.conf 2>/dev/null || true
    fi
    if command -v ipsec >/dev/null 2>&1; then
        ipsec update 2>/dev/null || true
    fi
    echo "IKEv2 uninstalled."
}

# ----------------- SSTP PROTOCOL -----------------
install_sstp() {
    local port=${1:-4443}
    local subnet=$(get_setting "sstp_subnet" "10.11.0.0")
    local dns1=$(get_setting "sstp_dns1" "8.8.8.8")
    local dns2=$(get_setting "sstp_dns2" "8.8.4.4")
    local auth_proto=$(get_setting "sstp_auth_proto" "MS-CHAPv2")
    local local_ip="${subnet%.*}.1"
    local remote_start="${subnet%.*}.10"
    local remote_end="${subnet%.*}.254"

    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y ppp curl git libpam-radius-auth iproute2 python3-pip >/dev/null 2>&1 || true
    generate_certs

    # Ensure dedicated SSTP Root CA and Server certificate with SAN & serverAuth exist
    mkdir -p /etc/sstp-ca
    if [ ! -f "/etc/sstp-ca/ca.crt" ] || [ ! -f "/etc/sstp-ca/ca.key" ]; then
        openssl req -x509 -newkey rsa:4096 -days 3650 -nodes -keyout /etc/sstp-ca/ca.key -out /etc/sstp-ca/ca.crt -subj "/CN=MH Panel SSTP Root CA" >/dev/null 2>&1 || true
        cp -f /etc/sstp-ca/ca.crt /etc/sstp-ca/ca.pem 2>/dev/null || true
        chmod 600 /etc/sstp-ca/ca.key 2>/dev/null || true
        chmod 644 /etc/sstp-ca/ca.crt /etc/sstp-ca/ca.pem 2>/dev/null || true
    fi

    if [ ! -f "/etc/sstp-ca/sstp-server.crt" ] || [ ! -f "/etc/sstp-ca/sstp-server.key" ]; then
        local srv_host="$(get_public_ipv4 2>/dev/null || echo 'sstp.example.com')"
        srv_host=${srv_host:-sstp.example.com}
        local cnf_path="/etc/sstp-ca/sstp_cert.cnf"
        cat > "${cnf_path}" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${srv_host}

[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${srv_host}
DNS.2 = *.${srv_host}
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF
        openssl genrsa -out /etc/sstp-ca/sstp-server.key 2048 >/dev/null 2>&1 || true
        chmod 600 /etc/sstp-ca/sstp-server.key 2>/dev/null || true
        openssl req -new -key /etc/sstp-ca/sstp-server.key -out /etc/sstp-ca/sstp_server.csr -config "${cnf_path}" >/dev/null 2>&1 || true
        openssl x509 -req -in /etc/sstp-ca/sstp_server.csr -CA /etc/sstp-ca/ca.crt -CAkey /etc/sstp-ca/ca.key -CAcreateserial -out /etc/sstp-ca/sstp-server.crt -days 3650 -extfile "${cnf_path}" -extensions v3_req >/dev/null 2>&1 || true
        chmod 644 /etc/sstp-ca/sstp-server.crt 2>/dev/null || true
        rm -f "${cnf_path}" /etc/sstp-ca/sstp_server.csr
    fi

    mkdir -p /etc/accel-ppp /var/log/accel-ppp /etc/ppp/ip-up.d /etc/ppp/ip-down.d

    cat > /etc/ppp/options.sstpd <<EOF
name sstpd
debug
ipcp-accept-local
ipcp-accept-remote
idle 1800
mtu 1400
mru 1400
proxyarp
nodeflate
nobsdcomp
lcp-echo-failure 4
lcp-echo-interval 30
ms-dns ${dns1}
ms-dns ${dns2}
nodefaultroute
require-mppe-128
mppe-stateful
require-mschap-v2
refuse-mschap
refuse-chap
refuse-pap
refuse-eap
plugin radius.so
radius-config-file /etc/radcli/radiusclient.conf
EOF

    # If sstpd Python binary is available or can be installed via pip, use it directly (super fast, robust)
    if [ ! -x /usr/local/bin/sstpd ]; then
        pip3 install sstp-server --break-system-packages >/dev/null 2>&1 || pip install sstp-server >/dev/null 2>&1 || true
    fi

    local sstp_cert_path="/etc/sstp-ca/sstp-server.crt"
    local sstp_key_path="/etc/sstp-ca/sstp-server.key"
    if [ ! -f "${sstp_cert_path}" ] || [ ! -f "${sstp_key_path}" ]; then
        sstp_cert_path="${SERVER_CERT}"
        sstp_key_path="${SERVER_KEY}"
    fi

    if [ -x /usr/local/bin/sstpd ]; then
        cat > /etc/systemd/system/sstpd.service <<EOF
[Unit]
Description=SSTP Server Daemon (sstpd)
After=network.target freeradius.service
Wants=freeradius.service

[Service]
Type=simple
ExecStart=/usr/local/bin/sstpd -l 0.0.0.0 -p ${port} -c ${sstp_cert_path} -k ${sstp_key_path} --local ${local_ip} --remote ${subnet%.*}.0/24 --range ${remote_start}-${remote_end} --pppd-config /etc/ppp/options.sstpd --ciphers "ECDHE-RSA-AES256-GCM-SHA384:AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:AES256-SHA384:!aNULL:!MD5:!RC4"
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
        allow_port "${port}" "tcp"
        systemctl daemon-reload
        systemctl enable sstpd >/dev/null 2>&1
        systemctl restart sstpd
        echo "SSTP (sstpd) installed on TCP port ${port}."
        return 0
    fi

    # Fallback to accel-ppp if sstpd could not be installed
    if ! command -v accel-pppd >/dev/null 2>&1 && [ ! -x /usr/sbin/accel-pppd ]; then
        if ! run_apt install accel-ppp; then
            echo "accel-ppp package not found in repositories. Compiling from source..."
            run_apt install build-essential cmake gcc git libpcre2-dev libssl-dev liblua5.1-0-dev linux-headers-$(uname -r) >/dev/null 2>&1 || true
            rm -rf /usr/src/accel-ppp
            git clone --depth 1 https://github.com/accel-ppp/accel-ppp.git /usr/src/accel-ppp >/dev/null 2>&1 || true
            mkdir -p /usr/src/accel-ppp/build
            cd /usr/src/accel-ppp/build 2>/dev/null || true
            cmake -DBUILD_IPOE_DRIVER=FALSE -DBUILD_VLAN_MON_DRIVER=FALSE -DCMAKE_INSTALL_PREFIX=/usr -DLUA=TRUE .. >/dev/null 2>&1 || true
            make -j$(nproc) >/dev/null 2>&1 || true
            make install >/dev/null 2>&1 || true
            cd - >/dev/null 2>&1 || true
            rm -rf /usr/src/accel-ppp
        fi
    fi

    local auth_line="mschap-v2"
    local auth_module="auth_mschap_v2"
    case "${auth_proto}" in
        PAP|pap) auth_line="pap"; auth_module="auth_pap" ;;
        CHAP|chap) auth_line="chap"; auth_module="auth_chap_md5" ;;
        *) auth_line="mschap-v2"; auth_module="auth_mschap_v2" ;;
    esac

    cat > /etc/ppp/options.sstpd <<EOF
name sstpd
require-mschap-v2
refuse-pap
refuse-chap
refuse-eap
ms-dns ${dns1}
ms-dns ${dns2}
mppe-stateful
auth
mtu 1400
mru 1400
nodefaultroute
proxyarp
EOF

    if [ "${auth_line}" = "pap" ]; then
        sed -i 's/^require-mschap-v2/# require-mschap-v2/' /etc/ppp/options.sstpd
        sed -i 's/^refuse-pap/# refuse-pap/' /etc/ppp/options.sstpd
    elif [ "${auth_line}" = "chap" ]; then
        sed -i 's/^require-mschap-v2/# require-mschap-v2/' /etc/ppp/options.sstpd
        sed -i 's/^refuse-chap/# refuse-chap/' /etc/ppp/options.sstpd
    fi

    cat > /etc/accel-ppp.conf <<EOF
[modules]
log_file
sstp
ppp
ippool
chap-secrets
${auth_module}

[core]
log-error=/var/log/accel-ppp/core.log
thread-count=4

[common]
single-session=replace

[ppp]
verbose=1
min-mtu=1280
mtu=1400
mru=1400
ipv4=require
ipv6=deny
ip-up=/etc/ppp/ip-up.d/mhpanel-sstp
ip-down=/etc/ppp/ip-down.d/mhpanel-sstp

[sstp]
bind=0.0.0.0
port=${port}
cert=${sstp_cert_path}
key=${sstp_key_path}
ssl=1

[dns]
dns1=${dns1}
dns2=${dns2}

[ip-pool]
gw-ip-address=${local_ip}
${remote_start}-${remote_end}

[chap-secrets]
chap-secrets=/etc/ppp/chap-secrets

[log]
log-file=/var/log/accel-ppp/accel-ppp.log
log-emerg=/var/log/accel-ppp/emerg.log
log-debug=/var/log/accel-ppp/debug.log
copy=1
level=3
EOF

    if [ ! -f /etc/ppp/chap-secrets ]; then
        echo '"admin" * "AdminPassword123" *' > /etc/ppp/chap-secrets
        chmod 600 /etc/ppp/chap-secrets
    fi

    cat > /etc/ppp/ip-up.d/mhpanel-sstp <<'EOF'
#!/usr/bin/env bash
EXT_IF=$(ip route show default | awk '/default/ {print $5}' | head -n1)
if [ -n "$EXT_IF" ]; then
    iptables -t nat -C POSTROUTING -s 10.11.0.0/16 -o "$EXT_IF" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s 10.11.0.0/16 -o "$EXT_IF" -j MASQUERADE
fi
EOF
    cat > /etc/ppp/ip-down.d/mhpanel-sstp <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x /etc/ppp/ip-up.d/mhpanel-sstp /etc/ppp/ip-down.d/mhpanel-sstp

    local accel_bin="/usr/sbin/accel-pppd"
    if [ ! -x "${accel_bin}" ] && [ -x "/usr/local/sbin/accel-pppd" ]; then
        accel_bin="/usr/local/sbin/accel-pppd"
    fi

    cat > /etc/systemd/system/sstpd.service <<EOF
[Unit]
Description=MHPanel SSTP Server (accel-ppp)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=${accel_bin} -c /etc/accel-ppp.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3
TimeoutStopSec=5s
KillMode=control-group

[Install]
WantedBy=multi-user.target
EOF

    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl enable sstpd
    systemctl restart sstpd
}

uninstall_sstp() {
    killall -9 accel-pppd sstpd 2>/dev/null || true
    systemctl stop sstpd || true
    systemctl disable sstpd || true
    port=$(grep -E '^port=' /etc/accel-ppp.conf 2>/dev/null | head -n1 | cut -d= -f2 || echo "4443")
    deny_port "${port}" "tcp"
    rm -f /etc/systemd/system/sstpd.service /etc/accel-ppp.conf /etc/ppp/options.sstpd
    systemctl daemon-reload
}

set_port_sstp() {
    local port=$1
    local old_port=$(grep -E '^port=' /etc/accel-ppp.conf 2>/dev/null | head -n1 | cut -d= -f2 || true)
    if [ -z "${old_port}" ]; then
        old_port=$(grep -oE '\-p [0-9]+' /etc/systemd/system/sstpd.service 2>/dev/null | awk '{print $2}' || true)
        old_port=${old_port:-4443}
    fi
    if [ -n "${old_port}" ] && [ "${old_port}" != "${port}" ]; then
        deny_port "${old_port}" "tcp"
    fi
    if [ -f /etc/accel-ppp.conf ]; then
        sed -i "s/^port=.*/port=${port}/" /etc/accel-ppp.conf
    else
        sed -i "s/\-p [0-9]*/-p ${port}/g" /etc/systemd/system/sstpd.service
    fi
    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl restart sstpd
}

# ----------------- PPTP PROTOCOL -----------------
install_pptp() {
    local port=${1:-1723}
    local subnet=$(get_setting "pptp_subnet" "10.14.0.0")
    local dns1=$(get_setting "pptp_dns1" "8.8.8.8")
    local dns2=$(get_setting "pptp_dns2" "8.8.4.4")
    local localip="${subnet%.*}.1"
    local remotestart="${subnet%.*}.10"
    local remoteend="${subnet%.*}.254"

    run_apt update >/dev/null 2>&1 || true
    run_apt install pptpd ppp libpam-radius-auth >/dev/null 2>&1 || true

    if [ -f /etc/pam_radius_auth.conf ]; then
        sed -i -E 's/\s+vrf=[^\s]+//g' /etc/pam_radius_auth.conf 2>/dev/null || true
    fi

    if ! command -v pptpd >/dev/null 2>&1 && [ ! -x /usr/sbin/pptpd ]; then
        echo "    [!] PPTP daemon (pptpd) is not supported or not available in this OS release (Ubuntu 24.04+ dropped pptpd). Skipping PPTP service."
        systemctl stop mhpanel-pptp 2>/dev/null || true
        systemctl disable mhpanel-pptp 2>/dev/null || true
        rm -f /etc/systemd/system/mhpanel-pptp.service /etc/pptpd.conf
        systemctl daemon-reload
        return 0
    fi

    # Configure pptpd
    cat > /etc/pptpd.conf <<EOF
option /etc/ppp/options.pptpd
logwtmp
localip ${localip}
remoteip ${remotestart}-${remoteend##*.}
EOF

    # PPP options for PPTP
    cat > /etc/ppp/options.pptpd <<EOF
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns ${dns1}
ms-dns ${dns2}
proxyarp
nodefaultroute
lock
nobsdcomp
novj
novjccomp
nologfd
plugin radius.so
plugin radattr.so
radius-config-file /etc/radcli/radiusclient.conf
EOF

    # PAM config for pptpd (standard unix auth by default)
    cat > /etc/pam.d/pptpd <<'EOF'
# PAM for MHPanel PPTP
@include common-auth
@include common-account
@include common-session
@include common-password
EOF

    # systemd service
    cat > /etc/systemd/system/pptpd.service <<EOF
[Unit]
Description=PoPToP Point to Point Tunneling Server (PPTP)
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/pptpd --fg -c /etc/pptpd.conf
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    allow_port "${port}" "tcp"
    # GRE protocol for PPTP tunneling
    iptables -A INPUT -p gre -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p gre -j ACCEPT 2>/dev/null || true
    if command -v iptables-save >/dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
    fi
    rm -f /etc/systemd/system/mhpanel-pptp.service
    systemctl daemon-reload
    systemctl enable pptpd
    systemctl restart pptpd

    # Install Global PPP Logging Scripts (covers PPTP, L2TP, SSTP)
    cat > /etc/ppp/ip-up.d/mhpanel-logging <<'EOF'
#!/usr/bin/env bash
LOG_FILE="/var/log/mhpanel-connections.log"
touch $LOG_FILE && chmod 666 $LOG_FILE
USERNAME=${PEERNAME:-"unknown"}
VPN_IP=$5
IFACE=$1
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

PROTO="PPP-VPN"
if pgrep -a pptpd | grep -q "$IFACE" || [ -n "$PPP_REMOTE" ]; then
    PROTO="PPTP"
elif pgrep -a xl2tpd | grep -q "$IFACE"; then
    PROTO="L2TP"
elif pgrep -a accel-pppd | grep -q "$IFACE"; then
    PROTO="SSTP"
fi

CLIENT_IP=${CALLER_ID:-${PPP_REMOTE:-"unknown"}}
echo "[$TIMESTAMP] CONNECT    | PROTO: $PROTO | USER: $USERNAME | CLIENT_IP: $CLIENT_IP | VPN_IP: $VPN_IP | IFACE: $IFACE" >> $LOG_FILE
EOF

    cat > /etc/ppp/ip-down.d/mhpanel-logging <<'EOF'
#!/usr/bin/env bash
LOG_FILE="/var/log/mhpanel-connections.log"
USERNAME=${PEERNAME:-"unknown"}
VPN_IP=$5
IFACE=$1
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

PROTO="PPP-VPN"
if [ -n "$PPP_REMOTE" ]; then
    PROTO="PPTP"
elif pgrep -a xl2tpd | grep -q "$IFACE"; then
    PROTO="L2TP"
fi
CLIENT_IP=${CALLER_ID:-${PPP_REMOTE:-"unknown"}}

echo "[$TIMESTAMP] DISCONNECT | PROTO: $PROTO | USER: $USERNAME | CLIENT_IP: $CLIENT_IP | VPN_IP: $VPN_IP | IFACE: $IFACE | BYTES_TX: $BYTES_SENT | BYTES_RX: $BYTES_RCVD" >> $LOG_FILE
EOF
    chmod +x /etc/ppp/ip-up.d/mhpanel-logging /etc/ppp/ip-down.d/mhpanel-logging

    echo "✓ MHPanel PPTP installed on port ${port}"
}

uninstall_pptp() {
    systemctl stop pptpd mhpanel-pptp || true
    systemctl disable pptpd mhpanel-pptp || true
    local port=$(grep -oE 'Port [0-9]+' /etc/systemd/system/mhpanel-pptp.service /etc/systemd/system/pptpd.service 2>/dev/null | awk '{print $2}' | head -n1 || echo "1723")
    deny_port "${port}" "tcp"
    rm -f /etc/pptpd.conf /etc/ppp/options.pptpd /etc/pam.d/pptpd /etc/systemd/system/mhpanel-pptp.service /etc/systemd/system/pptpd.service
    systemctl daemon-reload
}

set_port_pptp() {
    local port=$1
    local old_port=$(grep -oE 'Port [0-9]+' /etc/systemd/system/mhpanel-pptp.service 2>/dev/null | awk '{print $2}' | head -n1 || echo "1723")
    [ -n "${old_port}" ] && [ "${old_port}" != "${port}" ] && deny_port "${old_port}" "tcp"
    sed -i "s/Port [0-9]*/Port ${port}/g" /etc/systemd/system/mhpanel-pptp.service
    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl restart mhpanel-pptp
}

# ----------------- L2TP PROTOCOL -----------------
install_l2tp() {
    local subnet=$(get_setting "l2tp_subnet" "192.168.42.0")
    local psk=$(get_setting "l2tp_psk" "VpnSecret123")
    local dns1=$(get_setting "l2tp_dns1" "8.8.8.8")
    local dns2=$(get_setting "l2tp_dns2" "1.1.1.1")
    DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        xl2tpd ppp strongswan libpam-radius-auth iproute2 >/dev/null 2>&1 || true
    if ! dpkg -s ufw >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent >/dev/null 2>&1 || true
    fi
    apt-get install -y linux-modules-extra-$(uname -r) >/dev/null 2>&1 || true
    modprobe ppp_mppe || true
    modprobe l2tp_core || true
    modprobe l2tp_netlink || true
    modprobe l2tp_eth || true
    modprobe l2tp_ip || true
    
    # Configure via MH Panel python backend to preserve IKEv2 and sync with FreeRADIUS
    ${PANEL_PYTHON} -c "
import sys; sys.path.insert(0, '/www/wwwroot/mhpanel')
from app import save_l2tp_full_config, get_l2tp_config_data
cfg = get_l2tp_config_data()
cfg['psk'] = '${psk}'
cfg['dns1'] = '${dns1}'
cfg['dns2'] = '${dns2}'
save_l2tp_full_config(cfg)
" 2>/dev/null || true

    # Allow ports
    allow_port "1701" "udp"
    allow_port "500" "udp"
    allow_port "4500" "udp"
    
    systemctl enable xl2tpd
    systemctl restart xl2tpd
    systemctl restart strongswan-starter || true
    setup_global_nat
    echo "✓ L2TP/IPsec installed and linked to FreeRADIUS on ports UDP 1701, 500, 4500"
}

uninstall_l2tp() {
    systemctl stop xl2tpd || true
    systemctl disable xl2tpd || true
    deny_port "1701" "udp"
    deny_port "500" "udp"
    deny_port "4500" "udp"
    if [ -f "/etc/ipsec.conf" ]; then
        sed -i '/conn L2TP-PSK/,/^$/d' /etc/ipsec.conf || true
        systemctl restart strongswan-starter || true
    fi
    rm -f /etc/xl2tpd/xl2tpd.conf /etc/ppp/options.xl2tpd
}

# ----------------- FREERADIUS SERVER -----------------
install_freeradius() {
    local secret=${1:-"testing123"}
    export DEBIAN_FRONTEND=noninteractive

    local rad_conf_dir="/etc/freeradius/3.0"
    local rad_service="freeradius"
    local rad_user="freerad"
    local rad_group="freerad"
    local auth_file="${rad_conf_dir}/mods-config/files/authorize"

    if [ -f /etc/debian_version ] || command -v apt-get >/dev/null 2>&1; then
        rm -f /etc/apt/sources.list.d/tor.list 2>/dev/null || true
        apt-get update -y >/dev/null 2>&1 || true
        apt-get install -y --no-install-recommends freeradius freeradius-utils freeradius-config libpam-radius-auth libradcli4 >/dev/null 2>&1 || \
        apt-get install -y freeradius freeradius-utils libpam-radius-auth >/dev/null 2>&1 || true
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
            cat >> "$clients_conf" <<EOF

client localhost_ipv6 {
	ipv6addr	= ::1
	secret		= ${secret}
}

client vpn_network {
    ipaddr = 0.0.0.0/0
    secret = ${secret}
    require_message_authenticator = no
}
EOF
        fi
        sed -i 's/require_message_authenticator = yes/require_message_authenticator = no/g' "$clients_conf" 2>/dev/null || true
    fi

    cat > /etc/radcli/radiusclient.conf <<EOF
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
    echo "127.0.0.1 ${secret}" > /etc/radcli/servers
    chmod 600 /etc/radcli/servers /etc/radcli/radiusclient.conf 2>/dev/null || true
    [ ! -L "/etc/radiusclient" ] && [ ! -d "/etc/radiusclient" ] && ln -sf /etc/radcli /etc/radiusclient 2>/dev/null || true

    cat > /etc/pam_radius_auth.conf <<EOF
# RADIUS Server configuration generated by MH Panel
127.0.0.1:1812 ${secret} 3
EOF
    chmod 600 /etc/pam_radius_auth.conf 2>/dev/null || true

    if id "$rad_user" >/dev/null 2>&1; then
        chown -R "${rad_user}:${rad_group}" "${rad_conf_dir}" 2>/dev/null || true
    fi
    chmod 640 "$mh_users" 2>/dev/null || true

    allow_port "1812" "udp"
    allow_port "1813" "udp"

    systemctl unmask "$rad_service" 2>/dev/null || true
    systemctl enable "$rad_service" 2>/dev/null || true
    systemctl restart "$rad_service" 2>/dev/null || true

    # Synchronize users from MH Panel database
    if [ -f "/www/wwwroot/mhpanel/app.py" ]; then
        ${PANEL_PYTHON:-python3} -c "
import sys; sys.path.insert(0, '/www/wwwroot/mhpanel')
try:
    from app import sync_freeradius_users
    sync_freeradius_users()
except Exception:
    pass
" 2>/dev/null || true
    fi

    echo "✓ FreeRADIUS installed and configured on UDP 1812/1813"
}

uninstall_freeradius() {
    local rad_service="freeradius"
    systemctl is-active radiusd >/dev/null 2>&1 && rad_service="radiusd"
    systemctl stop "$rad_service" 2>/dev/null || true
    systemctl disable "$rad_service" 2>/dev/null || true
    deny_port "1812" "udp"
    deny_port "1813" "udp"
    echo "✓ FreeRADIUS service stopped and disabled"
}

install_l2tpv3() {
    local local_ip=${1:-""}
    local remote_ip=${2:-""}
    local tunnel_id=${3:-1}
    local session_id=${4:-1}
    local subnet=$(get_setting "l2tpv3_subnet" "10.15.0.0")
    local encap=$(get_setting "l2tpv3_encap" "udp")  # udp or ip
    local port=$(get_setting "l2tpv3_port" "5555")

    if [ -z "${local_ip}" ] || [ -z "${remote_ip}" ]; then
        echo "ERROR: L2TPv3 requires local_ip and remote_ip arguments"
        exit 1
    fi

    # Load kernel module
    modprobe l2tp_eth >/dev/null 2>&1 || true
    modprobe l2tp_netlink >/dev/null 2>&1 || true
    mkdir -p /etc/modules-load.d
    echo "l2tp_eth" >> /etc/modules-load.d/l2tpv3.conf 2>/dev/null || true

    # Create tunnel and session
    ip l2tp add tunnel \
        tunnel_id ${tunnel_id} \
        peer_tunnel_id ${tunnel_id} \
        encap ${encap} \
        local ${local_ip} \
        remote ${remote_ip} \
        udp_sport ${port} \
        udp_dport ${port}

    ip l2tp add session \
        tunnel_id ${tunnel_id} \
        session_id ${session_id} \
        peer_session_id ${session_id}

    # Create L2TPv3 interface
    ip link set l2tpeth0 up
    ip addr add ${subnet%.*}.1/24 dev l2tpeth0 || true

    # Create persistence config
    mkdir -p /etc/vpnpanel
    cat > /etc/vpnpanel/l2tpv3_config.json <<EOF
{
  "local_ip": "${local_ip}",
  "remote_ip": "${remote_ip}",
  "tunnel_id": ${tunnel_id},
  "session_id": ${session_id},
  "encap": "${encap}",
  "port": ${port},
  "subnet": "${subnet}"
}
EOF

    cat > /etc/systemd/system/mhpanel-l2tpv3.service <<EOF
[Unit]
Description=MHPanel L2TPv3 Ethernet Tunnel
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c "\
modprobe l2tp_eth || true; \
ip l2tp add tunnel tunnel_id ${tunnel_id} peer_tunnel_id ${tunnel_id} encap ${encap} local ${local_ip} remote ${remote_ip} udp_sport ${port} udp_dport ${port} || true; \
ip l2tp add session tunnel_id ${tunnel_id} session_id ${session_id} peer_session_id ${session_id} || true; \
ip link set l2tpeth0 up || true; \
ip addr add ${subnet%.*}.1/24 dev l2tpeth0 || true"
ExecStop=/bin/bash -c "\
ip l2tp del session tunnel_id ${tunnel_id} session_id ${session_id} || true; \
ip l2tp del tunnel tunnel_id ${tunnel_id} || true"

[Install]
WantedBy=multi-user.target
EOF

    [ "${encap}" = "udp" ] && allow_port "${port}" "udp"
    systemctl daemon-reload
    systemctl enable mhpanel-l2tpv3
    systemctl start mhpanel-l2tpv3
    echo "✓ L2TPv3 tunnel configured: ${local_ip} <-> ${remote_ip}"
}

uninstall_l2tpv3() {
    systemctl stop mhpanel-l2tpv3 || true
    systemctl disable mhpanel-l2tpv3 || true
    local port=$(python3 -c "import json; d=json.load(open('/etc/vpnpanel/l2tpv3_config.json')); print(d.get('port',5555))" 2>/dev/null || echo 5555)
    local encap=$(python3 -c "import json; d=json.load(open('/etc/vpnpanel/l2tpv3_config.json')); print(d.get('encap','udp'))" 2>/dev/null || echo udp)
    [ "${encap}" = "udp" ] && deny_port "${port}" "udp"
    rm -f /etc/systemd/system/mhpanel-l2tpv3.service /etc/vpnpanel/l2tpv3_config.json /etc/modules-load.d/l2tpv3.conf
    systemctl daemon-reload
}

# ----------------- WIREGUARD PROTOCOL -----------------
install_wireguard() {
    local port=${1:-51820}
    local subnet=$(get_setting "wireguard_subnet" "10.13.0.0")
    
    run_apt update && run_apt install wireguard wireguard-tools qrencode
    
    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard
    
    # Generate keys
    local server_private_key=$(wg genkey)
    local server_public_key=$(echo "${server_private_key}" | wg pubkey)
    
    echo "${server_private_key}" > /etc/wireguard/private.key
    echo "${server_public_key}" > /etc/wireguard/public.key
    
    # Create configuration
    cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = ${server_private_key}
Address = ${subnet%.*}.1/24
ListenPort = ${port}
EOF

    allow_port "${port}" "udp"
    systemctl enable wg-quick@wg0
    systemctl restart wg-quick@wg0
    
    # Enable and start WireGuard RADIUS daemon
    if [ -f "/etc/systemd/system/mhpanel-wg-radius.service" ]; then
        systemctl daemon-reload
        systemctl enable mhpanel-wg-radius || true
        systemctl restart mhpanel-wg-radius || true
    fi
}

uninstall_wireguard() {
    systemctl stop mhpanel-wg-radius || true
    systemctl disable mhpanel-wg-radius || true
    systemctl stop wg-quick@wg0 || true
    systemctl disable wg-quick@wg0 || true
    port=$(grep -Ei '^ListenPort' /etc/wireguard/wg0.conf | awk '{print $3}' 2>/dev/null || echo "51820")
    deny_port "${port}" "udp"
    rm -rf /etc/wireguard/wg0.conf /etc/wireguard/private.key /etc/wireguard/public.key
}

set_port_wireguard() {
    local port=$1
    local old_port=$(grep -Ei '^ListenPort' /etc/wireguard/wg0.conf | awk '{print $3}' 2>/dev/null || echo "904")
    if [ -n "${old_port}" ] && [ "${old_port}" != "${port}" ]; then
        deny_port "${old_port}" "udp"
    fi
    sed -i "s/^ListenPort = .*/ListenPort = ${port}/g" /etc/wireguard/wg0.conf
    allow_port "${port}" "udp"
    systemctl restart wg-quick@wg0
}

# ----------------- AMNEZIAWG PROTOCOL (ANTI-DPI) -----------------
install_amneziawg() {
    local port=${1:-51821}
    if [ -z "$port" ] || [ "$port" = "0" ] || [ "$port" = "443" ]; then
        port=51821
    fi
    local script_path="${PANEL_DIR}/scripts/install_amneziawg.sh"
    [ -f "$script_path" ] || script_path="${SCRIPT_DIR}/install_amneziawg.sh"
    [ -f "$script_path" ] || script_path="/root/mhpanel-repo/scripts/install_amneziawg.sh"
    bash "$script_path" "${port}"
}

uninstall_amneziawg() {
    systemctl stop awg-quick@awg0 || true
    systemctl disable awg-quick@awg0 || true
    local port=$(grep -Ei '^ListenPort' /etc/amnezia/amneziawg/awg0.conf | awk '{print $3}' 2>/dev/null || echo "51820")
    deny_port "${port}" "udp"
    rm -rf /etc/amnezia/amneziawg/awg0.conf /etc/amnezia/amneziawg/private.key /etc/amnezia/amneziawg/public.key
}

set_port_amneziawg() {
    local port=$1
    local conf="/etc/amnezia/amneziawg/awg0.conf"
    if [ ! -f "$conf" ]; then
        return 1
    fi
    local old_port=$(grep -Ei '^ListenPort' "$conf" | awk '{print $3}' 2>/dev/null || echo "51820")
    if [ -n "${old_port}" ] && [ "${old_port}" != "${port}" ]; then
        deny_port "${old_port}" "udp"
        sed -i "s/--dport ${old_port}/--dport ${port}/g" "$conf"
        sed -i -E "s/Endpoint = ([^:]+):${old_port}/Endpoint = \1:${port}/g" /www/wwwroot/mhpanel/awg_users.json 2>/dev/null || true
    fi
    sed -i "s/^ListenPort = .*/ListenPort = ${port}/g" "$conf"
    allow_port "${port}" "udp"
    systemctl restart awg-quick@awg0
}

# ----------------- HTTP / SOCKS / SHADOWSOCKS / MTPROTO PROXIES -----------------
ensure_proxy_python_tools() {
    run_apt update && run_apt install python3 python3-venv python3-pip openssl
    if [ ! -x "${PANEL_PYTHON}" ]; then
        python3 -m venv "${PANEL_VENV}"
    fi
    ${PANEL_PYTHON} -m pip install --upgrade pip --quiet 2>/dev/null || true
    if [ -f "${PANEL_DIR}/requirements.txt" ]; then
        ${PANEL_PYTHON} -m pip install -r "${PANEL_DIR}/requirements.txt" --quiet 2>/dev/null || true
    fi
    ${PANEL_PYTHON} -m pip install pyrad psutil cryptography requests flask --quiet 2>/dev/null || true
}

install_http() {
    local port=${1:-8080}
    ensure_proxy_python_tools
    cat > /etc/systemd/system/mhpanel-http-proxy.service <<EOF
[Unit]
Description=KIGA-SM HTTP Proxy
After=network-online.target

[Service]
Type=simple
ExecStart=${PANEL_PYTHON} ${PANEL_DIR}/scripts/radius_proxy.py --listen http://0.0.0.0:${port}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl enable mhpanel-http-proxy
    systemctl restart mhpanel-http-proxy
}

uninstall_http() {
    systemctl stop mhpanel-http-proxy || true
    systemctl disable mhpanel-http-proxy || true
    local port=$(grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/mhpanel-http-proxy.service 2>/dev/null | awk -F: '{print $2}' | tail -n1 || echo "8080")
    deny_port "${port}" "tcp"
    rm -f /etc/systemd/system/mhpanel-http-proxy.service
    systemctl daemon-reload
}

set_port_http() {
    local port=$1
    local old_port=$(grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/mhpanel-http-proxy.service 2>/dev/null | awk -F: '{print $2}' | tail -n1 || echo "8080")
    [ -n "${old_port}" ] && [ "${old_port}" != "${port}" ] && deny_port "${old_port}" "tcp"
    sed -i "s#http://0.0.0.0:[0-9]*#http://0.0.0.0:${port}#g" /etc/systemd/system/mhpanel-http-proxy.service
    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl restart mhpanel-http-proxy
}

install_socks() {
    local port=${1:-1080}
    ensure_proxy_python_tools
    cat > /etc/systemd/system/mhpanel-socks-proxy.service <<EOF
[Unit]
Description=KIGA-SM SOCKS5 Proxy
After=network-online.target

[Service]
Type=simple
ExecStart=${PANEL_PYTHON} ${PANEL_DIR}/scripts/radius_proxy.py --listen socks5://0.0.0.0:${port}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl enable mhpanel-socks-proxy
    systemctl restart mhpanel-socks-proxy
}

uninstall_socks() {
    systemctl stop mhpanel-socks-proxy || true
    systemctl disable mhpanel-socks-proxy || true
    local port=$(grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/mhpanel-socks-proxy.service 2>/dev/null | awk -F: '{print $2}' | tail -n1 || echo "1080")
    deny_port "${port}" "tcp"
    rm -f /etc/systemd/system/mhpanel-socks-proxy.service
    systemctl daemon-reload
}

set_port_socks() {
    local port=$1
    local old_port=$(grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/mhpanel-socks-proxy.service 2>/dev/null | awk -F: '{print $2}' | tail -n1 || echo "1080")
    [ -n "${old_port}" ] && [ "${old_port}" != "${port}" ] && deny_port "${old_port}" "tcp"
    sed -i "s#socks5://0.0.0.0:[0-9]*#socks5://0.0.0.0:${port}#g" /etc/systemd/system/mhpanel-socks-proxy.service
    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl restart mhpanel-socks-proxy
}

install_shadowsocks() {
    local port=${1:-8388}
    mkdir -p /etc/vpnpanel
    local config="/etc/vpnpanel/shadowsocks.json"
    if [ ! -f "${config}" ]; then
        local key=$(openssl rand -base64 16)
        cat > "${config}" <<EOF
{
  "server": "0.0.0.0",
  "server_port": ${port},
  "password": "${key}",
  "method": "2022-blake3-aes-128-gcm",
  "timeout": 300,
  "fast_open": true,
  "mode": "tcp_and_udp"
}
EOF
        chmod 600 "${config}"
    else
        sed -i -E "s/\"server_port\":\s*[0-9]+/\"server_port\": ${port}/g" "${config}"
    fi

    local arch="$(uname -m)"
    local ss_arch="x86_64"
    if [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ]; then ss_arch="aarch64"; fi
    if ! ensure_binary "ssserver" "https://raw.githubusercontent.com/t-51/MHPanel/main/bin/ssserver"; then
        echo "    Downloading Shadowsocks-rust server (ssserver)..."
        curl -fsSL "https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.22.0/shadowsocks-v1.22.0.${ss_arch}-unknown-linux-gnu.tar.xz" 2>/dev/null | tar -xJ -C /usr/local/bin/ ssserver 2>/dev/null || true
        chmod +x /usr/local/bin/ssserver 2>/dev/null || true
    fi

    if [ ! -x /usr/local/bin/ssserver ]; then
        echo "    [!] Shadowsocks-rust binary (/usr/local/bin/ssserver) could not be installed. Skipping service."
        systemctl stop mhpanel-shadowsocks 2>/dev/null || true
        systemctl disable mhpanel-shadowsocks 2>/dev/null || true
        rm -f /etc/systemd/system/mhpanel-shadowsocks.service
        systemctl daemon-reload
        return 0
    fi

    cat > /etc/systemd/system/mhpanel-shadowsocks.service <<EOF
[Unit]
Description=Shadowsocks-rust 2022 High-Performance Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ssserver -c /etc/vpnpanel/shadowsocks.json
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    allow_port "${port}" "tcp"
    allow_port "${port}" "udp"
    systemctl daemon-reload
    systemctl enable mhpanel-shadowsocks
    systemctl restart mhpanel-shadowsocks
}

uninstall_shadowsocks() {
    systemctl stop mhpanel-shadowsocks || true
    systemctl disable mhpanel-shadowsocks || true
    local port=$(grep -oE '"server_port":\s*[0-9]+' /etc/vpnpanel/shadowsocks.json 2>/dev/null | awk '{print $2}' || echo "8388")
    deny_port "${port}" "tcp"
    deny_port "${port}" "udp"
    rm -f /etc/systemd/system/mhpanel-shadowsocks.service
    systemctl daemon-reload
}

set_port_shadowsocks() {
    local port=$1
    local old_port=$(grep -oE '"server_port":\s*[0-9]+' /etc/vpnpanel/shadowsocks.json 2>/dev/null | awk '{print $2}' || echo "8388")
    [ -n "${old_port}" ] && [ "${old_port}" != "${port}" ] && deny_port "${old_port}" "tcp" && deny_port "${old_port}" "udp"
    sed -i -E "s/\"server_port\":\s*[0-9]+/\"server_port\": ${port}/g" /etc/vpnpanel/shadowsocks.json
    allow_port "${port}" "tcp"
    allow_port "${port}" "udp"
    systemctl daemon-reload
    systemctl restart mhpanel-shadowsocks
}

install_tuic() {
    local port=${1:-7443}
    mkdir -p /etc/vpnpanel
    local config="/etc/vpnpanel/tuic.json"
    generate_certs
    local cert="/etc/vpn-ca/vpn-server.crt"
    local key="/etc/vpn-ca/vpn-server.key"
    [ -f "$cert" ] || cert="/etc/vpnpanel/certs/server.crt"
    [ -f "$key" ] || key="/etc/vpnpanel/certs/server.key"
    [ -f "$cert" ] || cert="/etc/vpnpanel/server.crt"
    [ -f "$key" ] || key="/etc/vpnpanel/server.key"

    if [ ! -f "${config}" ]; then
        local uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)
        cat > "${config}" <<EOF
{
  "server": "0.0.0.0:${port}",
  "users": {
    "${uuid}": "tuicpassword"
  },
  "certificate": "${cert}",
  "private_key": "${key}",
  "congestion_control": "bbr",
  "alpn": [ "h3" ],
  "zero_rtt_handshake": true,
  "log_level": "info"
}
EOF
        chmod 600 "${config}"
    else
        sed -i -E "s/\"server\":\s*\"0\.0\.0\.0:[0-9]+\"/\"server\": \"0.0.0.0:${port}\"/g" "${config}"
    fi

    local arch="$(uname -m)"
    local tuic_arch="x86_64"
    if [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ]; then tuic_arch="aarch64"; fi
    if ! ensure_binary "tuic-server" "https://raw.githubusercontent.com/t-51/MHPanel/main/bin/tuic-server"; then
        if ! ensure_binary "tuic-server" "https://github.com/EAimTY/tuic/releases/download/tuic-server-1.0.0/tuic-server-1.0.0-${tuic_arch}-unknown-linux-musl"; then
            echo "ERROR: Failed to download tuic-server binary. Check internet connectivity." >&2
            return 1
        fi
    fi

    cat > /etc/systemd/system/mhpanel-tuic.service <<EOF
[Unit]
Description=TUIC v5 QUIC Anti-Censorship Proxy Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/tuic-server -c /etc/vpnpanel/tuic.json
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    allow_port "${port}" "udp"
    systemctl daemon-reload
    systemctl enable mhpanel-tuic
    systemctl restart mhpanel-tuic
}

uninstall_tuic() {
    systemctl stop mhpanel-tuic || true
    systemctl disable mhpanel-tuic || true
    local port=$(grep -oE '"server":\s*"[^"]*:[0-9]+"' /etc/vpnpanel/tuic.json 2>/dev/null | awk -F: '{print $NF}' | tr -d '"' || echo "7443")
    deny_port "${port}" "udp"
    rm -f /etc/systemd/system/mhpanel-tuic.service
    systemctl daemon-reload
}

set_port_tuic() {
    local port=$1
    local old_port=$(grep -oE '"server":\s*"[^"]*:[0-9]+"' /etc/vpnpanel/tuic.json 2>/dev/null | awk -F: '{print $NF}' | tr -d '"' || echo "7443")
    [ -n "${old_port}" ] && [ "${old_port}" != "${port}" ] && deny_port "${old_port}" "udp"
    sed -i -E "s/\"server\":\s*\"0\.0\.0\.0:[0-9]+\"/\"server\": \"0.0.0.0:${port}\"/g" /etc/vpnpanel/tuic.json
    allow_port "${port}" "udp"
    systemctl daemon-reload
    systemctl restart mhpanel-tuic
}


install_mtproto() {
    local port=${1:-4433}
    local ad_tag=${2:-}
    local config="/etc/vpnpanel/mtproto_config_${port}.py"
    ensure_proxy_python_tools
    ${PANEL_PYTHON} -m pip install mtprotoproxy --quiet 2>/dev/null || true

    # Patch Python 3.12/3.14 compatibility in mtprotoproxy script
    for mtproto_py in "${PANEL_VENV}/bin/mtprotoproxy.py" "/usr/local/bin/mtprotoproxy.py" "$(${PANEL_PYTHON} -c "import site; print(site.getsitepackages()[0])" 2>/dev/null || echo "")/mtprotoproxy.py"; do
        if [ -f "$mtproto_py" ]; then
            python3 -c "
with open('$mtproto_py', 'r') as f:
    c = f.read()
c = c.replace('loop = asyncio.get_event_loop()', '''try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)''')
c = c.replace('reuse_port=reuse_port, loop=loop', 'reuse_port=reuse_port')
c = c.replace('loop=loop', '')
with open('$mtproto_py', 'w') as f:
    f.write(c)
" 2>/dev/null || true
        fi
    done

    mkdir -p /etc/vpnpanel
    local secret=$(openssl rand -hex 16)
    cat > "${config}" <<EOF
PORT = ${port}
USERS = {
    "mhpanel": "${secret}",
}
MODES = {"classic": True, "secure": True, "tls": True}
AD_TAG = "${ad_tag}"
EOF
    chmod 600 "${config}"

    local mtproto_script="${PANEL_VENV}/bin/mtprotoproxy.py"
    [ -f "$mtproto_script" ] || mtproto_script="${PANEL_VENV}/bin/mtprotoproxy"

    cat > /etc/systemd/system/mhpanel-mtproto@.service <<EOF
[Unit]
Description=Telegram MTProto Proxy (Port %I)
After=network.target

[Service]
Type=simple
User=root
ExecStart=${PANEL_PYTHON} ${mtproto_script} /etc/vpnpanel/mtproto_config_%i.py
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl enable mhpanel-mtproto@${port}
    systemctl restart mhpanel-mtproto@${port}
    echo "MTProto secret: ${secret}"
    if [ -n "${ad_tag}" ]; then
        echo "MTProto advertising tag configured."
    fi
}

uninstall_mtproto() {
    local config_dir="/etc/vpnpanel"
    if [ -d "${config_dir}" ]; then
        for f in ${config_dir}/mtproto_config_*.py; do
            if [ -f "$f" ]; then
                local port=$(basename "$f" | grep -oE '[0-9]+')
                if [ -n "$port" ]; then
                    systemctl stop mhpanel-mtproto@${port} || true
                    systemctl disable mhpanel-mtproto@${port} || true
                    deny_port "${port}" "tcp"
                    rm -f "$f"
                fi
            fi
        done
    fi
    systemctl daemon-reload
}

set_port_mtproto() {
    local port=$1
    local first_config=$(ls /etc/vpnpanel/mtproto_config_*.py 2>/dev/null | head -n1 || true)
    if [ -n "${first_config}" ]; then
        local old_port=$(basename "${first_config}" | grep -oE '[0-9]+')
        if [ "${old_port}" != "${port}" ]; then
            systemctl stop mhpanel-mtproto@${old_port} || true
            systemctl disable mhpanel-mtproto@${old_port} || true
            deny_port "${old_port}" "tcp"
            
            local new_config="/etc/vpnpanel/mtproto_config_${port}.py"
            mv "${first_config}" "${new_config}"
            sed -i "s/^PORT = .*/PORT = ${port}/g" "${new_config}"
            
            allow_port "${port}" "tcp"
            systemctl daemon-reload
            systemctl enable mhpanel-mtproto@${port}
            systemctl restart mhpanel-mtproto@${port}
        fi
    fi
}

set_mtproto_ad_tag() {
    local ad_tag=$1
    # Set ad tag on all configured instances
    local config_dir="/etc/vpnpanel"
    if [ -d "${config_dir}" ]; then
        for f in ${config_dir}/mtproto_config_*.py; do
            if [ -f "$f" ]; then
                local port=$(basename "$f" | grep -oE '[0-9]+')
                if [ -n "$port" ]; then
                    if grep -q '^AD_TAG = ' "$f"; then
                        sed -i "s/^AD_TAG = .*/AD_TAG = \"${ad_tag}\"/g" "$f"
                    else
                        echo "AD_TAG = \"${ad_tag}\"" >> "$f"
                    fi
                    systemctl restart mhpanel-mtproto@${port}
                fi
            fi
        done
    fi
}

# ----------------- HYSTERIA 2 -----------------
install_hysteria2() {
    local port=${1:-11443}
    if [ -z "$port" ] || [ "$port" = "0" ] || [ "$port" = "7443" ]; then
        port=11443
    fi
    mkdir -p /etc/vpnpanel
    generate_certs
    if [ ! -f /etc/vpnpanel/hysteria2.yaml ]; then
        local secret=$(openssl rand -hex 16)
        local obfs_sec=$(openssl rand -hex 16)
        cat > /etc/vpnpanel/hysteria2.yaml <<EOF
listen: :${port}

tls:
  cert: /etc/vpnpanel/ssl/panel.crt
  key: /etc/vpnpanel/ssl/panel.key

auth:
  type: password
  password: ${secret}

obfs:
  type: salamander
  salamander:
    password: ${obfs_sec}

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  keepAlivePeriod: 10s

bandwidth:
  up: 100 mbps
  down: 100 mbps

outbounds:
  - name: default
    type: direct
EOF
    fi

    local arch="$(uname -m)"
    local hy_arch="amd64"
    if [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ]; then hy_arch="arm64"; fi
    ensure_binary "hysteria" "https://raw.githubusercontent.com/t-51/MHPanel/main/bin/hysteria" "https://github.com/apernet/hysteria/releases/download/app%2Fv2.5.2/hysteria-linux-${hy_arch}"

    cat > /etc/systemd/system/mhpanel-hysteria2.service <<EOF
[Unit]
Description=MHPanel - Hysteria 2 High-Speed QUIC Proxy
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/vpnpanel
ExecStart=/usr/local/bin/hysteria server -c /etc/vpnpanel/hysteria2.yaml
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    allow_port "${port}" "udp"
    systemctl daemon-reload
    systemctl enable mhpanel-hysteria2 2>/dev/null || true
    systemctl restart mhpanel-hysteria2 2>/dev/null || true
    echo "Hysteria 2 installed on UDP port ${port}."
}

uninstall_hysteria2() {
    systemctl stop mhpanel-hysteria2 2>/dev/null || true
    systemctl disable mhpanel-hysteria2 2>/dev/null || true
    local port=$(grep -oE 'listen: :[0-9]+' /etc/vpnpanel/hysteria2.yaml 2>/dev/null | awk -F: '{print $3}' || echo "11443")
    deny_port "${port}" "udp"
    rm -f /etc/systemd/system/mhpanel-hysteria2.service /etc/vpnpanel/hysteria2.yaml
    systemctl daemon-reload
    echo "Hysteria 2 uninstalled."
}

set_port_hysteria2() {
    local port=$1
    if [ -f /etc/vpnpanel/hysteria2.yaml ]; then
        local old_port=$(grep -oE 'listen: :[0-9]+' /etc/vpnpanel/hysteria2.yaml 2>/dev/null | awk -F: '{print $3}' || echo "11443")
        deny_port "${old_port}" "udp"
        sed -i -E "s/listen: :[0-9]+/listen: :${port}/g" /etc/vpnpanel/hysteria2.yaml
        allow_port "${port}" "udp"
        systemctl restart mhpanel-hysteria2 2>/dev/null || true
    fi
}

# ----------------- TROJAN -----------------
install_trojan() {
    local port=${1:-12443}
    if [ -z "$port" ] || [ "$port" = "0" ] || [ "$port" = "443" ]; then
        port=12443
    fi
    mkdir -p /etc/vpnpanel/ssl
    generate_certs
    if [ ! -s /etc/vpnpanel/ssl/panel.crt ] || [ ! -s /etc/vpnpanel/ssl/panel.key ]; then
        if [ -s /www/wwwroot/mhpanel/ssl/panel.crt ] && [ -s /www/wwwroot/mhpanel/ssl/panel.key ]; then
            cp -f /www/wwwroot/mhpanel/ssl/panel.crt /etc/vpnpanel/ssl/panel.crt
            cp -f /www/wwwroot/mhpanel/ssl/panel.key /etc/vpnpanel/ssl/panel.key
        fi
    fi

    local arch="$(uname -m)"
    local sb_arch="amd64"
    if [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ]; then sb_arch="arm64"; fi
    ensure_binary "sing-box" "https://raw.githubusercontent.com/t-51/MHPanel/main/bin/sing-box" "https://github.com/SagerNet/sing-box/releases/download/v1.9.3/sing-box-1.9.3-linux-${sb_arch}.tar.gz"

    # Fix any corrupted DNS fields in existing config
    if [ -f /etc/vpnpanel/trojan.json ]; then
        sed -i 's/"type": "udp",//g' /etc/vpnpanel/trojan.json 2>/dev/null || true
        sed -i 's/"server":/"address":/g' /etc/vpnpanel/trojan.json 2>/dev/null || true
    fi

    # If missing or invalid sing-box config, regenerate fresh clean config
    if [ ! -f /etc/vpnpanel/trojan.json ] || ! /usr/local/bin/sing-box check -c /etc/vpnpanel/trojan.json >/dev/null 2>&1; then
        local secret=$(openssl rand -hex 16)
        cat > /etc/vpnpanel/trojan.json <<EOF
{
  "log": {"level": "warn"},
  "dns": {"servers": [{"tag": "remote", "address": "8.8.8.8"}]},
  "inbounds": [
    {
      "type": "trojan",
      "tag": "trojan-in",
      "listen": "::",
      "listen_port": ${port},
      "users": [{"name": "default_user", "password": "${secret}"}],
      "tls": {
        "enabled": true,
        "server_name": "vpn.kigaping.com",
        "certificate_path": "/etc/vpnpanel/ssl/panel.crt",
        "key_path": "/etc/vpnpanel/ssl/panel.key"
      },
      "multiplex": {"enabled": true}
    }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF
    fi

    cat > /etc/systemd/system/mhpanel-trojan.service <<EOF
[Unit]
Description=MHPanel - Trojan TLS Censorship Bypass Proxy
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/vpnpanel
ExecStart=/usr/local/bin/sing-box run -c /etc/vpnpanel/trojan.json
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl enable mhpanel-trojan 2>/dev/null || true
    systemctl restart mhpanel-trojan 2>/dev/null || true
    sleep 1

    if systemctl is-active --quiet mhpanel-trojan; then
        echo "Trojan successfully installed and activated on TCP port ${port}."
    else
        echo "ERROR: mhpanel-trojan failed to start. Service error details:" >&2
        journalctl -u mhpanel-trojan -n 15 --no-pager >&2
        return 1
    fi
}

uninstall_trojan() {
    systemctl stop mhpanel-trojan 2>/dev/null || true
    systemctl disable mhpanel-trojan 2>/dev/null || true
    local port=$(grep -oE '"listen_port":\s*[0-9]+' /etc/vpnpanel/trojan.json 2>/dev/null | awk '{print $2}' || echo "12443")
    deny_port "${port}" "tcp"
    rm -f /etc/systemd/system/mhpanel-trojan.service /etc/vpnpanel/trojan.json
    systemctl daemon-reload
    echo "Trojan uninstalled."
}

set_port_trojan() {
    local port=$1
    if [ -f /etc/vpnpanel/trojan.json ]; then
        local old_port=$(grep -oE '"listen_port":\s*[0-9]+' /etc/vpnpanel/trojan.json 2>/dev/null | awk '{print $2}' || echo "12443")
        deny_port "${old_port}" "tcp"
        sed -i -E "s/\"listen_port\":\s*[0-9]+/\"listen_port\": ${port}/g" /etc/vpnpanel/trojan.json
        allow_port "${port}" "tcp"
        systemctl restart mhpanel-trojan 2>/dev/null || true
    fi
}

# ----------------- NAIVEPROXY -----------------
install_naiveproxy() {
    local port=${1:-13443}
    if [ -z "$port" ] || [ "$port" = "0" ] || [ "$port" = "443" ]; then
        port=13443
    fi
    mkdir -p /etc/vpnpanel/ssl
    generate_certs
    if [ ! -s /etc/vpnpanel/ssl/panel.crt ] || [ ! -s /etc/vpnpanel/ssl/panel.key ]; then
        if [ -s /www/wwwroot/mhpanel/ssl/panel.crt ] && [ -s /www/wwwroot/mhpanel/ssl/panel.key ]; then
            cp -f /www/wwwroot/mhpanel/ssl/panel.crt /etc/vpnpanel/ssl/panel.crt
            cp -f /www/wwwroot/mhpanel/ssl/panel.key /etc/vpnpanel/ssl/panel.key
        fi
    fi

    local arch="$(uname -m)"
    local sb_arch="amd64"
    if [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ]; then sb_arch="arm64"; fi
    ensure_binary "sing-box" "https://raw.githubusercontent.com/t-51/MHPanel/main/bin/sing-box" "https://github.com/SagerNet/sing-box/releases/download/v1.9.3/sing-box-1.9.3-linux-${sb_arch}.tar.gz"

    # Fix any corrupted DNS fields in existing config
    if [ -f /etc/vpnpanel/naiveproxy.json ]; then
        sed -i 's/"type": "udp",//g' /etc/vpnpanel/naiveproxy.json 2>/dev/null || true
        sed -i 's/"server":/"address":/g' /etc/vpnpanel/naiveproxy.json 2>/dev/null || true
    fi

    # If missing or invalid sing-box config, regenerate fresh clean config
    if [ ! -f /etc/vpnpanel/naiveproxy.json ] || ! /usr/local/bin/sing-box check -c /etc/vpnpanel/naiveproxy.json >/dev/null 2>&1; then
        local secret=$(openssl rand -hex 16)
        cat > /etc/vpnpanel/naiveproxy.json <<EOF
{
  "log": {"level": "warn"},
  "dns": {"servers": [{"tag": "remote", "address": "8.8.8.8"}]},
  "inbounds": [
    {
      "type": "naive",
      "tag": "naive-in",
      "listen": "::",
      "listen_port": ${port},
      "users": [{"username": "admin", "password": "${secret}"}],
      "tls": {
        "enabled": true,
        "server_name": "vpn.kigaping.com",
        "certificate_path": "/etc/vpnpanel/ssl/panel.crt",
        "key_path": "/etc/vpnpanel/ssl/panel.key"
      }
    }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF
    fi

    cat > /etc/systemd/system/mhpanel-naiveproxy.service <<EOF
[Unit]
Description=MHPanel - NaiveProxy Chromium Network Camouflage Proxy
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/vpnpanel
ExecStart=/usr/local/bin/sing-box run -c /etc/vpnpanel/naiveproxy.json
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl enable mhpanel-naiveproxy 2>/dev/null || true
    systemctl restart mhpanel-naiveproxy 2>/dev/null || true
    sleep 1

    if systemctl is-active --quiet mhpanel-naiveproxy; then
        echo "NaiveProxy successfully installed and activated on TCP port ${port}."
    else
        echo "ERROR: mhpanel-naiveproxy failed to start. Service error details:" >&2
        journalctl -u mhpanel-naiveproxy -n 15 --no-pager >&2
        return 1
    fi
}

uninstall_naiveproxy() {
    systemctl stop mhpanel-naiveproxy 2>/dev/null || true
    systemctl disable mhpanel-naiveproxy 2>/dev/null || true
    local port=$(grep -oE '"listen_port":\s*[0-9]+' /etc/vpnpanel/naiveproxy.json 2>/dev/null | awk '{print $2}' || echo "13443")
    deny_port "${port}" "tcp"
    rm -f /etc/systemd/system/mhpanel-naiveproxy.service /etc/vpnpanel/naiveproxy.json
    systemctl daemon-reload
    echo "NaiveProxy uninstalled."
}

set_port_naiveproxy() {
    local port=$1
    if [ -f /etc/vpnpanel/naiveproxy.json ]; then
        local old_port=$(grep -oE '"listen_port":\s*[0-9]+' /etc/vpnpanel/naiveproxy.json 2>/dev/null | awk '{print $2}' || echo "13443")
        deny_port "${old_port}" "tcp"
        sed -i -E "s/\"listen_port\":\s*[0-9]+/\"listen_port\": ${port}/g" /etc/vpnpanel/naiveproxy.json
        allow_port "${port}" "tcp"
        systemctl restart mhpanel-naiveproxy 2>/dev/null || true
    fi
}

# ----------------- STUNTLS -----------------
install_stuntls() {
    local port=${1:-3478}
    mkdir -p /etc/vpnpanel
    if [ ! -f /etc/vpnpanel/stuntls.json ]; then
        cat > /etc/vpnpanel/stuntls.json <<EOF
{
  "port": ${port},
  "secret": "stuntls-secret",
  "upstream": "127.0.0.1:22",
  "mode": "webrtc_stun"
}
EOF
    fi

    ensure_binary "stuntls-server" "https://raw.githubusercontent.com/t-51/MHPanel/main/bin/stuntls-server"

    cat > /etc/systemd/system/mhpanel-stuntls.service <<EOF
[Unit]
Description=MHPanel - StunTLS WebRTC STUN Obfuscated Tunnel
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/stuntls-server
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    allow_port "${port}" "tcp"
    allow_port "${port}" "udp"
    systemctl daemon-reload
    systemctl enable mhpanel-stuntls 2>/dev/null || true
    systemctl restart mhpanel-stuntls 2>/dev/null || true
    echo "StunTLS installed on port ${port}."
}

uninstall_stuntls() {
    systemctl stop mhpanel-stuntls 2>/dev/null || true
    systemctl disable mhpanel-stuntls 2>/dev/null || true
    local port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/stuntls.json 2>/dev/null | awk '{print $2}' || echo "3478")
    deny_port "${port}" "tcp"
    deny_port "${port}" "udp"
    rm -f /etc/systemd/system/mhpanel-stuntls.service /etc/vpnpanel/stuntls.json
    systemctl daemon-reload
    echo "StunTLS uninstalled."
}

set_port_stuntls() {
    local port=$1
    if [ -f /etc/vpnpanel/stuntls.json ]; then
        local old_port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/stuntls.json 2>/dev/null | awk '{print $2}' || echo "3478")
        deny_port "${old_port}" "tcp"
        deny_port "${old_port}" "udp"
        sed -i -E "s/\"port\":\s*[0-9]+/\"port\": ${port}/g" /etc/vpnpanel/stuntls.json
        allow_port "${port}" "tcp"
        allow_port "${port}" "udp"
        systemctl restart mhpanel-stuntls 2>/dev/null || true
    fi
}

# ----------------- NOIZDNS -----------------
install_noizdns() {
    local port=${1:-5355}
    mkdir -p /etc/vpnpanel
    if [ ! -f /etc/vpnpanel/noizdns.json ]; then
        cat > /etc/vpnpanel/noizdns.json <<EOF
{
  "port": ${port},
  "upstream_dns": "1.1.1.1:53",
  "noise_seed": "mhpanel-noiz-salt",
  "padding_min": 16,
  "padding_max": 64,
  "jitter_ms": 2
}
EOF
    fi

    ensure_binary "noizdns-server" "https://raw.githubusercontent.com/t-51/MHPanel/main/bin/noizdns-server"

    cat > /etc/systemd/system/mhpanel-noizdns.service <<EOF
[Unit]
Description=MHPanel - NoizDNS Noise Anti-DPI DNS Proxy
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/noizdns-server
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    allow_port "${port}" "udp"
    systemctl daemon-reload
    systemctl enable mhpanel-noizdns 2>/dev/null || true
    systemctl restart mhpanel-noizdns 2>/dev/null || true
    echo "NoizDNS installed on UDP port ${port}."
}

uninstall_noizdns() {
    systemctl stop mhpanel-noizdns 2>/dev/null || true
    systemctl disable mhpanel-noizdns 2>/dev/null || true
    local port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/noizdns.json 2>/dev/null | awk '{print $2}' || echo "5355")
    deny_port "${port}" "udp"
    rm -f /etc/systemd/system/mhpanel-noizdns.service /etc/vpnpanel/noizdns.json
    systemctl daemon-reload
    echo "NoizDNS uninstalled."
}

set_port_noizdns() {
    local port=$1
    if [ -f /etc/vpnpanel/noizdns.json ]; then
        local old_port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/noizdns.json 2>/dev/null | awk '{print $2}' || echo "5355")
        deny_port "${old_port}" "udp"
        sed -i -E "s/\"port\":\s*[0-9]+/\"port\": ${port}/g" /etc/vpnpanel/noizdns.json
        allow_port "${port}" "udp"
        systemctl restart mhpanel-noizdns 2>/dev/null || true
    fi
}

# ----------------- MASTERDNSVPN -----------------
install_masterdnsvpn() {
    local port=${1:-5356}
    mkdir -p /etc/vpnpanel
    if [ ! -f /etc/vpnpanel/masterdnsvpn.json ]; then
        cat > /etc/vpnpanel/masterdnsvpn.json <<EOF
{
  "port": ${port},
  "domain": "t.kigaping.com",
  "auth_key": "master-secret-key-mhpanel",
  "upstream": "127.0.0.1:1080",
  "mtu": 1280
}
EOF
    fi

    ensure_binary "masterdnsvpn-server" "https://raw.githubusercontent.com/t-51/MHPanel/main/bin/masterdnsvpn-server"

    cat > /etc/systemd/system/mhpanel-masterdnsvpn.service <<EOF
[Unit]
Description=MHPanel - MasterdnsVPN High-Speed Chunked DNS Tunnel
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/masterdnsvpn-server
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    allow_port "${port}" "udp"
    systemctl daemon-reload
    systemctl enable mhpanel-masterdnsvpn 2>/dev/null || true
    systemctl restart mhpanel-masterdnsvpn 2>/dev/null || true
    echo "MasterdnsVPN installed on UDP port ${port}."
}

uninstall_masterdnsvpn() {
    systemctl stop mhpanel-masterdnsvpn 2>/dev/null || true
    systemctl disable mhpanel-masterdnsvpn 2>/dev/null || true
    local port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/masterdnsvpn.json 2>/dev/null | awk '{print $2}' || echo "5356")
    deny_port "${port}" "udp"
    rm -f /etc/systemd/system/mhpanel-masterdnsvpn.service /etc/vpnpanel/masterdnsvpn.json
    systemctl daemon-reload
    echo "MasterdnsVPN uninstalled."
}

set_port_masterdnsvpn() {
    local port=$1
    if [ -f /etc/vpnpanel/masterdnsvpn.json ]; then
        local old_port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/masterdnsvpn.json 2>/dev/null | awk '{print $2}' || echo "5356")
        deny_port "${old_port}" "udp"
        sed -i -E "s/\"port\":\s*[0-9]+/\"port\": ${port}/g" /etc/vpnpanel/masterdnsvpn.json
        allow_port "${port}" "udp"
        systemctl restart mhpanel-masterdnsvpn 2>/dev/null || true
    fi
}

# ----------------- DNSTT PROTOCOL -----------------
install_dnstt() {
    local port=${1:-5300}
    mkdir -p /etc/vpnpanel /etc/dnstt

    if ! ensure_binary "dnstt-server" "https://raw.githubusercontent.com/t-51/MHPanel/main/bin/dnstt-server"; then
        echo "ERROR: Failed to obtain dnstt-server binary. Please check server internet access." >&2
        return 1
    fi
    ensure_binary "dnstt-client" "https://raw.githubusercontent.com/t-51/MHPanel/main/bin/dnstt-client" || true

    if [ ! -f /etc/dnstt/server.key ] || [ ! -f /etc/dnstt/server.pub ]; then
        /usr/local/bin/dnstt-server -gen-key -privkey-file /etc/dnstt/server.key -pubkey-file /etc/dnstt/server.pub || true
    fi

    local pubkey=""
    if [ -f /etc/dnstt/server.pub ]; then
        pubkey=$(cat /etc/dnstt/server.pub | tr -d '\r\n ')
    fi

    local domain="t.vpn.kigaping.com"
    local upstream="127.0.0.1:22"
    local mtu=1232

    if [ -f /etc/vpnpanel/dnstt.json ]; then
        domain=$(grep -oE '"domain":\s*"[^"]+"' /etc/vpnpanel/dnstt.json 2>/dev/null | awk -F'"' '{print $4}' || echo "t.vpn.kigaping.com")
        upstream=$(grep -oE '"upstream":\s*"[^"]+"' /etc/vpnpanel/dnstt.json 2>/dev/null | awk -F'"' '{print $4}' || echo "127.0.0.1:22")
        mtu=$(grep -oE '"mtu":\s*[0-9]+' /etc/vpnpanel/dnstt.json 2>/dev/null | awk '{print $2}' || echo "1232")
        sed -i -E "s/\"port\":\s*[0-9]+/\"port\": ${port}/g" /etc/vpnpanel/dnstt.json
    else
        cat > /etc/vpnpanel/dnstt.json <<EOF
{
  "port": ${port},
  "domain": "${domain}",
  "upstream": "${upstream}",
  "mtu": ${mtu},
  "pubkey": "${pubkey}"
}
EOF
    fi

    cat > /etc/systemd/system/mhpanel-dnstt.service <<EOF
[Unit]
Description=MHPanel - DNSTT DNS Tunnel Server
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/dnstt-server -udp 0.0.0.0:${port} -privkey-file /etc/dnstt/server.key -mtu ${mtu} ${domain} ${upstream}
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    allow_port "${port}" "udp"
    systemctl daemon-reload
    systemctl enable mhpanel-dnstt 2>/dev/null || true
    systemctl restart mhpanel-dnstt 2>/dev/null || true
    echo "DNSTT installed on UDP port ${port}."
}

uninstall_dnstt() {
    systemctl stop mhpanel-dnstt 2>/dev/null || true
    systemctl disable mhpanel-dnstt 2>/dev/null || true
    local port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/dnstt.json 2>/dev/null | awk '{print $2}' || echo "5300")
    deny_port "${port}" "udp"
    rm -f /etc/systemd/system/mhpanel-dnstt.service /etc/vpnpanel/dnstt.json
    systemctl daemon-reload
    echo "DNSTT uninstalled."
}

set_port_dnstt() {
    local port=$1
    if [ -f /etc/vpnpanel/dnstt.json ]; then
        local old_port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/dnstt.json 2>/dev/null | awk '{print $2}' || echo "5300")
        deny_port "${old_port}" "udp"
        sed -i -E "s/\"port\":\s*[0-9]+/\"port\": ${port}/g" /etc/vpnpanel/dnstt.json
        sed -i -E "s/-udp 0\.0\.0\.0:[0-9]+/-udp 0.0.0.0:${port}/g" /etc/systemd/system/mhpanel-dnstt.service 2>/dev/null || true
        allow_port "${port}" "udp"
        systemctl daemon-reload
        systemctl restart mhpanel-dnstt 2>/dev/null || true
    fi
}

# ----------------- VAYDNS PROTOCOL -----------------
install_vaydns() {
    local port=${1:-5353}
    mkdir -p /etc/vpnpanel /etc/vaydns

    if ! ensure_binary "vaydns-server" "https://raw.githubusercontent.com/t-51/MHPanel/main/bin/vaydns-server"; then
        echo "ERROR: Failed to obtain vaydns-server binary. Please check server internet access." >&2
        return 1
    fi
    ensure_binary "vaydns-client" "https://raw.githubusercontent.com/t-51/MHPanel/main/bin/vaydns-client" || true

    if [ ! -f /etc/vaydns/server.key ] || [ ! -f /etc/vaydns/server.pub ]; then
        /usr/local/bin/vaydns-server -gen-key -privkey-file /etc/vaydns/server.key -pubkey-file /etc/vaydns/server.pub || true
    fi

    local pubkey_v=""
    if [ -f /etc/vaydns/server.pub ]; then
        pubkey_v=$(cat /etc/vaydns/server.pub | tr -d '\r\n ')
    fi

    local domain="v.vpn.kigaping.com"
    local upstream="127.0.0.1:22"

    if [ -f /etc/vpnpanel/vaydns.json ]; then
        domain=$(grep -oE '"domain":\s*"[^"]+"' /etc/vpnpanel/vaydns.json 2>/dev/null | awk -F'"' '{print $4}' || echo "v.vpn.kigaping.com")
        upstream=$(grep -oE '"upstream":\s*"[^"]+"' /etc/vpnpanel/vaydns.json 2>/dev/null | awk -F'"' '{print $4}' || echo "127.0.0.1:22")
        sed -i -E "s/\"port\":\s*[0-9]+/\"port\": ${port}/g" /etc/vpnpanel/vaydns.json
    else
        cat > /etc/vpnpanel/vaydns.json <<EOF
{
  "port": ${port},
  "domain": "${domain}",
  "upstream": "${upstream}",
  "dnstt_compat": true,
  "pubkey": "${pubkey_v}"
}
EOF
    fi

    cat > /etc/systemd/system/mhpanel-vaydns.service <<EOF
[Unit]
Description=MHPanel - VayDNS High-Performance DNS Tunnel Server
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/vaydns-server -udp 0.0.0.0:${port} -privkey-file /etc/vaydns/server.key -domain ${domain} -upstream ${upstream} -dnstt-compat
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    allow_port "${port}" "udp"
    systemctl daemon-reload
    systemctl enable mhpanel-vaydns 2>/dev/null || true
    systemctl restart mhpanel-vaydns 2>/dev/null || true
    echo "VayDNS installed on UDP port ${port}."
}

uninstall_vaydns() {
    systemctl stop mhpanel-vaydns 2>/dev/null || true
    systemctl disable mhpanel-vaydns 2>/dev/null || true
    local port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/vaydns.json 2>/dev/null | awk '{print $2}' || echo "5353")
    deny_port "${port}" "udp"
    rm -f /etc/systemd/system/mhpanel-vaydns.service /etc/vpnpanel/vaydns.json
    systemctl daemon-reload
    echo "VayDNS uninstalled."
}

set_port_vaydns() {
    local port=$1
    if [ -f /etc/vpnpanel/vaydns.json ]; then
        local old_port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/vaydns.json 2>/dev/null | awk '{print $2}' || echo "5353")
        deny_port "${old_port}" "udp"
        sed -i -E "s/\"port\":\s*[0-9]+/\"port\": ${port}/g" /etc/vpnpanel/vaydns.json
        sed -i -E "s/-udp 0\.0\.0\.0:[0-9]+/-udp 0.0.0.0:${port}/g" /etc/systemd/system/mhpanel-vaydns.service 2>/dev/null || true
        allow_port "${port}" "udp"
        systemctl daemon-reload
        systemctl restart mhpanel-vaydns 2>/dev/null || true
    fi
}

# ----------------- SLIPSTREAM PROTOCOL -----------------
install_slipstream() {
    local port=${1:-5354}
    mkdir -p /etc/vpnpanel /etc/slipstream

    if ! ensure_binary "slipstream-server" "https://raw.githubusercontent.com/t-51/MHPanel/main/bin/slipstream-server"; then
        echo "ERROR: Failed to obtain slipstream-server binary. Please check server internet access." >&2
        return 1
    fi
    ensure_binary "slipstream-client" "https://raw.githubusercontent.com/t-51/MHPanel/main/bin/slipstream-client" || true

    if [ ! -f /etc/slipstream/cert.pem ] || [ ! -f /etc/slipstream/key.pem ]; then
        openssl req -x509 -newkey rsa:2048 -nodes -keyout /etc/slipstream/key.pem -out /etc/slipstream/cert.pem -days 3650 -subj "/CN=dns-tunnel" 2>/dev/null || true
    fi

    local domain="t.kigaping.com"
    local upstream="127.0.0.1:1080"

    if [ -f /etc/vpnpanel/slipstream.json ]; then
        domain=$(grep -oE '"domain":\s*"[^"]+"' /etc/vpnpanel/slipstream.json 2>/dev/null | awk -F'"' '{print $4}' || echo "t.kigaping.com")
        upstream=$(grep -oE '"upstream":\s*"[^"]+"' /etc/vpnpanel/slipstream.json 2>/dev/null | awk -F'"' '{print $4}' || echo "127.0.0.1:1080")
        sed -i -E "s/\"port\":\s*[0-9]+/\"port\": ${port}/g" /etc/vpnpanel/slipstream.json
    else
        cat > /etc/vpnpanel/slipstream.json <<EOF
{
  "port": ${port},
  "domain": "${domain}",
  "upstream": "${upstream}"
}
EOF
    fi

    cat > /etc/systemd/system/mhpanel-slipstream.service <<EOF
[Unit]
Description=MHPanel - Slipstream Covert DNS Tunnel Server
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/slipstream-server -l ${port} -d ${domain} -a ${upstream} -c /etc/slipstream/cert.pem -k /etc/slipstream/key.pem
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    allow_port "${port}" "udp"
    systemctl daemon-reload
    systemctl enable mhpanel-slipstream 2>/dev/null || true
    systemctl restart mhpanel-slipstream 2>/dev/null || true
    echo "Slipstream installed on UDP port ${port}."
}

uninstall_slipstream() {
    systemctl stop mhpanel-slipstream 2>/dev/null || true
    systemctl disable mhpanel-slipstream 2>/dev/null || true
    local port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/slipstream.json 2>/dev/null | awk '{print $2}' || echo "5354")
    deny_port "${port}" "udp"
    rm -f /etc/systemd/system/mhpanel-slipstream.service /etc/vpnpanel/slipstream.json
    systemctl daemon-reload
    echo "Slipstream uninstalled."
}

set_port_slipstream() {
    local port=$1
    if [ -f /etc/vpnpanel/slipstream.json ]; then
        local old_port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/slipstream.json 2>/dev/null | awk '{print $2}' || echo "5354")
        deny_port "${old_port}" "udp"
        sed -i -E "s/\"port\":\s*[0-9]+/\"port\": ${port}/g" /etc/vpnpanel/slipstream.json
        sed -i -E "s/-l [0-9]+/-l ${port}/g" /etc/systemd/system/mhpanel-slipstream.service 2>/dev/null || true
        allow_port "${port}" "udp"
        systemctl daemon-reload
        systemctl restart mhpanel-slipstream 2>/dev/null || true
    fi
}

# ----------------- TOR BRIDGES -----------------
install_tor() {
    local or_port=${1:-9001}
    local bridge_port=${2:-9002}
    export DEBIAN_FRONTEND=noninteractive

    rm -f /etc/apt/sources.list.d/tor.list 2>/dev/null || true
    run_apt update >/dev/null 2>&1 || true
    run_apt install tor tor-geoipdb obfs4proxy >/dev/null 2>&1 || run_apt install tor tor-geoipdb lyrebird >/dev/null 2>&1 || true

    # Stop default distro tor service to prevent conflict on port 9050
    systemctl stop tor tor@default 2>/dev/null || true
    systemctl disable tor tor@default 2>/dev/null || true

    local obfs_bin="$(command -v obfs4proxy || command -v lyrebird || echo '/usr/bin/obfs4proxy')"
    local tor_bin="$(command -v tor || echo '/usr/bin/tor')"

    local tor_ver=$(${tor_bin} --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || echo "0.4.0")
    local major=$(echo "$tor_ver" | cut -d. -f1)
    local minor=$(echo "$tor_ver" | cut -d. -f2)
    local patch=$(echo "$tor_ver" | cut -d. -f3)

    mkdir -p /etc/tor /etc/vpnpanel /var/lib/tor
    chown -R debian-tor:debian-tor /var/lib/tor 2>/dev/null || true
    chmod 700 /var/lib/tor 2>/dev/null || true

    # Tor consensus requires Tor >= 0.4.7 for public relays/bridges
    if [ "${major:-0}" -eq 0 ] && [ "${minor:-0}" -le 4 ] && [ "${patch:-0}" -lt 7 ]; then
        cat > /etc/tor/torrc <<EOF
SocksPort 127.0.0.1:9050
RunAsDaemon 0
PublishServerDescriptor 0
DataDirectory /var/lib/tor
EOF
    else
        cat > /etc/tor/torrc <<EOF
SocksPort 127.0.0.1:9050
RunAsDaemon 0
ORPort ${or_port}
BridgeRelay 1
ServerTransportPlugin obfs4 exec ${obfs_bin}
ServerTransportListenAddr obfs4 0.0.0.0:${bridge_port}
PublishServerDescriptor 0
ContactInfo admin@kigaping.com
Nickname MHPanelBridge
DataDirectory /var/lib/tor
EOF
    fi

    cat > /etc/systemd/system/mhpanel-tor.service <<EOF
[Unit]
Description=MHPanel - Tor Anti-Censorship Bridge Hub (obfs4 / WebTunnel / Snowflake)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=debian-tor
Group=debian-tor
ExecStart=${tor_bin} -f /etc/tor/torrc
ExecReload=/bin/kill -HUP \$MAINPID
KillSignal=SIGINT
TimeoutSec=60
TimeoutStopSec=5
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    allow_port "${or_port}" "tcp"
    allow_port "${bridge_port}" "tcp"
    systemctl daemon-reload
    systemctl enable mhpanel-tor 2>/dev/null || true
    systemctl restart mhpanel-tor 2>/dev/null || true
    echo "Tor Bridge installed with obfs4 on ports ${or_port}/${bridge_port}."
}

uninstall_tor() {
    systemctl stop mhpanel-tor 2>/dev/null || true
    systemctl disable mhpanel-tor 2>/dev/null || true
    deny_port "9001" "tcp"
    deny_port "9002" "tcp"
    rm -f /etc/systemd/system/mhpanel-tor.service
    systemctl daemon-reload
    echo "Tor uninstalled."
}

set_port_tor() {
    local port=$1
    if [ -f /etc/tor/torrc ]; then
        sed -i -E "s/^ORPort [0-9]+/ORPort ${port}/g" /etc/tor/torrc
        allow_port "${port}" "tcp"
        systemctl restart mhpanel-tor 2>/dev/null || true
    fi
}

# ----------------- SING-BOX UNIVERSAL SUITE CORE -----------------
install_singbox() {
    local port=${1:-20443}
    echo "Installing & verifying Sing-box Universal Suite Core..."
    for bdir in /www/wwwroot/mhpanel/bin /root/mhpanel-repo/bin; do
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
        (curl -fsSL --connect-timeout 10 --max-time 60 "https://github.com/SagerNet/sing-box/releases/download/v1.9.3/sing-box-1.9.3-linux-${sb_arch}.tar.gz" 2>/dev/null | tar -xz -C /tmp/ 2>/dev/null && mv /tmp/sing-box-*/sing-box /usr/local/bin/sing-box 2>/dev/null && rm -rf /tmp/sing-box* || true)
        chmod +x /usr/local/bin/sing-box 2>/dev/null || true
    fi

    mkdir -p /etc/sing-box
    if [ ! -f /etc/sing-box/config.json ] || [ ! -s /etc/sing-box/config.json ]; then
        if [ -x "${PANEL_PYTHON}" ]; then
            "${PANEL_PYTHON}" -c "import sys; sys.path.insert(0, '${PANEL_DIR}'); from app import ensure_singbox_service, ensure_singbox_default_config; ensure_singbox_default_config(); ensure_singbox_service()" 2>/dev/null || true
        fi
    fi

    # Standalone robust fallback if python config generator failed
    if [ ! -f /etc/sing-box/config.json ] || [ ! -s /etc/sing-box/config.json ]; then
        cat > /etc/sing-box/config.json <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality-in",
      "listen": "::",
      "listen_port": ${port},
      "sniff": true,
      "users": [
        {
          "uuid": "4c2dfa93-5bc2-466a-bca9-566bcba0cbdf",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "www.google.com",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "www.google.com",
            "server_port": 443
          },
          "private_key": "oJWFNihT4yj8sGXdj978eQjGajPK8N_It7EEPiPXD3s",
          "short_id": [
            "0123456789abcdef",
            ""
          ]
        }
      }
    },
    {
      "type": "shadowsocks",
      "tag": "ss-in",
      "listen": "::",
      "listen_port": 2080,
      "method": "2022-blake3-aes-128-gcm",
      "password": "bXBwYW5lbF9zZWNyZXQxMg=="
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ]
}
EOF
    fi

    cat > /etc/systemd/system/mhpanel-singbox.service <<'EOF'
[Unit]
Description=MHPanel - Sing-box Universal Suite Core
After=network.target network-online.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=always
RestartSec=3s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    for p in "${port}" 2080 20443 20444 20447 20448 20449 20450 20451; do
        allow_port "${p}" "tcp"
    done
    for p in 20445 20446; do
        allow_port "${p}" "udp"
    done

    systemctl daemon-reload
    systemctl enable mhpanel-singbox 2>/dev/null || true
    systemctl restart mhpanel-singbox 2>/dev/null || true
    echo "Sing-box Universal Suite Core active on port ${port}."
}

uninstall_singbox() {
    systemctl stop mhpanel-singbox 2>/dev/null || true
    systemctl disable mhpanel-singbox 2>/dev/null || true
    deny_port "20443" "tcp"
    rm -f /etc/systemd/system/mhpanel-singbox.service
    systemctl daemon-reload
    echo "Sing-box service uninstalled."
}

set_port_singbox() {
    local port=$1
    if [ -f /etc/sing-box/config.json ]; then
        sed -i -E "s/\"listen_port\": [0-9]+/\"listen_port\": ${port}/1" /etc/sing-box/config.json
        allow_port "${port}" "tcp"
        systemctl restart mhpanel-singbox 2>/dev/null || true
    fi
}

# ----------------- BADVPN UDPGW FORWARDER -----------------
install_badvpn() {
    local port=${1:-7300}
    echo "Installing BadVPN UDPGW on port ${port}..."
    for bdir in /www/wwwroot/mhpanel/bin /root/mhpanel-repo/bin "${PANEL_DIR}/bin" "${PANEL_DIR}/scripts/daemons"; do
        if [ -f "${bdir}/badvpn-udpgw" ]; then
            cp -f "${bdir}/badvpn-udpgw" /usr/local/bin/badvpn-udpgw 2>/dev/null || true
            chmod +x /usr/local/bin/badvpn-udpgw 2>/dev/null || true
            break
        fi
    done
    cat > /etc/systemd/system/badvpn.service <<EOF
[Unit]
Description=BadVPN UDPGW Service for Gaming & UDP Forwarding
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:${port} --max-clients 1000 --max-connections-for-client 20
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable badvpn.service >/dev/null 2>&1
    systemctl restart badvpn.service >/dev/null 2>&1 || true
    echo "BadVPN UDP-GW installed on UDP port ${port}."
}

uninstall_badvpn() {
    systemctl stop badvpn.service videocall.service 2>/dev/null || true
    systemctl disable badvpn.service videocall.service 2>/dev/null || true
    rm -f /etc/systemd/system/badvpn.service /etc/systemd/system/videocall.service
    systemctl daemon-reload
    echo "BadVPN service uninstalled."
}

# ----------------- GOOGLE APPS SCRIPT (GAS) FULL TUNNEL -----------------
install_google_script() {
    local port=${1:-8448}
    echo "Installing Google Apps Script (GAS) Full Tunnel Relay Server..."
    for bdir in /www/wwwroot/mhpanel/bin /root/mhpanel-repo/bin; do
        if [ -f "${bdir}/mhrv-tunnel-node" ]; then
            cp -f "${bdir}/mhrv-tunnel-node" /usr/local/bin/mhrv-tunnel-node 2>/dev/null || true
            chmod +x /usr/local/bin/mhrv-tunnel-node 2>/dev/null || true
            break
        fi
    done
    for sdir in /www/wwwroot/mhpanel/scripts/daemons /root/mhpanel-repo/scripts/daemons; do
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
  "port": ${port},
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

    cat > /etc/systemd/system/mhpanel-gas-tunnel.service <<'GEO'
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

    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl enable mhpanel-gas-tunnel 2>/dev/null || true
    systemctl restart mhpanel-gas-tunnel 2>/dev/null || true
    echo "Google Apps Script Full Tunnel Relay Server successfully installed on port ${port}."
}

uninstall_google_script() {
    systemctl stop mhpanel-gas-tunnel 2>/dev/null || true
    systemctl disable mhpanel-gas-tunnel 2>/dev/null || true
    local port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/google_script.json 2>/dev/null | awk '{print $2}' || echo "8448")
    deny_port "${port}" "tcp"
    rm -f /etc/systemd/system/mhpanel-gas-tunnel.service
    systemctl daemon-reload
    echo "Google Apps Script tunnel service uninstalled."
}

set_port_google_script() {
    local port=$1
    if [ -f /etc/vpnpanel/google_script.json ]; then
        local old_port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/google_script.json 2>/dev/null | awk '{print $2}' || echo "8448")
        deny_port "${old_port}" "tcp"
        sed -i -E "s/\"port\":\s*[0-9]+/\"port\": ${port}/g" /etc/vpnpanel/google_script.json
        allow_port "${port}" "tcp"
        systemctl restart mhpanel-gas-tunnel 2>/dev/null || true
    fi
}

# Color definitions for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0;37m'

# Helper: Get connection count for a protocol
get_connections_count() {
    local proto=$1
    local port=$2
    local count=0
    case "$proto" in
        ssh)
            if [ -n "${port}" ] && [ "${port}" != "-" ]; then
                count=$(ss -t -a | grep ":${port} " | grep -i estab | wc -l)
            else
                # fallback: try reading port from config
                local ssh_port=$(grep -Ei '^Port ' /etc/ssh/sshd_config_vpn 2>/dev/null | awk '{print $2}' || echo "2222")
                count=$(ss -t -a | grep ":${ssh_port} " | grep -i estab | wc -l)
            fi
            ;;
        openvpn)
            if [ -n "${port}" ] && [ "${port}" != "-" ]; then
                count=$(ss -u -a | grep ":${port} " | grep -i estab | wc -l)
            else
                count=0
            fi
            ;;
        ocserv)
            if command -v occtl >/dev/null 2>&1; then
                count=$(occtl show users 2>/dev/null | grep -v 'Unique ID' | grep -v '^$' | wc -l || echo "0")
                count=$((count > 0 ? count - 1 : 0))
            else
                count=0
            fi
            ;;
        ikev2)
            if command -v swanctl >/dev/null 2>&1; then
                count=$(swanctl --list-sas 2>/dev/null | grep 'established' | wc -l || echo "0")
            else
                count=0
            fi
            ;;
        sstp)
            if [ -n "${port}" ] && [ "${port}" != "-" ]; then
                count=$(ss -t -a | grep ":${port} " | grep -i estab | wc -l)
            else
                count=0
            fi
            ;;
        l2tp)
            count=$(ss -u -a | grep ":1701 " | grep -i estab | wc -l)
            ;;
        wireguard)
            if command -v wg >/dev/null 2>&1; then
                # Count peers with handshake in last 120 seconds
                local now=$(date +%s)
                local handshakes=$(wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}')
                for hs in $handshakes; do
                    if [[ "$hs" =~ ^[0-9]+$ ]] && [ "$hs" -gt 0 ] && [ "$((now - hs))" -lt 120 ]; then
                        count=$((count + 1))
                    fi
                done
            fi
            ;;
        pptp)
            count=$(ss -t -a | grep ":${port:-1723} " | grep -i estab | wc -l)
            ;;
        amneziawg)
            if command -v awg >/dev/null 2>&1; then
                local now=$(date +%s)
                local handshakes=$(awg show awg0 latest-handshakes 2>/dev/null | awk '{print $2}')
                for hs in $handshakes; do
                    if [[ "$hs" =~ ^[0-9]+$ ]] && [ "$hs" -gt 0 ] && [ "$((now - hs))" -lt 120 ]; then
                        count=$((count + 1))
                    fi
                done
            fi
            ;;
        http|socks|shadowsocks|mtproto|trojan|naiveproxy|stuntls|tor)
            if [ -n "${port}" ] && [ "${port}" != "-" ]; then
                count=$(ss -t -a | grep ":${port} " | grep -i estab | wc -l)
            else
                count=0
            fi
            ;;
        tuic|hysteria2|dnstt|vaydns|slipstream|noizdns|masterdnsvpn)
            if [ -n "${port}" ] && [ "${port}" != "-" ]; then
                count=$(ss -u -a | grep ":${port} " | grep -i -E 'estab|unconn' | wc -l)
            else
                count=0
            fi
            ;;
    esac
    echo "$count"
}

# Helper: Print formatted status report
print_status_report() {
    echo -e "\n${CYAN}================================================================${NC}"
    echo -e "${CYAN}               KIGA-SM System Status Report                   ${NC}"
    echo -e "${CYAN}================================================================${NC}"
    
    # 1. Web Dashboard Status
    local panel_installed="No"
    local panel_active="Inactive"
    local panel_port=$(cat ${PANEL_DIR}/panel_port.txt 2>/dev/null || echo "9090")
    if [ -f "${PANEL_DIR}/app.py" ]; then
        panel_installed="Yes"
        if systemctl is-active mhpanel >/dev/null 2>&1 || systemctl is-active vpnpanel >/dev/null 2>&1; then
            panel_active="Active (Running)"
        fi
    fi
    
    echo -e "Web Panel Dashboard:"
    if [ "$panel_installed" = "Yes" ]; then
        local ip=$(get_public_ipv4)
        echo -e "  - Installed: ${GREEN}Yes${NC}"
        echo -e "  - Status:    ${GREEN}${panel_active}${NC}"
        echo -e "  - Address:   ${CYAN}https://${ip}:${panel_port}/${NC}"
    else
        echo -e "  - Installed: ${RED}No${NC}"
    fi
    echo ""

    # 2. Protocols Status
    echo -e "VPN Protocols Status:"
    local protocols=("ssh" "openvpn" "ocserv" "ikev2" "sstp" "pptp" "l2tp" "wireguard" "amneziawg" "http" "socks" "shadowsocks" "tuic" "mtproto" "badvpn" "dnstt" "vaydns" "slipstream" "hysteria2" "trojan" "naiveproxy" "stuntls" "noizdns" "masterdnsvpn" "tor" "singbox" "google_script")
    for proto in "${protocols[@]}"; do
        local inst="No"
        local act="Inactive"
        local port="-"
        local conn="0"
        
        case "$proto" in
            ssh)
                if [ -f "/etc/ssh/sshd_config_vpn" ] || [ -f "/etc/ssh/sshd_config" ]; then
                    port=$(grep -Ei '^Port ' /etc/ssh/sshd_config_vpn /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -n1)
                    port=${port:-22}
                    inst="Yes"
                    if [ "$(service_status mhpanel-ssh ssh-ws sshd ssh)" = "active" ]; then
                        act="Active"
                        conn=$(get_connections_count "ssh" "$port")
                    fi
                fi
                ;;
            openvpn)
                if [ -f "/etc/openvpn/server.conf" ] || [ -f "/etc/openvpn/server/server.conf" ] || [ -f "/etc/openvpn/server-tcp.conf" ]; then
                    inst="Yes"
                    port=$(grep -Ei '^port ' /etc/openvpn/server.conf /etc/openvpn/server/server.conf /etc/openvpn/server-tcp.conf 2>/dev/null | awk '{print $2}' | head -n1)
                    port=${port:-1194}
                    if [ "$(service_status openvpn-server@server openvpn-server@server-tcp openvpn@server openvpn)" = "active" ]; then
                        act="Active"
                        conn=$(get_connections_count "openvpn" "$port")
                    fi
                fi
                ;;
            ocserv)
                if [ -f "/etc/ocserv/ocserv.conf" ]; then
                    inst="Yes"
                    port=$(grep -Ei '^tcp-port' /etc/ocserv/ocserv.conf | awk '{print $3}' || echo "443")
                    if systemctl is-active ocserv >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "ocserv" "$port")
                    fi
                fi
                ;;
            ikev2)
                if [ -f "/etc/swanctl/conf.d/ikev2.conf" ] || ([ -f "/etc/ipsec.conf" ] && grep -q "conn ikev2" /etc/ipsec.conf 2>/dev/null); then
                    inst="Yes"
                    port="500/4500 (UDP)"
                    if [ "$(service_status strongswan-starter strongswan strongswan-swanctl)" = "active" ]; then
                        act="Active"
                        conn=$(get_connections_count "ikev2")
                    fi
                fi
                ;;
            sstp)
                if [ -f "/etc/systemd/system/sstpd.service" ] || [ -f "/etc/accel-ppp.conf" ]; then
                    inst="Yes"
                    port=$(grep -E '^port=' /etc/accel-ppp.conf 2>/dev/null | head -n1 | cut -d= -f2 || true); port=${port:-$(grep -oE '\-p [0-9]+' /etc/systemd/system/sstpd.service 2>/dev/null | awk '{print $2}' || true)}; port=${port:-4443}
                    if systemctl is-active sstpd >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "sstp" "$port")
                    fi
                fi
                ;;
            pptp)
                if [ -f "/etc/pptpd.conf" ]; then
                    port=$(grep -oE 'Port [0-9]+' /etc/systemd/system/mhpanel-pptp.service 2>/dev/null | awk '{print $2}' | head -n1)
                    port=${port:-1723}
                    inst="Yes"
                    if [ "$(service_status pptpd mhpanel-pptp)" = "active" ]; then
                        act="Active"
                        conn=$(get_connections_count "pptp" "$port")
                    fi
                fi
                ;;
            badvpn)
                if [ -x /usr/local/bin/badvpn-udpgw ] || [ -x /usr/bin/badvpn-udpgw ] || [ -f "/etc/systemd/system/badvpn.service" ] || [ -f "/etc/systemd/system/videocall.service" ]; then
                    inst="Yes"
                    port="7300 (UDP)"
                    if [ "$(service_status badvpn videocall)" = "active" ]; then
                        act="Active"
                        conn="0"
                    fi
                fi
                ;;
            l2tp)
                if [ -f "/etc/xl2tpd/xl2tpd.conf" ]; then
                    inst="Yes"
                    port="1701 (UDP)"
                    if systemctl is-active xl2tpd >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "l2tp")
                    fi
                fi
                ;;
            wireguard)
                if [ -f "/etc/wireguard/wg0.conf" ]; then
                    inst="Yes"
                    port=$(grep -Ei '^ListenPort' /etc/wireguard/wg0.conf | awk '{print $3}' || echo "904")
                    if systemctl is-active wg-quick@wg0 >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "wireguard")
                    fi
                fi
                ;;
            amneziawg)
                if [ -f "/etc/amnezia/amneziawg/awg0.conf" ]; then
                    inst="Yes"
                    port=$(grep -Ei '^ListenPort' /etc/amnezia/amneziawg/awg0.conf | awk '{print $3}' || echo "51820")
                    if systemctl is-active awg-quick@awg0 >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "amneziawg")
                    fi
                fi
                ;;
            http)
                if [ -f "/etc/systemd/system/mhpanel-http-proxy.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/mhpanel-http-proxy.service | awk -F: '{print $2}' | tail -n1 || echo "8080")
                    if systemctl is-active mhpanel-http-proxy >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "http" "$port")
                    fi
                fi
                ;;
            socks)
                if [ -f "/etc/systemd/system/mhpanel-socks-proxy.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/mhpanel-socks-proxy.service | awk -F: '{print $2}' | tail -n1 || echo "1080")
                    if systemctl is-active mhpanel-socks-proxy >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "socks" "$port")
                    fi
                fi
                ;;
            shadowsocks)
                if [ -f "/etc/vpnpanel/shadowsocks.json" ] || [ -f "/etc/systemd/system/mhpanel-shadowsocks.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '"server_port":\s*[0-9]+' /etc/vpnpanel/shadowsocks.json 2>/dev/null | awk '{print $2}' || echo "8388")
                    if systemctl is-active mhpanel-shadowsocks >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "shadowsocks" "$port")
                    fi
                fi
                ;;
            tuic)
                if [ -f "/etc/vpnpanel/tuic.json" ] || [ -f "/etc/vpnpanel/tuic.toml" ] || [ -f "/etc/systemd/system/mhpanel-tuic.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '"server":\s*"[^"]*:[0-9]+"' /etc/vpnpanel/tuic.json 2>/dev/null | awk -F: '{print $NF}' | tr -d '"')
                    if [ -z "$port" ]; then
                        port=$(grep -oE 'server\s*=\s*"[^"]*:[0-9]+"' /etc/vpnpanel/tuic.toml 2>/dev/null | awk -F: '{print $NF}' | tr -d '"')
                    fi
                    port=${port:-7443}
                    if systemctl is-active mhpanel-tuic >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "tuic" "$port")
                    fi
                fi
                ;;
            mtproto)
                if [ -f "/etc/systemd/system/mhpanel-mtproto@.service" ]; then
                    inst="Yes"
                    first_conf=$(ls /etc/vpnpanel/mtproto_config_*.py 2>/dev/null | head -n1 || true)
                    if [ -n "${first_conf}" ]; then
                        port=$(grep -E '^PORT = ' "${first_conf}" | awk '{print $3}')
                    else
                        port="4433"
                    fi
                    if systemctl is-active mhpanel-mtproto@${port} >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "mtproto" "$port")
                    fi
                fi
                ;;
            dnstt)
                if [ -f "/etc/systemd/system/mhpanel-dnstt.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '\-udp [0-9.:]+' /etc/systemd/system/mhpanel-dnstt.service 2>/dev/null | awk -F: '{print $2}' || echo "5300")
                    if systemctl is-active mhpanel-dnstt >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "dnstt" "$port")
                    fi
                fi
                ;;
            vaydns)
                if [ -f "/etc/systemd/system/mhpanel-vaydns.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '\-udp [0-9.:]+' /etc/systemd/system/mhpanel-vaydns.service 2>/dev/null | awk -F: '{print $2}' || echo "5353")
                    if systemctl is-active mhpanel-vaydns >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "vaydns" "$port")
                    fi
                fi
                ;;
            slipstream)
                if [ -f "/etc/systemd/system/mhpanel-slipstream.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '\-l [0-9]+' /etc/systemd/system/mhpanel-slipstream.service 2>/dev/null | awk '{print $2}' || echo "5354")
                    if systemctl is-active mhpanel-slipstream >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "slipstream" "$port")
                    fi
                fi
                ;;
            hysteria2)
                if [ -f "/etc/vpnpanel/hysteria2.yaml" ] && [ -f "/etc/systemd/system/mhpanel-hysteria2.service" ]; then
                    inst="Yes"
                    port=$(grep -oE 'listen: :[0-9]+' /etc/vpnpanel/hysteria2.yaml 2>/dev/null | awk -F: '{print $3}' || echo "11443")
                    if systemctl is-active mhpanel-hysteria2 >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "hysteria2" "$port")
                    fi
                fi
                ;;
            trojan)
                if [ -f "/etc/vpnpanel/trojan.json" ] && [ -f "/etc/systemd/system/mhpanel-trojan.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '"listen_port":\s*[0-9]+' /etc/vpnpanel/trojan.json 2>/dev/null | awk '{print $2}' || echo "12443")
                    if systemctl is-active mhpanel-trojan >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "trojan" "$port")
                    fi
                fi
                ;;
            naiveproxy)
                if [ -f "/etc/vpnpanel/naiveproxy.json" ] && [ -f "/etc/systemd/system/mhpanel-naiveproxy.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '"listen_port":\s*[0-9]+' /etc/vpnpanel/naiveproxy.json 2>/dev/null | awk '{print $2}' || echo "13443")
                    if systemctl is-active mhpanel-naiveproxy >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "naiveproxy" "$port")
                    fi
                fi
                ;;
            stuntls)
                if [ -f "/etc/vpnpanel/stuntls.json" ] && [ -f "/etc/systemd/system/mhpanel-stuntls.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/stuntls.json 2>/dev/null | awk '{print $2}' || echo "3478")
                    if systemctl is-active mhpanel-stuntls >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "stuntls" "$port")
                    fi
                fi
                ;;
            noizdns)
                if [ -f "/etc/vpnpanel/noizdns.json" ] && [ -f "/etc/systemd/system/mhpanel-noizdns.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/noizdns.json 2>/dev/null | awk '{print $2}' || echo "5355")
                    if systemctl is-active mhpanel-noizdns >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "noizdns" "$port")
                    fi
                fi
                ;;
            masterdnsvpn)
                if [ -f "/etc/vpnpanel/masterdnsvpn.json" ] && [ -f "/etc/systemd/system/mhpanel-masterdnsvpn.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/masterdnsvpn.json 2>/dev/null | awk '{print $2}' || echo "5356")
                    if systemctl is-active mhpanel-masterdnsvpn >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "masterdnsvpn" "$port")
                    fi
                fi
                ;;
            tor)
                if [ -f "/etc/tor/torrc" ] && [ -f "/etc/systemd/system/mhpanel-tor.service" ]; then
                    inst="Yes"
                    port=$(grep -E '^\s*ORPort\s+[0-9]+' /etc/tor/torrc 2>/dev/null | awk '{print $2}' | tail -n1)
                    port=${port:-9001}
                    if systemctl is-active mhpanel-tor >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "tor" "$port")
                    fi
                fi
                ;;
            singbox)
                if ([ -x /usr/local/bin/sing-box ] && [ -f "/etc/sing-box/config.json" ]) || [ -f "/etc/systemd/system/mhpanel-singbox.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '"listen_port":\s*[0-9]+' /etc/sing-box/config.json 2>/dev/null | head -n1 | awk '{print $2}' || echo "20443")
                    if [ "$(service_status mhpanel-singbox sing-box)" = "active" ]; then
                        act="Active"
                        conn=$(get_connections_count "singbox" "$port")
                    fi
                fi
                ;;
            google_script)
                if ([ -f "/etc/vpnpanel/google_script.json" ] && [ -x /usr/local/bin/mhpanel-gas-server ]) || [ -f "/etc/systemd/system/mhpanel-gas-tunnel.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/google_script.json 2>/dev/null | awk '{print $2}' || echo "8448")
                    if [ "$(service_status mhpanel-gas-tunnel)" = "active" ]; then
                        act="Active"
                        conn=$(get_connections_count "google_script" "$port")
                    fi
                fi
                ;;
        esac

        if [ "$inst" = "Yes" ]; then
            local act_color="${RED}"
            if [ "$act" = "Active" ]; then
                act_color="${GREEN}"
                echo -e "  • ${proto^^}: ${GREEN}Installed${NC} | Port: ${CYAN}${port}${NC} | Status: ${act_color}${act}${NC} | Connections: ${CYAN}${conn} active${NC}"
            else
                echo -e "  • ${proto^^}: ${GREEN}Installed${NC} | Port: ${CYAN}${port}${NC} | Status: ${act_color}${act}${NC}"
            fi
        else
            echo -e "  • ${proto^^}: ${RED}Not Installed${NC}"
        fi
    done
    echo -e "${CYAN}================================================================${NC}\n"
}

# ----------------- MAIN COMMAND DISPATCHER -----------------
# Status/log/control calls must stay quiet; otherwise the panel receives helper
# setup output before "active" and shows every protocol as stopped.
case "${ACTION}" in
    install|set-port|reconfigure|"")
        generate_certs
        setup_global_nat
        ;;
esac

if [ -z "${ACTION}" ]; then
    exit 0
fi

service_status() {
    local svc
    for svc in "$@"; do
        if systemctl is-active --quiet "$svc"; then
            echo "active"
            return
        fi
    done
    echo "inactive"
}

case "${ACTION}" in
    install)
        # Only skip reinstall if already installed AND currently running active AND no specific port requested
        if is_protocol_installed "${PROTOCOL}" && [ -z "$ARG3" ]; then
            if systemctl is-active --quiet "mhpanel-${PROTOCOL}" 2>/dev/null || systemctl is-active --quiet "${PROTOCOL}" 2>/dev/null; then
                echo "${PROTOCOL} is already installed and active."
                exit 0
            fi
        fi

        # Port conflict resolution & web server (Apache/Nginx) protection
        if [ "$ARG3" = "0" ] || [ -z "$ARG3" ] || [ "$ARG3" = "null" ]; then
            case "${PROTOCOL}" in
                ssh) ARG3=2222 ;;
                openvpn) ARG3=1194 ;;
                ocserv) ARG3=10443 ;;
                sstp) ARG3=4443 ;;
                wireguard) ARG3=51820 ;;
                amneziawg) ARG3=51821 ;;
                http) ARG3=8080 ;;
                socks) ARG3=1080 ;;
                shadowsocks) ARG3=8388 ;;
                tuic) ARG3=7443 ;;
                mtproto) ARG3=4433 ;;
                pptp) ARG3=1723 ;;
                badvpn) ARG3=7300 ;;
                dnstt) ARG3=5300 ;;
                vaydns) ARG3=5353 ;;
                slipstream) ARG3=5354 ;;
                hysteria2) ARG3=11443 ;;
                trojan) ARG3=12443 ;;
                naiveproxy) ARG3=13443 ;;
                stuntls) ARG3=3478 ;;
                noizdns) ARG3=5355 ;;
                masterdnsvpn) ARG3=5356 ;;
                tor) ARG3=9001 ;;
            esac
        fi

        # Safeguard port 80 and 443 against web server conflict
        if [ "$ARG3" = "80" ] || [ "$ARG3" = "443" ]; then
            case "${PROTOCOL}" in
                ocserv) ARG3=10443 ;;
                amneziawg) ARG3=51821 ;;
                trojan) ARG3=12443 ;;
                naiveproxy) ARG3=13443 ;;
                hysteria2) ARG3=11443 ;;
                http) ARG3=8080 ;;
            esac
        fi

        case "${PROTOCOL}" in
            ssh) install_ssh "$ARG3" ;;
            openvpn) install_openvpn "$ARG3" ;;
            ocserv) install_ocserv "$ARG3" ;;
            ikev2) install_ikev2 ;;
            sstp) install_sstp "$ARG3" ;;
            l2tp) install_l2tp ;;
            l2tpv3) install_l2tpv3 "$ARG3" "$ARG4" ;;
            wireguard) install_wireguard "$ARG3" ;;
            amneziawg) install_amneziawg "$ARG3" ;;
            http) install_http "$ARG3" ;;
            socks) install_socks "$ARG3" ;;
            shadowsocks) install_shadowsocks "$ARG3" ;;
            tuic) install_tuic "$ARG3" ;;
            dnstt) install_dnstt "$ARG3" ;;
            vaydns) install_vaydns "$ARG3" ;;
            slipstream) install_slipstream "$ARG3" ;;
            mtproto) install_mtproto "$ARG3" "$ARG4" ;;
            pptp) install_pptp "$ARG3" ;;
            badvpn) install_badvpn "$ARG3" ;;
            hysteria2) install_hysteria2 "$ARG3" ;;
            trojan) install_trojan "$ARG3" ;;
            naiveproxy) install_naiveproxy "$ARG3" ;;
            stuntls) install_stuntls "$ARG3" ;;
            noizdns) install_noizdns "$ARG3" ;;
            masterdnsvpn) install_masterdnsvpn "$ARG3" ;;
            tor) install_tor "$ARG3" "$ARG4" ;;
            singbox) install_singbox "$ARG3" ;;
            google_script) install_google_script "$ARG3" ;;
            freeradius|radius) install_freeradius "$ARG3" ;;
            *) echo "Unknown protocol: ${PROTOCOL}" && exit 1 ;;
        esac
        ;;
    uninstall)
        case "${PROTOCOL}" in
            ssh) uninstall_ssh ;;
            openvpn) uninstall_openvpn ;;
            ocserv) uninstall_ocserv ;;
            ikev2) uninstall_ikev2 ;;
            sstp) uninstall_sstp ;;
            l2tp) uninstall_l2tp ;;
            l2tpv3) uninstall_l2tpv3 ;;
            wireguard) uninstall_wireguard ;;
            amneziawg) uninstall_amneziawg ;;
            http) uninstall_http ;;
            socks) uninstall_socks ;;
            shadowsocks) uninstall_shadowsocks ;;
            tuic) uninstall_tuic ;;
            dnstt) uninstall_dnstt ;;
            vaydns) uninstall_vaydns ;;
            slipstream) uninstall_slipstream ;;
            mtproto) uninstall_mtproto ;;
            pptp) uninstall_pptp ;;
            badvpn) uninstall_badvpn ;;
            hysteria2) uninstall_hysteria2 ;;
            trojan) uninstall_trojan ;;
            naiveproxy) uninstall_naiveproxy ;;
            stuntls) uninstall_stuntls ;;
            noizdns) uninstall_noizdns ;;
            masterdnsvpn) uninstall_masterdnsvpn ;;
            tor) uninstall_tor ;;
            singbox) uninstall_singbox ;;
            google_script) uninstall_google_script ;;
            freeradius|radius) uninstall_freeradius ;;
            *) echo "Unknown protocol: ${PROTOCOL}" && exit 1 ;;
        esac
        ;;
    set-port)
        case "${PROTOCOL}" in
            ssh) set_port_ssh "$ARG3" ;;
            openvpn) set_port_openvpn "$ARG3" ;;
            ocserv) set_port_ocserv "$ARG3" ;;
            ikev2) echo "Cannot set custom port for IKEv2 (fixed to UDP 500/4500)" && exit 1 ;;
            sstp) set_port_sstp "$ARG3" ;;
            l2tp) echo "Cannot set custom port for L2TP (fixed to UDP 1701)" && exit 1 ;;
            wireguard) set_port_wireguard "$ARG3" ;;
            amneziawg) set_port_amneziawg "$ARG3" ;;
            http) set_port_http "$ARG3" ;;
            socks) set_port_socks "$ARG3" ;;
            shadowsocks) set_port_shadowsocks "$ARG3" ;;
            tuic) set_port_tuic "$ARG3" ;;
            dnstt) set_port_dnstt "$ARG3" ;;
            vaydns) set_port_vaydns "$ARG3" ;;
            slipstream) set_port_slipstream "$ARG3" ;;
            mtproto) set_port_mtproto "$ARG3" ;;
            pptp) set_port_pptp "$ARG3" ;;
            hysteria2) set_port_hysteria2 "$ARG3" ;;
            trojan) set_port_trojan "$ARG3" ;;
            naiveproxy) set_port_naiveproxy "$ARG3" ;;
            stuntls) set_port_stuntls "$ARG3" ;;
            noizdns) set_port_noizdns "$ARG3" ;;
            masterdnsvpn) set_port_masterdnsvpn "$ARG3" ;;
            tor) set_port_tor "$ARG3" ;;
            singbox) set_port_singbox "$ARG3" ;;
            google_script) set_port_google_script "$ARG3" ;;
            *) echo "Unknown protocol: ${PROTOCOL}" && exit 1 ;;
        esac
        ;;
    reconfigure)
        case "${PROTOCOL}" in
            ssh)
                if [ -f "/etc/ssh/sshd_config_vpn" ]; then
                    port=$(grep -Ei '^Port ' /etc/ssh/sshd_config_vpn 2>/dev/null | awk '{print $2}' || echo "2222")
                    install_ssh "${port}"
                fi
                ;;
            openvpn)
                if [ -f "/etc/openvpn/server.conf" ]; then
                    port=$(grep -Ei '^port ' /etc/openvpn/server.conf 2>/dev/null | awk '{print $2}' || echo "1194")
                    proto=$(grep -Ei '^proto ' /etc/openvpn/server.conf 2>/dev/null | awk '{print $2}' || echo "udp")
                    deny_port "${port}" "${proto}"
                    install_openvpn "${port}"
                fi
                ;;
            ocserv)
                if [ -f "/etc/ocserv/ocserv.conf" ]; then
                    port=$(grep -Ei '^tcp-port' /etc/ocserv/ocserv.conf 2>/dev/null | awk '{print $3}' || echo "443")
                    deny_port "${port}" "tcp"
                    deny_port "${port}" "udp"
                    install_ocserv "${port}"
                fi
                ;;
            ikev2)
                if [ -f "/etc/swanctl/conf.d/ikev2.conf" ]; then
                    install_ikev2
                fi
                ;;
            sstp)
                if [ -f "/etc/systemd/system/sstpd.service" ]; then
                    port=$(grep -E '^port=' /etc/accel-ppp.conf 2>/dev/null | head -n1 | cut -d= -f2 || true); port=${port:-$(grep -oE '\-p [0-9]+' /etc/systemd/system/sstpd.service 2>/dev/null | awk '{print $2}' || true)}; port=${port:-4443}
                    deny_port "${port}" "tcp"
                    install_sstp "${port}"
                fi
                ;;
            l2tp)
                if [ -f "/etc/xl2tpd/xl2tpd.conf" ]; then
                    install_l2tp
                fi
                ;;
            wireguard)
                if [ -f "/etc/wireguard/wg0.conf" ]; then
                    port=$(grep -Ei '^ListenPort' /etc/wireguard/wg0.conf 2>/dev/null | awk '{print $3}' || echo "51820")
                    deny_port "${port}" "udp"
                    install_wireguard "${port}"
                fi
                ;;
            dnstt)
                if [ -f "/etc/vpnpanel/dnstt.json" ]; then
                    port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/dnstt.json 2>/dev/null | awk '{print $2}' || echo "5300")
                    install_dnstt "${port}"
                fi
                ;;
            vaydns)
                if [ -f "/etc/vpnpanel/vaydns.json" ]; then
                    port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/vaydns.json 2>/dev/null | awk '{print $2}' || echo "5353")
                    install_vaydns "${port}"
                fi
                ;;
            slipstream)
                if [ -f "/etc/vpnpanel/slipstream.json" ]; then
                    port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/slipstream.json 2>/dev/null | awk '{print $2}' || echo "5354")
                    install_slipstream "${port}"
                fi
                ;;
            pptp)
                if [ -f "/etc/pptpd.conf" ]; then
                    port=$(grep -oE 'Port [0-9]+' /etc/systemd/system/mhpanel-pptp.service 2>/dev/null | awk '{print $2}' | head -n1 || echo "1723")
                    deny_port "${port}" "tcp"
                    install_pptp "${port}"
                fi
                ;;
        esac
        ;;
    install_openvpn_xor)
        ${PANEL_DIR}/scripts/install_openvpn_xor.sh
        exit 0
        ;;
    install_openvpn_udpspeeder)
        ${PANEL_DIR}/scripts/install_udpspeeder.sh
        exit 0
        ;;
    install_openvpn_rosenpass)
        ${PANEL_DIR}/scripts/install_rosenpass.sh
        exit 0
        ;;
    uninstall_openvpn_xor)
        echo "Restoring standard OpenVPN package..."
        DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y openvpn
        systemctl restart openvpn-server@server openvpn-server@server-tcp 2>/dev/null || true
        echo "OpenVPN XOR uninstalled."
        exit 0
        ;;
    uninstall_openvpn_udpspeeder)
        echo "Removing UDPspeeder..."
        systemctl stop udpspeeder-openvpn 2>/dev/null || true
        systemctl disable udpspeeder-openvpn 2>/dev/null || true
        rm -f /etc/systemd/system/udpspeeder-openvpn.service
        rm -f /usr/bin/udpspeeder
        systemctl daemon-reload
        echo "UDPspeeder uninstalled."
        exit 0
        ;;
    uninstall_openvpn_rosenpass)
        echo "Removing Rosenpass..."
        rm -f /usr/bin/rosenpass
        echo "Rosenpass uninstalled."
        exit 0
        ;;
    set-ad-tag)
        case "${PROTOCOL}" in
            mtproto) set_mtproto_ad_tag "$ARG3" ;;
            *) echo "Advertising tag is only supported for mtproto" && exit 1 ;;
        esac
        ;;
    status)
        case "${PROTOCOL}" in
            ssh) service_status mhpanel-ssh ssh-ws sshd ssh ;;
            openvpn) service_status openvpn-server@server openvpn-server@server-tcp openvpn@server openvpn ;;
            ocserv) service_status ocserv ;;
            ikev2) service_status strongswan-starter strongswan strongswan-swanctl ;;
            sstp) service_status sstpd ;;
            l2tp) service_status xl2tpd ;;
            l2tpv3) service_status mhpanel-l2tpv3 ;;
            wireguard) service_status wg-quick@wg0 ;;
            amneziawg) service_status awg-quick@awg0 ;;
            http) service_status mhpanel-http-proxy ;;
            socks) service_status mhpanel-socks-proxy ;;
            shadowsocks) service_status mhpanel-shadowsocks ;;
            tuic) service_status mhpanel-tuic ;;
            dnstt) service_status mhpanel-dnstt ;;
            vaydns) service_status mhpanel-vaydns ;;
            slipstream) service_status mhpanel-slipstream ;;
            mtproto)
                first_conf=$(ls /etc/vpnpanel/mtproto_config_*.py 2>/dev/null | head -n1 || true)
                if [ -n "${first_conf}" ]; then
                    port=$(grep -E '^PORT = ' "${first_conf}" | awk '{print $3}')
                    service_status "mhpanel-mtproto@${port}"
                else
                    echo "inactive"
                fi
                ;;
            pptp) service_status pptpd mhpanel-pptp ;;
            badvpn) service_status badvpn videocall ;;
            hysteria2) service_status mhpanel-hysteria2 ;;
            trojan) service_status mhpanel-trojan ;;
            naiveproxy) service_status mhpanel-naiveproxy ;;
            stuntls) service_status mhpanel-stuntls ;;
            noizdns) service_status mhpanel-noizdns ;;
            masterdnsvpn) service_status mhpanel-masterdnsvpn ;;
            tor) service_status mhpanel-tor ;;
            singbox) service_status mhpanel-singbox sing-box ;;
            google_script) service_status mhpanel-gas-tunnel ;;
            freeradius|radius) service_status freeradius radiusd ;;
            *) echo "Unknown protocol: ${PROTOCOL}" && exit 1 ;;
        esac
        ;;
    status_report)
        print_status_report
        ;;
    logs)
        case "${PROTOCOL}" in
            ssh) journalctl -u mhpanel-ssh -u ssh-ws -u ssh -n 100 --no-pager ;;
            openvpn) journalctl -u openvpn-server@server -u openvpn-server@server-tcp -u openvpn@server -n 100 --no-pager ;;
            ocserv) journalctl -u ocserv -n 100 --no-pager ;;
            ikev2) journalctl -u strongswan-starter -u strongswan -u strongswan-swanctl -n 100 --no-pager ;;
            sstp) journalctl -u sstpd -n 100 --no-pager ;;
            l2tp) journalctl -u xl2tpd -n 100 --no-pager ;;
            l2tpv3) journalctl -u mhpanel-l2tpv3 -n 100 --no-pager ;;
            wireguard) journalctl -u wg-quick@wg0 -n 100 --no-pager ;;
            amneziawg) journalctl -u awg-quick@awg0 -n 100 --no-pager ;;
            http) journalctl -u mhpanel-http-proxy -n 100 --no-pager ;;
            socks) journalctl -u mhpanel-socks-proxy -n 100 --no-pager ;;
            shadowsocks) journalctl -u mhpanel-shadowsocks -n 100 --no-pager ;;
            tuic) journalctl -u mhpanel-tuic -n 100 --no-pager ;;
            dnstt) journalctl -u mhpanel-dnstt -n 100 --no-pager ;;
            vaydns) journalctl -u mhpanel-vaydns -n 100 --no-pager ;;
            slipstream) journalctl -u mhpanel-slipstream -n 100 --no-pager ;;
            mtproto) journalctl -u 'mhpanel-mtproto@*' -n 100 --no-pager ;;
            pptp) journalctl -u pptpd -u mhpanel-pptp -n 100 --no-pager ;;
            badvpn) journalctl -u badvpn -u videocall -n 100 --no-pager ;;
            hysteria2) journalctl -u mhpanel-hysteria2 -n 100 --no-pager ;;
            trojan) journalctl -u mhpanel-trojan -n 100 --no-pager ;;
            naiveproxy) journalctl -u mhpanel-naiveproxy -n 100 --no-pager ;;
            stuntls) journalctl -u mhpanel-stuntls -n 100 --no-pager ;;
            noizdns) journalctl -u mhpanel-noizdns -n 100 --no-pager ;;
            masterdnsvpn) journalctl -u mhpanel-masterdnsvpn -n 100 --no-pager ;;
            tor) journalctl -u mhpanel-tor -n 100 --no-pager ;;
            singbox) journalctl -u mhpanel-singbox -u sing-box -n 100 --no-pager ;;
            google_script) journalctl -u mhpanel-gas-tunnel -n 100 --no-pager ;;
            freeradius|radius) journalctl -u freeradius -u radiusd -n 100 --no-pager ;;
            *) echo "Unknown protocol: ${PROTOCOL}" && exit 1 ;;
        esac
        ;;
    *)
        echo "Usage: $0 {install|uninstall|set-port|set-ad-tag|status|status_report|logs} {ssh|openvpn|ocserv|ikev2|sstp|pptp|l2tp|wireguard|amneziawg|http|socks|shadowsocks|tuic|dnstt|vaydns|slipstream|mtproto|hysteria2|trojan|naiveproxy|stuntls|noizdns|masterdnsvpn|tor|singbox|google_script} [port/ad-tag]"
        exit 1
        ;;
esac
