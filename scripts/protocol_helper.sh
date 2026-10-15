#!/usr/bin/env bash
# Antigravity VPN Dashboard Protocol Helper Script
# Must be executed as root.

set -e

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
        openssl req -x509 -new -nodes -key "${CA_DIR}/ca.key" -subj "/CN=AetherVPN Root CA" -days 3650 -out "${CA_CERT}"
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
        openssl req -x509 -newkey rsa:2048 -nodes -keyout "${PANEL_KEY}" -out "${PANEL_CERT}" -subj "/CN=AetherVPN Panel" -days 3650
        chmod 600 "${PANEL_KEY}"
        chmod 644 "${PANEL_CERT}"
    fi
}

# Helper: Setup Firewall & NAT Routing globally
setup_global_nat() {
    # 1. Enable IP Forwarding
    sysctl -w net.ipv4.ip_forward=1
    sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
    
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
        shadowsocks) [ -f "/etc/systemd/system/aethervpn-shadowsocks.service" ] ;;
        tuic) [ -f "/etc/systemd/system/aethervpn-tuic.service" ] ;;
        dnstt) [ -f "/etc/systemd/system/aethervpn-dnstt.service" ] ;;
        vaydns) [ -f "/etc/systemd/system/aethervpn-vaydns.service" ] ;;
        slipstream) [ -f "/etc/systemd/system/aethervpn-slipstream.service" ] ;;
        mtproto) ls /etc/vpnpanel/mtproto_config_*.py >/dev/null 2>&1 ;;
        pptp) [ -f "/etc/pptpd.conf" ] ;;
        l2tpv3) [ -f "/etc/vpnpanel/l2tpv3_config.json" ] ;;
        hysteria2) [ -f "/etc/vpnpanel/hysteria2.yaml" ] ;;
        trojan) [ -f "/etc/vpnpanel/trojan.json" ] ;;
        naiveproxy) [ -f "/etc/vpnpanel/naiveproxy.json" ] ;;
        stuntls) [ -f "/etc/vpnpanel/stuntls.json" ] ;;
        noizdns) [ -f "/etc/vpnpanel/noizdns.json" ] ;;
        masterdnsvpn) [ -f "/etc/vpnpanel/masterdnsvpn.json" ] ;;
        tor) [ -f "/etc/tor/torrc" ] ;;
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

    apt-get update -y && apt-get install -y openssh-server libpam-radius-auth

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
# AetherVPN — Dedicated SSH Tunnel Daemon
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
Banner /etc/ssh/aethervpn_banner
EOF
    chmod 600 /etc/ssh/sshd_config_vpn

    # ── Login Banner ──
    cat > /etc/ssh/aethervpn_banner <<'BANNER'
╔═══════════════════════════════════════════════╗
║          AetherVPN — SSH Tunnel Server        ║
║     Unauthorized access is strictly banned    ║
╚═══════════════════════════════════════════════╝
BANNER

    # ── PAM config (isolated — standard unix auth by default) ──
    cat > /etc/pam.d/sshd-vpn <<'EOF'
# PAM for AetherVPN SSH Tunnel
@include common-auth
@include common-account
@include common-session
@include common-password
EOF

    # ── systemd service ──
    cat > /etc/systemd/system/aethervpn-ssh.service <<EOF
[Unit]
Description=AetherVPN SSH Tunnel Daemon (Port ${port})
Documentation=https://github.com/aethervpn
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
    systemctl enable aethervpn-ssh
    systemctl restart aethervpn-ssh

    echo "✓ AetherVPN SSH installed on port ${port}"
    echo "✓ System SSH on port 22 is UNCHANGED"
}

uninstall_ssh() {
    systemctl stop aethervpn-ssh || true
    systemctl disable aethervpn-ssh || true
    
    port=$(grep -Ei '^Port ' /etc/ssh/sshd_config_vpn | awk '{print $2}' 2>/dev/null || echo "2222")
    [ -n "${port}" ] && deny_port "${port}" "tcp"
    
    rm -f /etc/ssh/sshd_config_vpn /etc/pam.d/sshd-vpn /etc/systemd/system/aethervpn-ssh.service /usr/sbin/sshd-vpn
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
    systemctl restart aethervpn-ssh
}

# ----------------- OPENVPN PROTOCOL -----------------
install_openvpn() {
    local port=${1:-1194}
    local proto=$(get_setting "openvpn_proto" "udp")
    local cipher=$(get_setting "openvpn_cipher" "AES-256-GCM")
    local subnet=$(get_setting "openvpn_subnet" "10.8.0.0")
    local dns1=$(get_setting "openvpn_dns1" "8.8.8.8")
    local dns2=$(get_setting "openvpn_dns2" "8.8.4.4")

    apt-get update -y && apt-get install -y openvpn libpam-radius-auth
    generate_certs

    if [ ! -f /etc/openvpn/tls-crypt.key ]; then
        openvpn --genkey --secret /etc/openvpn/tls-crypt.key
        chmod 600 /etc/openvpn/tls-crypt.key
    fi
    
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
plugin /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so openvpn
username-as-common-name
verify-client-cert none
EOF

    cat > /etc/pam.d/openvpn <<EOF
auth sufficient pam_radius_auth.so
account sufficient pam_radius_auth.so
session sufficient pam_radius_auth.so
auth required pam_unix.so
account required pam_unix.so
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
    local port=${1:-443}
    local subnet=$(get_setting "ocserv_subnet" "10.9.0.0")
    local dns1=$(get_setting "ocserv_dns1" "8.8.8.8")
    local dns2=$(get_setting "ocserv_dns2" "8.8.4.4")

    apt-get update -y && apt-get install -y ocserv libradcli4
    generate_certs
    
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

    apt-get update -y && apt-get install -y strongswan strongswan-pki libcharon-extra-plugins libstrongswan-extra-plugins strongswan-swanctl
    generate_certs
    
    # Symlink Certs for strongSwan swanctl
    mkdir -p /etc/swanctl/x509ca /etc/swanctl/x509 /etc/swanctl/private /etc/swanctl/conf.d
    ln -sf "${CA_CERT}" /etc/swanctl/x509ca/ca.crt
    ln -sf "${SERVER_CERT}" /etc/swanctl/x509/vpn-server.crt
    ln -sf "${SERVER_KEY}" /etc/swanctl/private/vpn-server.key
    
    # Create IKEv2 Config
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
LOG_FILE="/var/log/aethervpn-connections.log"
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
    
    # Try enabling and restarting strongswan-swanctl, strongswan-starter or strongswan service depending on what's installed
    local svc_name="strongswan"
    if systemctl list-unit-files | grep -q strongswan-swanctl.service; then
        svc_name="strongswan-swanctl"
    elif systemctl list-unit-files | grep -q strongswan-starter.service; then
        svc_name="strongswan-starter"
    elif systemctl list-unit-files | grep -q strongswan.service; then
        svc_name="strongswan"
    fi

    echo "Enabling and starting strongSwan service: ${svc_name}"
    systemctl daemon-reload
    systemctl enable "${svc_name}" || true
    systemctl restart "${svc_name}" || true
    
    # Wait a few seconds to let charon initialize and create the vici socket
    sleep 3
    swanctl --load-all || true
}

uninstall_ikev2() {
    systemctl stop strongswan-swanctl || true
    systemctl disable strongswan-swanctl || true
    systemctl stop strongswan-starter || true
    systemctl disable strongswan-starter || true
    systemctl stop strongswan || true
    systemctl disable strongswan || true
    deny_port "500" "udp"
    deny_port "4500" "udp"
    rm -f /etc/swanctl/conf.d/ikev2.conf
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

    apt-get update -y
    apt-get install -y ppp curl git libpam-radius-auth iproute2
    
    # Try installing accel-ppp from repositories. If it fails, compile from source.
    if ! apt-get install -y accel-ppp; then
        echo "accel-ppp package not found in repositories. Compiling from source..."
        
        # Install build dependencies
        apt-get install -y build-essential cmake gcc git libpcre2-dev libssl-dev liblua5.1-0-dev linux-headers-$(uname -r)
        
        # Clone, build, and package accel-ppp without IPOE/VLAN modules to avoid kernel source compilation requirements
        rm -rf /usr/src/accel-ppp
        git clone https://github.com/accel-ppp/accel-ppp.git /usr/src/accel-ppp
        mkdir -p /usr/src/accel-ppp/build
        cd /usr/src/accel-ppp/build
        cmake -DBUILD_IPOE_DRIVER=FALSE -DBUILD_VLAN_MON_DRIVER=FALSE -DCMAKE_INSTALL_PREFIX=/usr -DKDIR=/usr/src/linux-headers-$(uname -r) -DLUA=TRUE ..
        make -j$(nproc)
        cpack -G DEB
        dpkg -i accel-ppp*.deb || apt-get install -f -y
        
        # Cleanup
        cd -
        rm -rf /usr/src/accel-ppp
    fi
    generate_certs

    mkdir -p /etc/accel-ppp /var/log/accel-ppp /etc/ppp/ip-up.d /etc/ppp/ip-down.d

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
ip-up=/etc/ppp/ip-up.d/aethervpn-sstp
ip-down=/etc/ppp/ip-down.d/aethervpn-sstp

[sstp]
bind=0.0.0.0
port=${port}
cert=${SERVER_CERT}
key=${SERVER_KEY}
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

    cat > /etc/ppp/ip-up.d/aethervpn-sstp <<'EOF'
#!/usr/bin/env bash
EXT_IF=$(ip route show default | awk '/default/ {print $5}' | head -n1)
if [ -n "$EXT_IF" ]; then
    iptables -t nat -C POSTROUTING -s 10.11.0.0/16 -o "$EXT_IF" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s 10.11.0.0/16 -o "$EXT_IF" -j MASQUERADE
fi
EOF
    cat > /etc/ppp/ip-down.d/aethervpn-sstp <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x /etc/ppp/ip-up.d/aethervpn-sstp /etc/ppp/ip-down.d/aethervpn-sstp

    local accel_bin="/usr/sbin/accel-pppd"
    if [ ! -x "${accel_bin}" ] && [ -x "/usr/local/sbin/accel-pppd" ]; then
        accel_bin="/usr/local/sbin/accel-pppd"
    fi

    cat > /etc/systemd/system/sstpd.service <<EOF
[Unit]
Description=AetherVPN SSTP Server (accel-ppp)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=${accel_bin} -c /etc/accel-ppp.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl enable sstpd
    systemctl restart sstpd
}

uninstall_sstp() {
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

    apt-get update -y && apt-get install -y pptpd ppp libpam-radius-auth

    # Configure pptpd
    cat > /etc/pptpd.conf <<EOF
option /etc/ppp/options.pptpd
logwtmp
localip ${localip}
remoteip ${remotestart}-${remoteend}
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
# PAM for AetherVPN PPTP
@include common-auth
@include common-account
@include common-session
@include common-password
EOF

    # systemd service
    cat > /etc/systemd/system/aethervpn-pptp.service <<EOF
[Unit]
Description=AetherVPN PPTP VPN Server (Port ${port})
After=network.target
Wants=network.target

[Service]
Type=forking
ExecStartPre=/usr/sbin/pptpd --check
ExecStart=/usr/sbin/pptpd --fg --conf /etc/pptpd.conf
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartSec=3
PIDFile=/var/run/pptpd.pid

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
    systemctl daemon-reload
    systemctl enable aethervpn-pptp
    systemctl restart aethervpn-pptp

    # Install Global PPP Logging Scripts (covers PPTP, L2TP, SSTP)
    cat > /etc/ppp/ip-up.d/aethervpn-logging <<'EOF'
#!/usr/bin/env bash
LOG_FILE="/var/log/aethervpn-connections.log"
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

    cat > /etc/ppp/ip-down.d/aethervpn-logging <<'EOF'
#!/usr/bin/env bash
LOG_FILE="/var/log/aethervpn-connections.log"
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
    chmod +x /etc/ppp/ip-up.d/aethervpn-logging /etc/ppp/ip-down.d/aethervpn-logging

    echo "✓ AetherVPN PPTP installed on port ${port}"
}

uninstall_pptp() {
    systemctl stop aethervpn-pptp || true
    systemctl disable aethervpn-pptp || true
    local port=$(grep -oE 'Port [0-9]+' /etc/systemd/system/aethervpn-pptp.service 2>/dev/null | awk '{print $2}' | head -n1 || echo "1723")
    deny_port "${port}" "tcp"
    rm -f /etc/pptpd.conf /etc/ppp/options.pptpd /etc/pam.d/pptpd /etc/systemd/system/aethervpn-pptp.service
    systemctl daemon-reload
}

set_port_pptp() {
    local port=$1
    local old_port=$(grep -oE 'Port [0-9]+' /etc/systemd/system/aethervpn-pptp.service 2>/dev/null | awk '{print $2}' | head -n1 || echo "1723")
    [ -n "${old_port}" ] && [ "${old_port}" != "${port}" ] && deny_port "${old_port}" "tcp"
    sed -i "s/Port [0-9]*/Port ${port}/g" /etc/systemd/system/aethervpn-pptp.service
    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl restart aethervpn-pptp
}

# ----------------- L2TP PROTOCOL -----------------
install_l2tp() {
    local subnet=$(get_setting "l2tp_subnet" "192.168.42.0")
    local psk=$(get_setting "l2tp_psk" "VpnSecret123")
    local dns1=$(get_setting "l2tp_dns1" "8.8.8.8")
    local dns2=$(get_setting "l2tp_dns2" "1.1.1.1")
    local auth_mode=$(get_setting "l2tp_auth_mode" "mschapv2")

    apt-get update -y && apt-get install -y xl2tpd ppp strongswan libpam-radius-auth iproute2 iptables-persistent linux-modules-extra-$(uname -r) || true
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
    modprobe l2tp_eth || true
    modprobe l2tp_netlink || true
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

    cat > /etc/systemd/system/aethervpn-l2tpv3.service <<EOF
[Unit]
Description=AetherVPN L2TPv3 Ethernet Tunnel
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
    systemctl enable aethervpn-l2tpv3
    systemctl start aethervpn-l2tpv3
    echo "✓ L2TPv3 tunnel configured: ${local_ip} <-> ${remote_ip}"
}

uninstall_l2tpv3() {
    systemctl stop aethervpn-l2tpv3 || true
    systemctl disable aethervpn-l2tpv3 || true
    local port=$(python3 -c "import json; d=json.load(open('/etc/vpnpanel/l2tpv3_config.json')); print(d.get('port',5555))" 2>/dev/null || echo 5555)
    local encap=$(python3 -c "import json; d=json.load(open('/etc/vpnpanel/l2tpv3_config.json')); print(d.get('encap','udp'))" 2>/dev/null || echo udp)
    [ "${encap}" = "udp" ] && deny_port "${port}" "udp"
    rm -f /etc/systemd/system/aethervpn-l2tpv3.service /etc/vpnpanel/l2tpv3_config.json /etc/modules-load.d/l2tpv3.conf
    systemctl daemon-reload
}

# ----------------- WIREGUARD PROTOCOL -----------------
install_wireguard() {
    local port=${1:-51820}
    local subnet=$(get_setting "wireguard_subnet" "10.13.0.0")
    
    apt-get update -y && apt-get install -y wireguard wireguard-tools qrencode
    
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
    if [ -f "/etc/systemd/system/aethervpn-wg-radius.service" ]; then
        systemctl daemon-reload
        systemctl enable aethervpn-wg-radius || true
        systemctl restart aethervpn-wg-radius || true
    fi
}

uninstall_wireguard() {
    systemctl stop aethervpn-wg-radius || true
    systemctl disable aethervpn-wg-radius || true
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
    local port=${1:-51820}
    /www/wwwroot/mhpanel/scripts/install_amneziawg.sh "${port}"
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
    apt-get update -y && apt-get install -y python3 python3-venv python3-pip openssl
    if [ ! -x "${PANEL_PYTHON}" ]; then
        python3 -m venv "${PANEL_VENV}"
    fi
    ${PANEL_PYTHON} -m pip install --upgrade pip
}

install_http() {
    local port=${1:-8080}
    ensure_proxy_python_tools
    cat > /etc/systemd/system/aethervpn-http-proxy.service <<EOF
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
    systemctl enable aethervpn-http-proxy
    systemctl restart aethervpn-http-proxy
}

uninstall_http() {
    systemctl stop aethervpn-http-proxy || true
    systemctl disable aethervpn-http-proxy || true
    local port=$(grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/aethervpn-http-proxy.service 2>/dev/null | awk -F: '{print $2}' | tail -n1 || echo "8080")
    deny_port "${port}" "tcp"
    rm -f /etc/systemd/system/aethervpn-http-proxy.service
    systemctl daemon-reload
}

set_port_http() {
    local port=$1
    local old_port=$(grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/aethervpn-http-proxy.service 2>/dev/null | awk -F: '{print $2}' | tail -n1 || echo "8080")
    [ -n "${old_port}" ] && [ "${old_port}" != "${port}" ] && deny_port "${old_port}" "tcp"
    sed -i "s#http://0.0.0.0:[0-9]*#http://0.0.0.0:${port}#g" /etc/systemd/system/aethervpn-http-proxy.service
    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl restart aethervpn-http-proxy
}

install_socks() {
    local port=${1:-1080}
    ensure_proxy_python_tools
    cat > /etc/systemd/system/aethervpn-socks-proxy.service <<EOF
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
    systemctl enable aethervpn-socks-proxy
    systemctl restart aethervpn-socks-proxy
}

uninstall_socks() {
    systemctl stop aethervpn-socks-proxy || true
    systemctl disable aethervpn-socks-proxy || true
    local port=$(grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/aethervpn-socks-proxy.service 2>/dev/null | awk -F: '{print $2}' | tail -n1 || echo "1080")
    deny_port "${port}" "tcp"
    rm -f /etc/systemd/system/aethervpn-socks-proxy.service
    systemctl daemon-reload
}

set_port_socks() {
    local port=$1
    local old_port=$(grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/aethervpn-socks-proxy.service 2>/dev/null | awk -F: '{print $2}' | tail -n1 || echo "1080")
    [ -n "${old_port}" ] && [ "${old_port}" != "${port}" ] && deny_port "${old_port}" "tcp"
    sed -i "s#socks5://0.0.0.0:[0-9]*#socks5://0.0.0.0:${port}#g" /etc/systemd/system/aethervpn-socks-proxy.service
    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl restart aethervpn-socks-proxy
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

    cat > /etc/systemd/system/aethervpn-shadowsocks.service <<EOF
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
    systemctl enable aethervpn-shadowsocks
    systemctl restart aethervpn-shadowsocks
}

uninstall_shadowsocks() {
    systemctl stop aethervpn-shadowsocks || true
    systemctl disable aethervpn-shadowsocks || true
    local port=$(grep -oE '"server_port":\s*[0-9]+' /etc/vpnpanel/shadowsocks.json 2>/dev/null | awk '{print $2}' || echo "8388")
    deny_port "${port}" "tcp"
    deny_port "${port}" "udp"
    rm -f /etc/systemd/system/aethervpn-shadowsocks.service
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
    systemctl restart aethervpn-shadowsocks
}

install_tuic() {
    local port=${1:-7443}
    mkdir -p /etc/vpnpanel
    local config="/etc/vpnpanel/tuic.toml"
    if [ ! -f "${config}" ]; then
        local uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)
        local cert="/etc/vpnpanel/certs/server.crt"
        local key="/etc/vpnpanel/certs/server.key"
        [ -f "$cert" ] || cert="/etc/vpnpanel/server.crt"
        [ -f "$key" ] || key="/etc/vpnpanel/server.key"
        cat > "${config}" <<EOF
server = "0.0.0.0:${port}"
users = { "${uuid}" = "tuicpassword" }
certificate = "${cert}"
private_key = "${key}"
congestion_control = "bbr"
alpn = [ "h3" ]
zero_rtt_handshake = true
log_level = "info"
EOF
        chmod 600 "${config}"
    else
        sed -i -E "s/server = \"0\.0\.0\.0:[0-9]+\"/server = \"0.0.0.0:${port}\"/g" "${config}"
    fi

    cat > /etc/systemd/system/aethervpn-tuic.service <<EOF
[Unit]
Description=TUIC v5 QUIC Anti-Censorship Proxy Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/tuic-server -c /etc/vpnpanel/tuic.toml
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    allow_port "${port}" "udp"
    systemctl daemon-reload
    systemctl enable aethervpn-tuic
    systemctl restart aethervpn-tuic
}

uninstall_tuic() {
    systemctl stop aethervpn-tuic || true
    systemctl disable aethervpn-tuic || true
    local port=$(grep -oE 'server = "[^"]*:[0-9]+"' /etc/vpnpanel/tuic.toml 2>/dev/null | awk -F: '{print $2}' | tr -d '"' || echo "7443")
    deny_port "${port}" "udp"
    rm -f /etc/systemd/system/aethervpn-tuic.service
    systemctl daemon-reload
}

set_port_tuic() {
    local port=$1
    local old_port=$(grep -oE 'server = "[^"]*:[0-9]+"' /etc/vpnpanel/tuic.toml 2>/dev/null | awk -F: '{print $2}' | tr -d '"' || echo "7443")
    [ -n "${old_port}" ] && [ "${old_port}" != "${port}" ] && deny_port "${old_port}" "udp"
    sed -i -E "s/server = \"0\.0\.0\.0:[0-9]+\"/server = \"0.0.0.0:${port}\"/g" /etc/vpnpanel/tuic.toml
    allow_port "${port}" "udp"
    systemctl daemon-reload
    systemctl restart aethervpn-tuic
}


install_mtproto() {
    local port=${1:-4433}
    local ad_tag=${2:-}
    local config="/etc/vpnpanel/mtproto_config_${port}.py"
    ensure_proxy_python_tools
    ${PANEL_PYTHON} -m pip install mtprotoproxy
    # Patch Python 3.12 compatibility issue in mtprotoproxy library
    local mtproto_py=$(${PANEL_PYTHON} -c "import site; print(site.getsitepackages()[0])" 2>/dev/null || echo "")/mtprotoproxy.py
    [ -f "$mtproto_py" ] && sed -i 's/reuse_port=reuse_port, loop=loop/reuse_port=reuse_port/g' "$mtproto_py"
    mkdir -p /etc/vpnpanel
    local secret=$(openssl rand -hex 16)
    cat > "${config}" <<EOF
PORT = ${port}
USERS = {
    "aethervpn": "${secret}",
}
MODES = {"classic": True, "secure": True, "tls": True}
AD_TAG = "${ad_tag}"
EOF
    chmod 600 "${config}"
    
    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl enable aethervpn-mtproto@${port}
    systemctl restart aethervpn-mtproto@${port}
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
                    systemctl stop aethervpn-mtproto@${port} || true
                    systemctl disable aethervpn-mtproto@${port} || true
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
            systemctl stop aethervpn-mtproto@${old_port} || true
            systemctl disable aethervpn-mtproto@${old_port} || true
            deny_port "${old_port}" "tcp"
            
            local new_config="/etc/vpnpanel/mtproto_config_${port}.py"
            mv "${first_config}" "${new_config}"
            sed -i "s/^PORT = .*/PORT = ${port}/g" "${new_config}"
            
            allow_port "${port}" "tcp"
            systemctl daemon-reload
            systemctl enable aethervpn-mtproto@${port}
            systemctl restart aethervpn-mtproto@${port}
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
                    systemctl restart aethervpn-mtproto@${port}
                fi
            fi
        done
    fi
}

# ----------------- HYSTERIA 2 -----------------
install_hysteria2() {
    local port=${1:-11443}
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
    allow_port "${port}" "udp"
    systemctl daemon-reload
    systemctl enable aethervpn-hysteria2
    systemctl restart aethervpn-hysteria2
    echo "Hysteria 2 installed on UDP port ${port}."
}

uninstall_hysteria2() {
    systemctl stop aethervpn-hysteria2 || true
    systemctl disable aethervpn-hysteria2 || true
    local port=$(grep -oE 'listen: :[0-9]+' /etc/vpnpanel/hysteria2.yaml 2>/dev/null | awk -F: '{print $3}' || echo "7443")
    deny_port "${port}" "udp"
    rm -f /etc/vpnpanel/hysteria2.yaml
    echo "Hysteria 2 uninstalled."
}

set_port_hysteria2() {
    local port=$1
    if [ -f /etc/vpnpanel/hysteria2.yaml ]; then
        local old_port=$(grep -oE 'listen: :[0-9]+' /etc/vpnpanel/hysteria2.yaml 2>/dev/null | awk -F: '{print $3}' || echo "7443")
        deny_port "${old_port}" "udp"
        sed -i -E "s/listen: :[0-9]+/listen: :${port}/g" /etc/vpnpanel/hysteria2.yaml
        allow_port "${port}" "udp"
        systemctl restart aethervpn-hysteria2
    fi
}

# ----------------- TROJAN -----------------
install_trojan() {
    local port=${1:-8443}
    mkdir -p /etc/vpnpanel
    generate_certs
    if [ ! -f /etc/vpnpanel/trojan.json ]; then
        local secret=$(openssl rand -hex 16)
        cat > /etc/vpnpanel/trojan.json <<EOF
{
  "log": {"level": "warn"},
  "dns": {"servers": [{"tag": "remote", "type": "udp", "server": "8.8.8.8"}]},
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
    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl enable aethervpn-trojan
    systemctl restart aethervpn-trojan
    echo "Trojan installed on TCP port ${port}."
}

uninstall_trojan() {
    systemctl stop aethervpn-trojan || true
    systemctl disable aethervpn-trojan || true
    local port=$(grep -oE '"listen_port":\s*[0-9]+' /etc/vpnpanel/trojan.json 2>/dev/null | awk '{print $2}' || echo "8443")
    deny_port "${port}" "tcp"
    rm -f /etc/vpnpanel/trojan.json
    echo "Trojan uninstalled."
}

set_port_trojan() {
    local port=$1
    if [ -f /etc/vpnpanel/trojan.json ]; then
        local old_port=$(grep -oE '"listen_port":\s*[0-9]+' /etc/vpnpanel/trojan.json 2>/dev/null | awk '{print $2}' || echo "8443")
        deny_port "${old_port}" "tcp"
        sed -i -E "s/\"listen_port\":\s*[0-9]+/\"listen_port\": ${port}/g" /etc/vpnpanel/trojan.json
        allow_port "${port}" "tcp"
        systemctl restart aethervpn-trojan
    fi
}

# ----------------- NAIVEPROXY -----------------
install_naiveproxy() {
    local port=${1:-8444}
    mkdir -p /etc/vpnpanel
    generate_certs
    if [ ! -f /etc/vpnpanel/naiveproxy.json ]; then
        local secret=$(openssl rand -hex 16)
        cat > /etc/vpnpanel/naiveproxy.json <<EOF
{
  "log": {"level": "warn"},
  "dns": {"servers": [{"tag": "remote", "type": "udp", "server": "8.8.8.8"}]},
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
    allow_port "${port}" "tcp"
    systemctl daemon-reload
    systemctl enable aethervpn-naiveproxy
    systemctl restart aethervpn-naiveproxy
    echo "NaiveProxy installed on TCP port ${port}."
}

uninstall_naiveproxy() {
    systemctl stop aethervpn-naiveproxy || true
    systemctl disable aethervpn-naiveproxy || true
    local port=$(grep -oE '"listen_port":\s*[0-9]+' /etc/vpnpanel/naiveproxy.json 2>/dev/null | awk '{print $2}' || echo "8444")
    deny_port "${port}" "tcp"
    rm -f /etc/vpnpanel/naiveproxy.json
    echo "NaiveProxy uninstalled."
}

set_port_naiveproxy() {
    local port=$1
    if [ -f /etc/vpnpanel/naiveproxy.json ]; then
        local old_port=$(grep -oE '"listen_port":\s*[0-9]+' /etc/vpnpanel/naiveproxy.json 2>/dev/null | awk '{print $2}' || echo "8444")
        deny_port "${old_port}" "tcp"
        sed -i -E "s/\"listen_port\":\s*[0-9]+/\"listen_port\": ${port}/g" /etc/vpnpanel/naiveproxy.json
        allow_port "${port}" "tcp"
        systemctl restart aethervpn-naiveproxy
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
    allow_port "${port}" "tcp"
    allow_port "${port}" "udp"
    systemctl daemon-reload
    systemctl enable aethervpn-stuntls
    systemctl restart aethervpn-stuntls
    echo "StunTLS installed on port ${port}."
}

uninstall_stuntls() {
    systemctl stop aethervpn-stuntls || true
    systemctl disable aethervpn-stuntls || true
    local port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/stuntls.json 2>/dev/null | awk '{print $2}' || echo "3478")
    deny_port "${port}" "tcp"
    deny_port "${port}" "udp"
    rm -f /etc/vpnpanel/stuntls.json
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
        systemctl restart aethervpn-stuntls
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
    allow_port "${port}" "udp"
    systemctl daemon-reload
    systemctl enable aethervpn-noizdns
    systemctl restart aethervpn-noizdns
    echo "NoizDNS installed on UDP port ${port}."
}

uninstall_noizdns() {
    systemctl stop aethervpn-noizdns || true
    systemctl disable aethervpn-noizdns || true
    local port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/noizdns.json 2>/dev/null | awk '{print $2}' || echo "5355")
    deny_port "${port}" "udp"
    rm -f /etc/vpnpanel/noizdns.json
    echo "NoizDNS uninstalled."
}

set_port_noizdns() {
    local port=$1
    if [ -f /etc/vpnpanel/noizdns.json ]; then
        local old_port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/noizdns.json 2>/dev/null | awk '{print $2}' || echo "5355")
        deny_port "${old_port}" "udp"
        sed -i -E "s/\"port\":\s*[0-9]+/\"port\": ${port}/g" /etc/vpnpanel/noizdns.json
        allow_port "${port}" "udp"
        systemctl restart aethervpn-noizdns
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
    allow_port "${port}" "udp"
    systemctl daemon-reload
    systemctl enable aethervpn-masterdnsvpn
    systemctl restart aethervpn-masterdnsvpn
    echo "MasterdnsVPN installed on UDP port ${port}."
}

uninstall_masterdnsvpn() {
    systemctl stop aethervpn-masterdnsvpn || true
    systemctl disable aethervpn-masterdnsvpn || true
    local port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/masterdnsvpn.json 2>/dev/null | awk '{print $2}' || echo "5356")
    deny_port "${port}" "udp"
    rm -f /etc/vpnpanel/masterdnsvpn.json
    echo "MasterdnsVPN uninstalled."
}

set_port_masterdnsvpn() {
    local port=$1
    if [ -f /etc/vpnpanel/masterdnsvpn.json ]; then
        local old_port=$(grep -oE '"port":\s*[0-9]+' /etc/vpnpanel/masterdnsvpn.json 2>/dev/null | awk '{print $2}' || echo "5356")
        deny_port "${old_port}" "udp"
        sed -i -E "s/\"port\":\s*[0-9]+/\"port\": ${port}/g" /etc/vpnpanel/masterdnsvpn.json
        allow_port "${port}" "udp"
        systemctl restart aethervpn-masterdnsvpn
    fi
}

# ----------------- TOR BRIDGES -----------------
install_tor() {
    local or_port=${1:-9001}
    local bridge_port=${2:-9002}
    mkdir -p /etc/vpnpanel /var/lib/tor
    chown -R debian-tor:debian-tor /var/lib/tor 2>/dev/null || true
    cat > /etc/tor/torrc <<EOF
SocksPort 127.0.0.1:9050
RunAsDaemon 0
ORPort ${or_port}
BridgeRelay 1
ServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy
ServerTransportListenAddr obfs4 0.0.0.0:${bridge_port}
PublishServerDescriptor 0
ContactInfo admin@kigaping.com
Nickname MHPanelBridge
DataDirectory /var/lib/tor
EOF
    allow_port "${or_port}" "tcp"
    allow_port "${bridge_port}" "tcp"
    systemctl daemon-reload
    systemctl enable aethervpn-tor
    systemctl restart aethervpn-tor
    echo "Tor Bridge installed with obfs4 on ports ${or_port}/${bridge_port}."
}

uninstall_tor() {
    systemctl stop aethervpn-tor || true
    systemctl disable aethervpn-tor || true
    deny_port "9001" "tcp"
    deny_port "9002" "tcp"
    echo "Tor uninstalled."
}

set_port_tor() {
    local port=$1
    if [ -f /etc/tor/torrc ]; then
        sed -i -E "s/^ORPort [0-9]+/ORPort ${port}/g" /etc/tor/torrc
        allow_port "${port}" "tcp"
        systemctl restart aethervpn-tor
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
        http|socks|shadowsocks|mtproto)
            if [ -n "${port}" ] && [ "${port}" != "-" ]; then
                count=$(ss -t -a | grep ":${port} " | grep -i estab | wc -l)
            else
                count=0
            fi
            ;;
        tuic)
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
        local ip=$(curl -s --max-time 3 ifconfig.me || echo "YOUR_SERVER_IP")
        echo -e "  - Installed: ${GREEN}Yes${NC}"
        echo -e "  - Status:    ${GREEN}${panel_active}${NC}"
        echo -e "  - Address:   ${CYAN}https://${ip}:${panel_port}/${NC}"
    else
        echo -e "  - Installed: ${RED}No${NC}"
    fi
    echo ""

    # 2. Protocols Status
    echo -e "VPN Protocols Status:"
    local protocols=("ssh" "openvpn" "ocserv" "ikev2" "sstp" "pptp" "l2tp" "wireguard" "amneziawg" "http" "socks" "shadowsocks" "tuic" "mtproto" "dnstt" "vaydns" "slipstream")
    for proto in "${protocols[@]}"; do
        local inst="No"
        local act="Inactive"
        local port="-"
        local conn="0"
        
        case "$proto" in
            ssh)
                if [ -f "/etc/ssh/sshd_config_vpn" ]; then
                    port=$(grep -Ei '^Port ' /etc/ssh/sshd_config_vpn | awk '{print $2}' || echo "2222")
                    inst="Yes"
                else
                    inst="No"
                    port="-"
                fi
                if systemctl is-active aethervpn-ssh >/dev/null 2>&1; then
                    act="Active"
                    conn=$(get_connections_count "ssh" "$port")
                fi
                ;;
            openvpn)
                if [ -f "/etc/openvpn/server.conf" ]; then
                    inst="Yes"
                    port=$(grep -Ei '^port ' /etc/openvpn/server.conf | awk '{print $2}' || echo "1194")
                    if systemctl is-active openvpn@server >/dev/null 2>&1; then
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
                if [ -f "/etc/swanctl/conf.d/ikev2.conf" ]; then
                    inst="Yes"
                    port="500/4500 (UDP)"
                    if [ "$(service_status strongswan-starter strongswan strongswan-swanctl)" = "active" ]; then
                        act="Active"
                        conn=$(get_connections_count "ikev2")
                    fi
                fi
                ;;
            sstp)
                if [ -f "/etc/systemd/system/sstpd.service" ]; then
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
                    port=$(grep -oE 'Port [0-9]+' /etc/systemd/system/aethervpn-pptp.service 2>/dev/null | awk '{print $2}' | head -n1 || echo "1723")
                    inst="Yes"
                else
                    inst="No"
                    port="-"
                fi
                if systemctl is-active aethervpn-pptp >/dev/null 2>&1; then
                    act="Active"
                    conn=$(get_connections_count "pptp" "$port")
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
                if [ -f "/etc/systemd/system/aethervpn-http-proxy.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/aethervpn-http-proxy.service | awk -F: '{print $2}' | tail -n1 || echo "8080")
                    if systemctl is-active aethervpn-http-proxy >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "http" "$port")
                    fi
                fi
                ;;
            socks)
                if [ -f "/etc/systemd/system/aethervpn-socks-proxy.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '0\.0\.0\.0:[0-9]+' /etc/systemd/system/aethervpn-socks-proxy.service | awk -F: '{print $2}' | tail -n1 || echo "1080")
                    if systemctl is-active aethervpn-socks-proxy >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "socks" "$port")
                    fi
                fi
                ;;
            shadowsocks)
                if [ -f "/etc/vpnpanel/shadowsocks.json" ] || [ -f "/etc/systemd/system/aethervpn-shadowsocks.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '"server_port":\s*[0-9]+' /etc/vpnpanel/shadowsocks.json 2>/dev/null | awk '{print $2}' || echo "8388")
                    if systemctl is-active aethervpn-shadowsocks >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "shadowsocks" "$port")
                    fi
                fi
                ;;
            tuic)
                if [ -f "/etc/vpnpanel/tuic.toml" ] || [ -f "/etc/systemd/system/aethervpn-tuic.service" ]; then
                    inst="Yes"
                    port=$(grep -oE 'server = "[^"]*:[0-9]+"' /etc/vpnpanel/tuic.toml 2>/dev/null | awk -F: '{print $2}' | tr -d '"' || echo "7443")
                    if systemctl is-active aethervpn-tuic >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "tuic" "$port")
                    fi
                fi
                ;;
            mtproto)
                if [ -f "/etc/systemd/system/aethervpn-mtproto@.service" ]; then
                    inst="Yes"
                    first_conf=$(ls /etc/vpnpanel/mtproto_config_*.py 2>/dev/null | head -n1 || true)
                    if [ -n "${first_conf}" ]; then
                        port=$(grep -E '^PORT = ' "${first_conf}" | awk '{print $3}')
                    else
                        port="4433"
                    fi
                    if systemctl is-active aethervpn-mtproto@${port} >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "mtproto" "$port")
                    fi
                fi
                ;;
            dnstt)
                if [ -f "/etc/systemd/system/aethervpn-dnstt.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '\-udp [0-9.:]+' /etc/systemd/system/aethervpn-dnstt.service 2>/dev/null | awk -F: '{print $2}' || echo "5300")
                    if systemctl is-active aethervpn-dnstt >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "dnstt" "$port")
                    fi
                fi
                ;;
            vaydns)
                if [ -f "/etc/systemd/system/aethervpn-vaydns.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '\-udp [0-9.:]+' /etc/systemd/system/aethervpn-vaydns.service 2>/dev/null | awk -F: '{print $2}' || echo "5353")
                    if systemctl is-active aethervpn-vaydns >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "vaydns" "$port")
                    fi
                fi
                ;;
            slipstream)
                if [ -f "/etc/systemd/system/aethervpn-slipstream.service" ]; then
                    inst="Yes"
                    port=$(grep -oE '\-l [0-9]+' /etc/systemd/system/aethervpn-slipstream.service 2>/dev/null | awk '{print $2}' || echo "5354")
                    if systemctl is-active aethervpn-slipstream >/dev/null 2>&1; then
                        act="Active"
                        conn=$(get_connections_count "slipstream" "$port")
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
        if is_protocol_installed "${PROTOCOL}"; then
            echo "${PROTOCOL} is already installed; skipping reinstall."
            exit 0
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
            mtproto) install_mtproto "$ARG3" "$ARG4" ;;
            pptp) install_pptp "$ARG3" ;;
            hysteria2) install_hysteria2 "$ARG3" ;;
            trojan) install_trojan "$ARG3" ;;
            naiveproxy) install_naiveproxy "$ARG3" ;;
            stuntls) install_stuntls "$ARG3" ;;
            noizdns) install_noizdns "$ARG3" ;;
            masterdnsvpn) install_masterdnsvpn "$ARG3" ;;
            tor) install_tor "$ARG3" "$ARG4" ;;
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
            mtproto) uninstall_mtproto ;;
            pptp) uninstall_pptp ;;
            hysteria2) uninstall_hysteria2 ;;
            trojan) uninstall_trojan ;;
            naiveproxy) uninstall_naiveproxy ;;
            stuntls) uninstall_stuntls ;;
            noizdns) uninstall_noizdns ;;
            masterdnsvpn) uninstall_masterdnsvpn ;;
            tor) uninstall_tor ;;
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
            mtproto) set_port_mtproto "$ARG3" ;;
            pptp) set_port_pptp "$ARG3" ;;
            hysteria2) set_port_hysteria2 "$ARG3" ;;
            trojan) set_port_trojan "$ARG3" ;;
            naiveproxy) set_port_naiveproxy "$ARG3" ;;
            stuntls) set_port_stuntls "$ARG3" ;;
            noizdns) set_port_noizdns "$ARG3" ;;
            masterdnsvpn) set_port_masterdnsvpn "$ARG3" ;;
            tor) set_port_tor "$ARG3" ;;
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
            pptp)
                if [ -f "/etc/pptpd.conf" ]; then
                    port=$(grep -oE 'Port [0-9]+' /etc/systemd/system/aethervpn-pptp.service 2>/dev/null | awk '{print $2}' | head -n1 || echo "1723")
                    deny_port "${port}" "tcp"
                    install_pptp "${port}"
                fi
                ;;
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
            pptp)
                if [ -f "/etc/pptpd.conf" ]; then
                    port=$(grep -oE 'Port [0-9]+' /etc/systemd/system/aethervpn-pptp.service 2>/dev/null | awk '{print $2}' | head -n1 || echo "1723")
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
            ssh) service_status aethervpn-ssh ;;
            openvpn) service_status openvpn@server ;;
            ocserv) service_status ocserv ;;
            ikev2) service_status strongswan-starter strongswan strongswan-swanctl ;;
            sstp) service_status sstpd ;;
            l2tp) service_status xl2tpd ;;
            l2tpv3) service_status aethervpn-l2tpv3 ;;
            wireguard) service_status wg-quick@wg0 ;;
            amneziawg) service_status awg-quick@awg0 ;;
            http) service_status aethervpn-http-proxy ;;
            socks) service_status aethervpn-socks-proxy ;;
            shadowsocks) service_status aethervpn-shadowsocks ;;
            tuic) service_status aethervpn-tuic ;;
            dnstt) service_status aethervpn-dnstt ;;
            vaydns) service_status aethervpn-vaydns ;;
            slipstream) service_status aethervpn-slipstream ;;
            mtproto)
                first_conf=$(ls /etc/vpnpanel/mtproto_config_*.py 2>/dev/null | head -n1 || true)
                if [ -n "${first_conf}" ]; then
                    port=$(grep -E '^PORT = ' "${first_conf}" | awk '{print $3}')
                    service_status "aethervpn-mtproto@${port}"
                else
                    echo "inactive"
                fi
                ;;
            pptp) service_status aethervpn-pptp ;;
            *) echo "Unknown protocol: ${PROTOCOL}" && exit 1 ;;
        esac
        ;;
    status_report)
        print_status_report
        ;;
    logs)
        case "${PROTOCOL}" in
            ssh) journalctl -u aethervpn-ssh -n 100 --no-pager ;;
            openvpn) journalctl -u openvpn@server -n 100 --no-pager ;;
            ocserv) journalctl -u ocserv -n 100 --no-pager ;;
            ikev2) journalctl -u strongswan-swanctl -u strongswan-starter -u strongswan -n 100 --no-pager ;;
            sstp) journalctl -u sstpd -n 100 --no-pager ;;
            l2tp) journalctl -u xl2tpd -n 100 --no-pager ;;
            l2tpv3) journalctl -u aethervpn-l2tpv3 -n 100 --no-pager ;;
            wireguard) journalctl -u wg-quick@wg0 -n 100 --no-pager ;;
            amneziawg) journalctl -u awg-quick@awg0 -n 100 --no-pager ;;
            http) journalctl -u aethervpn-http-proxy -n 100 --no-pager ;;
            socks) journalctl -u aethervpn-socks-proxy -n 100 --no-pager ;;
            shadowsocks) journalctl -u aethervpn-shadowsocks -n 100 --no-pager ;;
            tuic) journalctl -u aethervpn-tuic -n 100 --no-pager ;;
            dnstt) journalctl -u aethervpn-dnstt -n 100 --no-pager ;;
            vaydns) journalctl -u aethervpn-vaydns -n 100 --no-pager ;;
            slipstream) journalctl -u aethervpn-slipstream -n 100 --no-pager ;;
            mtproto) journalctl -u aethervpn-mtproto -n 100 --no-pager ;;
            pptp) journalctl -u aethervpn-pptp -n 100 --no-pager ;;
            *) echo "Unknown protocol: ${PROTOCOL}" && exit 1 ;;
        esac
        ;;
    *)
        echo "Usage: $0 {install|uninstall|set-port|set-ad-tag|status|status_report|logs} {ssh|openvpn|ocserv|ikev2|sstp|pptp|l2tp|wireguard|http|socks|shadowsocks|tuic|mtproto} [port/ad-tag]"
        exit 1
        ;;
esac
