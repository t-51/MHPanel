#!/usr/bin/env bash
# ==============================================================================
# MH Panel - AmneziaWG (Anti-DPI Obfuscated WireGuard) Installer & Setup Script
# ==============================================================================
set -euo pipefail

PORT="${1:-51821}"
SUBNET="${2:-10.77.77.0/24}"
DNS="${3:-8.8.8.8, 1.1.1.1}"

echo "[*] Setting up AmneziaWG with Anti-DPI Obfuscation..."
export DEBIAN_FRONTEND=noninteractive

# Force IPv4 in APT to prevent slow/broken IPv6 lookups
mkdir -p /etc/apt/apt.conf.d
echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4

# Add Amnezia PPA if not already configured
if ! grep -rq "ppa.launchpadcontent.net/amnezia/ppa" /etc/apt/ /etc/apt/sources.list.d/ 2>/dev/null; then
    apt-get update -y
    apt-get install -y software-properties-common
    add-apt-repository -y ppa:amnezia/ppa
    apt-get update -y
fi

# Install kernel headers and amneziawg packages
KERNEL_VER="$(uname -r)"
apt-get install -y "linux-headers-${KERNEL_VER}" dkms amneziawg amneziawg-tools qrencode iptables

# Ensure kernel module is loaded
if ! lsmod | grep -q '^amneziawg '; then
    if command -v mokutil >/dev/null 2>&1 && mokutil --sb-state 2>/dev/null | grep -qi "enabled"; then
        echo "[!] Warning: Secure Boot is enabled on this system. Third-party DKMS kernel modules cannot be inserted without MOK enrollment."
        echo "[!] Please use standard WireGuard (which is signed by the kernel) or disable Secure Boot."
        exit 0
    fi

    # Patch compat.h if on Linux kernel 7.0+
    if [ -f /usr/src/amneziawg-1.0.0/compat/compat.h ]; then
        python3 -c "
with open('/usr/src/amneziawg-1.0.0/compat/compat.h', 'r') as f:
    c = f.read()
if 'KERNEL_VERSION(7, 0, 0)' not in c:
    c = c.replace('#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 1, 5)\n#include <net/udp_tunnel.h>\n#define setup_udp_tunnel_sock(net, sk, sock_cfg) setup_udp_tunnel_sock(net, sk->sk_socket, sock_cfg)\n#define udp_tunnel_sock_release(sk) udp_tunnel_sock_release(sk->sk_socket)\n#endif', '''#include <net/udp_tunnel.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 0, 0)
#define setup_udp_tunnel_sock(net, sk, sock_cfg) setup_udp_tunnel_sock(net, sk->sk_socket, sock_cfg)
#endif
#define udp_tunnel_sock_release(sk) udp_tunnel_sock_release(sk->sk_socket)''')
    with open('/usr/src/amneziawg-1.0.0/compat/compat.h', 'w') as f:
        f.write(c)
" 2>/dev/null || true
    fi

    modprobe amneziawg 2>/dev/null || {
        echo "[!] Rebuilding DKMS module for kernel ${KERNEL_VER}..."
        dkms autoinstall -k "${KERNEL_VER}" 2>/dev/null || true
        depmod -a 2>/dev/null || true
        modprobe amneziawg 2>/dev/null || {
            echo "[!] Kernel module amneziawg not available. Falling back to userspace amneziawg-go..."
            for bdir in /www/wwwroot/mhpanel/bin /usr/local/bin /usr/bin; do
                if [ -f "${bdir}/amneziawg-go" ]; then
                    cp -f "${bdir}/amneziawg-go" /usr/local/bin/amneziawg-go 2>/dev/null || true
                    chmod +x /usr/local/bin/amneziawg-go 2>/dev/null || true
                    cp -f "${bdir}/amneziawg-go" /usr/bin/amneziawg-go 2>/dev/null || true
                    chmod +x /usr/bin/amneziawg-go 2>/dev/null || true
                    break
                fi
            done
            if [ ! -x /usr/local/bin/amneziawg-go ] && [ ! -x /usr/bin/amneziawg-go ]; then
                echo "[!] Could not insert amneziawg kernel module nor find amneziawg-go. Skipping service activation."
                exit 0
            fi
        }
    }
fi

# Detect default network interface
IFACE=$(ip -4 route show default | awk '{print $5}' | head -n1)
if [[ -z "${IFACE}" ]]; then
    IFACE="ens6"
fi

# Enable IPv4 forwarding
touch /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
grep -qxF 'net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

AMNEZIA_DIR="/etc/amnezia/amneziawg"
mkdir -p "${AMNEZIA_DIR}"
chmod 700 "${AMNEZIA_DIR}"

SERVER_IP_BASE="${SUBNET%.*}.1"

# Generate or preserve server keys
if [[ -f "${AMNEZIA_DIR}/private.key" && -f "${AMNEZIA_DIR}/public.key" ]]; then
    SERVER_PRIVKEY=$(cat "${AMNEZIA_DIR}/private.key")
    SERVER_PUBKEY=$(cat "${AMNEZIA_DIR}/public.key")
else
    SERVER_PRIVKEY=$(awg genkey)
    SERVER_PUBKEY=$(echo "${SERVER_PRIVKEY}" | awg pubkey)
    echo "${SERVER_PRIVKEY}" > "${AMNEZIA_DIR}/private.key"
    echo "${SERVER_PUBKEY}" > "${AMNEZIA_DIR}/public.key"
    chmod 600 "${AMNEZIA_DIR}/private.key"
    chmod 644 "${AMNEZIA_DIR}/public.key"
fi

# Preserve existing peers & Anti-DPI params if already configured
PEERS=""
JC="4"
JMIN="50"
JMAX="1000"
S1="56"
S2="56"
H1=$(shuf -i 10000000-2147483647 -n 1)
H2=$(shuf -i 10000000-2147483647 -n 1)
H3=$(shuf -i 10000000-2147483647 -n 1)
H4=$(shuf -i 10000000-2147483647 -n 1)

if [[ -f "${AMNEZIA_DIR}/awg0.conf" ]]; then
    get_val() {
        grep -E "^$1[[:space:]]*=" "${AMNEZIA_DIR}/awg0.conf" 2>/dev/null | head -n1 | awk -F'=' '{print $2}' | tr -d ' ' || true
    }
    _JC=$(get_val "Jc"); [[ -n "${_JC}" ]] && JC="${_JC}"
    _JMIN=$(get_val "Jmin"); [[ -n "${_JMIN}" ]] && JMIN="${_JMIN}"
    _JMAX=$(get_val "Jmax"); [[ -n "${_JMAX}" ]] && JMAX="${_JMAX}"
    _S1=$(get_val "S1"); [[ -n "${_S1}" ]] && S1="${_S1}"
    _S2=$(get_val "S2"); [[ -n "${_S2}" ]] && S2="${_S2}"
    _H1=$(get_val "H1"); [[ -n "${_H1}" ]] && H1="${_H1}"
    _H2=$(get_val "H2"); [[ -n "${_H2}" ]] && H2="${_H2}"
    _H3=$(get_val "H3"); [[ -n "${_H3}" ]] && H3="${_H3}"
    _H4=$(get_val "H4"); [[ -n "${_H4}" ]] && H4="${_H4}"
    PEERS=$(awk '/^\[Peer\]/{flag=1} flag' "${AMNEZIA_DIR}/awg0.conf" || true)
fi

cat > "${AMNEZIA_DIR}/awg0.conf" <<EOF
[Interface]
Address = ${SERVER_IP_BASE}/24, fd77:77::1/64
ListenPort = ${PORT}
PrivateKey = ${SERVER_PRIVKEY}
MTU = 1300

# Anti-DPI Obfuscation Parameters (AmneziaWG)
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
S1 = ${S1}
S2 = ${S2}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}

PostUp = iptables -I INPUT -p udp --dport ${PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${IFACE} -o awg0 -j ACCEPT
PostUp = iptables -I FORWARD -i awg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${IFACE} -j MASQUERADE
PostUp = ip6tables -I FORWARD -i awg0 -j ACCEPT 2>/dev/null || true
PostUp = ip6tables -t nat -A POSTROUTING -o ${IFACE} -j MASQUERADE 2>/dev/null || true

PostDown = iptables -D INPUT -p udp --dport ${PORT} -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -i ${IFACE} -o awg0 -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -i awg0 -j ACCEPT 2>/dev/null || true
PostDown = iptables -t nat -D POSTROUTING -o ${IFACE} -j MASQUERADE 2>/dev/null || true
PostDown = ip6tables -D FORWARD -i awg0 -j ACCEPT 2>/dev/null || true
PostDown = ip6tables -t nat -D POSTROUTING -o ${IFACE} -j MASQUERADE 2>/dev/null || true
${PEERS}
EOF

chmod 600 "${AMNEZIA_DIR}/awg0.conf"

systemctl daemon-reload
systemctl enable awg-quick@awg0
ip link del dev awg0 2>/dev/null || true
systemctl restart awg-quick@awg0

echo "[+] AmneziaWG installed and running on port UDP ${PORT} with Anti-DPI params:"
echo "    Jc=${JC}, Jmin=${JMIN}, Jmax=${JMAX}, S1=${S1}, S2=${S2}"
echo "    H1=${H1}, H2=${H2}, H3=${H3}, H4=${H4}"
