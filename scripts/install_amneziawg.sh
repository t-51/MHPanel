#!/usr/bin/env bash
# ==============================================================================
# MH Panel - AmneziaWG (Anti-DPI Obfuscated WireGuard) Installer & Setup Script
# ==============================================================================
set -o pipefail

PORT="${1:-51821}"
SUBNET="${2:-10.77.77.0/24}"
DNS="${3:-8.8.8.8, 1.1.1.1}"

echo "[*] Setting up AmneziaWG with Anti-DPI Obfuscation..."
export DEBIAN_FRONTEND=noninteractive

# Clean up any previously broken dkms package to keep dpkg healthy
if dpkg -s amneziawg-dkms 2>/dev/null | grep -qE "Status:.*(half|failed|unpack)"; then
    echo "[*] Cleaning up broken amneziawg-dkms package..."
    dpkg --purge amneziawg-dkms amneziawg 2>/dev/null || true
    apt-get -f install -y >/dev/null 2>&1 || true
fi

# 1. Install pre-bundled AmneziaWG tools & userspace binaries from panel package
for bdir in /www/wwwroot/mhpanel/bin /root/mhpanel-repo/bin /root/bin "${SCRIPT_DIR:-}/bin"; do
    if [ -d "$bdir" ]; then
        for b in awg awg-quick amneziawg-go; do
            if [ -f "${bdir}/${b}" ]; then
                cp -f "${bdir}/${b}" "/usr/bin/${b}" 2>/dev/null || true
                cp -f "${bdir}/${b}" "/usr/local/bin/${b}" 2>/dev/null || true
                chmod +x "/usr/bin/${b}" "/usr/local/bin/${b}" 2>/dev/null || true
            fi
        done
    fi
done

# Ensure systemd service template exists
if [ ! -f /etc/systemd/system/awg-quick@.service ] && [ ! -f /lib/systemd/system/awg-quick@.service ] && [ ! -f /usr/lib/systemd/system/awg-quick@.service ]; then
    cat > /etc/systemd/system/awg-quick@.service <<'EOF'
[Unit]
Description=AmneziaWG via awg-quick(8) for %I
After=network-online.target nss-lookup.target
Wants=network-online.target nss-lookup.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/awg-quick up %i
ExecStop=/usr/bin/awg-quick down %i
ExecReload=/bin/bash -c 'exec /usr/bin/awg syncconf %i <(exec /usr/bin/awg-quick strip %i)'
Environment=WG_ENDPOINT_RESOLUTION_RETRIES=infinity

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload 2>/dev/null || true
fi

# 2. Try native kernel module installation (Ubuntu / Debian DKMS)
mkdir -p /etc/apt/apt.conf.d 2>/dev/null || true
echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4 2>/dev/null || true

IS_UBUNTU=0
if [ -f /etc/os-release ] && grep -qi "ubuntu" /etc/os-release; then
    IS_UBUNTU=1
fi

if [ "$IS_UBUNTU" -eq 1 ]; then
    if ! grep -rq "ppa.launchpadcontent.net/amnezia/ppa" /etc/apt/ /etc/apt/sources.list.d/ 2>/dev/null; then
        apt-get update -y >/dev/null 2>&1 || true
        apt-get install -y --no-install-recommends software-properties-common gnupg curl >/dev/null 2>&1 || true
        add-apt-repository -y ppa:amnezia/ppa >/dev/null 2>&1 || true
        apt-get update -y >/dev/null 2>&1 || true
    fi
fi

KERNEL_VER="$(uname -r)"
if apt-get install -y --no-install-recommends "linux-headers-${KERNEL_VER}" dkms amneziawg amneziawg-tools qrencode iptables >/dev/null 2>&1; then
    echo "[*] AmneziaWG packages installed."
else
    # DKMS module build failed on this kernel, purge broken package immediately to keep dpkg clean
    echo "[*] Kernel DKMS build not supported on this kernel version (${KERNEL_VER}). Using userspace amneziawg-go fallback."
    dpkg --purge amneziawg-dkms amneziawg 2>/dev/null || true
    apt-get -f install -y >/dev/null 2>&1 || true
    apt-get install -y --no-install-recommends wireguard-tools qrencode iptables >/dev/null 2>&1 || true
fi

# Re-verify bundled binaries in case apt didn't provide awg or amneziawg-go
for bdir in /www/wwwroot/mhpanel/bin /root/mhpanel-repo/bin; do
    if [ -d "$bdir" ]; then
        for b in awg awg-quick amneziawg-go; do
            if [ -f "${bdir}/${b}" ]; then
                cp -f "${bdir}/${b}" "/usr/bin/${b}" 2>/dev/null || true
                cp -f "${bdir}/${b}" "/usr/local/bin/${b}" 2>/dev/null || true
                chmod +x "/usr/bin/${b}" "/usr/local/bin/${b}" 2>/dev/null || true
            fi
        done
    fi
done

# Ensure kernel module or userspace fallback
if ! lsmod | grep -q '^amneziawg '; then
    modprobe amneziawg 2>/dev/null || {
        echo "[*] AmneziaWG kernel module not active. Operating via high-performance userspace amneziawg-go daemon."
        if [ ! -x /usr/bin/amneziawg-go ] && [ -x /usr/local/bin/amneziawg-go ]; then
            cp -f /usr/local/bin/amneziawg-go /usr/bin/amneziawg-go 2>/dev/null || true
            chmod +x /usr/bin/amneziawg-go 2>/dev/null || true
        fi
    }
fi

# Detect default network interface
IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5}' | head -n1)
if [[ -z "${IFACE}" ]]; then
    IFACE=$(ip link | grep -E '^[0-9]+: (eth|ens|enp|eno)' | awk -F': ' '{print $2}' | head -n1)
fi
if [[ -z "${IFACE}" ]]; then
    IFACE="ens6"
fi

# Enable IPv4 & IPv6 forwarding
touch /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
grep -qxF 'net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

AMNEZIA_DIR="/etc/amnezia/amneziawg"
mkdir -p "${AMNEZIA_DIR}"
chmod 700 "${AMNEZIA_DIR}"

SERVER_IP_BASE="${SUBNET%.*}.1"

# Key generation helper
gen_key() {
    local k=""
    if command -v awg >/dev/null 2>&1; then
        k=$(awg genkey 2>/dev/null || true)
    fi
    if [ -z "$k" ] && command -v wg >/dev/null 2>&1; then
        k=$(wg genkey 2>/dev/null || true)
    fi
    if [ -z "$k" ]; then
        k=$(python3 -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())" 2>/dev/null || true)
    fi
    echo "$k"
}

pub_key() {
    local priv="$1"
    local p=""
    if command -v awg >/dev/null 2>&1; then
        p=$(echo "$priv" | awg pubkey 2>/dev/null || true)
    fi
    if [ -z "$p" ] && command -v wg >/dev/null 2>&1; then
        p=$(echo "$priv" | wg pubkey 2>/dev/null || true)
    fi
    if [ -z "$p" ]; then
        p=$(python3 -c "
import base64, sys
try:
    from cryptography.hazmat.primitives.asymmetric import x25519
    priv_bytes = base64.b64decode('$priv')
    k = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
    print(base64.b64encode(k.public_key().public_bytes_raw()).decode())
    sys.exit(0)
except Exception:
    pass

# Pure Python RFC 7748 X25519 fallback
P = 2**255 - 19
A24 = 121665
def cswap(swap, x2, x3):
    dummy = swap * ((x2 - x3) % P)
    return (x2 - dummy) % P, (x3 + dummy) % P
def x25519_calc(k_bytes, u=9):
    k = int.from_bytes(k_bytes, 'little')
    x1, x2, z2, x3, z3 = u, 1, 0, u, 1
    swap = 0
    for t in reversed(range(255)):
        k_t = (k >> t) & 1
        swap ^= k_t
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = k_t
        A = (x2 + z2) % P; AA = (A * A) % P; B = (x2 - z2) % P; BB = (B * B) % P
        E = (AA - BB) % P; C = (x3 + z3) % P; D = (x3 - z3) % P
        DA = (D * A) % P; CB = (C * B) % P
        x3 = ((DA + CB) ** 2) % P; z3 = (x1 * ((DA - CB) ** 2)) % P
        x2 = (AA * BB) % P; z2 = (E * (AA + A24 * E)) % P
    x2, x3 = cswap(swap, x2, x3)
    z2, z3 = cswap(swap, z2, z3)
    return (x2 * pow(z2, P - 2, P)) % P

try:
    b = bytearray(base64.b64decode('$priv'))
    b[0] &= 248; b[31] &= 127; b[31] |= 64
    pub = x25519_calc(bytes(b))
    print(base64.b64encode(pub.to_bytes(32, 'little')).decode())
except Exception:
    print('')
" 2>/dev/null || true)
    fi
    echo "$p"
}

# Generate or preserve server keys
SERVER_PRIVKEY=""
SERVER_PUBKEY=""
if [[ -f "${AMNEZIA_DIR}/private.key" && -f "${AMNEZIA_DIR}/public.key" && -s "${AMNEZIA_DIR}/private.key" && -s "${AMNEZIA_DIR}/public.key" ]]; then
    SERVER_PRIVKEY=$(cat "${AMNEZIA_DIR}/private.key" 2>/dev/null || true)
    SERVER_PUBKEY=$(cat "${AMNEZIA_DIR}/public.key" 2>/dev/null || true)
fi

if [ -z "${SERVER_PRIVKEY}" ]; then
    SERVER_PRIVKEY=$(gen_key)
    SERVER_PUBKEY=$(pub_key "${SERVER_PRIVKEY}")
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
H1=$(shuf -i 10000000-2147483647 -n 1 2>/dev/null || echo "12345678")
H2=$(shuf -i 10000000-2147483647 -n 1 2>/dev/null || echo "23456789")
H3=$(shuf -i 10000000-2147483647 -n 1 2>/dev/null || echo "34567890")
H4=$(shuf -i 10000000-2147483647 -n 1 2>/dev/null || echo "45678901")

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
mkdir -p /etc/wireguard 2>/dev/null || true
ln -sf "${AMNEZIA_DIR}/awg0.conf" /etc/wireguard/awg0.conf 2>/dev/null || true

systemctl daemon-reload
systemctl enable awg-quick@awg0 >/dev/null 2>&1 || true
ip link del dev awg0 2>/dev/null || true
systemctl restart awg-quick@awg0 >/dev/null 2>&1 || true

# Test status
if systemctl is-active --quiet awg-quick@awg0; then
    echo "[+] AmneziaWG installed and running on port UDP ${PORT} with Anti-DPI params:"
    echo "    Jc=${JC}, Jmin=${JMIN}, Jmax=${JMAX}, S1=${S1}, S2=${S2}"
    echo "    H1=${H1}, H2=${H2}, H3=${H3}, H4=${H4}"
else
    echo "[!] Warning: awg-quick@awg0 unit exited. Attempting direct awg-quick start..."
    awg-quick up /etc/amnezia/amneziawg/awg0.conf >/dev/null 2>&1 || true
fi
