#!/usr/bin/env bash
# ==============================================================================
# MH Panel - WireGuard Standard Installer & Configuration Script
# ==============================================================================
set -euo pipefail

PORT="${1:-51820}"
SUBNET="${2:-10.13.0.0/24}"
DNS="${3:-8.8.8.8, 1.1.1.1}"

echo "[*] Installing WireGuard dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y wireguard wireguard-tools qrencode iptables

# Detect public network interface
IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5}' | head -n1)
if [[ -z "${IFACE}" ]]; then
    IFACE=$(ip link | grep -E '^[0-9]+: (eth|ens|enp|eno)' | awk -F': ' '{print $2}' | head -n1)
fi
if [[ -z "${IFACE}" ]]; then
    IFACE="eth0"
fi

# Enable IPv4 forwarding
touch /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
grep -qxF 'net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

SERVER_IP_BASE="${SUBNET%.*}.1"

# Generate or preserve server keys
if [[ -f /etc/wireguard/private.key && -f /etc/wireguard/public.key ]]; then
    SERVER_PRIVKEY=$(cat /etc/wireguard/private.key)
    SERVER_PUBKEY=$(cat /etc/wireguard/public.key)
else
    SERVER_PRIVKEY=$(wg genkey)
    SERVER_PUBKEY=$(echo "${SERVER_PRIVKEY}" | wg pubkey)
    echo "${SERVER_PRIVKEY}" > /etc/wireguard/private.key
    echo "${SERVER_PUBKEY}" > /etc/wireguard/public.key
    chmod 600 /etc/wireguard/private.key
    chmod 644 /etc/wireguard/public.key
fi

# If wg0.conf already exists, preserve peers
PEERS=""
if [[ -f /etc/wireguard/wg0.conf ]]; then
    PEERS=$(awk '/^\[Peer\]/{flag=1} flag' /etc/wireguard/wg0.conf || true)
fi

cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = ${SERVER_IP_BASE}/24
ListenPort = ${PORT}
PrivateKey = ${SERVER_PRIVKEY}
MTU = 1280

PostUp = iptables -I INPUT -p udp --dport ${PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${IFACE} -o wg0 -j ACCEPT
PostUp = iptables -I FORWARD -i wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${IFACE} -j MASQUERADE
PostUp = iptables -t mangle -I FORWARD -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1221:65535 -j TCPMSS --set-mss 1220 2>/dev/null || true
PostUp = iptables -t mangle -I POSTROUTING -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1221:65535 -j TCPMSS --set-mss 1220 2>/dev/null || true

PostDown = iptables -D INPUT -p udp --dport ${PORT} -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -i ${IFACE} -o wg0 -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true
PostDown = iptables -t nat -D POSTROUTING -o ${IFACE} -j MASQUERADE 2>/dev/null || true
PostDown = iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1221:65535 -j TCPMSS --set-mss 1220 2>/dev/null || true
PostDown = iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1221:65535 -j TCPMSS --set-mss 1220 2>/dev/null || true
${PEERS}
EOF

chmod 600 /etc/wireguard/wg0.conf

# Restart or reload systemd service
systemctl daemon-reload
systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0

echo "[+] WireGuard standard installed and running on port UDP ${PORT} (IP: ${SERVER_IP_BASE}/24)"
