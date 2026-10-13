#!/usr/bin/env bash
# ==============================================================================
# MH Panel - WireGuard Standard Installer & Configuration Script
# ==============================================================================
set -euo pipefail

PORT="${1:-904}"
SUBNET="${2:-10.66.66.0/24}"
DNS="${3:-8.8.8.8, 1.1.1.1}"

echo "[*] Installing WireGuard dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y wireguard wireguard-tools qrencode iptables

# Detect public network interface
IFACE=$(ip -4 route show default | awk '{print $5}' | head -n1)
if [[ -z "${IFACE}" ]]; then
    IFACE="ens6"
fi

# Enable IPv4 forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -qxF 'net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

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
MTU = 1300

PostUp = iptables -I INPUT -p udp --dport ${PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${IFACE} -o wg0 -j ACCEPT
PostUp = iptables -I FORWARD -i wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${IFACE} -j MASQUERADE

PostDown = iptables -D INPUT -p udp --dport ${PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${IFACE} -o wg0 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${IFACE} -j MASQUERADE
${PEERS}
EOF

chmod 600 /etc/wireguard/wg0.conf

# Restart or reload systemd service
systemctl daemon-reload
systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0

echo "[+] WireGuard standard installed and running on port UDP ${PORT} (IP: ${SERVER_IP_BASE}/24)"
