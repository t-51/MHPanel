#!/bin/bash
# ==============================================================================
# MHPanel - AmneziaWG Cloudflare WARP Outbound Gateway Routing Setup
# Routes Web/TCP traffic via WARP tun2socks and directly resolves DNS/UDP traffic
# ==============================================================================

# Dynamic subnet detection
AWG_SUBNET="10.77.77.0/24"
if [ -f "/etc/amnezia/amneziawg/awg0.conf" ]; then
    DETECTED=$(grep -Ei '^[[:space:]]*Address[[:space:]]*=' /etc/amnezia/amneziawg/awg0.conf 2>/dev/null | head -n1 | awk '{print $3}' | cut -d',' -f1)
    if [ -n "$DETECTED" ]; then
        PREFIX=$(echo "$DETECTED" | awk -F'.' '{print $1"."$2"."$3}')
        if [ -n "$PREFIX" ]; then
            AWG_SUBNET="${PREFIX}.0/24"
        fi
    fi
fi

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# Wait for interface to exist
for i in {1..10}; do
    if ip link show awg-warp >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

# Assign IP and set UP
/sbin/ip addr replace 172.16.250.1/24 dev awg-warp 2>/dev/null || /sbin/ip addr add 172.16.250.1/24 dev awg-warp
/sbin/ip link set awg-warp up

# Clean previous rules
/sbin/ip rule del from "$AWG_SUBNET" ipproto udp table main priority 990 2>/dev/null || true
/sbin/ip rule del from "$AWG_SUBNET" table 51821 priority 1000 2>/dev/null || true
/sbin/ip rule del from "$AWG_SUBNET" table 51821 priority 51821 2>/dev/null || true

# UDP traffic (DNS & calls) routed directly via main table to prevent SOCKS5 UDP drops
/sbin/ip rule add from "$AWG_SUBNET" ipproto udp table main priority 990

# TCP and general traffic routed to table 51821 (WARP)
/sbin/ip rule add from "$AWG_SUBNET" table 51821 priority 1000
/sbin/ip route replace default dev awg-warp table 51821

# NAT Masquerade (wait 5s for xtables lock if busy)
/sbin/iptables -w 5 -t nat -C POSTROUTING -s "$AWG_SUBNET" -o awg-warp -j MASQUERADE 2>/dev/null || /sbin/iptables -w 5 -t nat -I POSTROUTING 1 -s "$AWG_SUBNET" -o awg-warp -j MASQUERADE
/sbin/iptables -w 5 -t nat -C POSTROUTING -s "$AWG_SUBNET" -o eth0 -j MASQUERADE 2>/dev/null || /sbin/iptables -w 5 -t nat -I POSTROUTING 2 -s "$AWG_SUBNET" -o eth0 -j MASQUERADE

# Forwarding acceptance
/sbin/iptables -w 5 -C FORWARD -i awg0 -o awg-warp -j ACCEPT 2>/dev/null || /sbin/iptables -w 5 -I FORWARD 1 -i awg0 -o awg-warp -j ACCEPT
/sbin/iptables -w 5 -C FORWARD -i awg-warp -o awg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || /sbin/iptables -w 5 -I FORWARD 2 -i awg-warp -o awg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

exit 0
