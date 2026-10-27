#!/bin/bash
# ==============================================================================
# MHPanel - AmneziaWG Cloudflare WARP Outbound Gateway Teardown
# Cleans up rules and restores direct routing
# ==============================================================================
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

/sbin/ip rule del from "$AWG_SUBNET" ipproto udp table main priority 990 2>/dev/null || true
/sbin/ip rule del from "$AWG_SUBNET" table 51821 priority 1000 2>/dev/null || true
/sbin/ip rule del from "$AWG_SUBNET" table 51821 priority 51821 2>/dev/null || true
/sbin/ip rule del from 10.13.0.0/24 table 51821 priority 1001 2>/dev/null || true
/sbin/ip route flush table 51821 2>/dev/null || true
/sbin/iptables -w 5 -t nat -D POSTROUTING -s "$AWG_SUBNET" -o awg-warp -j MASQUERADE 2>/dev/null || true
/sbin/iptables -w 5 -t nat -D POSTROUTING -s 10.13.0.0/24 -o awg-warp -j MASQUERADE 2>/dev/null || true
/sbin/iptables -w 5 -D FORWARD -i awg0 -o awg-warp -j ACCEPT 2>/dev/null || true
/sbin/iptables -w 5 -D FORWARD -i awg-warp -o awg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
/sbin/ip link delete awg-warp 2>/dev/null || true

exit 0
