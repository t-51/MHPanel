#!/bin/bash
# ==============================================================================
# MHPanel - AmneziaWG Cloudflare WARP Outbound Gateway Routing Setup
# Routes Web/TCP traffic via WARP tun2socks and directly resolves DNS/UDP traffic
# ==============================================================================
/sbin/ip addr replace 172.16.250.1/24 dev awg-warp 2>/dev/null || /sbin/ip addr add 172.16.250.1/24 dev awg-warp
/sbin/ip link set awg-warp up
/sbin/ip rule del from 10.77.77.0/24 ipproto udp table main priority 990 2>/dev/null || true
/sbin/ip rule del from 10.77.77.0/24 table 51821 priority 1000 2>/dev/null || true
/sbin/ip rule del from 10.77.77.0/24 table 51821 priority 51821 2>/dev/null || true

# UDP traffic (DNS & calls) routed directly via main table to prevent SOCKS5 UDP drops
/sbin/ip rule add from 10.77.77.0/24 ipproto udp table main priority 990

# TCP and general traffic routed to table 51821 (WARP)
/sbin/ip rule add from 10.77.77.0/24 table 51821 priority 1000
/sbin/ip route replace default dev awg-warp table 51821

# NAT Masquerade
/sbin/iptables -t nat -C POSTROUTING -s 10.77.77.0/24 -o awg-warp -j MASQUERADE 2>/dev/null || /sbin/iptables -t nat -I POSTROUTING 1 -s 10.77.77.0/24 -o awg-warp -j MASQUERADE
/sbin/iptables -t nat -C POSTROUTING -s 10.77.77.0/24 -o eth0 -j MASQUERADE 2>/dev/null || /sbin/iptables -t nat -I POSTROUTING 2 -s 10.77.77.0/24 -o eth0 -j MASQUERADE
