#!/bin/bash
# ==============================================================================
# MHPanel - AmneziaWG Cloudflare WARP Outbound Gateway Teardown
# Cleans up rules and restores direct routing
# ==============================================================================
/sbin/ip rule del from 10.77.77.0/24 ipproto udp table main priority 990 2>/dev/null || true
/sbin/ip rule del from 10.77.77.0/24 table 51821 priority 1000 2>/dev/null || true
/sbin/ip rule del from 10.77.77.0/24 table 51821 priority 51821 2>/dev/null || true
/sbin/ip route flush table 51821 2>/dev/null || true
/sbin/iptables -t nat -D POSTROUTING -s 10.77.77.0/24 -o awg-warp -j MASQUERADE 2>/dev/null || true
/sbin/ip link delete awg-warp 2>/dev/null || true
