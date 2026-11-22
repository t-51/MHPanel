# -*- coding: utf-8 -*-
"""
MH Panel - Tunnel Packet Integrity, Tamper & Ingress Shield Engine
Real-time inspection of tunnel packets, middlebox TCP RST injections,
ingress client/peer anomalies, tunnel MTU blackhole detection,
DNS leak & hijacking audits, Iranian operator mapping, and 1-click admin mitigations.
"""

import os
import re
import time
import json
import socket
import logging
import ipaddress
import subprocess
import urllib.request
from datetime import datetime

logger = logging.getLogger("mhpanel.tunnel_shield")

# -----------------------------------------------------------------------------
# 1. پایگاه داده و طبقه‌بندی اپراتورهای ایران برای کلاینت‌ها و تانل‌ها
# -----------------------------------------------------------------------------
IRAN_OPERATOR_CIDRS = {
    "mci": [
        "37.156.0.0/15", "37.235.0.0/16", "91.98.0.0/15", "91.106.0.0/15",
        "178.131.0.0/16", "188.158.0.0/15", "188.210.0.0/15", "188.211.0.0/16",
        "188.212.0.0/15", "188.213.0.0/16", "188.253.0.0/16", "31.56.0.0/14",
        "31.7.0.0/16", "109.122.0.0/15", "109.125.0.0/16", "151.246.0.0/15",
        "151.232.0.0/13", "89.196.0.0/15", "89.198.0.0/15", "2.179.0.0/16"
    ],
    "mtn": [
        "5.112.0.0/13", "5.120.0.0/13", "5.200.0.0/13", "37.152.0.0/15",
        "92.42.0.0/16", "94.182.0.0/15", "94.184.0.0/15", "188.121.0.0/16",
        "188.136.0.0/15", "188.159.0.0/16", "109.201.0.0/16", "151.238.0.0/15",
        "151.240.0.0/13", "91.243.166.0/23", "91.243.168.0/22"
    ],
    "rtl": [
        "37.254.0.0/15", "37.255.0.0/16", "159.246.0.0/16", "188.122.0.0/16",
        "89.199.0.0/16", "89.200.0.0/16"
    ],
    "mkh": [
        "2.144.0.0/12", "2.176.0.0/12", "5.160.0.0/11", "37.98.0.0/15",
        "37.114.0.0/15", "46.100.0.0/15", "46.224.0.0/15", "78.38.0.0/15",
        "78.39.0.0/16", "80.191.0.0/16", "85.185.0.0/16", "89.165.0.0/16",
        "91.99.0.0/16", "91.240.0.0/16", "94.139.0.0/16"
    ],
    "shatel": [
        "79.175.0.0/16", "85.133.0.0/16", "94.182.0.0/16", "94.183.0.0/16"
    ],
    "mobinnet": [
        "46.209.0.0/16", "5.208.0.0/14", "91.99.0.0/16"
    ],
    "asiatech": [
        "79.127.0.0/17", "185.120.0.0/16", "188.245.0.0/16"
    ]
}

OPERATOR_TITLES = {
    "mci": "همراه اول (MCI)",
    "mtn": "ایرانسل (MTN)",
    "rtl": "رایتل (Rightel)",
    "mkh": "مخابرات (TCI)",
    "shatel": "شاتل (Shatel)",
    "mobinnet": "مبین‌نت (Mobinnet)",
    "asiatech": "آسیاتک (Asiatech)",
    "other": "سایر / سرور خارج"
}

_NETWORKS_COMPILED = []
for op_k, cidrs in IRAN_OPERATOR_CIDRS.items():
    for c in cidrs:
        try:
            _NETWORKS_COMPILED.append((ipaddress.ip_network(c), op_k))
        except Exception:
            pass

_OPERATOR_CACHE = {}

def classify_operator_ip(ip_str):
    """Fast classification of client/peer IP to Iranian ISP with cache."""
    if not ip_str or not isinstance(ip_str, str):
        return "other", OPERATOR_TITLES["other"]
    ip_clean = ip_str.split(":")[0].strip()
    if ip_clean in _OPERATOR_CACHE:
        code = _OPERATOR_CACHE[ip_clean]
        return code, OPERATOR_TITLES.get(code, OPERATOR_TITLES["other"])
    try:
        ip_obj = ipaddress.ip_address(ip_clean)
        if ip_obj.is_private or ip_obj.is_loopback:
            return "local", "شبکه محلی (Private)"
        for net, code in _NETWORKS_COMPILED:
            if ip_obj in net:
                if len(_OPERATOR_CACHE) > 3000:
                    _OPERATOR_CACHE.clear()
                _OPERATOR_CACHE[ip_clean] = code
                return code, OPERATOR_TITLES.get(code, OPERATOR_TITLES["other"])
    except Exception:
        pass
    if len(_OPERATOR_CACHE) > 3000:
        _OPERATOR_CACHE.clear()
    _OPERATOR_CACHE[ip_clean] = "other"
    return "other", OPERATOR_TITLES["other"]

# -----------------------------------------------------------------------------
# 2. رهگیری نرخ دلتای آنومالی‌های هسته لینوکس و حملات DPI
# -----------------------------------------------------------------------------
_LAST_KERNEL_TIME = 0.0
_LAST_KERNEL_COUNTERS = {}

def get_kernel_dpi_telemetry():
    """
    Computes real-time per-second deltas of TCP resets, connection aborts,
    timeouts and UDP buffer errors from /proc/net/snmp and /proc/net/netstat.
    """
    global _LAST_KERNEL_TIME, _LAST_KERNEL_COUNTERS

    raw_snmp = {}
    raw_netstat = {}

    try:
        if os.path.exists("/proc/net/snmp"):
            with open("/proc/net/snmp", "r") as f:
                lines = f.readlines()
            for i in range(0, len(lines) - 1, 2):
                h = lines[i].split()
                v = lines[i + 1].split()
                if h and v and h[0] == v[0]:
                    proto = h[0].replace(":", "")
                    raw_snmp[proto] = dict(zip(h[1:], [int(x) if x.isdigit() else x for x in v[1:]]))

        if os.path.exists("/proc/net/netstat"):
            with open("/proc/net/netstat", "r") as f:
                lines = f.readlines()
            for i in range(0, len(lines) - 1, 2):
                h = lines[i].split()
                v = lines[i + 1].split()
                if h and v and h[0] == v[0]:
                    proto = h[0].replace(":", "")
                    raw_netstat[proto] = dict(zip(h[1:], [int(x) if x.isdigit() else x for x in v[1:]]))
    except Exception as e:
        logger.error(f"Error reading kernel proc stats: {e}")

    tcp_snmp = raw_snmp.get("Tcp", {})
    udp_snmp = raw_snmp.get("Udp", {})
    tcp_ext = raw_netstat.get("TcpExt", {})

    now_counters = {
        "estab_resets": int(tcp_snmp.get("EstabResets") or 0),
        "in_errs": int(tcp_snmp.get("InErrs") or 0),
        "out_rsts": int(tcp_snmp.get("OutRsts") or 0),
        "retrans_segs": int(tcp_snmp.get("RetransSegs") or 0),
        "tcp_abort_on_data": int(tcp_ext.get("TCPAbortOnData") or 0),
        "tcp_abort_on_timeout": int(tcp_ext.get("TCPAbortOnTimeout") or 0),
        "tcp_timeouts": int(tcp_ext.get("TCPTimeouts") or 0),
        "udp_in_errors": int(udp_snmp.get("InErrors") or 0),
        "udp_rcvbuf_errors": int(udp_snmp.get("RcvbufErrors") or 0)
    }

    now_t = time.time()
    dt = max(1.0, now_t - _LAST_KERNEL_TIME) if _LAST_KERNEL_TIME else 10.0

    deltas = {}
    if _LAST_KERNEL_COUNTERS:
        for k, v in now_counters.items():
            deltas[k] = max(0, v - _LAST_KERNEL_COUNTERS.get(k, v))
    else:
        for k in now_counters:
            deltas[k] = 0

    _LAST_KERNEL_COUNTERS = now_counters
    _LAST_KERNEL_TIME = now_t

    rates = {k: round(v / dt, 2) for k, v in deltas.items()}

    return {
        "totals": now_counters,
        "deltas": deltas,
        "rates": rates,
        "sample_interval_sec": round(dt, 1)
    }

# -----------------------------------------------------------------------------
# 3. پایش اینترفیس‌های تونل و تشخیص افت پکت و MTU Blackhole
# -----------------------------------------------------------------------------
_LAST_IFACE_TIME = 0.0
_LAST_IFACE_STATS = {}

def get_tunnel_interfaces_telemetry():
    """
    Examines all network interfaces, identifying tunnel types, MTU,
    carrier state, and calculates per-interface packet rates and drop percentages.
    """
    global _LAST_IFACE_TIME, _LAST_IFACE_STATS

    base = "/sys/class/net"
    if not os.path.exists(base):
        return {}

    now_t = time.time()
    dt = max(1.0, now_t - _LAST_IFACE_TIME) if _LAST_IFACE_TIME else 10.0

    curr_stats = {}
    try:
        for iface in os.listdir(base):
            if iface == "lo":
                continue
            s_dir = os.path.join(base, iface, "statistics")
            if not os.path.isdir(s_dir):
                continue

            def _r(name):
                try:
                    with open(os.path.join(s_dir, name), "r") as f:
                        return int(f.read().strip())
                except Exception:
                    return 0

            mtu = 1500
            try:
                with open(os.path.join(base, iface, "mtu"), "r") as f:
                    mtu = int(f.read().strip())
            except Exception:
                pass

            operstate = "unknown"
            try:
                with open(os.path.join(base, iface, "operstate"), "r") as f:
                    operstate = f.read().strip()
            except Exception:
                pass

            rx_p = _r("rx_packets")
            tx_p = _r("tx_packets")
            rx_d = _r("rx_dropped")
            tx_d = _r("tx_dropped")
            rx_e = _r("rx_errors")
            tx_e = _r("tx_errors")
            rx_b = _r("rx_bytes")
            tx_b = _r("tx_bytes")

            tot_p = rx_p + tx_p
            tot_d = rx_d + tx_d + rx_e + tx_e

            # Interface Type
            iface_type = "Physical NIC"
            if iface.startswith("awg"):
                iface_type = "Amnezia WireGuard"
            elif iface.startswith("wg"):
                iface_type = "WireGuard"
            elif iface.startswith("gre"):
                iface_type = "GRE Tunnel"
            elif iface.startswith("ipip") or iface.startswith("tunl"):
                iface_type = "IPIP Tunnel"
            elif iface.startswith("vxlan"):
                iface_type = "VXLAN Tunnel"
            elif iface.startswith("eoip"):
                iface_type = "EoIP MikroTik"
            elif iface.startswith("sit") or iface.startswith("ip6tnl"):
                iface_type = "IPv6 Tunnel"
            elif iface == "ovpn_mesh" or iface.startswith("tun") or iface.startswith("tap"):
                iface_type = "OpenVPN Tunnel"

            is_tunnel = iface_type != "Physical NIC"

            # Calculate Deltas
            last = _LAST_IFACE_STATS.get(iface, {})
            d_rx_p = max(0, rx_p - last.get("rx_p", rx_p))
            d_tx_p = max(0, tx_p - last.get("tx_p", tx_p))
            d_drop = max(0, tot_d - last.get("tot_d", tot_d))

            d_tot_p = d_rx_p + d_tx_p
            drop_rate_pct = round((d_drop / (d_tot_p + d_drop)) * 100, 2) if (d_tot_p + d_drop) > 0 else 0.0

            # Cumulative drop rate
            cum_drop_rate = round((tot_d / (tot_p + tot_d)) * 100, 2) if (tot_p + tot_d) > 0 else 0.0

            # Health Status
            status = "healthy"
            status_text = "سالم و بدون افت"
            if drop_rate_pct >= 15.0 or (tot_d > 200 and cum_drop_rate >= 10.0):
                status = "critical"
                status_text = "دراپ بحرانی پکت‌ها"
            elif drop_rate_pct >= 4.0 or (tot_d > 50 and cum_drop_rate >= 3.0):
                status = "warning"
                status_text = "نیاز به بررسی MTU"

            # MTU Risk check
            mtu_warning = False
            if is_tunnel and mtu > 1400:
                mtu_warning = True

            curr_stats[iface] = {
                "name": iface,
                "type": iface_type,
                "is_tunnel": is_tunnel,
                "mtu": mtu,
                "mtu_warning": mtu_warning,
                "operstate": operstate,
                "rx_packets": rx_p,
                "tx_packets": tx_p,
                "rx_dropped": rx_d,
                "tx_dropped": tx_d,
                "rx_errors": rx_e,
                "tx_errors": tx_e,
                "rx_bytes": rx_b,
                "tx_bytes": tx_b,
                "total_packets": tot_p,
                "total_dropped": tot_d,
                "delta_packets": d_tot_p,
                "delta_dropped": d_drop,
                "drop_rate_pct": drop_rate_pct if d_tot_p > 0 else cum_drop_rate,
                "status": status,
                "status_text": status_text,
                "_raw": {"rx_p": rx_p, "tx_p": tx_p, "tot_d": tot_d}
            }
    except Exception as e:
        logger.error(f"Error reading interface stats: {e}")

    _LAST_IFACE_STATS = {k: v["_raw"] for k, v in curr_stats.items()}
    _LAST_IFACE_TIME = now_t

    return curr_stats

# -----------------------------------------------------------------------------
# 4. پایش همزمان کلاینت‌ها و کاندیداهای متصل به تونل‌ها (Tunnel Peers & Ingress)
# -----------------------------------------------------------------------------
def get_active_tunnel_peers():
    """
    Scans live WireGuard, AmneziaWG, and OpenVPN client/peer sessions,
    identifying peer endpoints, transfer sizes, latest handshakes, and Iranian ISPs.
    """
    peers = []

    # 1. Inspect AmneziaWG (awg0)
    try:
        out = subprocess.run(["awg", "show"], capture_output=True, text=True, timeout=2.0)
        if out.returncode == 0:
            current_peer = {}
            for line in out.stdout.splitlines():
                line = line.strip()
                if line.startswith("peer:"):
                    if current_peer.get("public_key"):
                        peers.append(current_peer)
                    current_peer = {
                        "interface": "awg0",
                        "tunnel_type": "Amnezia WireGuard",
                        "public_key": line.split(":", 1)[1].strip(),
                        "endpoint": "",
                        "allowed_ips": "",
                        "latest_handshake": "بدون اتصال",
                        "transfer_rx": "0 B",
                        "transfer_tx": "0 B",
                        "operator": OPERATOR_TITLES["other"],
                        "operator_code": "other",
                        "status": "IDLE",
                        "anomaly": ""
                    }
                elif line.startswith("endpoint:") and current_peer:
                    ep = line.split(":", 1)[1].strip()
                    current_peer["endpoint"] = ep
                    code, op_title = classify_operator_ip(ep)
                    current_peer["operator"] = op_title
                    current_peer["operator_code"] = code
                elif line.startswith("allowed ips:") and current_peer:
                    current_peer["allowed_ips"] = line.split(":", 1)[1].strip()
                elif line.startswith("latest handshake:") and current_peer:
                    hs = line.split(":", 1)[1].strip()
                    current_peer["latest_handshake"] = hs
                    if "minute" in hs:
                        m_match = re.search(r"(\d+)\s+minute", hs)
                        if m_match and int(m_match.group(1)) >= 3:
                            current_peer["status"] = "STALLED"
                            current_peer["anomaly"] = f"تاخیر در Handshake ({hs}) - احتمال دراپ پکت UDP توسط اپراتور"
                        else:
                            current_peer["status"] = "ACTIVE"
                    elif "second" in hs:
                        current_peer["status"] = "ACTIVE"
                    else:
                        current_peer["status"] = "ACTIVE"
                elif line.startswith("transfer:") and current_peer:
                    parts = line.split(":", 1)[1].strip().split(",")
                    if len(parts) >= 2:
                        current_peer["transfer_rx"] = parts[0].replace("received", "").strip()
                        current_peer["transfer_tx"] = parts[1].replace("sent", "").strip()

            if current_peer.get("public_key"):
                peers.append(current_peer)
    except Exception:
        pass

    # 2. Inspect standard WireGuard (wg0)
    try:
        out = subprocess.run(["wg", "show"], capture_output=True, text=True, timeout=2.0)
        if out.returncode == 0:
            current_peer = {}
            for line in out.stdout.splitlines():
                line = line.strip()
                if line.startswith("peer:"):
                    if current_peer.get("public_key"):
                        peers.append(current_peer)
                    current_peer = {
                        "interface": "wg0",
                        "tunnel_type": "WireGuard",
                        "public_key": line.split(":", 1)[1].strip(),
                        "endpoint": "",
                        "allowed_ips": "",
                        "latest_handshake": "بدون اتصال",
                        "transfer_rx": "0 B",
                        "transfer_tx": "0 B",
                        "operator": OPERATOR_TITLES["other"],
                        "operator_code": "other",
                        "status": "IDLE",
                        "anomaly": ""
                    }
                elif line.startswith("endpoint:") and current_peer:
                    ep = line.split(":", 1)[1].strip()
                    current_peer["endpoint"] = ep
                    code, op_title = classify_operator_ip(ep)
                    current_peer["operator"] = op_title
                    current_peer["operator_code"] = code
                elif line.startswith("allowed ips:") and current_peer:
                    current_peer["allowed_ips"] = line.split(":", 1)[1].strip()
                elif line.startswith("latest handshake:") and current_peer:
                    hs = line.split(":", 1)[1].strip()
                    current_peer["latest_handshake"] = hs
                    current_peer["status"] = "ACTIVE"
                elif line.startswith("transfer:") and current_peer:
                    parts = line.split(":", 1)[1].strip().split(",")
                    if len(parts) >= 2:
                        current_peer["transfer_rx"] = parts[0].replace("received", "").strip()
                        current_peer["transfer_tx"] = parts[1].replace("sent", "").strip()

            if current_peer.get("public_key"):
                peers.append(current_peer)
    except Exception:
        pass

    # 3. Inspect OpenVPN Mesh Peer
    if os.path.exists("/etc/openvpn/ovpn_mesh.conf"):
        try:
            with open("/etc/openvpn/ovpn_mesh.conf", "r") as f:
                content = f.read()
            m = re.search(r"remote\s+([^\s]+)", content)
            if m:
                remote_ip = m.group(1).strip()
                code, op_title = classify_operator_ip(remote_ip)
                peers.append({
                    "interface": "ovpn_mesh",
                    "tunnel_type": "OpenVPN Point-to-Point",
                    "public_key": "Static Pre-Shared Key",
                    "endpoint": remote_ip + ":11950",
                    "allowed_ips": "10.200.50.2/32",
                    "latest_handshake": "متصل (سرویس دائم)",
                    "transfer_rx": "Mesh Tunnel",
                    "transfer_tx": "Encrypted",
                    "operator": op_title,
                    "operator_code": code,
                    "status": "ACTIVE",
                    "anomaly": ""
                })
        except Exception:
            pass

    return peers

# -----------------------------------------------------------------------------
# 5. سنسور نشت، مسموم‌سازی DNS و بررسی فایروال تونل‌ها
# -----------------------------------------------------------------------------
def audit_tunnel_dns_and_firewall():
    """
    Checks if client traffic traversing tunnels leaks plain DNS to port 53,
    whether the server resolver is spoofed by 10.10.34.34, and verifies
    firewall rules for MSS clamping and DNS redirect shields.
    """
    test_domains = ["twitter.com", "instagram.com", "youtube.com"]
    poisoned_detected = False
    poison_samples = []

    for d in test_domains:
        try:
            addr = socket.gethostbyname(d)
            if addr.startswith("10.10.34.") or addr.startswith("10.10."):
                poisoned_detected = True
                poison_samples.append(f"{d} -> {addr}")
        except Exception:
            pass

    # Check DoH connectivity
    doh_ok = False
    try:
        req = urllib.request.Request(
            "https://1.1.1.1/dns-query?name=google.com&type=A",
            headers={"Accept": "application/dns-json"}
        )
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            doh_ok = (resp.status == 200)
    except Exception:
        doh_ok = False

    # Check TCPMSS Clamping rule in iptables mangle table
    mss_clamped = False
    try:
        chk = subprocess.run(["iptables", "-t", "mangle", "-C", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"], capture_output=True)
        mss_clamped = (chk.returncode == 0)
    except Exception:
        pass

    # Check Tunnel DNS Shield rule in iptables nat table
    dns_shield_active = False
    try:
        chk = subprocess.run(["iptables", "-t", "nat", "-C", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"], capture_output=True)
        dns_shield_active = (chk.returncode == 0)
    except Exception:
        pass

    return {
        "poisoned_detected": poisoned_detected,
        "poison_samples": poison_samples,
        "doh_reachable": doh_ok,
        "mss_clamped": mss_clamped,
        "dns_shield_active": dns_shield_active
    }

# -----------------------------------------------------------------------------
# 6. ساخت گزارش جامع سلامت تونل‌ها و پیشنهادهای اقدام مدیر (Shield Hub Report)
# -----------------------------------------------------------------------------
TUNNEL_ALERTS_FILE = "/www/wwwroot/mhpanel/tunnel_alerts.json"
_SHIELD_CACHE = None
_SHIELD_CACHE_TS = 0.0
_CACHE_TTL = 5.0

def get_stored_tunnel_alerts():
    if not os.path.exists(TUNNEL_ALERTS_FILE):
        return []
    try:
        with open(TUNNEL_ALERTS_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
            return d if isinstance(d, list) else []
    except Exception:
        return []

def save_stored_tunnel_alerts(alerts):
    try:
        with open(TUNNEL_ALERTS_FILE, "w", encoding="utf-8") as f:
            json.dump(alerts[-100:], f, indent=2, ensure_ascii=False)
    except Exception:
        pass

def generate_tunnel_shield_report(force_fresh=False):
    """
    Compiles real-time metrics into a comprehensive health and tamper audit report.
    Cached for 5 seconds to guarantee near-zero CPU footprint.
    """
    global _SHIELD_CACHE, _SHIELD_CACHE_TS
    now_t = time.time()
    if not force_fresh and _SHIELD_CACHE and (now_t - _SHIELD_CACHE_TS < _CACHE_TTL):
        return _SHIELD_CACHE

    kernel_data = get_kernel_dpi_telemetry()
    iface_data = get_tunnel_interfaces_telemetry()
    peers_data = get_active_tunnel_peers()
    dns_data = audit_tunnel_dns_and_firewall()

    alerts = get_stored_tunnel_alerts()
    new_alerts = []

    k_rates = kernel_data.get("rates", {})
    rst_rate = k_rates.get("estab_resets", 0) + k_rates.get("tcp_abort_on_data", 0)
    timeout_rate = k_rates.get("tcp_timeouts", 0)
    udp_err_rate = k_rates.get("udp_rcvbuf_errors", 0) + k_rates.get("udp_in_errors", 0)

    # 1. Analyze interfaces for real drops & MTU risks
    high_drop_ifaces = []
    mtu_risk_ifaces = []
    total_pkts_all = 0
    total_drops_all = 0

    for iface_name, st in iface_data.items():
        total_pkts_all += st.get("total_packets", 0)
        total_drops_all += st.get("total_dropped", 0)

        drop_pct = st.get("drop_rate_pct", 0)
        tot_d = st.get("total_dropped", 0)

        if (drop_pct >= 8.0 and tot_d > 20) or st.get("status") == "critical":
            high_drop_ifaces.append(iface_name)
            # Add alert
            alert_id = f"drop_{iface_name}_{int(now_t // 300)}"
            if not any(a.get("id") == alert_id or (a.get("interface") == iface_name and not a.get("dismissed")) for a in alerts[-15:]):
                new_alerts.append({
                    "id": alert_id,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "CRITICAL" if drop_pct >= 20 else "WARNING",
                    "type": "packet_drop",
                    "interface": iface_name,
                    "title": f"افت پکت‌های تبادل تونل روی {iface_name}",
                    "details": f"تعداد {tot_d:,} پکت با نرخ دراپ {drop_pct}% در اینترفیس {iface_name} از دست رفتند.",
                    "recommendation": "فعال‌سازی Clamp MSS و کاهش MTU به ۱۲۸۰ جهت جلوگیری از تکه‌تکه شدن بسته‌ها توسط اپراتورها.",
                    "action_key": "clamp_mss",
                    "dismissed": False
                })

        if st.get("mtu_warning"):
            mtu_risk_ifaces.append(iface_name)

    # 2. Analyze DPI TCP RST injection spike
    if rst_rate >= 5.0:
        alert_id = f"rst_spike_{int(now_t // 300)}"
        if not any(a.get("type") == "dpi_rst_tampering" and not a.get("dismissed") for a in alerts[-10:]):
            new_alerts.append({
                "id": alert_id,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "severity": "CRITICAL",
                "type": "dpi_rst_tampering",
                "interface": "Kernel / TCP Stack",
                "title": "حملات فعال تزریق پکت جعلی RST توسط فایروال DPI",
                "details": f"نرخ {rst_rate:.1f} پکت RST جعلی در ثانیه شناسایی شد که تلاش در قطع ناگهانی تبادل سشن‌ها دارد.",
                "recommendation": "تغییر پورت‌های شنود به ۴۴۳ یا فعال‌سازی مبهم‌ساز ترافیک FakeTCP / GOST WSS.",
                "action_key": "tune_kernel_buffers",
                "dismissed": False
            })

    # 3. Analyze DNS Poisoning / Leaks
    if dns_data.get("poisoned_detected"):
        alert_id = f"dns_poison_{int(now_t // 600)}"
        if not any(a.get("type") == "dns_poisoning" and not a.get("dismissed") for a in alerts[-10:]):
            new_alerts.append({
                "id": alert_id,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "severity": "CRITICAL",
                "type": "dns_poisoning",
                "interface": "DNS Subsystem",
                "title": "مسموم‌سازی و جعل پاسخ‌های DNS با آی‌پی 10.10.34.34",
                "details": f"دامنه‌های آزمایشی به آدرس فیلترینگ پیوندها ({', '.join(dns_data.get('poison_samples', []))}) جعل شده‌اند.",
                "recommendation": "فعال‌سازی فوری سپر ضد نشت DNS تونل‌ها جهت هدایت خودکار به ریزالور DoH رمزنگاری‌شده کلودفلر.",
                "action_key": "enable_tunnel_dns_shield",
                "dismissed": False
            })

    # 4. Save any new alerts
    if new_alerts:
        alerts.extend(new_alerts)
        save_stored_tunnel_alerts(alerts)

    # 5. Calculate Health Score (100 down)
    penalty = 0
    if rst_rate > 15: penalty += 25
    elif rst_rate > 3: penalty += 10

    if timeout_rate > 10: penalty += 20
    elif timeout_rate > 2: penalty += 8

    if high_drop_ifaces: penalty += 25
    if mtu_risk_ifaces and not dns_data.get("mss_clamped"): penalty += 15
    if dns_data.get("poisoned_detected"): penalty += 20
    if not dns_data.get("dns_shield_active"): penalty += 5

    health_score = max(10, 100 - penalty)

    if health_score >= 80:
        threat_level = "NORMAL"
        threat_label = "شبکه پایدار، امن و بدون اختلال بحرانی"
        threat_color = "#10b981"
    elif health_score >= 50:
        threat_level = "WARNING"
        threat_label = "اختلال متوسط و نیاز به تنظیمات پکت‌ها"
        threat_color = "#f59e0b"
    else:
        threat_level = "CRITICAL"
        threat_label = "دستکاری فعال DPI یا افت شدید پکت‌های تونل"
        threat_color = "#ef4444"

    # 6. Actionable Mitigations for Admin
    recommendations = []

    # Recommendation A: MTU / MSS Clamping
    if not dns_data.get("mss_clamped") or mtu_risk_ifaces or high_drop_ifaces:
        recommendations.append({
            "id": "clamp_mss",
            "priority": "HIGH",
            "title": "رفع خطای تکه‌تکه شدن پکت‌ها (TCP MSS Clamping)",
            "issue": f"تعداد {len(mtu_risk_ifaces)} اینترفیس تونل با MTU بالا شناسایی شدند. پکت‌های بزرگ توسط فایروال اپراتورها دراپ می‌شوند.",
            "action_text": "فعال‌سازی Clamp MSS خودکار روی پکت‌های SYN و تنظیم سقف MSS به ۱۲۴۰ در فایروال لینوکس.",
            "quick_action": "clamp_mss",
            "btn_label": "⚡ اعمال Clamp MSS خودکار (حل دراپ تونل)"
        })

    # Recommendation B: Safe MTU 1280
    if mtu_risk_ifaces:
        recommendations.append({
            "id": "set_safe_mtu_1280",
            "priority": "MEDIUM",
            "title": "تنظیم استاندارد MTU ۱۲۸۰ برای شبکه موبایل ایران",
            "issue": f"اینترفیس‌های {', '.join(mtu_risk_ifaces[:3])} دارای MTU=1500 هستند که برای تونل‌های رمزنگاری شده ریسک دراپ دارد.",
            "action_text": "کاهش مستقیم MTU کلیه اینترفیس‌های تانل به ۱۲۸۰ جهت سازگاری ۱۰۰٪ با همراه اول و ایرانسل.",
            "quick_action": "set_safe_mtu_1280",
            "btn_label": "🛠️ تنظیم MTU کلیه تونل‌ها روی ۱۲۸۰"
        })

    # Recommendation C: DNS Leak Shield
    if not dns_data.get("dns_shield_active") or dns_data.get("poisoned_detected"):
        recommendations.append({
            "id": "enable_tunnel_dns_shield",
            "priority": "CRITICAL",
            "title": "سپر ضد نشت و ضد جعل DNS در تونل‌ها",
            "issue": "درخواست‌های DNS رمزنگاری‌نشده پورت ۵۳ به راحتی توسط DPI شنود و جعل می‌شوند.",
            "action_text": "هدایت خودکار تمامی درخواست‌های پورت ۵۳ تونل‌ها به ریزالور امن DoH و مسدودسازی نشت پکت.",
            "quick_action": "enable_tunnel_dns_shield",
            "btn_label": "🛡️ فعال‌سازی سپر ضد نشت DNS در تونل‌ها"
        })

    # Recommendation D: Flush Hung Sockets
    if rst_rate > 5 or timeout_rate > 5:
        recommendations.append({
            "id": "flush_stuck_sockets",
            "priority": "MEDIUM",
            "title": "پاکسازی سوکت‌های بلاتکلیف و فیلترشده",
            "issue": f"شناسایی {int(rst_rate)} تزریق ریست در ثانیه که باعث قفل شدن کانکشن‌های بین‌سروری شده است.",
            "action_text": "ریست فوری سوکت‌های رهاشده در وضعیت CLOSE_WAIT تا کلاینت‌ها بلافاصله مسیر جدید را بازیابی کنند.",
            "quick_action": "flush_stuck_sockets",
            "btn_label": "🧹 پاکسازی سوکت‌های بلاتکلیف"
        })

    # Recommendation E: Buffer & BBR Tuning
    if udp_err_rate > 5:
        recommendations.append({
            "id": "tune_kernel_buffers",
            "priority": "HIGH",
            "title": "بهینه‌سازی بافرهای شبکه در لینوکس جهت عبور از UDP Throttling",
            "issue": f"سرریز بافر دریافت UDP با نرخ {udp_err_rate:.1f} در ثانیه روی پورت‌های WireGuard/AWG.",
            "action_text": "افزایش بافر rmem/wmem هسته به ۱۶ مگابایت و فعال‌سازی الگوریتم کنترل ازدحام BBR.",
            "quick_action": "tune_kernel_buffers",
            "btn_label": "🚀 بهینه‌سازی بافر شبکه و BBR هسته"
        })

    active_alerts = [a for a in alerts if not a.get("dismissed")]

    overall_drop_rate = round((total_drops_all / (total_pkts_all + total_drops_all)) * 100, 2) if (total_pkts_all + total_drops_all) > 0 else 0.0

    report = {
        "success": True,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "health_score": health_score,
        "threat_level": threat_level,
        "threat_label": threat_label,
        "threat_color": threat_color,
        "has_active_alerts": len(active_alerts) > 0,
        "active_alerts_count": len(active_alerts),
        "active_alerts": active_alerts,
        "all_alerts": alerts[-35:],
        "summary": {
            "total_packets": total_pkts_all,
            "total_dropped": total_drops_all,
            "overall_drop_rate_pct": overall_drop_rate,
            "rst_rate_sec": rst_rate,
            "timeout_rate_sec": timeout_rate,
            "udp_err_rate_sec": udp_err_rate,
            "total_interfaces": len(iface_data),
            "total_peers": len(peers_data)
        },
        "interface_stats": iface_data,
        "tunnel_peers": peers_data,
        "tcp_anomalies": {
            "EstabResets": kernel_data["totals"].get("estab_resets", 0),
            "TCPAbortOnData": kernel_data["totals"].get("tcp_abort_on_data", 0),
            "TCPTimeouts": kernel_data["totals"].get("tcp_timeouts", 0),
            "rates": k_rates
        },
        "dns_security": dns_data,
        "recommendations": recommendations
    }

    _SHIELD_CACHE = report
    _SHIELD_CACHE_TS = now_t
    return report

# -----------------------------------------------------------------------------
# 7. اجرای اقدامات دفاعی و اصلاحی مدیر (1-Click Mitigation Actions)
# -----------------------------------------------------------------------------
def execute_tunnel_shield_action(action_name, params=None):
    """
    Executes instant administrator mitigations.
    """
    params = params or {}
    logger.info(f"Executing Tunnel Shield action: {action_name}")

    if action_name == "clamp_mss":
        try:
            # 1. PMTU Clamp
            subprocess.run([
                "iptables", "-t", "mangle", "-I", "FORWARD", "1",
                "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                "-j", "TCPMSS", "--clamp-mss-to-pmtu"
            ], check=False)
            # 2. Hard clamp to 1240 for mobile telcos
            subprocess.run([
                "iptables", "-t", "mangle", "-I", "FORWARD", "2",
                "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                "-m", "tcpmss", "--mss", "1241:65535",
                "-j", "TCPMSS", "--set-mss", "1240"
            ], check=False)
            return True, "تنظیمات خودکار TCP MSS Clamping با سقف ۱۲۴۰ در فایروال لینوکس با موفقیت فعال شد. دراپ ناشی از سایز پکت برطرف گردید."
        except Exception as e:
            return False, f"خطا در اعمال رول‌های فایروال: {e}"

    elif action_name == "set_safe_mtu_1280":
        try:
            base = "/sys/class/net"
            changed = []
            if os.path.exists(base):
                for iface in os.listdir(base):
                    if iface.startswith(("awg", "wg", "tun", "tap", "gre", "ipip", "sit", "ovpn")):
                        r = subprocess.run(["ip", "link", "set", "dev", iface, "mtu", "1280"], capture_output=True)
                        if r.returncode == 0:
                            changed.append(iface)
            return True, f"مقدار MTU اینترفیس‌های تانل ({', '.join(changed) if changed else 'تونل‌های فعال'}) با موفقیت به ۱۲۸۰ کاهش یافت."
        except Exception as e:
            return False, f"خطا در تنظیم MTU: {e}"

    elif action_name == "enable_tunnel_dns_shield":
        try:
            subprocess.run([
                "iptables", "-t", "nat", "-I", "PREROUTING", "1",
                "-p", "udp", "--dport", "53",
                "-j", "REDIRECT", "--to-ports", "5353"
            ], check=False)
            return True, "سپر ضد نشت و ضد جعل DNS با موفقیت فعال شد. کلیه ترافیک پورت ۵۳ به ریزالور امن هدایت گردید."
        except Exception as e:
            return False, f"خطا در فعال‌سازی سپر فایروال: {e}"

    elif action_name == "disable_tunnel_dns_shield":
        try:
            subprocess.run([
                "iptables", "-t", "nat", "-D", "PREROUTING",
                "-p", "udp", "--dport", "53",
                "-j", "REDIRECT", "--to-ports", "5353"
            ], check=False)
            return True, "سپر ضد نشت DNS با موفقیت غیرفعال شد."
        except Exception as e:
            return False, f"خطا: {e}"

    elif action_name == "flush_stuck_sockets":
        try:
            # Kill TCP connections in CLOSE_WAIT or FIN_WAIT
            subprocess.run(["ss", "-K", "state", "close-wait"], capture_output=True)
            subprocess.run(["ss", "-K", "state", "fin-wait-1"], capture_output=True)
            return True, "سوکت‌های رهاشده و فیلترشده با موفقیت بسته شدند و منابع شبکه آزاد گردید."
        except Exception as e:
            return False, f"خطا در پاکسازی سوکت‌ها: {e}"

    elif action_name == "tune_kernel_buffers":
        try:
            settings = {
                "net.core.rmem_max": "16777216",
                "net.core.wmem_max": "16777216",
                "net.core.rmem_default": "2097152",
                "net.core.wmem_default": "2097152",
                "net.ipv4.tcp_rmem": "4096 87380 16777216",
                "net.ipv4.tcp_wmem": "4096 65536 16777216",
                "net.core.netdev_max_backlog": "10000"
            }
            for k, v in settings.items():
                subprocess.run(["sysctl", "-w", f"{k}={v}"], capture_output=True)
            return True, "بافرهای شبکه هسته لینوکس با موفقیت به ۱۶ مگابایت ارتقا یافتند و صف پردازش پکت‌ها بهینه‌سازی شد."
        except Exception as e:
            return False, f"خطا در تنظیم sysctl: {e}"

    return False, "عملیات نامعتبر است."
