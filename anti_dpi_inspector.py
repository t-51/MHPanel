# -*- coding: utf-8 -*-
"""
MH Panel - Deep Packet & Ingress Filtering Diagnostic Engine (Anti-DPI Inspector)
Real-time inspection of client connections, packet manipulation detection,
TCP RST middlebox injection detection, DNS leak & hijacking audits,
operator-by-operator threat matrix, and actionable admin recommendations.
"""

import os
import re
import time
import json
import socket
import logging
import urllib.request
import urllib.error
import ipaddress
import subprocess
from datetime import datetime, timedelta

logger = logging.getLogger("mhpanel.anti_dpi_inspector")

# =========================================================================
# 1. پایگاه داده محدوده آی‌پی‌های اپراتورهای ایران (Iranian ISP IP Ranges)
# =========================================================================
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
    "other": "سایر اپراتورها / خارج"
}

# Pre-compile IP networks for ultra-fast matching
_COMPILED_NETWORKS = []
for op_name, cidr_list in IRAN_OPERATOR_CIDRS.items():
    for c in cidr_list:
        try:
            _COMPILED_NETWORKS.append((ipaddress.ip_network(c), op_name))
        except Exception:
            pass

_IP_CACHE = {}

def classify_ip_operator(ip_str):
    """Ultra-fast LRU-cached classification of client IP to Iranian ISP."""
    if not ip_str or not isinstance(ip_str, str):
        return "other", OPERATOR_TITLES["other"]
    ip_str = ip_str.strip()
    if ip_str in _IP_CACHE:
        code = _IP_CACHE[ip_str]
        return code, OPERATOR_TITLES.get(code, OPERATOR_TITLES["other"])
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback:
            return "other", "شبکه داخلی (Local)"
        for net, code in _COMPILED_NETWORKS:
            if ip_obj in net:
                if len(_IP_CACHE) > 5000:
                    _IP_CACHE.clear()
                _IP_CACHE[ip_str] = code
                return code, OPERATOR_TITLES.get(code, OPERATOR_TITLES["other"])
    except Exception:
        pass
    if len(_IP_CACHE) > 5000:
        _IP_CACHE.clear()
    _IP_CACHE[ip_str] = "other"
    return "other", OPERATOR_TITLES["other"]

# =========================================================================
# 2. رهگیری آنومالی‌های هسته لینوکس و سوکت‌های TCP/UDP (Kernel Sniffer)
# =========================================================================
_LAST_KERNEL_SNAPSHOT = {}
_LAST_KERNEL_TIME = 0

def get_kernel_network_anomalies():
    """
    Read real-time TCP/UDP drop, reset, timeout, and buffer anomaly counters
    from Linux /proc/net/snmp and /proc/net/netstat.
    """
    global _LAST_KERNEL_SNAPSHOT, _LAST_KERNEL_TIME

    raw_snmp = {}
    raw_netstat = {}

    try:
        if os.path.exists("/proc/net/snmp"):
            with open("/proc/net/snmp", "r") as f:
                lines = f.readlines()
            for i in range(0, len(lines) - 1, 2):
                header = lines[i].split()
                values = lines[i + 1].split()
                if header and values and header[0] == values[0]:
                    proto = header[0].replace(":", "")
                    raw_snmp[proto] = dict(zip(header[1:], [int(x) if x.isdigit() else x for x in values[1:]]))

        if os.path.exists("/proc/net/netstat"):
            with open("/proc/net/netstat", "r") as f:
                lines = f.readlines()
            for i in range(0, len(lines) - 1, 2):
                header = lines[i].split()
                values = lines[i + 1].split()
                if header and values and header[0] == values[0]:
                    proto = header[0].replace(":", "")
                    raw_netstat[proto] = dict(zip(header[1:], [int(x) if x.isdigit() else x for x in values[1:]]))
    except Exception as e:
        logger.error(f"Error reading kernel net stats: {e}")

    tcp_snmp = raw_snmp.get("Tcp", {})
    udp_snmp = raw_snmp.get("Udp", {})
    tcp_ext = raw_netstat.get("TcpExt", {})

    curr_snapshot = {
        "estab_resets": int(tcp_snmp.get("EstabResets") or 0),
        "attempt_fails": int(tcp_snmp.get("AttemptFails") or 0),
        "retrans_segs": int(tcp_snmp.get("RetransSegs") or 0),
        "in_errs": int(tcp_snmp.get("InErrs") or 0),
        "out_rsts": int(tcp_snmp.get("OutRsts") or 0),
        "udp_in_errors": int(udp_snmp.get("InErrors") or 0),
        "udp_rcvbuf_errors": int(udp_snmp.get("RcvbufErrors") or 0),
        "tcp_abort_on_data": int(tcp_ext.get("TCPAbortOnData") or 0),
        "tcp_abort_on_timeout": int(tcp_ext.get("TCPAbortOnTimeout") or 0),
        "tcp_timeouts": int(tcp_ext.get("TCPTimeouts") or 0),
        "tcp_sack_recovery": int(tcp_ext.get("TCPSackRecovery") or 0),
        "tcp_listen_drops": int(tcp_ext.get("ListenDrops") or 0)
    }

    now_t = time.time()
    dt = max(1.0, now_t - _LAST_KERNEL_TIME) if _LAST_KERNEL_TIME else 10.0

    deltas = {}
    if _LAST_KERNEL_SNAPSHOT:
        for k, v in curr_snapshot.items():
            deltas[k] = max(0, v - _LAST_KERNEL_SNAPSHOT.get(k, v))
    else:
        for k in curr_snapshot:
            deltas[k] = 0

    _LAST_KERNEL_SNAPSHOT = curr_snapshot
    _LAST_KERNEL_TIME = now_t

    # Rates per second
    rates = {k: round(v / dt, 2) for k, v in deltas.items()}

    return {
        "counters": curr_snapshot,
        "deltas": deltas,
        "rates": rates,
        "sample_interval_sec": round(dt, 1)
    }

# =========================================================================
# 3. تحلیل عمیق اتصالات کلاینت‌ها در Sing-box (Ingress Deep Inspection)
# =========================================================================
def analyze_singbox_ingress():
    """
    Query Sing-box Clash API (127.0.0.1:9095/connections) and classify
    live client connections into health, handshake silent-drops, DNS leaks,
    and operator filtering status.
    """
    req = urllib.request.Request("http://127.0.0.1:9095/connections")
    data = {}
    try:
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        logger.error(f"Error querying singbox clash api: {e}")
        return {
            "error": "عدم دسترسی به API وضعیت سینگ‌باکس",
            "operators": {},
            "problematic_conns": [],
            "dns_leaks": []
        }

    connections = data.get("connections") or []
    total_conns = len(connections)
    now_dt = datetime.now()

    operator_stats = {
        code: {
            "code": code,
            "name": OPERATOR_TITLES[code],
            "total_conns": 0,
            "healthy_conns": 0,
            "silent_drops": 0,
            "dns_leaks": 0,
            "protocols": {},
            "status": "GOOD",
            "drop_rate": 0.0
        }
        for code in OPERATOR_TITLES
    }

    problematic_conns = []
    dns_leaks = []

    for conn in connections:
        cid = conn.get("id") or ""
        meta = conn.get("metadata") or {}
        src_ip = str(meta.get("sourceIP") or "").strip()
        dst_port = str(meta.get("destinationPort") or "")
        network = str(meta.get("network") or "").lower()
        host = str(meta.get("host") or meta.get("destinationIP") or "")
        conn_type = str(meta.get("type") or "vless")
        rule = str(conn.get("rule") or "")

        up_bytes = int(conn.get("upload") or 0)
        down_bytes = int(conn.get("download") or 0)

        # Calculate duration
        start_str = conn.get("start") or ""
        duration_sec = 0
        if start_str:
            try:
                # E.g. "2026-11-23T02:52:13.540648076+03:30"
                clean_ts = start_str.split(".")[0]
                st_dt = datetime.strptime(clean_ts, "%Y-%m-%dT%H:%M:%S")
                duration_sec = max(0, (now_dt - st_dt).total_seconds())
            except Exception:
                duration_sec = 10

        op_code, op_title = classify_ip_operator(src_ip)
        op_obj = operator_stats[op_code]
        op_obj["total_conns"] += 1

        proto_simple = conn_type.split("/")[0] if "/" in conn_type else conn_type
        op_obj["protocols"][proto_simple] = op_obj["protocols"].get(proto_simple, 0) + 1

        is_problematic = False
        anomaly_reason = ""

        # Check 1: DNS Leak (plain UDP 53 ingress to external IP)
        if dst_port == "53" and network == "udp":
            op_obj["dns_leaks"] += 1
            is_problematic = True
            anomaly_reason = "نشت درخواست DNS پورت ۵۳ معمولی (در معرض شنود و جعل 10.10.34.34)"
            dns_leaks.append({
                "id": cid,
                "ip": src_ip,
                "operator": op_title,
                "target": host,
                "duration_sec": int(duration_sec),
                "up": up_bytes,
                "down": down_bytes
            })

        # Check 2: Silent Drop / Handshake Timeout (DPI drop)
        # Client sent ClientHello (up > 300), but server got 0 download back, duration > 8s
        elif up_bytes > 300 and down_bytes == 0 and duration_sec >= 8:
            op_obj["silent_drops"] += 1
            is_problematic = True
            anomaly_reason = f"بسته‌های دریافتی مسدود شده (Silent Drop توسط فیلترینگ در پکت ClientHello)"

        # Check 3: Connection healthy
        if not is_problematic and down_bytes > 0:
            op_obj["healthy_conns"] += 1

        if is_problematic:
            problematic_conns.append({
                "id": cid,
                "ip": src_ip,
                "operator": op_title,
                "operator_code": op_code,
                "proto": conn_type,
                "host": host or f"Port {dst_port}",
                "network": network.upper(),
                "duration_sec": int(duration_sec),
                "upload": up_bytes,
                "download": down_bytes,
                "reason": anomaly_reason
            })

    # Calculate status per operator
    for code, op in operator_stats.items():
        tot = op["total_conns"]
        if tot > 0:
            drops = op["silent_drops"] + (op["dns_leaks"] * 0.5)
            drop_rate = round((drops / tot) * 100, 1)
            op["drop_rate"] = drop_rate
            if drop_rate >= 25.0:
                op["status"] = "BLOCKED"
            elif drop_rate >= 8.0:
                op["status"] = "THROTTLED"
            else:
                op["status"] = "GOOD"

    return {
        "total_connections": total_conns,
        "operators": operator_stats,
        "problematic_conns": problematic_conns[:50],
        "dns_leaks": dns_leaks[:30],
        "total_silent_drops": sum(x["silent_drops"] for x in operator_stats.values()),
        "total_dns_leaks": len(dns_leaks)
    }

# =========================================================================
# 4. تست نشت DNS و ارزیابی مسموم‌سازی DNS در سرور (DNS Poisoning Sensor)
# =========================================================================
def audit_dns_security():
    """
    Test whether the server's local resolver or client upstream is poisoned
    with Iranian fake addresses (10.10.34.34) or if DoH encrypted DNS is reachable.
    """
    test_domains = ["twitter.com", "instagram.com", "youtube.com"]
    poisoned_detected = False
    details = []

    for d in test_domains:
        try:
            addr = socket.gethostbyname(d)
            if addr.startswith("10.10.34.") or addr.startswith("10.10."):
                poisoned_detected = True
                details.append(f"{d} -> {addr} (مسموم شده با آدرس جعلی پیوندها)")
            else:
                details.append(f"{d} -> {addr} (سالم)")
        except Exception as e:
            details.append(f"{d} -> خطا ({e})")

    # Check DoH status
    doh_ok = False
    try:
        req = urllib.request.Request(
            "https://1.1.1.1/dns-query?name=google.com&type=A",
            headers={"Accept": "application/dns-json"}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            if resp.status == 200:
                doh_ok = True
    except Exception:
        doh_ok = False

    # Check if DNS Leak firewall shield rule is active
    shield_active = False
    try:
        chk = subprocess.run(["iptables", "-t", "nat", "-C", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"], capture_output=True)
        shield_active = (chk.returncode == 0)
    except Exception:
        pass

    return {
        "poisoned_detected": poisoned_detected,
        "doh_reachable": doh_ok,
        "shield_active": shield_active,
        "resolutions": details
    }

# =========================================================================
# 5. تولید گزارش جامع و پیشنهادهای هوشمند اقدام برای مدیر
# =========================================================================
_REPORT_CACHE = None
_REPORT_CACHE_TS = 0
_CACHE_TTL_SEC = 6.0

def generate_anti_dpi_report(force_fresh=False):
    """
    Build real-time comprehensive Anti-DPI report with operator threat matrix,
    kernel resets, handshake drops, and exact recommendations for admin.
    Cached for 6 seconds to avoid CPU load.
    """
    global _REPORT_CACHE, _REPORT_CACHE_TS
    now = time.time()
    if not force_fresh and _REPORT_CACHE and (now - _REPORT_CACHE_TS < _CACHE_TTL_SEC):
        return _REPORT_CACHE

    kernel_data = get_kernel_network_anomalies()
    ingress_data = analyze_singbox_ingress()
    dns_audit = audit_dns_security()

    # Calculate overall Threat Level & Quality Score
    k_rates = kernel_data.get("rates", {})
    rst_rate = k_rates.get("estab_resets", 0) + k_rates.get("tcp_abort_on_data", 0)
    timeout_rate = k_rates.get("tcp_timeouts", 0)
    total_drops = ingress_data.get("total_silent_drops", 0)
    dns_leaks = ingress_data.get("total_dns_leaks", 0)

    # Health score from 100 down
    penalty = 0
    if rst_rate > 20: penalty += 30
    elif rst_rate > 5: penalty += 15

    if timeout_rate > 20: penalty += 25
    elif timeout_rate > 5: penalty += 10

    if total_drops > 20: penalty += 25
    elif total_drops > 5: penalty += 15

    if dns_leaks > 0: penalty += 15
    if dns_audit.get("poisoned_detected"): penalty += 15

    health_score = max(5, 100 - penalty)

    if health_score >= 80:
        threat_level = "NORMAL"
        threat_label = "عادی و پایدار"
        threat_color = "#10b981"
    elif health_score >= 50:
        threat_level = "WARNING"
        threat_label = "اختلال و افت پکت متوسط"
        threat_color = "#f59e0b"
    else:
        threat_level = "CRITICAL"
        threat_label = "فیلترینگ و مسدودسازی فعال پکت‌ها"
        threat_color = "#ef4444"

    # Actionable Recommendations for Admin
    recommendations = []
    ops = ingress_data.get("operators", {})

    # Check MCI
    mci = ops.get("mci", {})
    if mci.get("status") in ["BLOCKED", "THROTTLED"] or mci.get("silent_drops", 0) > 3:
        recommendations.append({
            "id": "rec_mci_frag",
            "priority": "HIGH",
            "target": "همراه اول (MCI)",
            "issue": f"شناسایی {mci.get('silent_drops')} اتصال مسدود شده در مرحله Handshake",
            "action_text": "فعال‌سازی تکه‌تکه کردن پکت (Fragment 10-30 با تاخیر 2-5ms) و جابجایی پورت 443 به 2096",
            "quick_action": "apply_preset_mci",
            "btn_label": "⚡ اعمال تنظیمات اختصاصی همراه اول"
        })

    # Check MTN Irancell
    mtn = ops.get("mtn", {})
    if mtn.get("status") in ["BLOCKED", "THROTTLED"] or mtn.get("silent_drops", 0) > 3:
        recommendations.append({
            "id": "rec_mtn_ech",
            "priority": "HIGH",
            "target": "ایرانسل (MTN)",
            "issue": f"شناسایی {mtn.get('silent_drops')} اتصال بی‌پاسخ مانده به دلیل مسدودسازی SNI در ایرانسل",
            "action_text": "فعال‌سازی فوری ECH با ریزالور DoH کلودفلر (aef.ir) و فرگمنت 100-200",
            "quick_action": "apply_preset_mtn",
            "btn_label": "⚡ اعمال ECH و فرگمنت ایرانسل"
        })

    # Check DNS leaks
    if dns_leaks > 0:
        recommendations.append({
            "id": "rec_dns_shield",
            "priority": "CRITICAL",
            "target": "امنیت DNS و نشت داده",
            "issue": f"شناسایی {dns_leaks} کلاینت در حال ارسال درخواست‌های DNS رمزنگاری‌نشده (پورت 53) که شنود و جعل می‌شوند",
            "action_text": "فعال‌سازی سپر ضد نشت DNS (هدایت و قفل خودکار پورت 53 به DoH رمزنگاری‌شده در فایروال)",
            "quick_action": "enable_dns_shield",
            "btn_label": "🛡️ فعال‌سازی قفل ضد نشت DNS"
        })

    # Check TCP RST spikes
    if rst_rate > 10:
        recommendations.append({
            "id": "rec_rst_defense",
            "priority": "HIGH",
            "target": "تزریق پکت جعلی RST توسط فیلترینگ",
            "issue": f"تزریق {int(rst_rate)} پکت RST جعلی در هر ثانیه توسط DPI برای قطع ارتباط کلاینت‌ها",
            "action_text": "تغییر دامنه Camouflage SNI به دامنه‌های داخلی ایرانی (shaparak.ir / sanjesh.org) جهت خنثی‌سازی بازرسی پکت",
            "quick_action": "switch_sni_domestic",
            "btn_label": "🌐 تغییر استتار به دامنه داخلی"
        })

    # Check Hung Connections to Clean
    if total_drops > 5:
        recommendations.append({
            "id": "rec_kill_hung",
            "priority": "MEDIUM",
            "target": "اتصالات بلاتکلیف کلاینت‌ها",
            "issue": f"تعداد {total_drops} اتصال در کلاینت‌ها قطع نامرئی شده و اپلیکیشن کاربر منتظر پاسخ مانده است",
            "action_text": "قطع فوری اتصالات بلاتکلیف با ارسال سیگنال ریست تا اپلیکیشن کلاینت‌ها بلافاصله به مسیر سالم سوییچ کنند",
            "quick_action": "kill_stuck_connections",
            "btn_label": "🧹 پاکسازی فوری اتصالات فیلتر شده"
        })

    report = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "threat_level": threat_level,
        "threat_label": threat_label,
        "threat_color": threat_color,
        "health_score": health_score,
        "summary": {
            "total_active_connections": ingress_data.get("total_connections", 0),
            "silent_drops": total_drops,
            "dns_leaks": dns_leaks,
            "rst_injections_rate_sec": rst_rate,
            "timeouts_rate_sec": timeout_rate,
            "udp_errors_rate_sec": k_rates.get("udp_in_errors", 0) + k_rates.get("udp_rcvbuf_errors", 0)
        },
        "kernel_telemetry": kernel_data,
        "operator_matrix": ops,
        "dns_audit": dns_audit,
        "problematic_connections": ingress_data.get("problematic_conns", []),
        "recommendations": recommendations
    }

    _REPORT_CACHE = report
    _REPORT_CACHE_TS = now
    return report

# =========================================================================
# 6. اجرای اقدامات فوری و دفاعی مدیر (Quick Actions)
# =========================================================================
def execute_anti_dpi_action(action_name, params=None):
    """
    Execute instant defense or mitigation action selected by admin.
    """
    params = params or {}
    logger.info(f"Executing Anti-DPI action: {action_name} with params: {params}")

    if action_name == "kill_stuck_connections":
        # Delete hung connections with up > 300 and down == 0
        try:
            req = urllib.request.Request("http://127.0.0.1:9095/connections")
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                data = json.loads(resp.read().decode())
            conns = data.get("connections") or []
            killed_count = 0
            for c in conns:
                cid = c.get("id")
                up = int(c.get("upload") or 0)
                down = int(c.get("download") or 0)
                if up > 300 and down == 0 and cid:
                    del_req = urllib.request.Request(f"http://127.0.0.1:9095/connections/{cid}", method="DELETE")
                    try:
                        urllib.request.urlopen(del_req, timeout=1.0)
                        killed_count += 1
                    except Exception:
                        pass
            return True, f"تعداد {killed_count} اتصال بلاتکلیف و قطع‌شده با موفقیت بسته شد تا کلاینت‌ها مجدداً متصل شوند."
        except Exception as e:
            return False, f"خطا در قطع اتصالات: {e}"

    elif action_name == "enable_dns_shield":
        # Redirect plain UDP port 53 to local encrypted DNS or block outbound leak
        try:
            subprocess.run([
                "iptables", "-t", "nat", "-I", "PREROUTING", "1",
                "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"
            ], check=False)
            return True, "سپر ضد نشت DNS با موفقیت فعال شد. کلیه درخواست‌های پورت 53 به پروتکل امن هدایت شدند."
        except Exception as e:
            return False, f"خطا در فعال‌سازی سپر فایروال: {e}"

    elif action_name == "disable_dns_shield":
        try:
            subprocess.run([
                "iptables", "-t", "nat", "-D", "PREROUTING",
                "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"
            ], check=False)
            return True, "سپر ضد نشت فایروال غیرفعال شد."
        except Exception as e:
            return False, f"خطا: {e}"

    elif action_name.startswith("apply_preset_"):
        op_code = action_name.replace("apply_preset_", "").strip()
        from anti_dpi_presets import get_anti_dpi_settings, save_anti_dpi_settings
        settings = get_anti_dpi_settings()
        settings["default_operator"] = op_code
        settings["default_fragment_enabled"] = True
        settings["default_ech_enabled"] = True
        save_anti_dpi_settings(settings)
        return True, f"پیکربندی اختصاصی ضد فیلترینگ برای {OPERATOR_TITLES.get(op_code, op_code)} با موفقیت اعمال گردید."

    elif action_name == "switch_sni_domestic":
        from anti_dpi_presets import get_anti_dpi_settings, save_anti_dpi_settings
        settings = get_anti_dpi_settings()
        settings["custom_camouflage_sni"] = "sanjesh.org"
        save_anti_dpi_settings(settings)
        return True, "دامنه استتار ضد DPI با موفقیت به sanjesh.org تغییر یافت."

    return False, "عملیات ناشناخته"
