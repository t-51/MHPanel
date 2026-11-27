# -*- coding: utf-8 -*-
"""
MH Panel - Server & Network Security Manager
Handles:
  - Persistent IP Blacklist / Whitelist via iptables (MHPANEL_IP_RULES)
  - Persistent P2P / BitTorrent blocking (Sing-box route rules + iptables MHPANEL_P2P_BLOCK)
  - Server Security Audit, Firewall Status, and Security Event Logs
  - Multi-Admin RBAC management (PBKDF2-HMAC-SHA256 hashed passwords + allowed_tabs)
"""

import os
import re
import json
import time
import hmac
import shutil
import hashlib
import secrets
import ipaddress
import subprocess
from datetime import datetime

SECURITY_DIR = "/etc/vpnpanel"
SECURITY_SETTINGS_FILE = os.path.join(SECURITY_DIR, "security_settings.json")
IP_RULES_FILE = os.path.join(SECURITY_DIR, "security_ip_rules.json")
PANEL_ADMINS_FILE = os.path.join(SECURITY_DIR, "panel_admins.json")
SECURITY_LOG_FILE = os.path.join(SECURITY_DIR, "security_events.log")
ABUSE_REPORTS_FILE = os.path.join(SECURITY_DIR, "abuse_reports.json")
SINGBOX_CONFIG_FILE = "/etc/sing-box/config.json"
MHPANEL_ROOT = "/www/wwwroot/mhpanel"

ABUSE_SMTP_PORTS = [25, 465, 587, 2525]
ABUSE_INTRUSION_PORTS = [23, 135, 137, 138, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017]
ABUSE_ALL_PORTS = ABUSE_SMTP_PORTS + ABUSE_INTRUSION_PORTS
ABUSE_PORT_LABELS = {
    25: "SMTP Email Spam (Port 25)",
    465: "SMTPS Email Spam (Port 465)",
    587: "SMTP Submission Spam (Port 587)",
    2525: "SMTP Alt Spam (Port 2525)",
    23: "Telnet Scan/Brute (Port 23)",
    135: "RPC/DCOM Exploit (Port 135)",
    137: "NetBIOS Scan (Port 137)",
    138: "NetBIOS Scan (Port 138)",
    139: "SMB/NetBIOS (Port 139)",
    445: "SMB/Ransomware Scan (Port 445)",
    1433: "MSSQL Brute-Force (Port 1433)",
    1521: "Oracle DB Brute-Force (Port 1521)",
    3306: "MySQL Scan/Brute (Port 3306)",
    3389: "RDP Brute-Force (Port 3389)",
    5432: "PostgreSQL Scan (Port 5432)",
    5900: "VNC Brute-Force (Port 5900)",
    6379: "Redis Unauth Exploit (Port 6379)",
    27017: "MongoDB Scan (Port 27017)"
}

P2P_PORTS = "6881:6889,6969,51413"
P2P_BLOCK_DOMAINS = [
    "torrent", "tracker", "announce", "bittorrent", "utorrent",
    "qbittorrent", "piratebay", "1337x", "rutracker", "nyaa", "rarbg"
]
P2P_BLOCK_PORTS = [6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6969, 51413]

PANEL_SECTION_CATALOG = [
    {"id": "overview", "label": "نمای کلی (Overview)"},
    {"id": "radar", "label": "رادار فیلترینگ"},
    {"id": "protocols", "label": "وضعیت کلی پروتکل‌ها"},
    {"id": "singbox", "label": "هسته Sing-box و کاربران"},
    {"id": "ssh", "label": "مدیریت SSH"},
    {"id": "wireguard", "label": "WireGuard"},
    {"id": "amneziawg", "label": "AmneziaWG"},
    {"id": "openvpn", "label": "OpenVPN"},
    {"id": "dns-tunnels", "label": "تونل‌های DNS"},
    {"id": "tunnels", "label": "تونل‌های سرور"},
    {"id": "snispoof", "label": "جعل SNI و ضد انسداد"},
    {"id": "cloudflare-hub", "label": "مرکز کلاود (Cloudflare)"},
    {"id": "radius", "label": "رادیوس (RADIUS)"},
    {"id": "servers", "label": "مدیریت سرورها"},
    {"id": "system", "label": "تنظیمات سیستم"},
    {"id": "terminal", "label": "ترمینال وب"},
    {"id": "docs", "label": "مستندات"}
]


def _ensure_dir():
    os.makedirs(SECURITY_DIR, exist_ok=True)


def log_security_event(event_type, message, actor="system", ip_addr=""):
    try:
        _ensure_dir()
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [{event_type}] [actor={actor}]"
        if ip_addr:
            line += f" [ip={ip_addr}]"
        line += f" {message}\n"
        with open(SECURITY_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
        # Keep log bounded to last 500 lines
        with open(SECURITY_LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        if len(lines) > 500:
            with open(SECURITY_LOG_FILE, "w", encoding="utf-8") as f:
                f.writelines(lines[-500:])
    except Exception:
        pass


def get_security_events(limit=60):
    events = []
    if os.path.exists(SECURITY_LOG_FILE):
        try:
            with open(SECURITY_LOG_FILE, "r", encoding="utf-8") as f:
                lines = [ln.strip() for ln in f.readlines() if ln.strip()]
            events = list(reversed(lines[-limit:]))
        except Exception:
            pass
    return events


def get_security_settings():
    defaults = {
        "p2p_block_enabled": False,
        "p2p_block_singbox": True,
        "p2p_block_iptables": True,
        "abuse_shield_enabled": False,
        "auto_suspend_abusers": True,
        "updated_at": ""
    }
    if os.path.exists(SECURITY_SETTINGS_FILE):
        try:
            with open(SECURITY_SETTINGS_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                if isinstance(saved, dict):
                    defaults.update(saved)
        except Exception:
            pass
    return defaults


def save_security_settings(cfg):
    _ensure_dir()
    cfg["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(SECURITY_SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def _run_iptables(args):
    ipt = shutil.which("iptables") or "/usr/sbin/iptables"
    return subprocess.run([ipt] + args, capture_output=True, text=True, timeout=5)


def _ensure_chain(chain_name, parent_chains):
    _run_iptables(["-N", chain_name])
    for parent in parent_chains:
        chk = _run_iptables(["-C", parent, "-j", chain_name])
        if chk.returncode != 0:
            _run_iptables(["-I", parent, "1", "-j", chain_name])


def apply_p2p_iptables_rules(enable):
    """Create or flush MHPANEL_P2P_BLOCK iptables chain for permanent BitTorrent/P2P blocking."""
    chain = "MHPANEL_P2P_BLOCK"
    _ensure_chain(chain, ["FORWARD", "OUTPUT"])
    _run_iptables(["-F", chain])
    if not enable:
        return True, "قوانین کرنل P2P پاکسازی شد."

    rules = [
        ["-A", chain, "-p", "tcp", "-m", "multiport", "--dports", P2P_PORTS, "-j", "DROP"],
        ["-A", chain, "-p", "udp", "-m", "multiport", "--dports", P2P_PORTS, "-j", "DROP"],
        ["-A", chain, "-p", "tcp", "-m", "string", "--string", "BitTorrent protocol", "--algo", "bm", "-j", "DROP"],
        ["-A", chain, "-p", "udp", "-m", "string", "--string", "d1:ad2:id20:", "--algo", "bm", "-j", "DROP"],
        ["-A", chain, "-p", "udp", "-m", "string", "--string", "announce_peer", "--algo", "bm", "-j", "DROP"],
        ["-A", chain, "-p", "tcp", "-m", "string", "--string", "info_hash", "--algo", "bm", "-j", "DROP"],
    ]
    applied = 0
    for r in rules:
        res = _run_iptables(r)
        if res.returncode == 0:
            applied += 1
    return True, f"{applied} قانون مسدودسازی P2P در کرنل (iptables) اعمال شد."


def apply_p2p_singbox_rules(enable):
    """Inject or remove permanent BitTorrent/P2P block rules in /etc/sing-box/config.json."""
    if not os.path.exists(SINGBOX_CONFIG_FILE):
        return False, "فایل کانفیگ Sing-box یافت نشد."
    try:
        with open(SINGBOX_CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)

        outbounds = cfg.setdefault("outbounds", [])
        if not any(isinstance(o, dict) and o.get("tag") == "block" for o in outbounds):
            outbounds.append({"type": "block", "tag": "block"})

        route = cfg.setdefault("route", {})
        rules = route.setdefault("rules", [])

        # Remove previous MHPanel P2P rules
        cleaned = []
        for r in rules:
            if not isinstance(r, dict):
                cleaned.append(r)
                continue
            if r.get("_mhpanel_p2p"):
                continue
            if r.get("protocol") == ["bittorrent"] or r.get("protocol") == "bittorrent":
                continue
            cleaned.append(r)

        if enable:
            p2p_rules = [
                {"_mhpanel_p2p": True, "protocol": ["bittorrent"], "outbound": "block"},
                {"_mhpanel_p2p": True, "port": P2P_BLOCK_PORTS, "outbound": "block"},
                {"_mhpanel_p2p": True, "domain_keyword": P2P_BLOCK_DOMAINS, "outbound": "block"}
            ]
            # Insert after sniff/hijack-dns rules if present
            insert_idx = 0
            for idx, r in enumerate(cleaned):
                if isinstance(r, dict) and (r.get("action") in ("sniff", "hijack-dns") or r.get("protocol") == "dns"):
                    insert_idx = idx + 1
            for offset, pr in enumerate(p2p_rules):
                cleaned.insert(insert_idx + offset, pr)

        route["rules"] = cleaned
        with open(SINGBOX_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)

        subprocess.run(["systemctl", "restart", "sing-box"], capture_output=True, timeout=8)
        return True, "قوانین مسدودسازی P2P در هسته Sing-box اعمال و سرویس ری‌استارت شد."
    except Exception as e:
        return False, f"خطا در اعمال قوانین Sing-box: {e}"


def set_p2p_block(enable):
    cfg = get_security_settings()
    cfg["p2p_block_enabled"] = bool(enable)
    save_security_settings(cfg)
    ok_ipt, msg_ipt = apply_p2p_iptables_rules(bool(enable))
    ok_sb, msg_sb = apply_p2p_singbox_rules(bool(enable))
    log_security_event("P2P_BLOCK", f"P2P permanent block set to {bool(enable)} ({msg_ipt} | {msg_sb})")
    return {
        "success": True,
        "enabled": bool(enable),
        "iptables": {"ok": ok_ipt, "message": msg_ipt},
        "singbox": {"ok": ok_sb, "message": msg_sb},
        "message": f"مسدودسازی دائم P2P / BitTorrent {'فعال' if enable else 'غیرفعال'} شد."
    }


# =========================================================================
# IP Whitelist / Blacklist Management (iptables MHPANEL_IP_RULES)
# =========================================================================

def load_ip_rules():
    if os.path.exists(IP_RULES_FILE):
        try:
            with open(IP_RULES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            pass
    return []


def save_ip_rules(rules):
    _ensure_dir()
    with open(IP_RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2, ensure_ascii=False)


def normalize_ip_or_cidr(val):
    val = (val or "").strip()
    if not val:
        return None
    try:
        if "/" in val:
            net = ipaddress.ip_network(val, strict=False)
            return str(net)
        ip = ipaddress.ip_address(val)
        return str(ip)
    except Exception:
        return None


def sync_ip_rules_to_iptables(rules=None):
    if rules is None:
        rules = load_ip_rules()
    chain = "MHPANEL_IP_RULES"
    _ensure_chain(chain, ["INPUT", "FORWARD"])
    _run_iptables(["-F", chain])

    # Apply 'allow' rules before 'block' rules
    ordered = sorted(rules, key=lambda r: 0 if r.get("action") == "allow" else 1)
    for r in ordered:
        target_ip = r.get("ip")
        action = r.get("action", "block")
        if not target_ip:
            continue
        jump = "ACCEPT" if action == "allow" else "DROP"
        _run_iptables(["-A", chain, "-s", target_ip, "-j", jump])
        _run_iptables(["-A", chain, "-d", target_ip, "-j", jump])


def add_ip_rule(raw_ip, action="block", note="", actor="admin"):
    norm = normalize_ip_or_cidr(raw_ip)
    if not norm:
        return False, "فرمت آی‌پی یا CIDR نامعتبر است (مثال: 1.2.3.4 یا 1.2.3.0/24)."
    action = "allow" if action == "allow" else "block"
    rules = load_ip_rules()
    rules = [r for r in rules if r.get("ip") != norm]
    rules.insert(0, {
        "ip": norm,
        "action": action,
        "note": (note or "").strip(),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    save_ip_rules(rules)
    sync_ip_rules_to_iptables(rules)
    log_security_event("IP_RULE", f"{action.upper()} {norm} ({note})", actor=actor)
    return True, f"آی‌پی {norm} با وضعیت {'مجاز (Allow)' if action == 'allow' else 'مسدود (Block)'} ثبت و در فایروال اعمال شد."


def remove_ip_rule(raw_ip, actor="admin"):
    norm = normalize_ip_or_cidr(raw_ip) or (raw_ip or "").strip()
    rules = load_ip_rules()
    new_rules = [r for r in rules if r.get("ip") != norm]
    if len(new_rules) == len(rules):
        return False, "قانونی برای این آی‌پی یافت نشد."
    save_ip_rules(new_rules)
    sync_ip_rules_to_iptables(new_rules)
    log_security_event("IP_RULE_DEL", f"Removed rule for {norm}", actor=actor)
    return True, f"قانون آی‌پی {norm} حذف و از فایروال پاک شد."


def restore_all_security_rules():
    """Called on panel startup to ensure IP rules, P2P block, and Abuse Shield persist across reboots."""
    try:
        sync_ip_rules_to_iptables()
    except Exception:
        pass
    try:
        cfg = get_security_settings()
        if cfg.get("p2p_block_enabled"):
            apply_p2p_iptables_rules(True)
        if cfg.get("abuse_shield_enabled"):
            apply_abuse_iptables_rules(True)
    except Exception:
        pass


# =========================================================================
# EU/US Datacenter Anti-Abuse, Anti-Spam, Anti-Hack & Auto-Suspension
# =========================================================================

def apply_abuse_iptables_rules(enable):
    """Create or flush MHPANEL_ABUSE_SHIELD chain to block SMTP spam, SMB/RDP/DB hacking & log offenders."""
    chain = "MHPANEL_ABUSE_SHIELD"
    _ensure_chain(chain, ["FORWARD", "OUTPUT"])
    _run_iptables(["-F", chain])
    if not enable:
        return True, "قوانین ضد اسپم و نفوذ کرنل غیرفعال شد."

    ports_csv = ",".join(str(p) for p in ABUSE_ALL_PORTS)
    rules = [
        # Allow root/local system mail or DNS if needed, block & log forwarded VPN abuse and non-root output
        ["-A", chain, "-p", "tcp", "-m", "multiport", "--dports", ports_csv, "-m", "limit", "--limit", "15/min", "-j", "LOG", "--log-prefix", "MHPANEL_ABUSE: ", "--log-level", "4"],
        ["-A", chain, "-p", "tcp", "-m", "multiport", "--dports", ports_csv, "-j", "DROP"],
        ["-A", chain, "-p", "udp", "-m", "multiport", "--dports", "137:139,445,1433,1900", "-m", "limit", "--limit", "10/min", "-j", "LOG", "--log-prefix", "MHPANEL_ABUSE: ", "--log-level", "4"],
        ["-A", chain, "-p", "udp", "-m", "multiport", "--dports", "137:139,445,1433,1900", "-j", "DROP"],
    ]
    applied = 0
    for r in rules:
        res = _run_iptables(r)
        if res.returncode == 0:
            applied += 1
    return True, f"{applied} قانون ضد اسپم/نفوذ (اروپا و آمریکا) در کرنل اعمال شد."


def apply_abuse_singbox_rules(enable):
    """Block SMTP spam, intrusion ports, and private/cloud-metadata IP scanning in Sing-box."""
    if not os.path.exists(SINGBOX_CONFIG_FILE):
        return False, "فایل کانفیگ Sing-box یافت نشد."
    try:
        with open(SINGBOX_CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)

        outbounds = cfg.setdefault("outbounds", [])
        if not any(isinstance(o, dict) and o.get("tag") == "block" for o in outbounds):
            outbounds.append({"type": "block", "tag": "block"})

        route = cfg.setdefault("route", {})
        rules = route.setdefault("rules", [])

        cleaned = [r for r in rules if not (isinstance(r, dict) and r.get("_mhpanel_abuse"))]
        if enable:
            abuse_rules = [
                {"_mhpanel_abuse": True, "ip_is_private": True, "outbound": "block"},
                {"_mhpanel_abuse": True, "port": ABUSE_ALL_PORTS, "outbound": "block"}
            ]
            insert_idx = 0
            for idx, r in enumerate(cleaned):
                if isinstance(r, dict) and (r.get("action") in ("sniff", "hijack-dns") or r.get("protocol") == "dns" or r.get("_mhpanel_p2p")):
                    insert_idx = idx + 1
            for offset, ar in enumerate(abuse_rules):
                cleaned.insert(insert_idx + offset, ar)

        route["rules"] = cleaned
        with open(SINGBOX_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)

        subprocess.run(["systemctl", "restart", "sing-box"], capture_output=True, timeout=8)
        return True, "قوانین ضد اسپم/نفوذ و مسدودسازی اسکن شبکه داخلی در Sing-box اعمال شد."
    except Exception as e:
        return False, f"خطا در اعمال قوانین Sing-box: {e}"


def set_abuse_shield(enabled=None, auto_suspend=None):
    cfg = get_security_settings()
    if enabled is not None:
        cfg["abuse_shield_enabled"] = bool(enabled)
    if auto_suspend is not None:
        cfg["auto_suspend_abusers"] = bool(auto_suspend)
    save_security_settings(cfg)

    msg_ipt, msg_sb = "", ""
    if enabled is not None:
        _, msg_ipt = apply_abuse_iptables_rules(bool(enabled))
        _, msg_sb = apply_abuse_singbox_rules(bool(enabled))
        log_security_event("ABUSE_SHIELD", f"EU/US Abuse Shield set to {bool(enabled)} ({msg_ipt} | {msg_sb})")
    elif auto_suspend is not None:
        log_security_event("ABUSE_AUTOSUSPEND", f"Auto-suspend abusers set to {bool(auto_suspend)}")

    return {
        "success": True,
        "abuse_shield_enabled": cfg.get("abuse_shield_enabled", False),
        "auto_suspend_abusers": cfg.get("auto_suspend_abusers", True),
        "message": f"سپر ضد اسپم و تخلفات اروپا/آمریکا {'فعال' if cfg.get('abuse_shield_enabled') else 'غیرفعال'} شد."
    }


def load_abuse_reports():
    if os.path.exists(ABUSE_REPORTS_FILE):
        try:
            with open(ABUSE_REPORTS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            pass
    return []


def save_abuse_reports(reports):
    _ensure_dir()
    with open(ABUSE_REPORTS_FILE, "w", encoding="utf-8") as f:
        json.dump(reports[:300], f, indent=2, ensure_ascii=False)


def _suspend_or_restore_user(protocol, username, suspend=True):
    """Actually suspend or restore a user account across Sing-box, SSH, WireGuard, AmneziaWG, or OpenVPN."""
    proto = (protocol or "").lower()
    uname = (username or "").strip()
    if not uname:
        return False, "نام کاربری خالی است."

    if proto == "singbox":
        sb_ufile = os.path.join(MHPANEL_ROOT, "singbox_users.json")
        if os.path.exists(sb_ufile):
            with open(sb_ufile, "r", encoding="utf-8") as f:
                users = json.load(f)
            found = False
            for u in users:
                if u.get("username") == uname:
                    u["enabled"] = (not suspend)
                    if suspend:
                        u["suspended_reason"] = "Abuse/Spam/Hack Auto-Suspend"
                    else:
                        u.pop("suspended_reason", None)
                    found = True
                    break
            if found:
                with open(sb_ufile, "w", encoding="utf-8") as f:
                    json.dump(users, f, indent=2, ensure_ascii=False)
                # Remove or restore user in /etc/sing-box/config.json immediately
                if os.path.exists(SINGBOX_CONFIG_FILE):
                    with open(SINGBOX_CONFIG_FILE, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                    target_u = next((x for x in users if x.get("username") == uname), {})
                    for ib in cfg.get("inbounds", []):
                        ib_users = ib.get("users")
                        if not isinstance(ib_users, list):
                            continue
                        if suspend:
                            ib["users"] = [x for x in ib_users if x.get("name") != uname and x.get("username") != uname]
                        else:
                            allowed_ibs = target_u.get("inbounds") or []
                            if not allowed_ibs or ib.get("tag") in allowed_ibs:
                                if not any(x.get("name") == uname or x.get("username") == uname for x in ib_users):
                                    entry = {"name": uname}
                                    if ib.get("type") in ("vless", "vmess", "tuic") and target_u.get("uuid"):
                                        entry["uuid"] = target_u["uuid"]
                                    if ib.get("type") in ("trojan", "hysteria2", "tuic", "naive", "socks", "mixed") and target_u.get("password"):
                                        entry["password"] = target_u["password"]
                                    if ib.get("type") == "naive":
                                        entry["username"] = uname
                                    ib_users.append(entry)
                    with open(SINGBOX_CONFIG_FILE, "w", encoding="utf-8") as f:
                        json.dump(cfg, f, indent=2, ensure_ascii=False)
                    subprocess.run(["systemctl", "restart", "sing-box"], capture_output=True, timeout=8)
                return True, f"کاربر Sing-box «{uname}» {'تعلیق' if suspend else 'رفع تعلیق'} شد."

    elif proto == "ssh":
        ssh_file = os.path.join(MHPANEL_ROOT, "ssh_users.json")
        if os.path.exists(ssh_file):
            with open(ssh_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if uname in data and isinstance(data[uname], dict):
                data[uname]["active"] = (not suspend)
                with open(ssh_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
        subprocess.run(["usermod", "-L" if suspend else "-U", uname], capture_output=True)
        if suspend:
            subprocess.run(["pkill", "-u", uname], capture_output=True)
        return True, f"کاربر SSH «{uname}» {'تعلیق و قفل' if suspend else 'رفع تعلیق'} شد."

    elif proto in ("wireguard", "amneziawg"):
        fn = "wg_users.json" if proto == "wireguard" else "awg_users.json"
        iface = "wg0" if proto == "wireguard" else "awg0"
        cli_bin = "wg" if proto == "wireguard" else (shutil.which("awg") or "/usr/local/bin/awg")
        ufile = os.path.join(MHPANEL_ROOT, fn)
        if os.path.exists(ufile):
            with open(ufile, "r", encoding="utf-8") as f:
                users = json.load(f)
            for pubkey, udata in users.items():
                if not isinstance(udata, dict):
                    continue
                if udata.get("name") == uname or pubkey == uname or f"Peer_{pubkey[:8]}" == uname:
                    udata["active"] = (not suspend)
                    with open(ufile, "w", encoding="utf-8") as f:
                        json.dump(users, f, indent=2, ensure_ascii=False)
                    if suspend:
                        subprocess.run([cli_bin, "set", iface, "peer", pubkey, "remove"], capture_output=True)
                    else:
                        ip = udata.get("ip")
                        if not ip:
                            m_ip = re.search(r"Address\s*=\s*([0-9\.]+)", udata.get("config", ""))
                            if m_ip:
                                ip = m_ip.group(1)
                        if ip:
                            subprocess.run([cli_bin, "set", iface, "peer", pubkey, "allowed-ips", f"{ip}/32"], capture_output=True)
                    return True, f"کاربر {proto} «{uname}» {'تعلیق' if suspend else 'رفع تعلیق'} شد."

    elif proto == "openvpn":
        ovpn_file = os.path.join(MHPANEL_ROOT, "ovpn_users.json")
        if os.path.exists(ovpn_file):
            with open(ovpn_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if uname in data and isinstance(data[uname], dict):
                data[uname]["active"] = (not suspend)
                with open(ovpn_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
        ccd_dir = "/etc/openvpn/ccd"
        if os.path.isdir(ccd_dir):
            ccd_path = os.path.join(ccd_dir, uname)
            if suspend:
                with open(ccd_path, "w", encoding="utf-8") as f:
                    f.write("disable\n")
            elif os.path.exists(ccd_path):
                with open(ccd_path, "r", encoding="utf-8") as f:
                    lines = [ln for ln in f.readlines() if ln.strip() != "disable"]
                with open(ccd_path, "w", encoding="utf-8") as f:
                    f.writelines(lines)
        return True, f"کاربر OpenVPN «{uname}» {'تعلیق' if suspend else 'رفع تعلیق'} شد."

    return False, f"کاربر «{uname}» در پروتکل «{proto}» یافت نشد."


def _build_vpn_ip_map():
    """Map VPN tunnel IPs (WireGuard, AmneziaWG, OpenVPN) to (protocol, username)."""
    ip_map = {}
    for proto, fn in [("wireguard", "wg_users.json"), ("amneziawg", "awg_users.json")]:
        fpath = os.path.join(MHPANEL_ROOT, fn)
        if os.path.exists(fpath):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for pubkey, udata in data.items():
                    if not isinstance(udata, dict):
                        continue
                    ip = udata.get("ip")
                    if not ip:
                        m_ip = re.search(r"Address\s*=\s*([0-9\.]+)", udata.get("config", ""))
                        if m_ip:
                            ip = m_ip.group(1)
                    if ip:
                        uname = udata.get("name") or f"Peer_{pubkey[:8]}"
                        ip_map[ip] = (proto, uname)
            except Exception:
                pass
    # OpenVPN ipp.txt
    for ipp in ["/etc/openvpn/ipp.txt", "/etc/openvpn/server/ipp.txt"]:
        if os.path.exists(ipp):
            try:
                with open(ipp, "r", encoding="utf-8") as f:
                    for ln in f:
                        parts = ln.strip().split(",")
                        if len(parts) >= 2:
                            ip_map[parts[1].strip()] = ("openvpn", parts[0].strip())
            except Exception:
                pass
    return ip_map


def scan_and_enforce_abuse():
    """
    Scan live Sing-box connections, kernel MHPANEL_ABUSE logs, and SSH outbound sockets
    to detect spam/hacking/port-scanning per user, report to admin, and auto-suspend offenders.
    """
    cfg = get_security_settings()
    auto_suspend = bool(cfg.get("auto_suspend_abusers", True))
    detected = []

    # 1. Sing-box Clash API live connections (127.0.0.1:9095/connections)
    try:
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:9095/connections", timeout=2) as resp:
            cdata = json.loads(resp.read().decode("utf-8"))
        conns = cdata.get("connections") or []
        user_port_scan = {}
        for c in conns:
            meta = c.get("metadata") or {}
            uname = (meta.get("user") or "").strip()
            if not uname:
                continue
            dst_ip = meta.get("destinationIP") or meta.get("host") or ""
            try:
                dst_port = int(meta.get("destinationPort") or 0)
            except Exception:
                dst_port = 0
            if dst_port in ABUSE_ALL_PORTS:
                reason = ABUSE_PORT_LABELS.get(dst_port, f"Abuse Port {dst_port}")
                detected.append(("singbox", uname, reason, f"{dst_ip}:{dst_port}"))
            user_port_scan.setdefault(uname, set()).add((dst_ip, dst_port))
        for uname, targets in user_port_scan.items():
            if len(targets) >= 60:
                detected.append(("singbox", uname, f"Port/Network Scan ({len(targets)} simultaneous targets)", "Multiple IPs/Ports"))
    except Exception:
        pass

    # 2. Kernel MHPANEL_ABUSE logs -> WireGuard / AmneziaWG / OpenVPN attribution via SRC IP
    vpn_ip_map = _build_vpn_ip_map()
    if vpn_ip_map:
        try:
            jr = subprocess.run(["journalctl", "-k", "-n", "120", "--no-pager"], capture_output=True, text=True, timeout=3)
            log_lines = jr.stdout.splitlines() if jr.returncode == 0 else []
            if not log_lines:
                dm = subprocess.run(["dmesg", "--since", "5 minutes ago"], capture_output=True, text=True, timeout=2)
                log_lines = dm.stdout.splitlines() if dm.returncode == 0 else []
            for ln in log_lines:
                if "MHPANEL_ABUSE:" not in ln:
                    continue
                ms = re.search(r"SRC=([0-9\.]+)", ln)
                md = re.search(r"DST=([0-9\.]+)", ln)
                mp = re.search(r"DPT=(\d+)", ln)
                if ms and mp:
                    src_ip = ms.group(1)
                    dst_ip = md.group(1) if md else "?"
                    dpt = int(mp.group(1))
                    if src_ip in vpn_ip_map and dpt in ABUSE_ALL_PORTS:
                        proto, uname = vpn_ip_map[src_ip]
                        reason = ABUSE_PORT_LABELS.get(dpt, f"Abuse Port {dpt}")
                        detected.append((proto, uname, reason, f"{dst_ip}:{dpt}"))
        except Exception:
            pass

    # 3. SSH outbound abuse detection via ss -tnp (matching sshd: <user> or UID)
    try:
        ssh_file = os.path.join(MHPANEL_ROOT, "ssh_users.json")
        ssh_users = set()
        if os.path.exists(ssh_file):
            with open(ssh_file, "r", encoding="utf-8") as f:
                ssh_users = set(json.load(f).keys())
        if ssh_users:
            ss_res = subprocess.run(["ss", "-tnp", "state", "established"], capture_output=True, text=True, timeout=3)
            if ss_res.returncode == 0:
                for ln in ss_res.stdout.splitlines():
                    for p in ABUSE_ALL_PORTS:
                        if f":{p} " in ln or f":{p}\t" in ln:
                            mpid = re.search(r"pid=(\d+)", ln)
                            if mpid:
                                ps_res = subprocess.run(["ps", "-o", "user=", "-p", mpid.group(1)], capture_output=True, text=True, timeout=1)
                                u_owner = ps_res.stdout.strip()
                                if u_owner in ssh_users:
                                    reason = ABUSE_PORT_LABELS.get(p, f"Abuse Port {p}")
                                    detected.append(("ssh", u_owner, reason, f"Outbound:{p}"))
    except Exception:
        pass

    # Record unique new detections & auto-suspend if enabled
    reports = load_abuse_reports()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    new_count = 0
    seen_active = {(r.get("protocol"), r.get("username"), r.get("reason")) for r in reports if r.get("status") == "suspended"}

    for proto, uname, reason, target in detected:
        if (proto, uname, reason) in seen_active:
            continue
        seen_active.add((proto, uname, reason))
        suspended_ok = False
        if auto_suspend:
            suspended_ok, _ = _suspend_or_restore_user(proto, uname, suspend=True)
        rep = {
            "id": secrets.token_hex(6),
            "protocol": proto,
            "username": uname,
            "reason": reason,
            "target": target,
            "detected_at": now_str,
            "status": "suspended" if suspended_ok else "reported"
        }
        reports.insert(0, rep)
        new_count += 1
        log_security_event("ABUSE_DETECTED", f"User={uname} Proto={proto} Reason={reason} Target={target} AutoSuspended={suspended_ok}")

    if new_count > 0:
        save_abuse_reports(reports)

    return {
        "success": True,
        "new_detections": new_count,
        "reports": reports
    }


def resolve_abuse_report(report_id, action="unsuspend", actor="admin"):
    """Unsuspend offending user after admin review or dismiss/delete the report."""
    reports = load_abuse_reports()
    target = next((r for r in reports if r.get("id") == report_id), None)
    if not target:
        return False, "گزارش تخلف یافت نشد."

    if action == "unsuspend":
        ok, msg = _suspend_or_restore_user(target.get("protocol"), target.get("username"), suspend=False)
        target["status"] = "reviewed"
        target["reviewed_by"] = actor
        target["reviewed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        save_abuse_reports(reports)
        log_security_event("ABUSE_UNSUSPEND", f"Unsuspended {target.get('username')} ({target.get('protocol')})", actor=actor)
        return True, msg
    elif action == "delete":
        reports = [r for r in reports if r.get("id") != report_id]
        save_abuse_reports(reports)
        return True, "گزارش از لیست حذف شد."
    return False, "عملیات نامعتبر."


# =========================================================================
# Security Audit, Firewall Status & Reports
# =========================================================================

def get_security_audit_report(totp_enabled=False, panel_path="", listening_ports_count=0):
    sec_cfg = get_security_settings()
    ip_rules = load_ip_rules()
    admins = load_panel_admins()
    p2p_on = bool(sec_cfg.get("p2p_block_enabled"))

    # Inspect iptables counters
    ipt_input_count = 0
    ipt_p2p_count = 0
    try:
        r1 = _run_iptables(["-L", "MHPANEL_IP_RULES", "-n"])
        if r1.returncode == 0:
            ipt_input_count = max(0, len([ln for ln in r1.stdout.splitlines() if ln.strip()]) - 2)
        r2 = _run_iptables(["-L", "MHPANEL_P2P_BLOCK", "-n"])
        if r2.returncode == 0:
            ipt_p2p_count = max(0, len([ln for ln in r2.stdout.splitlines() if ln.strip()]) - 2)
    except Exception:
        pass

    # Recent SSH failed logins if journalctl is available
    ssh_failed_recent = 0
    try:
        jr = subprocess.run(
            ["journalctl", "-u", "ssh", "-u", "sshd", "-n", "100", "--no-pager"],
            capture_output=True, text=True, timeout=3
        )
        if jr.returncode == 0:
            ssh_failed_recent = sum(1 for ln in jr.stdout.splitlines() if "Failed password" in ln or "Invalid user" in ln)
    except Exception:
        pass

    issues = []
    score = 100
    if not totp_enabled:
        score -= 25
        issues.append({
            "severity": "high",
            "title": "احراز هویت دو مرحله‌ای (2FA) غیرفعال است",
            "desc": "فعال‌سازی کد یکبار مصرف TOTP مانع ورود غیرمجاز حتی در صورت افشای رمز عبور می‌شود."
        })
    if not panel_path:
        score -= 15
        issues.append({
            "severity": "medium",
            "title": "مسیر مخفی پنل (Secret Path) تنظیم نشده است",
            "desc": "صفحه ورود روی مسیر اصلی (/) در دسترس اسکنرهاست."
        })
    if not p2p_on:
        score -= 15
        issues.append({
            "severity": "medium",
            "title": "مسدودسازی دائم P2P / BitTorrent غیرفعال است",
            "desc": "کاربران ممکن است با دانلود تورنت باعث اخطار دیتاسنتر (Abuse) و ساسپند شدن سرور شوند."
        })
    if ssh_failed_recent >= 10:
        score -= 15
        issues.append({
            "severity": "high",
            "title": f"{ssh_failed_recent} تلاش ناموفق ورود SSH در لاگ‌های اخیر",
            "desc": "حملات Brute-Force روی پورت SSH مشاهده شده است؛ مسدودسازی آی‌پی مهاجمان یا تغییر پورت توصیه می‌شود."
        })

    score = max(0, min(100, score))
    return {
        "score": score,
        "totp_enabled": bool(totp_enabled),
        "secret_path_enabled": bool(panel_path),
        "p2p_block_enabled": p2p_on,
        "ip_rules_count": len(ip_rules),
        "blocked_ips_count": sum(1 for r in ip_rules if r.get("action") == "block"),
        "allowed_ips_count": sum(1 for r in ip_rules if r.get("action") == "allow"),
        "iptables_ip_rules_active": ipt_input_count,
        "iptables_p2p_rules_active": ipt_p2p_count,
        "sub_admins_count": len(admins),
        "ssh_failed_recent": ssh_failed_recent,
        "listening_ports_count": listening_ports_count,
        "issues": issues,
        "events": get_security_events(50)
    }


# =========================================================================
# Multi-Admin RBAC Management
# =========================================================================

def _hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000)
    return f"{salt}${dk.hex()}"


def _verify_password(password, stored_hash):
    try:
        salt, hex_dk = stored_hash.split("$", 1)
        expected = _hash_password(password, salt)
        return hmac.compare_digest(expected, stored_hash)
    except Exception:
        return False


def load_panel_admins():
    if os.path.exists(PANEL_ADMINS_FILE):
        try:
            with open(PANEL_ADMINS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            pass
    return []


def save_panel_admins(admins):
    _ensure_dir()
    with open(PANEL_ADMINS_FILE, "w", encoding="utf-8") as f:
        json.dump(admins, f, indent=2, ensure_ascii=False)


def authenticate_sub_admin(username, password):
    username = (username or "").strip()
    if not username or not password:
        return None
    for adm in load_panel_admins():
        if adm.get("username") == username and adm.get("enabled", True):
            if _verify_password(password, adm.get("password_hash", "")):
                return adm
    return None


def upsert_panel_admin(username, password="", allowed_tabs=None, enabled=True, super_username="admin", actor="admin"):
    username = (username or "").strip()
    if not username or not re.match(r"^[a-zA-Z0-9_.-]{3,32}$", username):
        return False, "نام کاربری ادمین باید ۳ تا ۳۲ کاراکتر (حروف انگلیسی، اعداد، _، -، .) باشد."
    if username == super_username:
        return False, "نمی‌توانید نام کاربری ادمین اصلی (Super Admin) را به عنوان ادمین محدود ثبت کنید."

    valid_ids = {s["id"] for s in PANEL_SECTION_CATALOG}
    clean_tabs = [t for t in (allowed_tabs or []) if t in valid_ids]
    if not clean_tabs:
        clean_tabs = ["overview"]

    admins = load_panel_admins()
    existing = next((a for a in admins if a.get("username") == username), None)
    if existing:
        if password:
            existing["password_hash"] = _hash_password(password)
        existing["allowed_tabs"] = clean_tabs
        existing["enabled"] = bool(enabled)
        existing["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = f"دسترسی ادمین «{username}» بروزرسانی شد."
    else:
        if not password or len(password) < 4:
            return False, "برای ایجاد ادمین جدید، رمز عبور حداقل ۴ کاراکتری الزامی است."
        admins.append({
            "username": username,
            "password_hash": _hash_password(password),
            "allowed_tabs": clean_tabs,
            "enabled": bool(enabled),
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        msg = f"ادمین جدید «{username}» با موفقیت ایجاد شد."

    save_panel_admins(admins)
    log_security_event("ADMIN_RBAC", f"Upsert admin={username} tabs={clean_tabs} enabled={enabled}", actor=actor)
    return True, msg


def delete_panel_admin(username, actor="admin"):
    admins = load_panel_admins()
    new_admins = [a for a in admins if a.get("username") != username]
    if len(new_admins) == len(admins):
        return False, "ادمین مورد نظر یافت نشد."
    save_panel_admins(new_admins)
    log_security_event("ADMIN_DEL", f"Deleted admin={username}", actor=actor)
    return True, f"ادمین «{username}» حذف شد."
