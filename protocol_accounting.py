#!/usr/bin/env python3
"""
MHPanel Unified Protocol Accounting & FreeRADIUS Central Integration Engine
Manages Multi-User Accounts, Bandwidth Quotas (Upload & Download), Expiration Dates,
and Dual-Mode Authentication (Local vs FreeRADIUS / MikroTik User Manager)
for Shadowsocks, TUIC, Hysteria 2, Trojan, and StunTLS.
"""

import os
import json
import sqlite3
import subprocess
import secrets
import uuid
import re
from datetime import datetime

DB_PATH = "/etc/vpnpanel/protocol_accounting.db"
RADIUS_USERS_FILE = "/www/wwwroot/mhpanel/radius_users.json"
FREERADIUS_USERS_FILE = "/etc/freeradius/3.0/mhpanel_users"

SUPPORTED_PROTOCOLS = ["shadowsocks", "tuic", "hysteria2", "trojan", "stuntls"]

def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS protocol_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                auth_mode TEXT DEFAULT 'dual',
                upload_bytes INTEGER DEFAULT 0,
                download_bytes INTEGER DEFAULT 0,
                traffic_limit_gb REAL DEFAULT 0,
                upload_limit_gb REAL DEFAULT 0,
                download_limit_gb REAL DEFAULT 0,
                expire_date TEXT,
                active INTEGER DEFAULT 1,
                created_at TEXT,
                updated_at TEXT,
                UNIQUE(protocol, username)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS protocol_auth_config (
                protocol TEXT PRIMARY KEY,
                auth_mode TEXT DEFAULT 'dual',
                updated_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS protocol_traffic_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT NOT NULL,
                username TEXT NOT NULL,
                upload_delta INTEGER DEFAULT 0,
                download_delta INTEGER DEFAULT 0,
                timestamp TEXT
            )
        """)

        # Ensure defaults for each protocol
        for proto in SUPPORTED_PROTOCOLS:
            conn.execute("""
                INSERT OR IGNORE INTO protocol_auth_config (protocol, auth_mode, updated_at)
                VALUES (?, 'dual', ?)
            """, (proto, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    conn.close()

def get_auth_mode(protocol):
    init_db()
    conn = get_db()
    row = conn.execute("SELECT auth_mode FROM protocol_auth_config WHERE protocol = ?", (protocol,)).fetchone()
    conn.close()
    return row["auth_mode"] if row else "dual"

def set_auth_mode(protocol, mode):
    init_db()
    if mode not in ["local", "radius", "dual"]:
        mode = "dual"
    conn = get_db()
    with conn:
        conn.execute("""
            INSERT INTO protocol_auth_config (protocol, auth_mode, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(protocol) DO UPDATE SET auth_mode = excluded.auth_mode, updated_at = excluded.updated_at
        """, (protocol, mode, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.close()
    sync_daemon_users(protocol)
    return mode

def get_radius_users_raw():
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_radius_users_raw(users):
    try:
        os.makedirs(os.path.dirname(RADIUS_USERS_FILE), exist_ok=True)
        with open(RADIUS_USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)
        return True
    except Exception:
        return False

def get_protocol_users(protocol):
    """
    Returns list of all users applicable for this protocol,
    combining local SQLite users and FreeRADIUS users based on auth_mode.
    """
    init_db()
    mode = get_auth_mode(protocol)
    conn = get_db()
    rows = conn.execute("SELECT * FROM protocol_users WHERE protocol = ? ORDER BY id DESC", (protocol,)).fetchall()
    conn.close()

    local_users = []
    seen_usernames = set()
    now_str = datetime.now().strftime("%Y-%m-%d")

    for r in rows:
        u_dict = dict(r)
        u_dict["source"] = "local"
        seen_usernames.add(u_dict["username"])

        # Check expiration
        exp = u_dict.get("expire_date")
        if exp and now_str > exp:
            u_dict["status"] = "expired"
        elif not u_dict.get("active"):
            u_dict["status"] = "disabled"
        else:
            # Check quota
            tot = u_dict["upload_bytes"] + u_dict["download_bytes"]
            lim = (u_dict.get("traffic_limit_gb") or 0) * (1024**3)
            up_lim = (u_dict.get("upload_limit_gb") or 0) * (1024**3)
            down_lim = (u_dict.get("download_limit_gb") or 0) * (1024**3)

            if (lim > 0 and tot >= lim) or (up_lim > 0 and u_dict["upload_bytes"] >= up_lim) or (down_lim > 0 and u_dict["download_bytes"] >= down_lim):
                u_dict["status"] = "quota_exceeded"
            else:
                u_dict["status"] = "active"

        u_dict["used_upload_gb"] = round(u_dict["upload_bytes"] / (1024**3), 3)
        u_dict["used_download_gb"] = round(u_dict["download_bytes"] / (1024**3), 3)
        u_dict["total_used_gb"] = round((u_dict["upload_bytes"] + u_dict["download_bytes"]) / (1024**3), 3)
        local_users.append(u_dict)

    result_users = []
    if mode in ["local", "dual"]:
        result_users.extend(local_users)

    if mode in ["radius", "dual"]:
        r_users = get_radius_users_raw()
        for uname, udata in r_users.items():
            if uname in seen_usernames and mode == "dual":
                continue # Local definition takes precedence in dual view, or merged
            allowed_protocols = udata.get("protocols", ["all"])
            if "all" not in allowed_protocols and protocol not in allowed_protocols:
                continue

            r_active = udata.get("active", True)
            r_exp = udata.get("expire_date")
            r_rx = int(udata.get("rx", 0))
            r_tx = int(udata.get("tx", 0))
            r_tot = r_rx + r_tx
            r_lim = udata.get("limit_gb") or 0
            r_up_lim = udata.get("upload_limit_gb") or 0
            r_down_lim = udata.get("download_limit_gb") or 0

            status = "active"
            if r_exp and now_str > r_exp:
                status = "expired"
            elif not r_active:
                status = "disabled"
            elif (r_lim and r_tot >= float(r_lim) * (1024**3)) or \
                 (r_up_lim and r_rx >= float(r_up_lim) * (1024**3)) or \
                 (r_down_lim and r_tx >= float(r_down_lim) * (1024**3)):
                status = "quota_exceeded"

            result_users.append({
                "id": f"rad_{uname}",
                "protocol": protocol,
                "username": uname,
                "password": udata.get("password", ""),
                "auth_mode": "radius",
                "source": "radius",
                "upload_bytes": r_rx,
                "download_bytes": r_tx,
                "used_upload_gb": round(r_rx / (1024**3), 3),
                "used_download_gb": round(r_tx / (1024**3), 3),
                "total_used_gb": round(r_tot / (1024**3), 3),
                "traffic_limit_gb": r_lim or 0,
                "upload_limit_gb": r_up_lim or 0,
                "download_limit_gb": r_down_lim or 0,
                "expire_date": r_exp,
                "active": 1 if r_active else 0,
                "status": status,
                "created_at": udata.get("created_at", "-"),
                "updated_at": udata.get("updated_at", "-")
            })

    return result_users

def add_protocol_user(protocol, username, password, auth_mode="dual", traffic_limit_gb=0, upload_limit_gb=0, download_limit_gb=0, expire_date=None, active=1):
    init_db()
    username = username.strip()
    password = password.strip()
    if not username:
        return False, "نام کاربری نمی‌تواند خالی باشد."
    if not password:
        return False, "رمز عبور نمی‌تواند خالی باشد."

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    with conn:
        conn.execute("""
            INSERT INTO protocol_users (
                protocol, username, password, auth_mode, traffic_limit_gb, upload_limit_gb, download_limit_gb, expire_date, active, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(protocol, username) DO UPDATE SET
                password = excluded.password,
                auth_mode = excluded.auth_mode,
                traffic_limit_gb = excluded.traffic_limit_gb,
                upload_limit_gb = excluded.upload_limit_gb,
                download_limit_gb = excluded.download_limit_gb,
                expire_date = excluded.expire_date,
                active = excluded.active,
                updated_at = excluded.updated_at
        """, (protocol, username, password, auth_mode, traffic_limit_gb, upload_limit_gb, download_limit_gb, expire_date, active, now, now))
    conn.close()

    # Also register in FreeRADIUS if auth_mode is radius or dual
    if auth_mode in ["radius", "dual"]:
        r_users = get_radius_users_raw()
        if username not in r_users:
            r_users[username] = {
                "password": password,
                "active": bool(active),
                "expire_date": expire_date,
                "limit_gb": traffic_limit_gb if traffic_limit_gb > 0 else None,
                "upload_limit_gb": upload_limit_gb if upload_limit_gb > 0 else None,
                "download_limit_gb": download_limit_gb if download_limit_gb > 0 else None,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "protocols": [protocol, "all"],
                "sub_token": secrets.token_urlsafe(12)
            }
        else:
            r_users[username]["password"] = password
            r_users[username]["active"] = bool(active)
            r_users[username]["expire_date"] = expire_date
            if traffic_limit_gb > 0: r_users[username]["limit_gb"] = traffic_limit_gb
            if upload_limit_gb > 0: r_users[username]["upload_limit_gb"] = upload_limit_gb
            if download_limit_gb > 0: r_users[username]["download_limit_gb"] = download_limit_gb
            protos = set(r_users[username].get("protocols", []))
            protos.add(protocol)
            r_users[username]["protocols"] = list(protos)

        save_radius_users_raw(r_users)
        # Trigger freeradius file sync
        try:
            from app import sync_freeradius_users
            sync_freeradius_users()
        except Exception:
            pass

    sync_daemon_users(protocol)
    return True, "کاربر با موفقیت ثبت و ذخیره شد."

def delete_protocol_user(protocol, username):
    init_db()
    conn = get_db()
    with conn:
        conn.execute("DELETE FROM protocol_users WHERE protocol = ? AND username = ?", (protocol, username))
    conn.close()
    sync_daemon_users(protocol)
    return True, "کاربر حذف شد."

def toggle_protocol_user(protocol, username):
    init_db()
    conn = get_db()
    row = conn.execute("SELECT active FROM protocol_users WHERE protocol = ? AND username = ?", (protocol, username)).fetchone()
    if row:
        new_active = 0 if row["active"] else 1
        with conn:
            conn.execute("UPDATE protocol_users SET active = ?, updated_at = ? WHERE protocol = ? AND username = ?",
                         (new_active, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), protocol, username))
        conn.close()
        # Also toggle in radius if present
        r_users = get_radius_users_raw()
        if username in r_users:
            r_users[username]["active"] = bool(new_active)
            save_radius_users_raw(r_users)
        sync_daemon_users(protocol)
        return True, "وضعیت کاربر تغییر کرد."
    conn.close()

    # Check radius directly
    r_users = get_radius_users_raw()
    if username in r_users:
        r_users[username]["active"] = not r_users[username].get("active", True)
        save_radius_users_raw(r_users)
        sync_daemon_users(protocol)
        return True, "وضعیت کاربر FreeRADIUS تغییر کرد."

    return False, "کاربر یافت نشد."

def reset_protocol_user_traffic(protocol, username):
    init_db()
    conn = get_db()
    with conn:
        conn.execute("UPDATE protocol_users SET upload_bytes = 0, download_bytes = 0, updated_at = ? WHERE protocol = ? AND username = ?",
                     (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), protocol, username))
    conn.close()

    r_users = get_radius_users_raw()
    if username in r_users:
        r_users[username]["rx"] = 0
        r_users[username]["tx"] = 0
        save_radius_users_raw(r_users)

    return True, "حجم مصرفی کاربر صفر شد."

def sync_daemon_users(protocol=None):
    """
    Regenerates daemon configs with active eligible users and reloads services.
    Supports: Hysteria 2, Trojan, TUIC, Shadowsocks, StunTLS.
    """
    targets = [protocol] if protocol and protocol in SUPPORTED_PROTOCOLS else SUPPORTED_PROTOCOLS

    for proto in targets:
        users = get_protocol_users(proto)
        active_users = [u for u in users if u.get("status") == "active"]

        try:
            if proto == "trojan":
                _sync_trojan(active_users)
            elif proto == "tuic":
                _sync_tuic(active_users)
            elif proto == "shadowsocks":
                _sync_shadowsocks(active_users)
            elif proto == "hysteria2":
                _sync_hysteria2(active_users)
            elif proto == "stuntls":
                _sync_stuntls(active_users)
        except Exception as e:
            print(f"[Accounting] Error syncing daemon users for {proto}: {e}")

def _sync_trojan(active_users):
    cfg_file = "/etc/vpnpanel/trojan.json"
    if not os.path.exists(cfg_file):
        return
    with open(cfg_file, "r") as f:
        cfg = json.load(f)

    # Convert active users to sing-box trojan users format
    sing_users = []
    if active_users:
        for u in active_users:
            sing_users.append({
                "name": u["username"],
                "password": u["password"]
            })
    else:
        sing_users.append({"name": "default_user", "password": "mhpanel_trojan_secret"})

    for inbound in cfg.get("inbounds", []):
        if inbound.get("type") == "trojan":
            inbound["users"] = sing_users

    with open(cfg_file, "w") as f:
        json.dump(cfg, f, indent=2)

    subprocess.run(["systemctl", "restart", "mhpanel-trojan"], capture_output=True)

def _sync_tuic(active_users):
    cfg_file = "/etc/vpnpanel/tuic.toml"
    if not os.path.exists(cfg_file):
        return
    with open(cfg_file, "r") as f:
        content = f.read()

    user_lines = []
    if active_users:
        for u in active_users:
            uuid_str = u["username"]
            # Ensure UUID format or convert username to deterministic UUID
            try:
                uuid.UUID(uuid_str)
            except Exception:
                uuid_str = str(uuid.uuid5(uuid.NAMESPACE_DNS, u["username"]))
            user_lines.append(f'{uuid_str} = "{u["password"]}"')
    else:
        user_lines.append('9121f1fa-af2e-48e4-99ed-5c4bf59658ff = "RF60OJvJV2odte30riK7ZQ"')

    replacement = "[users]\n" + "\n".join(user_lines)
    content = re.sub(r'\[users\](.*?)(?=\n\[|\Z)', replacement, content, flags=re.DOTALL)

    with open(cfg_file, "w") as f:
        f.write(content)

    subprocess.run(["systemctl", "restart", "mhpanel-tuic"], capture_output=True)

def _sync_shadowsocks(active_users):
    cfg_file = "/etc/vpnpanel/shadowsocks.json"
    if not os.path.exists(cfg_file):
        return
    with open(cfg_file, "r") as f:
        cfg = json.load(f)

    ss_users = []
    if active_users:
        for u in active_users:
            ss_users.append({
                "name": u["username"],
                "password": u["password"]
            })
    else:
        ss_users.append({"name": "vip_user1", "password": "bNL3GpHWWnaChpDfihVuZA=="})

    cfg["users"] = ss_users
    with open(cfg_file, "w") as f:
        json.dump(cfg, f, indent=4)

    subprocess.run(["systemctl", "restart", "mhpanel-shadowsocks"], capture_output=True)

def _sync_hysteria2(active_users):
    cfg_file = "/etc/vpnpanel/hysteria2.yaml"
    if not os.path.exists(cfg_file):
        return
    with open(cfg_file, "r") as f:
        content = f.read()

    # If active users exist, configure userpass block or HTTP auth hook
    # Hysteria 2 userpass format:
    # auth:
    #   type: userpass
    #   userpass:
    #     user1: pass1
    #     user2: pass2
    if active_users:
        up_lines = ["auth:", "  type: userpass", "  userpass:"]
        for u in active_users:
            up_lines.append(f'    {u["username"]}: {u["password"]}')
        auth_block = "\n".join(up_lines)
    else:
        auth_block = "auth:\n  type: password\n  password: mhpanel_hysteria_secret"

    content = re.sub(r'auth:.*?(?=\n[a-z]|\Z)', auth_block, content, flags=re.DOTALL)
    with open(cfg_file, "w") as f:
        f.write(content)

    subprocess.run(["systemctl", "restart", "mhpanel-hysteria2"], capture_output=True)

def _sync_stuntls(active_users):
    cfg_file = "/etc/vpnpanel/stuntls.json"
    cfg = {"port": 3478, "secret": "mhpanel_stuntls_key", "upstream": "127.0.0.1:22", "mode": "webrtc_stun"}
    if os.path.exists(cfg_file):
        try:
            with open(cfg_file, "r") as f:
                cfg.update(json.load(f))
        except Exception:
            pass

    st_users = []
    if active_users:
        for u in active_users:
            st_users.append({"name": u["username"], "secret": u["password"]})
    else:
        st_users.append({"name": "default", "secret": cfg.get("secret", "mhpanel_stuntls_key")})

    cfg["users"] = st_users
    with open(cfg_file, "w") as f:
        json.dump(cfg, f, indent=2)

    subprocess.run(["systemctl", "restart", "mhpanel-stuntls"], capture_output=True)

def authenticate_hysteria_webhook(addr, auth_str):
    """
    HTTP auth callback endpoint for Hysteria 2.
    auth_str can be 'username:password' or just 'password'.
    """
    init_db()
    users = get_protocol_users("hysteria2")
    active_users = {u["username"]: u for u in users if u.get("status") == "active"}

    if ":" in auth_str:
        u_name, u_pass = auth_str.split(":", 1)
        if u_name in active_users and active_users[u_name]["password"] == u_pass:
            return True, u_name
    else:
        # Check if auth_str matches any active password
        for u_name, u in active_users.items():
            if u["password"] == auth_str:
                return True, u_name

    return False, "Authentication failed or account expired/exhausted"
