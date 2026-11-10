"""
MHPanel - Centralized Cloudflare Automation Suite & Manager
Supports:
  - Token verification & permissions audit
  - Multi-zone discovery & management
  - Full DNS records CRUD + 1-click Proxy (Orange Cloud) toggling
  - 1-Click automated subdomain provisioning for all active protocols
  - 1-Click automated DNS Tunnel NS & A record provisioning (DNSTT, Slipstream, VayDNS, etc.)
  - 1-Click Port Forwarding / Origin Rules (rewriting ports from 443 to arbitrary backend ports)
  - 1-Click Cloudflare Workers & Google Apps Script (GAS) deployment & relaying
  - Cloudflare Pages helper
"""

import os
import json
import logging
import requests
from datetime import datetime

logger = logging.getLogger("cloudflare_manager")

CF_CONFIG_FILE = "/etc/vpnpanel/cloudflare_hub.json"
CF_SNISPOOF_FILE = "/etc/vpnpanel/cloudflare_snispoof.json"
GAS_CONFIG_FILE = "/etc/vpnpanel/google_script.json"

def get_cf_config():
    default_cfg = {
        "cf_token": "",
        "account_id": "",
        "account_name": "",
        "user_email": "",
        "active_zone_id": "",
        "active_zone_name": "",
        "last_verified": "",
        "permissions": [],
        "zones": []
    }
    
    if os.path.exists(CF_CONFIG_FILE):
        try:
            with open(CF_CONFIG_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                default_cfg.update(saved)
        except Exception as e:
            logger.error(f"Error reading CF config: {e}")

    # Fallback to existing tokens if empty
    if not default_cfg.get("cf_token"):
        # Check google_script.json
        if os.path.exists(GAS_CONFIG_FILE):
            try:
                with open(GAS_CONFIG_FILE, "r", encoding="utf-8") as f:
                    gdata = json.load(f)
                    for _, acc in gdata.get("accounts", {}).items():
                        if acc.get("cf_api_token"):
                            default_cfg["cf_token"] = acc["cf_api_token"]
                            if acc.get("cf_account_id"):
                                default_cfg["account_id"] = acc["cf_account_id"]
                            break
            except Exception:
                pass
        # Check snispoof
        if not default_cfg.get("cf_token") and os.path.exists(CF_SNISPOOF_FILE):
            try:
                with open(CF_SNISPOOF_FILE, "r", encoding="utf-8") as f:
                    sdata = json.load(f)
                    if sdata.get("cf_token"):
                        default_cfg["cf_token"] = sdata["cf_token"]
                        if sdata.get("zone_id"):
                            default_cfg["active_zone_id"] = sdata["zone_id"]
                        if sdata.get("domain"):
                            default_cfg["active_zone_name"] = sdata["domain"]
            except Exception:
                pass

    return default_cfg

def save_cf_config(cfg):
    os.makedirs(os.path.dirname(CF_CONFIG_FILE), exist_ok=True)
    with open(CF_CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    
    # Also sync with snispoof if active
    if os.path.exists(CF_SNISPOOF_FILE):
        try:
            with open(CF_SNISPOOF_FILE, "r", encoding="utf-8") as f:
                sdata = json.load(f)
            if cfg.get("cf_token"):
                sdata["cf_token"] = cfg["cf_token"]
            if cfg.get("active_zone_id"):
                sdata["zone_id"] = cfg["active_zone_id"]
            if cfg.get("active_zone_name"):
                sdata["domain"] = cfg["active_zone_name"]
            with open(CF_SNISPOOF_FILE, "w", encoding="utf-8") as f:
                json.dump(sdata, f, indent=2)
        except Exception:
            pass

def cf_api(method, endpoint, token=None, json_data=None, params=None, raw_body=None, content_type="application/json"):
    if not token:
        cfg = get_cf_config()
        token = cfg.get("cf_token", "").strip()

    if not token:
        return 400, {"success": False, "errors": [{"message": "توکن کلودفلر وارد نشده است."}]}

    url = f"https://api.cloudflare.com/client/v4{endpoint}"
    headers = {
        "Authorization": f"Bearer {token.strip()}"
    }
    if content_type:
        headers["Content-Type"] = content_type

    try:
        if raw_body is not None:
            resp = requests.request(method, url, headers=headers, data=raw_body, params=params, timeout=15)
        else:
            resp = requests.request(method, url, headers=headers, json=json_data, params=params, timeout=15)
        
        try:
            res_json = resp.json()
        except Exception:
            res_json = {"success": resp.ok, "errors": [{"message": resp.text[:300]}]}
        return resp.status_code, res_json
    except requests.exceptions.Timeout:
        return 504, {"success": False, "errors": [{"message": "مهلت اتصال به کلودفلر به پایان رسید (Timeout)."}]}
    except Exception as e:
        return 500, {"success": False, "errors": [{"message": str(e)}]}

def audit_token(token):
    """Verifies token and audits accounts & zones"""
    st, res = cf_api("GET", "/user/tokens/verify", token=token)
    if not res.get("success"):
        err = res.get("errors", [{}])[0].get("message", "توکن نامعتبر است.")
        return {"success": False, "error": f"اعتبارسنجی توکن ناموفق بود: {err}"}

    # Fetch user info / accounts
    account_id = ""
    account_name = ""
    st_acc, res_acc = cf_api("GET", "/accounts?per_page=10", token=token)
    if res_acc.get("success") and res_acc.get("result"):
        accs = res_acc["result"]
        account_id = accs[0].get("id", "")
        account_name = accs[0].get("name", "")

    # Fetch zones
    st_zones, res_zones = cf_api("GET", "/zones?per_page=50", token=token)
    zones_list = []
    has_dns_permission = False
    
    if res_zones.get("success") and res_zones.get("result"):
        for z in res_zones["result"]:
            zones_list.append({
                "id": z.get("id"),
                "name": z.get("name"),
                "status": z.get("status"),
                "plan": z.get("plan", {}).get("name", "Free"),
                "name_servers": z.get("name_servers", []),
                "account_id": z.get("account", {}).get("id") or account_id,
                "account_name": z.get("account", {}).get("name") or account_name
            })
            if not account_id and z.get("account", {}).get("id"):
                account_id = z.get("account", {}).get("id")
            if not account_name and z.get("account", {}).get("name"):
                account_name = z.get("account", {}).get("name")

    # Test DNS permission on first zone if available
    dns_audit_msg = "بررسی نشده"
    if zones_list:
        test_z = zones_list[0]["id"]
        st_dns, res_dns = cf_api("GET", f"/zones/{test_z}/dns_records?per_page=1", token=token)
        if res_dns.get("success"):
            has_dns_permission = True
            dns_audit_msg = "مجاز (دسترسی کامل خواندن و ثبت رکوردهای DNS)"
        else:
            err_code = res_dns.get("errors", [{}])[0].get("code", 0)
            if err_code == 10000:
                dns_audit_msg = "فاقد دسترسی DNS! لطفاً در تنظیمات توکن کلودفلر دسترسی Zone > DNS > Edit را فعال کنید."
            else:
                dns_audit_msg = f"خطای دسترسی DNS: {res_dns.get('errors')}"

    return {
        "success": True,
        "token_status": res.get("result", {}).get("status", "active"),
        "account_id": account_id,
        "account_name": account_name,
        "zones": zones_list,
        "has_dns_permission": has_dns_permission,
        "dns_audit_msg": dns_audit_msg
    }

def get_active_zone_details(token=None, zone_id=None):
    cfg = get_cf_config()
    token = token or cfg.get("cf_token")
    zone_id = zone_id or cfg.get("active_zone_id")
    if not token or not zone_id:
        return None
    st, res = cf_api("GET", f"/zones/{zone_id}", token=token)
    if res.get("success") and res.get("result"):
        return res["result"]
    return None


# ============================================================================
# DNS RECORDS CRUD & MANAGEMENT
# ============================================================================

def list_dns_records(zone_id, token=None, rtype=None, search=None):
    params = {"per_page": 100}
    if rtype:
        params["type"] = rtype.upper()
    if search:
        params["search"] = search
    
    st, res = cf_api("GET", f"/zones/{zone_id}/dns_records", token=token, params=params)
    if res.get("success"):
        return {"success": True, "records": res.get("result", []), "info": res.get("result_info", {})}
    err = res.get("errors", [{}])[0].get("message", "خطا در دریافت لیست رکوردهای DNS")
    return {"success": False, "error": err, "records": []}

def upsert_dns_record(zone_id, token, name, rtype, content, proxied=False, ttl=1, priority=None):
    """Creates or updates a DNS record with the same name and type."""
    name = name.strip().lower()
    rtype = rtype.strip().upper()
    content = content.strip()
    
    # 1. Check if record already exists
    st_s, res_s = cf_api("GET", f"/zones/{zone_id}/dns_records", token=token, params={"name": name, "type": rtype})
    existing = res_s.get("result", []) if res_s.get("success") else []
    
    payload = {
        "type": rtype,
        "name": name,
        "content": content,
        "proxied": bool(proxied) if rtype in ["A", "AAAA", "CNAME"] else False,
        "ttl": int(ttl) if ttl else 1
    }
    if priority is not None and rtype in ["MX", "SRV"]:
        payload["priority"] = int(priority)

    if existing:
        rec_id = existing[0]["id"]
        st_u, res_u = cf_api("PUT", f"/zones/{zone_id}/dns_records/{rec_id}", token=token, json_data=payload)
        if res_u.get("success"):
            return {"success": True, "action": "updated", "record": res_u.get("result"), "message": f"رکورد {rtype} برای {name} با موفقیت بروزرسانی شد."}
        err = res_u.get("errors", [{}])[0].get("message", "خطا در بروزرسانی رکورد")
        return {"success": False, "error": err}
    else:
        st_c, res_c = cf_api("POST", f"/zones/{zone_id}/dns_records", token=token, json_data=payload)
        if res_c.get("success"):
            return {"success": True, "action": "created", "record": res_c.get("result"), "message": f"رکورد {rtype} برای {name} با موفقیت ساخته شد."}
        err = res_c.get("errors", [{}])[0].get("message", "خطا در ساخت رکورد")
        return {"success": False, "error": err}

def delete_dns_record(zone_id, token, record_id):
    st, res = cf_api("DELETE", f"/zones/{zone_id}/dns_records/{record_id}", token=token)
    if res.get("success"):
        return {"success": True, "message": "رکورد با موفقیت حذف گردید."}
    err = res.get("errors", [{}])[0].get("message", "خطا در حذف رکورد")
    return {"success": False, "error": err}

def toggle_dns_proxy(zone_id, token, record_id):
    # Get current record
    st, res = cf_api("GET", f"/zones/{zone_id}/dns_records/{record_id}", token=token)
    if not res.get("success") or not res.get("result"):
        return {"success": False, "error": "رکورد مورد نظر یافت نشد."}
    
    rec = res["result"]
    cur_proxied = rec.get("proxied", False)
    new_proxied = not cur_proxied
    
    payload = {
        "type": rec["type"],
        "name": rec["name"],
        "content": rec["content"],
        "proxied": new_proxied,
        "ttl": 1
    }
    st_u, res_u = cf_api("PUT", f"/zones/{zone_id}/dns_records/{record_id}", token=token, json_data=payload)
    if res_u.get("success"):
        status_txt = "فعال (عبور از شبکه ابر نارنجی کلودفلر)" if new_proxied else "خاموش (اتصال مستقیم DNS Only)"
        return {"success": True, "proxied": new_proxied, "message": f"وضعیت پروکسی کلودفلر تغییر یافت: {status_txt}"}
    err = res_u.get("errors", [{}])[0].get("message", "خطا در تغییر وضعیت پروکسی")
    return {"success": False, "error": err}


# ============================================================================
# 1-CLICK PROTOCOL SUBDOMAINS PROVISIONING
# ============================================================================

def provision_protocol_subdomains(zone_id, token, server_ip, root_domain, protocols_to_provision=None, custom_prefixes=None):
    """
    Automates creating subdomains for different protocols.
    Protocols like Reality / Hy2 / TUIC / SSH are direct (Proxied: False).
    Protocols like VLESS-WS / VMess-WS / Trojan-WS / GAS can be CDN Proxied (Proxied: True).
    """
    root_domain = root_domain.strip().lower()
    custom_prefixes = custom_prefixes or {}

    default_specs = {
        "reality": {
            "title": "Sing-box Reality / Direct",
            "prefix": custom_prefixes.get("reality", "reality"),
            "proxied": False,
            "type": "A",
            "desc": "اتصال مستقیم بدون پروکسی کلودفلر برای پروتکل Reality"
        },
        "vless_ws": {
            "title": "VLESS WebSocket CDN",
            "prefix": custom_prefixes.get("vless_ws", "vless"),
            "proxied": True,
            "type": "A",
            "desc": "عبور از شبکه CDN کلودفلر (ابر نارنجی روشن)"
        },
        "vmess_ws": {
            "title": "VMess / Trojan WS",
            "prefix": custom_prefixes.get("vmess_ws", "ws"),
            "proxied": True,
            "type": "A",
            "desc": "ساب‌دامین وب‌سوکت برای تروجان و وی‌مس"
        },
        "hysteria2": {
            "title": "Hysteria 2 (QUIC/UDP)",
            "prefix": custom_prefixes.get("hysteria2", "hy2"),
            "proxied": False,
            "type": "A",
            "desc": "اتصال پرسرعت پروتکل هیستریا ۲ (UDP مستقیم)"
        },
        "tuic": {
            "title": "TUIC v5 (QUIC/UDP)",
            "prefix": custom_prefixes.get("tuic", "tuic"),
            "proxied": False,
            "type": "A",
            "desc": "اتصال مستقیم پروتکل TUIC"
        },
        "shadowsocks": {
            "title": "Shadowsocks TCP/UDP",
            "prefix": custom_prefixes.get("shadowsocks", "ss"),
            "proxied": False,
            "type": "A",
            "desc": "اتصال شادوساکس مستقیم"
        },
        "ssh": {
            "title": "SSH / Direct TLS",
            "prefix": custom_prefixes.get("ssh", "ssh"),
            "proxied": False,
            "type": "A",
            "desc": "دامنه مستقیم سرور برای تونل‌های SSH"
        },
        "gas_relay": {
            "title": "Google Apps Script Relay",
            "prefix": custom_prefixes.get("gas_relay", "gas"),
            "proxied": True,
            "type": "A",
            "desc": "ساب‌دامین متصل به گوگل اسکریپت و ریورس پروکسی"
        },
        "naiveproxy": {
            "title": "NaiveProxy (Chromium TLS)",
            "prefix": custom_prefixes.get("naiveproxy", "naive"),
            "proxied": False,
            "type": "A",
            "desc": "استتار شبکه کرومیوم برای نایوپروکسی"
        },
        "wireguard": {
            "title": "WireGuard / WSTunnel",
            "prefix": custom_prefixes.get("wireguard", "wg"),
            "proxied": False,
            "type": "A",
            "desc": "اتصال وایرگارد مستقیم یا WSTunnel"
        }
    }

    if protocols_to_provision is None:
        protocols_to_provision = list(default_specs.keys())

    results = []
    success_count = 0

    for proto_key in protocols_to_provision:
        if proto_key not in default_specs:
            continue
        spec = default_specs[proto_key]
        prefix = spec["prefix"].strip().lower()
        if not prefix or prefix == "@":
            sub_full = root_domain
        else:
            sub_full = f"{prefix}.{root_domain}"

        res = upsert_dns_record(
            zone_id=zone_id,
            token=token,
            name=sub_full,
            rtype=spec["type"],
            content=server_ip,
            proxied=spec["proxied"],
            ttl=1
        )
        if res.get("success"):
            success_count += 1
            results.append({
                "protocol": proto_key,
                "title": spec["title"],
                "subdomain": sub_full,
                "proxied": spec["proxied"],
                "status": "success",
                "action": res.get("action", "applied"),
                "message": f"ساب‌دامین {sub_full} با موفقیت ({'پروکسی کلودفلر روشن' if spec['proxied'] else 'DNS مستقیم'}) ثبت شد."
            })
        else:
            results.append({
                "protocol": proto_key,
                "title": spec["title"],
                "subdomain": sub_full,
                "proxied": spec["proxied"],
                "status": "error",
                "message": res.get("error", "خطای نامشخص در ثبت")
            })

    return {
        "success": success_count > 0,
        "total": len(protocols_to_provision),
        "success_count": success_count,
        "results": results
    }


# ============================================================================
# 1-CLICK DNS TUNNEL & NS RECORDS PROVISIONING
# ============================================================================

def provision_dns_tunnel_records(zone_id, token, server_ip, root_domain, tunnel_type="dnstt", ns_name="ns", tunnel_name="t"):
    """
    Provisions:
      1. A record:   ns.<root_domain> -> server_ip  (Proxied: False)
      2. NS record:  t.<root_domain>  -> ns.<root_domain>
    Also syncs with panel tunnel configs (dnstt, slipstream, vaydns, etc.)
    """
    root_domain = root_domain.strip().lower()
    ns_name = ns_name.strip().lower()
    tunnel_name = tunnel_name.strip().lower()

    ns_full = f"{ns_name}.{root_domain}"
    tunnel_full = f"{tunnel_name}.{root_domain}"
    logs = []

    # 1. Create/Update A record for NS (DNS-only)
    res_a = upsert_dns_record(
        zone_id=zone_id,
        token=token,
        name=ns_full,
        rtype="A",
        content=server_ip,
        proxied=False,
        ttl=1
    )
    if not res_a.get("success"):
        return {"success": False, "error": f"خطا در ایجاد رکورد A برای نام‌سرور ({ns_full}): {res_a.get('error')}"}
    logs.append(f"✅ رکورد A نام‌سرور با موفقیت ایجاد شد: {ns_full} ➔ {server_ip} (DNS Only)")

    # 2. Create/Update NS record for Tunnel domain pointing to NS domain
    res_ns = upsert_dns_record(
        zone_id=zone_id,
        token=token,
        name=tunnel_full,
        rtype="NS",
        content=ns_full,
        proxied=False,
        ttl=1
    )
    if not res_ns.get("success"):
        return {"success": False, "error": f"خطا در ایجاد رکورد NS برای دامنه تانل ({tunnel_full}): {res_ns.get('error')}"}
    logs.append(f"✅ رکورد NS تانل با موفقیت ایجاد شد: {tunnel_full} ➔ {ns_full}")

    # 3. Synchronize with local DNS tunnel config if requested
    import subprocess
    synced_services = []
    
    # DNSTT
    if tunnel_type in ["dnstt", "all"]:
        dnstt_cfg_file = "/etc/vpnpanel/dnstt.json"
        try:
            d_cfg = {}
            if os.path.exists(dnstt_cfg_file):
                with open(dnstt_cfg_file, "r") as f:
                    d_cfg = json.load(f)
            d_cfg["domain"] = tunnel_full
            d_cfg["ns_domain"] = ns_full
            with open(dnstt_cfg_file, "w") as f:
                json.dump(d_cfg, f, indent=2)
            
            # Restart service if active
            subprocess.run(["systemctl", "restart", "mhpanel-dnstt"], capture_output=True)
            synced_services.append("DNSTT (SlowDNS)")
            logs.append(f"🔄 تنظیمات و سرویس DNSTT با دامنه جدید {tunnel_full} همگام‌سازی و راه‌اندازی مجدد شد.")
        except Exception as e:
            logs.append(f"⚠️ همگام‌سازی سرویس DNSTT با خطا مواجه شد: {e}")

    # Slipstream
    if tunnel_type in ["slipstream", "all"]:
        slip_cfg_file = "/etc/vpnpanel/slipstream.json"
        try:
            s_cfg = {}
            if os.path.exists(slip_cfg_file):
                with open(slip_cfg_file, "r") as f:
                    s_cfg = json.load(f)
            s_cfg["domain"] = tunnel_full
            with open(slip_cfg_file, "w") as f:
                json.dump(s_cfg, f, indent=2)
            subprocess.run(["systemctl", "restart", "mhpanel-slipstream"], capture_output=True)
            synced_services.append("Slipstream")
            logs.append(f"🔄 سرویس Slipstream با دامنه {tunnel_full} هماهنگ شد.")
        except Exception as e:
            pass

    # VayDNS
    if tunnel_type in ["vaydns", "all"]:
        vay_cfg_file = "/etc/vpnpanel/vaydns.json"
        try:
            v_cfg = {}
            if os.path.exists(vay_cfg_file):
                with open(vay_cfg_file, "r") as f:
                    v_cfg = json.load(f)
            v_cfg["domain"] = tunnel_full
            with open(vay_cfg_file, "w") as f:
                json.dump(v_cfg, f, indent=2)
            subprocess.run(["systemctl", "restart", "mhpanel-vaydns"], capture_output=True)
            synced_services.append("VayDNS")
            logs.append(f"🔄 سرویس VayDNS با دامنه {tunnel_full} هماهنگ شد.")
        except Exception as e:
            pass

    # Read public key for ready client command
    pubkey = ""
    if os.path.exists("/etc/dnstt/server.pub"):
        try:
            with open("/etc/dnstt/server.pub", "r") as f:
                pubkey = f.read().strip()
        except Exception:
            pass

    client_cmd = f"dnstt-client -doh https://cloudflare-dns.com/dns-query -pubkey {pubkey or 'YOUR_PUBKEY'} {tunnel_full} 127.0.0.1:1080"

    return {
        "success": True,
        "message": f"رکوردهای NS و A تانل DNS با موفقیت روی کلودفلر ایجاد و با سرور همگام شدند!",
        "ns_domain": ns_full,
        "tunnel_domain": tunnel_full,
        "server_ip": server_ip,
        "synced_services": synced_services,
        "client_command": client_cmd,
        "logs": logs
    }


# ============================================================================
# 1-CLICK PORT FORWARDING / ORIGIN RULES
# ============================================================================

def list_origin_rules(zone_id, token):
    st, res = cf_api("GET", f"/zones/{zone_id}/rulesets/phases/http_request_origin/entrypoint", token=token)
    if res.get("success") and res.get("result"):
        rules = res["result"].get("rules", [])
        formatted = []
        for r in rules:
            target_p = r.get("action_parameters", {}).get("origin", {}).get("port", "443")
            formatted.append({
                "id": r.get("id"),
                "description": r.get("description", "بدون توضیح"),
                "expression": r.get("expression", ""),
                "target_port": target_p,
                "enabled": r.get("enabled", True)
            })
        return {"success": True, "rules": formatted, "raw": rules}
    return {"success": True, "rules": [], "raw": []}

def add_origin_rule(zone_id, token, subdomain_or_hostname, target_port, description=""):
    hostname = subdomain_or_hostname.strip().lower()
    port = int(target_port)
    desc = description.strip() or f"MHPanel Forward {hostname} to Port {port}"

    new_rule = {
        "description": desc,
        "expression": f'http.host eq "{hostname}"',
        "action": "route",
        "action_parameters": {
            "origin": {
                "port": port
            }
        },
        "enabled": True
    }

    # Fetch existing
    st, res = cf_api("GET", f"/zones/{zone_id}/rulesets/phases/http_request_origin/entrypoint", token=token)
    if res.get("success") and res.get("result"):
        existing_rules = res["result"].get("rules", [])
        # Filter out old rule with same hostname
        updated_rules = [r for r in existing_rules if hostname not in r.get("expression", "")]
        updated_rules.append(new_rule)
        
        st_p, res_p = cf_api("PUT", f"/zones/{zone_id}/rulesets/phases/http_request_origin/entrypoint", token=token, json_data={"rules": updated_rules})
        if res_p.get("success"):
            return {"success": True, "message": f"قانون فوروارد پورت کلودفلر (Origin Rule) با موفقیت ثبت شد: ترافیک دامنه {hostname} به پورت {port} سرور هدایت می‌شود."}
        err = res_p.get("errors", [{}])[0].get("message", "خطا در بروزرسانی رول‌ست")
        return {"success": False, "error": err}
    else:
        # Create new ruleset
        st_cr, res_cr = cf_api("POST", f"/zones/{zone_id}/rulesets", token=token, json_data={
            "name": "default",
            "kind": "zone",
            "phase": "http_request_origin",
            "rules": [new_rule]
        })
        if res_cr.get("success"):
            return {"success": True, "message": f"رول‌ست Origin Rule ایجاد و ترافیک دامنه {hostname} به پورت {port} فوروارد گردید."}
        err = res_cr.get("errors", [{}])[0].get("message", "خطا در ایجاد رول‌ست")
        return {"success": False, "error": err}

def delete_origin_rule(zone_id, token, rule_id=None, hostname=None):
    st, res = cf_api("GET", f"/zones/{zone_id}/rulesets/phases/http_request_origin/entrypoint", token=token)
    if not res.get("success") or not res.get("result"):
        return {"success": False, "error": "قوانین فوروارد پورت در کلودفلر یافت نشد."}

    existing_rules = res["result"].get("rules", [])
    if rule_id:
        filtered = [r for r in existing_rules if r.get("id") != rule_id]
    elif hostname:
        filtered = [r for r in existing_rules if hostname.strip().lower() not in r.get("expression", "")]
    else:
        return {"success": False, "error": "شناسه قانون یا نام هاست مشخص نشده است."}

    st_p, res_p = cf_api("PUT", f"/zones/{zone_id}/rulesets/phases/http_request_origin/entrypoint", token=token, json_data={"rules": filtered})
    if res_p.get("success"):
        return {"success": True, "message": "قانون فوروارد پورت با موفقیت حذف گردید."}
    err = res_p.get("errors", [{}])[0].get("message", "خطا در بروزرسانی قوانین")
    return {"success": False, "error": err}


# ============================================================================
# 1-CLICK CLOUDFLARE WORKERS & GOOGLE APPS SCRIPT RELAY
# ============================================================================

def generate_worker_script(worker_type, vps_host, vps_port, gas_url="", auth_secret="", uuid=""):
    """
    Generates high-performance Cloudflare Worker scripts:
      - gas_relay: Relays requests to Google Apps Script Web App
      - vless_proxy: VLESS / WebSocket proxy direct to VPS
      - reverse_proxy: HTTP/HTTPS Reverse proxy to VPS
    """
    if worker_type == "gas_relay":
        # Google Apps Script Relay Worker
        return f"""/**
 * Cloudflare Worker - Google Apps Script Ultra-Relay
 * Auto-generated by MHPanel
 */
const GAS_BACKEND_URL = "{gas_url}";
const VPS_FALLBACK_URL = "http://{vps_host}:{vps_port}";
const AUTH_SECRET = "{auth_secret}";

addEventListener('fetch', event => {{
  event.respondWith(handleRequest(event.request));
}});

async function handleRequest(request) {{
  const url = new URL(request.url);

  // Health check / probe
  if (request.method === 'GET' && url.pathname === '/') {{
    return new Response(JSON.stringify({{
      status: "active",
      node: "Cloudflare Worker + Google Apps Script Relay",
      time: new Date().toISOString()
    }}), {{
      headers: {{ "content-type": "application/json;charset=UTF-8" }}
    }});
  }}

  // Forward to Google Apps Script or VPS
  const targetUrl = GAS_BACKEND_URL || (VPS_FALLBACK_URL + url.pathname + url.search);
  
  const headers = new Headers(request.headers);
  headers.set('X-Forwarded-Host', url.hostname);
  if (AUTH_SECRET) {{
    headers.set('X-MH-Secret', AUTH_SECRET);
  }}

  try {{
    const response = await fetch(targetUrl, {{
      method: request.method,
      headers: headers,
      body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
      redirect: 'follow'
    }});
    return response;
  }} catch (err) {{
    // Failover directly to VPS
    if (GAS_BACKEND_URL && VPS_FALLBACK_URL) {{
      try {{
        const fallbackResp = await fetch(VPS_FALLBACK_URL + url.pathname + url.search, {{
          method: request.method,
          headers: headers,
          body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined
        }});
        return fallbackResp;
      }} catch (e2) {{}}
    }}
    return new Response("Relay Error: " + err.message, {{ status: 502 }});
  }}
}}
"""

    elif worker_type == "reverse_proxy":
        # Universal Reverse Proxy Worker
        return f"""/**
 * Cloudflare Worker - Reverse Proxy
 * Auto-generated by MHPanel
 */
const BACKEND_HOST = "{vps_host}";
const BACKEND_PORT = "{vps_port}";

addEventListener('fetch', event => {{
  event.respondWith(handleRequest(event.request));
}});

async function handleRequest(request) {{
  const url = new URL(request.url);
  url.hostname = BACKEND_HOST;
  url.port = BACKEND_PORT;
  url.protocol = (BACKEND_PORT == '443' || BACKEND_PORT == '8443' || BACKEND_PORT == '2083' || BACKEND_PORT == '2096') ? 'https:' : 'http:';

  const newHeaders = new Headers(request.headers);
  newHeaders.set('Host', BACKEND_HOST);

  return fetch(url.toString(), {{
    method: request.method,
    headers: newHeaders,
    body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
    redirect: 'follow'
  }});
}}
"""
    else:
        # Default VLESS / WS Worker template
        return f"""/**
 * Cloudflare Worker - High Speed Proxy
 * Auto-generated by MHPanel
 */
const TARGET_HOST = "{vps_host}";
const TARGET_PORT = {vps_port};

addEventListener('fetch', event => {{
  event.respondWith(handleRequest(event.request));
}});

async function handleRequest(request) {{
  if (request.headers.get('Upgrade') === 'websocket') {{
    return handleWebSocket(request);
  }}
  const url = new URL(request.url);
  url.hostname = TARGET_HOST;
  url.port = TARGET_PORT;
  return fetch(url.toString(), request);
}}

async function handleWebSocket(request) {{
  const webSocketPair = new WebSocketPair();
  const [client, server] = Object.values(webSocketPair);
  server.accept();
  return new Response(null, {{
    status: 101,
    webSocket: client
  }});
}}
"""

def deploy_worker_to_cloudflare(account_id, token, script_name, script_content, zone_id=None, custom_domain_route=None, enable_subdomain=True):
    """
    Deploys a Worker script directly via Cloudflare Workers API.
    """
    script_name = script_name.strip().lower().replace(" ", "-")
    
    # 1. Upload Worker Script
    endpoint = f"/accounts/{account_id}/workers/scripts/{script_name}"
    st, res = cf_api("PUT", endpoint, token=token, raw_body=script_content.encode("utf-8"), content_type="application/javascript")
    if not res.get("success"):
        err = res.get("errors", [{}])[0].get("message", "خطا در استقرار اسکریپت ورکر")
        return {"success": False, "error": err}

    worker_url = ""
    logs = [f"✅ اسکریپت ورکر '{script_name}' با موفقیت در حساب کلودفلر شما بارگذاری شد."]

    # 2. Enable workers.dev subdomain route
    if enable_subdomain:
        st_sub, res_sub = cf_api("POST", f"/accounts/{account_id}/workers/scripts/{script_name}/subdomain", token=token, json_data={"enabled": True})
        # Check workers.dev root subdomain
        st_w, res_w = cf_api("GET", f"/accounts/{account_id}/workers/subdomain", token=token)
        if res_w.get("success") and res_w.get("result", {}).get("subdomain"):
            dev_sub = res_w["result"]["subdomain"]
            worker_url = f"https://{script_name}.{dev_sub}.workers.dev"
            logs.append(f"🌐 آدرس عمومی ورکر: {worker_url}")
        else:
            worker_url = f"https://{script_name}.workers.dev"

    # 3. Add Custom Route on Zone if provided
    if zone_id and custom_domain_route:
        route_pattern = custom_domain_route.strip()
        if not route_pattern.endswith("/*"):
            route_pattern = route_pattern.rstrip("/") + "/*"
        
        st_r, res_r = cf_api("POST", f"/zones/{zone_id}/workers/routes", token=token, json_data={
            "pattern": route_pattern,
            "script": script_name
        })
        if res_r.get("success"):
            logs.append(f"✅ روت اختصاصی ورکر روی دامنه شما ثبت شد: {route_pattern}")
            worker_url = f"https://{route_pattern.replace('/*', '')}"
        else:
            logs.append(f"⚠️ ثبت روت دامنه با پاسخ: {res_r.get('errors')}")

    return {
        "success": True,
        "script_name": script_name,
        "worker_url": worker_url,
        "message": f"ورکر کلودفلر '{script_name}' با موفقیت مستقر گردید!",
        "logs": logs
    }

