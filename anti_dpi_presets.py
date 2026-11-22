# -*- coding: utf-8 -*-
"""
MH Panel - Anti-DPI, TLS Fragmentation & Encrypted Client Hello (ECH) Engine
Comprehensive presets for Iranian Operators (MCI, MTN Irancell, Rightel, TCI, FTTH),
Encrypted Client Hello (ECH) resolvers, Patterniha Advanced Fragmentation,
and Domestic Camouflage Domain databases.
"""

import os
import json
import logging
from urllib.parse import quote

logger = logging.getLogger("mhpanel.anti_dpi")

ANTI_DPI_SETTINGS_FILE = "/etc/vpnpanel/anti_dpi_settings.json"

# =========================================================================
# 1. اپراتورهای مخابراتی ایران و پارامترهای شکستن پکت TLS (Fragmentation)
# =========================================================================
DEFAULT_OPERATOR_PRESETS = {
    "mci": {
        "code": "mci",
        "name": "همراه اول (MCI)",
        "desc": "تنظیمات بهینه‌سازی شده برای گذر از سیستم DPI همراه اول با بسته‌های کوچک و تاخیر کم",
        "frag_len": "10-30",
        "frag_int": "2-5",
        "packets": "tlshello",
        "clean_ips": [
            "104.18.119.142",
            "104.25.165.92",
            "104.16.153.15",
            "104.19.241.93"
        ],
        "clean_ip6": [
            "2606:4700::6812:778e",
            "2606:4700::6819:a55c"
        ],
        "singbox": {
            "fragment": True,
            "record_fragment": True,
            "fragment_fallback_delay": "500ms"
        },
        "xray": {
            "packets": "1-2",
            "length": "10-30",
            "interval": "2-5"
        }
    },
    "mtn": {
        "code": "mtn",
        "name": "ایرانسل (MTN)",
        "desc": "تنظیمات ویژه عبور از فیلترینگ هوشمند و مسدودسازی پورت‌های ایرانسل",
        "frag_len": "100-200",
        "frag_int": "5-10",
        "packets": "tlshello",
        "clean_ips": [
            "172.67.69.51",
            "104.25.224.90",
            "172.66.193.96",
            "104.16.242.176"
        ],
        "clean_ip6": [
            "2606:4700::ac43:4533",
            "2606:4700::6819:e05a"
        ],
        "singbox": {
            "fragment": True,
            "record_fragment": True,
            "fragment_fallback_delay": "400ms"
        },
        "xray": {
            "packets": "1-3",
            "length": "100-200",
            "interval": "5-10"
        }
    },
    "rtl": {
        "code": "rtl",
        "name": "رایتل (Rightel)",
        "desc": "تنظیمات فرگمنت متعادل برای شبکه رایتل",
        "frag_len": "50-100",
        "frag_int": "2-5",
        "packets": "tlshello",
        "clean_ips": [
            "159.246.55.228",
            "162.159.138.85",
            "172.64.150.28"
        ],
        "singbox": {
            "fragment": True,
            "record_fragment": True,
            "fragment_fallback_delay": "300ms"
        },
        "xray": {
            "packets": "1-2",
            "length": "50-100",
            "interval": "2-5"
        }
    },
    "mkh": {
        "code": "mkh",
        "name": "مخابرات (TCI)",
        "desc": "تنظیمات پایدار برای اینترنت ثابت مخابرات و شرکت‌های FCP",
        "frag_len": "50-200",
        "frag_int": "1-3",
        "packets": "tlshello",
        "clean_ips": [
            "199.33.231.234",
            "91.209.253.54",
            "104.18.119.142"
        ],
        "singbox": {
            "fragment": True,
            "record_fragment": True,
            "fragment_fallback_delay": "500ms"
        },
        "xray": {
            "packets": "1-2",
            "length": "50-200",
            "interval": "1-3"
        }
    },
    "gaming": {
        "code": "gaming",
        "name": "گیمینگ و پینگ پایین (Gaming / FTTH)",
        "desc": "حداقل تاخیر ممکن برای بازی‌های آنلاین و استریم با حفظ پایداری ارتباط",
        "frag_len": "200-3000",
        "frag_int": "1-2",
        "packets": "tlshello",
        "clean_ips": [
            "104.16.242.176",
            "172.64.150.28",
            "104.18.119.142"
        ],
        "singbox": {
            "fragment": True,
            "record_fragment": False,
            "fragment_fallback_delay": "200ms"
        },
        "xray": {
            "packets": "1-1",
            "length": "200-3000",
            "interval": "1-2"
        }
    }
}

# =========================================================================
# 2. تنظیمات بهینه‌ساز پیشرفته Patterniha (Advanced fm & Cipher Suites)
# =========================================================================
PATTERNIHA_ADVANCED_FRAG = '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["0", "104", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["114", "1"], "delays": ["1"], "maxSplit": "11"}}]}'

PATTERNIHA_CIPHER_SUITES = (
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:"
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
)

# =========================================================================
# 3. پایگاه داده دامنه‌ها و ریزالورهای Encrypted Client Hello (ECH)
# =========================================================================
ECH_OUTER_DOMAINS = [
    "aef.ir",
    "cloudflare-ech.com",
    "tgju.org",
    "iranva.ir",
    "voorivex.ir",
    "react.ir",
    "padidehkhodro.com",
    "cdnjs.cloudflare.com",
    "discordapp.com",
    "gitlab.io",
    "ifconfig.io"
]

ECH_RESOLVERS = [
    {"type": "doh", "name": "Cloudflare DoH", "url": "https://1.1.1.1/dns-query", "ip": "1.1.1.1"},
    {"type": "doh", "name": "Cloudflare Alt DoH", "url": "https://1.0.0.1/dns-query", "ip": "1.0.0.1"},
    {"type": "doh", "name": "Google DoH", "url": "https://8.8.8.8/dns-query", "ip": "8.8.8.8"},
    {"type": "doh", "name": "Google Alt DoH", "url": "https://8.8.4.4/dns-query", "ip": "8.8.4.4"},
    {"type": "doh", "name": "Quad9 DoH", "url": "https://9.9.9.9/dns-query", "ip": "9.9.9.9"},
    {"type": "doh", "name": "Yandex DoH", "url": "https://77.88.8.8/dns-query", "ip": "77.88.8.8"},
    {"type": "doh", "name": "AdGuard DoH", "url": "https://94.140.14.14/dns-query", "ip": "94.140.14.14"},
    {"type": "tcp", "name": "Cloudflare TCP", "url": "tcp://1.1.1.1", "ip": "1.1.1.1"},
    {"type": "tcp", "name": "Google TCP", "url": "tcp://8.8.8.8", "ip": "8.8.8.8"},
    {"type": "udp", "name": "Cloudflare UDP", "url": "udp://1.1.1.1", "ip": "1.1.1.1"}
]

ECH_DEFAULT_PRESETS = [
    "aef.ir+https://1.1.1.1/dns-query",
    "aef.ir+https://8.8.8.8/dns-query",
    "cloudflare-ech.com+https://1.1.1.1/dns-query",
    "tgju.org+https://1.1.1.1/dns-query",
    "iranva.ir+https://1.1.1.1/dns-query",
    "voorivex.ir+https://1.1.1.1/dns-query",
    "aef.ir+tcp://1.1.1.1",
    "cloudflare-ech.com+udp://1.1.1.1"
]

# =========================================================================
# 4. پایگاه داده دامنه‌های استتار داخلی تمیز (Iranian Domestic SNI Mask)
# =========================================================================
DOMESTIC_CAMOUFLAGE_DOMAINS = [
    "sanjesh.org",
    "shaparak.ir",
    "telewebion.com",
    "divar.ir",
    "digikala.com",
    "aparat.com",
    "rubika.ir",
    "bale.ai",
    "snapp.ir",
    "tsetmc.com",
    "netgig.ir",
    "ipcel.ir",
    "mediawach.com",
    "alvandsteel.ir",
    "daket.ir",
    "mahdigit.ir",
    "speedtest.net",
    "cdn.jsdelivr.net"
]

# =========================================================================
# 5. متدهای مدیریت ذخیره‌سازی و پیکربندی ضد DPI
# =========================================================================
def get_anti_dpi_settings():
    """Load anti-DPI settings from disk or return default values."""
    defaults = {
        "enabled": True,
        "default_ech_enabled": True,
        "default_ech": "aef.ir+https://1.1.1.1/dns-query",
        "default_fragment_enabled": True,
        "default_operator": "all",
        "patterniha_enabled": False,
        "custom_camouflage_sni": "",
        "custom_ech_presets": [],
        "custom_camouflage_domains": []
    }
    if os.path.exists(ANTI_DPI_SETTINGS_FILE):
        try:
            with open(ANTI_DPI_SETTINGS_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                if isinstance(saved, dict):
                    defaults.update(saved)
        except Exception as e:
            logger.error(f"Error loading {ANTI_DPI_SETTINGS_FILE}: {e}")
    return defaults

def save_anti_dpi_settings(settings):
    """Save anti-DPI settings to disk safely."""
    try:
        os.makedirs(os.path.dirname(ANTI_DPI_SETTINGS_FILE), exist_ok=True)
        with open(ANTI_DPI_SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error(f"Error saving {ANTI_DPI_SETTINGS_FILE}: {e}")
        return False

# =========================================================================
# 6. ساخت پارامترهای لینک V2Ray / Singbox / Xray
# =========================================================================
def build_v2ray_anti_dpi_query(operator_code=None,
                               enable_ech=False,
                               custom_ech=None,
                               enable_fragment=False,
                               enable_patterniha=False,
                               custom_mask=None,
                               is_tls_port=True):
    """
    Generate URI query string for Anti-DPI (&fragment=, &fm=, &cs=, &mask=, &ech=)
    compatible with v2rayN, v2rayNG, NikaNG, Matsuri, Nekoray, Karing, Sing-box.
    """
    query_parts = []

    # 1. Fragment
    if enable_fragment:
        op_info = DEFAULT_OPERATOR_PRESETS.get(operator_code) or DEFAULT_OPERATOR_PRESETS["mci"]
        frag_len = op_info.get("frag_len", "100-200")
        frag_int = op_info.get("frag_int", "5-10")
        packets = ",tlshello" if is_tls_port else ""
        frag_str = f"{frag_len},{frag_int}{packets}"
        query_parts.append(f"fragment={quote(frag_str)}")

    # 2. Patterniha Advanced Fragment (fm) & Cipher Suites (cs)
    if enable_patterniha:
        query_parts.append(f"fm={quote(PATTERNIHA_ADVANCED_FRAG)}")
        if is_tls_port:
            query_parts.append(f"cs={quote(PATTERNIHA_CIPHER_SUITES)}")

    # 3. Custom TLS Mask
    if custom_mask and is_tls_port:
        query_parts.append(f"mask={quote(custom_mask)}")

    # 4. Encrypted Client Hello (ECH)
    if enable_ech and is_tls_port:
        ech_val = (custom_ech or "").strip()
        if not ech_val:
            s = get_anti_dpi_settings()
            ech_val = s.get("default_ech") or "aef.ir+https://1.1.1.1/dns-query"
        query_parts.append(f"ech={quote(ech_val)}")

    if query_parts:
        return "&" + "&".join(query_parts)
    return ""

def apply_singbox_tls_anti_dpi(tls_obj, operator_code=None, enable_ech=None, enable_fragment=None):
    """
    Inject modern Sing-box 1.10 - 1.14+ Anti-DPI parameters into the outbound TLS dictionary.
    """
    if not isinstance(tls_obj, dict):
        return tls_obj

    s = get_anti_dpi_settings()
    do_ech = s.get("default_ech_enabled", True) if enable_ech is None else bool(enable_ech)
    do_frag = s.get("default_fragment_enabled", True) if enable_fragment is None else bool(enable_fragment)

    if do_frag:
        op_code = operator_code or s.get("default_operator", "mci")
        op_info = DEFAULT_OPERATOR_PRESETS.get(op_code) or DEFAULT_OPERATOR_PRESETS["mci"]
        sb_frag = op_info.get("singbox", {})
        tls_obj["fragment"] = sb_frag.get("fragment", True)
        tls_obj["record_fragment"] = sb_frag.get("record_fragment", True)
        tls_obj["fragment_fallback_delay"] = sb_frag.get("fragment_fallback_delay", "500ms")

    if do_ech:
        tls_obj["ech"] = {
            "enabled": True,
            "dynamic_record_sizing_disabled": False
        }

    return tls_obj

def inject_singbox_client_anti_dpi(singbox_cfg, operator_code=None, enable_ech=None, enable_fragment=None):
    """
    Inject fragment/ECH into all TLS outbounds in a full Sing-box client JSON config,
    and ensure DoH servers are present in the DNS section for ECH key retrieval.
    """
    if not isinstance(singbox_cfg, dict):
        return singbox_cfg

    s = get_anti_dpi_settings()
    do_ech = s.get("default_ech_enabled", True) if enable_ech is None else bool(enable_ech)
    do_frag = s.get("default_fragment_enabled", True) if enable_fragment is None else bool(enable_fragment)

    # 1. Apply to TLS outbounds
    for ob in singbox_cfg.get("outbounds", []):
        if not isinstance(ob, dict):
            continue
        tls = ob.get("tls")
        if isinstance(tls, dict) and tls.get("enabled"):
            # Reality cannot be combined with ECH in Sing-box (Reality has its own Camouflage Handshake)
            is_reality = bool(tls.get("reality", {}).get("enabled"))
            apply_singbox_tls_anti_dpi(tls, operator_code=operator_code,
                                       enable_ech=(False if is_reality else do_ech),
                                       enable_fragment=do_frag)

    # 2. Add DoH DNS server for ECH lookup if ECH is enabled
    if do_ech:
        dns_sec = singbox_cfg.setdefault("dns", {})
        servers = dns_sec.setdefault("servers", [])
        has_doh = any(srv.get("type") in ["https", "doh"] or "/dns-query" in srv.get("server", "") for srv in servers if isinstance(srv, dict))
        if not has_doh:
            servers.insert(0, {
                "tag": "dns-ech-doh",
                "type": "https",
                "server": "1.1.1.1",
                "path": "/dns-query"
            })

    return singbox_cfg
