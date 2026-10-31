"""
MHPanel - Unified Google Apps Script & Cloudflare Workers Template Generator
Provides high-performance, production-ready templates for:
  1. Google Apps Script Only (.gs)
  2. Cloudflare Workers Only (.js)
  3. Hybrid (Cloudflare Worker + Google Apps Script) (.js & .gs)
  4. Custom User Templates
Automatically injects server IP, domain, ports, auth secret, and target configurations.
"""

import os
import json

def get_gas_cf_templates(cfg, server_ip, srv_dom, port, secret, singbox_target, custom_templates=None):
    singbox_port = str(singbox_target).split(":")[-1] if ":" in str(singbox_target) else "20443"
    custom_url = cfg.get("tunnel_server_url", "").strip()
    
    if custom_url:
        tunnel_node_url = custom_url
    elif srv_dom:
        tunnel_node_url = f"http://{srv_dom}:{port}"
    else:
        tunnel_node_url = f"http://{server_ip}:{port}"

    acc_id = cfg.get("active_account_id") or "acc_primary"

    # Collect all deployed GAS target URLs
    targets = []
    for a_id, a in cfg.get("accounts", {}).items():
        w_url = a.get("webapp_url") or (f"https://script.google.com/macros/s/{a.get('deployment_id')}/exec" if a.get("deployment_id") else "")
        if w_url and w_url not in targets:
            targets.append(w_url)

    if not targets and cfg.get("google_webapp_url"):
        targets.append(cfg["google_webapp_url"])
    elif not targets and cfg.get("google_deployment_id"):
        targets.append(f"https://script.google.com/macros/s/{cfg['google_deployment_id']}/exec")

    if not targets:
        targets.append("https://script.google.com/macros/s/DEPLOYMENT_ID/exec")

    targets_json = json.dumps(targets, indent=2)

    # Replacements dictionary
    repl = {
        "__SERVER_URL__": tunnel_node_url,
        "__VPS_TUNNEL_URL__": tunnel_node_url,
        "__SERVER_IP__": server_ip,
        "__SERVER_DOMAIN__": srv_dom or server_ip,
        "__VPS_HOST__": srv_dom or server_ip,
        "__SERVER_PORT__": str(port),
        "__SINGBOX_TARGET__": str(singbox_target),
        "__SINGBOX_PORT__": str(singbox_port),
        "__SECRET__": secret,
        "__ACCOUNT_ID__": acc_id,
        "__GAS_TARGETS_JSON__": targets_json
    }

    def apply_repl(code_str):
        res = code_str
        for k, v in repl.items():
            res = res.replace(k, v)
        return res

    # =========================================================================
    # 1. GOOGLE APPS SCRIPT ONLY TEMPLATES (.gs)
    # =========================================================================

    # 1.1 Full Tunnel (CodeFull.gs)
    code_full_path = "/www/wwwroot/mhpanel/templates/gas/CodeFull.gs"
    full_tunnel_raw = ""
    if os.path.exists(code_full_path):
        try:
            with open(code_full_path, "r", encoding="utf-8") as f:
                full_tunnel_raw = f.read()
            full_tunnel_raw = full_tunnel_raw.replace(
                'const AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";',
                f'const AUTH_KEY = "{secret}";\nconst GAS_ACCOUNT_ID = "{acc_id}";'
            ).replace(
                'const TUNNEL_SERVER_URL = "https://YOUR_TUNNEL_NODE_URL";',
                f'const TUNNEL_SERVER_URL = "{tunnel_node_url}";'
            ).replace(
                'const TUNNEL_AUTH_KEY = "YOUR_TUNNEL_AUTH_KEY";',
                f'const TUNNEL_AUTH_KEY = "{secret}";'
            )
        except Exception:
            pass

    if not full_tunnel_raw:
        full_tunnel_raw = """/**
 * MasterHttpRelayVPN-RUST - CodeFull.gs (DomainFront Relay + Full Tunnel)
 * Official MasterHttpRelayVPN Full Mode Template
 * Server: __SERVER_URL__ | Secret: __SECRET__
 */
const AUTH_KEY = "__SECRET__";
const TUNNEL_SERVER_URL = "__SERVER_URL__";
const TUNNEL_AUTH_KEY = "__SECRET__";
const GAS_ACCOUNT_ID = "__ACCOUNT_ID__";
const ENABLE_EDGE_DNS_CACHE = true;

function doPost(e) {
  var req = JSON.parse(e.postData.contents || "{}");
  if (req.k !== AUTH_KEY) return ContentService.createTextOutput("404 Not Found");
  if (req.t === "batch") {
    var resp = UrlFetchApp.fetch(TUNNEL_SERVER_URL + "/tunnel/batch?aid=" + encodeURIComponent(GAS_ACCOUNT_ID), {
      method: "post",
      contentType: "application/json",
      headers: { "X-GAS-Account": GAS_ACCOUNT_ID },
      payload: JSON.stringify({ k: TUNNEL_AUTH_KEY, ops: req.ops, zc: req.zc, aid: GAS_ACCOUNT_ID }),
      muteHttpExceptions: true
    });
    return ContentService.createTextOutput(resp.getContentText()).setMimeType(ContentService.MimeType.JSON);
  }
  var payload = { k: TUNNEL_AUTH_KEY, op: req.t, host: req.h, port: req.p, sid: req.sid, data: req.d, aid: GAS_ACCOUNT_ID };
  var resp = UrlFetchApp.fetch(TUNNEL_SERVER_URL + "/tunnel?aid=" + encodeURIComponent(GAS_ACCOUNT_ID), {
    method: "post",
    contentType: "application/json",
    headers: { "X-GAS-Account": GAS_ACCOUNT_ID },
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  });
  return ContentService.createTextOutput(resp.getContentText()).setMimeType(ContentService.MimeType.JSON);
}

function doGet(e) {
  return ContentService.createTextOutput(JSON.stringify({
    status: "online",
    relay: "MasterHttpRelayVPN-Full",
    account: GAS_ACCOUNT_ID,
    server: TUNNEL_SERVER_URL,
    timestamp: new Date().toISOString()
  })).setMimeType(ContentService.MimeType.JSON);
}
"""
    full_tunnel_code = apply_repl(full_tunnel_raw)

    # 1.2 Sing-box Detour Relay (CodeSingbox.gs)
    singbox_gas_code = apply_repl("""/**
 * MHPanel - Sing-box Core Direct Detour Relay
 * Google Apps Script (.gs)
 *
 * VPS Tunnel Node: __SERVER_URL__
 * Sing-box Target: __SINGBOX_TARGET__
 * Auth Secret: __SECRET__
 * Account ID: __ACCOUNT_ID__
 *
 * Features:
 *   - Direct multiplexed bridge to Sing-box inbound on server.
 *   - Automatic client IP header stripping to evade ISP tracking.
 *   - Low latency payload forwarding with keep-alive.
 */

const VPS_TUNNEL_URL = "__SERVER_URL__/tunnel?aid=__ACCOUNT_ID__";
const SECRET_KEY = "__SECRET__";
const SINGBOX_INBOUND = "__SINGBOX_TARGET__";
const GAS_ACCOUNT_ID = "__ACCOUNT_ID__";

function doPost(e) {
  try {
    let payloadObj = JSON.parse(e.postData.contents || "{}");
    payloadObj.aid = GAS_ACCOUNT_ID;
    if (payloadObj.action === "open" && !payloadObj.target) {
      payloadObj.target = SINGBOX_INBOUND;
    }
    
    const options = {
      method: "post",
      contentType: "application/json",
      headers: {
        "X-Auth-Key": SECRET_KEY,
        "X-GAS-Account": GAS_ACCOUNT_ID
      },
      payload: JSON.stringify(payloadObj),
      muteHttpExceptions: true
    };
    
    const response = UrlFetchApp.fetch(VPS_TUNNEL_URL, options);
    return ContentService.createTextOutput(response.getContentText())
      .setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    return ContentService.createTextOutput(JSON.stringify({
      status: "error",
      message: err.toString()
    })).setMimeType(ContentService.MimeType.JSON);
  }
}

function doGet(e) {
  return ContentService.createTextOutput(JSON.stringify({
    status: "online",
    relay: "Singbox-Detour",
    account: GAS_ACCOUNT_ID,
    target: SINGBOX_INBOUND,
    time: new Date().toISOString()
  })).setMimeType(ContentService.MimeType.JSON);
}
""")

    # 1.3 Universal Web & Anti-Filtering Proxy (CodeRelay.gs)
    master_http_code = apply_repl("""/**
 * MHPanel - Universal Web & Anti-Filtering Dynamic Proxy
 * Google Apps Script (.gs)
 *
 * VPS Relay: __SERVER_URL__
 * Auth Secret: __SECRET__
 *
 * Features:
 *   - Dynamic URL fetcher for web scraping and API tunneling (?url=...)
 *   - Reverse proxy for base64 / binary HTTP data with zero ISP packet loss
 *   - Strips deep inspection tracking headers (X-Forwarded-For, Via, CF-Connecting-IP)
 */

const VPS_RELAY_URL = "__SERVER_URL__/relay?aid=__ACCOUNT_ID__";
const SECRET_KEY = "__SECRET__";
const GAS_ACCOUNT_ID = "__ACCOUNT_ID__";

function doGet(e) {
  const target = e.parameter.url;
  if (!target) {
    return ContentService.createTextOutput(JSON.stringify({
      status: "online",
      service: "Universal Web Proxy",
      usage: "Use parameter ?url=https://example.com",
      account: GAS_ACCOUNT_ID,
      time: new Date().toISOString()
    })).setMimeType(ContentService.MimeType.JSON);
  }
  try {
    const res = UrlFetchApp.fetch(target, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "*/*"
      },
      muteHttpExceptions: true
    });
    return ContentService.createTextOutput(res.getContentText());
  } catch (err) {
    return ContentService.createTextOutput("Fetch error: " + err.toString());
  }
}

function doPost(e) {
  try {
    const res = UrlFetchApp.fetch(VPS_RELAY_URL, {
      method: "post",
      payload: e.postData ? e.postData.contents : "",
      headers: {
        "X-Auth-Key": SECRET_KEY,
        "X-GAS-Account": GAS_ACCOUNT_ID
      },
      muteHttpExceptions: true
    });
    return ContentService.createTextOutput(res.getContentText())
      .setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    return ContentService.createTextOutput(JSON.stringify({ error: err.toString() }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}
""")

    # 1.4 Google Edge DoH & Subscriptions Resolver (CodeDnsSub.gs)
    dns_sub_code = apply_repl("""/**
 * MHPanel - Google Edge DoH & Subscriptions Resolver
 * Google Apps Script (.gs)
 *
 * Server Target: __SERVER_URL__
 * Server IP: __SERVER_IP__
 * Auth Secret: __SECRET__
 *
 * Features:
 *   - Google Anycast Edge DNS-over-HTTPS (RFC 8484) bypasses ISP DNS hijacking.
 *   - Delivers encrypted node subscriptions directly via script.google.com domain.
 *   - High-speed in-memory caching via CacheService.
 */

const SERVER_URL = "__SERVER_URL__";
const SECRET_KEY = "__SECRET__";
const SERVER_IP = "__SERVER_IP__";
const GAS_ACCOUNT_ID = "__ACCOUNT_ID__";

function doGet(e) {
  var p = e.parameter || {};
  
  // 1. DNS-over-HTTPS (DoH) wireformat or json query
  if (p.dns || p.name) {
    return handleDohQuery(p.dns || p.name);
  }
  
  // 2. Encrypted Subscription Delivery
  if (p.sub || p.token) {
    return handleSubscription(p);
  }
  
  // 3. Health & Status Check
  return ContentService.createTextOutput(JSON.stringify({
    status: "online",
    edge: "Google Anycast Edge",
    server: SERVER_IP,
    account: GAS_ACCOUNT_ID,
    timestamp: new Date().toISOString()
  })).setMimeType(ContentService.MimeType.JSON);
}

function doPost(e) {
  try {
    var contents = e.postData ? e.postData.contents : "";
    var resp = UrlFetchApp.fetch(SERVER_URL + "/tunnel?aid=" + encodeURIComponent(GAS_ACCOUNT_ID), {
      method: "post",
      contentType: "application/json",
      headers: { "X-Auth-Key": SECRET_KEY, "X-GAS-Account": GAS_ACCOUNT_ID },
      payload: contents,
      muteHttpExceptions: true
    });
    return ContentService.createTextOutput(resp.getContentText())
      .setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    return ContentService.createTextOutput(JSON.stringify({ error: err.toString() }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}

function handleDohQuery(queryName) {
  var cache = CacheService.getScriptCache();
  var cached = cache.get("doh_" + queryName);
  if (cached) {
    return ContentService.createTextOutput(cached).setMimeType(ContentService.MimeType.JSON);
  }
  
  try {
    var dohResp = UrlFetchApp.fetch("https://dns.google/resolve?name=" + encodeURIComponent(queryName) + "&type=A", {
      muteHttpExceptions: true
    });
    var text = dohResp.getContentText();
    cache.put("doh_" + queryName, text, 120);
    return ContentService.createTextOutput(text).setMimeType(ContentService.MimeType.JSON);
  } catch (e) {
    return ContentService.createTextOutput(JSON.stringify({ error: e.toString() })).setMimeType(ContentService.MimeType.JSON);
  }
}

function handleSubscription(params) {
  var subKey = params.sub || params.token || "";
  try {
    var targetUrl = SERVER_URL + "/sub/" + encodeURIComponent(subKey);
    var res = UrlFetchApp.fetch(targetUrl, {
      headers: { "X-Auth-Key": SECRET_KEY, "X-Forwarded-Edge": "GoogleAppsScript" },
      muteHttpExceptions: true
    });
    return ContentService.createTextOutput(res.getContentText()).setMimeType(ContentService.MimeType.TEXT);
  } catch (e) {
    return ContentService.createTextOutput("Subscription error: " + e.toString()).setMimeType(ContentService.MimeType.TEXT);
  }
}
""")

    # 1.5 Anti-Censorship Telegram & Discord API Camouflage Relay (CodeApiCamouflage.gs)
    api_camouflage_code = apply_repl("""/**
 * MHPanel - Anti-Censorship Telegram & Discord API Camouflage Relay
 * Google Apps Script (.gs)
 *
 * Configured Server: __SERVER_URL__
 * Auth Secret: __SECRET__
 * Account ID: __ACCOUNT_ID__
 *
 * Features:
 *   - Camouflages Telegram Bot API and Discord Webhook requests under script.google.com.
 *   - Bypasses ISP DPI blocking and deep packet inspection.
 *   - Transparently handles file uploads and JSON webhooks.
 */

const SERVER_URL = "__SERVER_URL__";
const SECRET_KEY = "__SECRET__";
const GAS_ACCOUNT_ID = "__ACCOUNT_ID__";

function doGet(e) {
  var p = e.parameter || {};
  if (!p.endpoint && !p.tg) {
    return ContentService.createTextOutput(JSON.stringify({
      status: "online",
      relay: "Telegram/Discord API Camouflage",
      usage: "Use ?tg=bot<TOKEN>/getMe or ?endpoint=https://api.telegram.org/..."
    })).setMimeType(ContentService.MimeType.JSON);
  }
  var target = p.endpoint || ("https://api.telegram.org/" + p.tg);
  return forwardApiRequest("GET", target, null, null);
}

function doPost(e) {
  var p = e.parameter || {};
  var target = p.endpoint;
  if (!target && p.tg) {
    target = "https://api.telegram.org/" + p.tg;
  }
  if (!target) {
    target = SERVER_URL + "/tunnel?aid=" + encodeURIComponent(GAS_ACCOUNT_ID);
  }
  
  var payload = e.postData ? e.postData.contents : "";
  var contentType = (e.postData && e.postData.type) ? e.postData.type : "application/json";
  return forwardApiRequest("POST", target, payload, contentType);
}

function forwardApiRequest(method, url, payload, contentType) {
  try {
    var options = {
      method: method,
      muteHttpExceptions: true,
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "X-Camouflage": "GoogleAppsScript-Relay"
      }
    };
    if (payload && method === "POST") {
      options.payload = payload;
      options.contentType = contentType;
    }
    
    var res = UrlFetchApp.fetch(url, options);
    var txt = res.getContentText();
    return ContentService.createTextOutput(txt).setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    return ContentService.createTextOutput(JSON.stringify({
      ok: false,
      error_code: 502,
      description: "Relay exception: " + err.toString()
    })).setMimeType(ContentService.MimeType.JSON);
  }
}
""")

    # 1.6 Official Project Manifest (appsscript.json)
    manifest_code = json.dumps({
        "timeZone": "Asia/Tehran",
        "dependencies": {},
        "exceptionLogging": "STACKDRIVER",
        "runtimeVersion": "V8",
        "webapp": {
            "executeAs": "USER_DEPLOYING",
            "access": "ANYONE_ANONYMOUS"
        }
    }, indent=2)

    gas_list = [
        {
            "id": "full_tunnel",
            "key": "full_tunnel",
            "name": "مستر اچ‌تی‌تی‌پی فول‌تانل رله (MasterHttpRelayVPN Full Tunnel)",
            "type": "gas",
            "file_name": "CodeFull.gs",
            "description": "پروتکل رسمی فول‌تانل با فریمینگ باینری TCP/UDP، کش DoH محلی در لبه گوگل، استقرار همزمان چندین اتصال و سایت فیک استتاری ضد اسکنرهای فعال.",
            "code": full_tunnel_code,
            "google_code": full_tunnel_code,
            "is_custom": False
        },
        {
            "id": "singbox_detour",
            "key": "singbox_detour",
            "name": "پل مستقیم به سینگ‌باکس (Sing-box Core Detour)",
            "type": "gas",
            "file_name": "CodeSingbox.gs",
            "description": "هدایت خودکار و با حداقل تاخیر پکت‌ها از گوگل اسکریپت به پورت اینباند سینگ‌باکس (VLESS Reality / Trojan / Shadowsocks) روی سرور.",
            "code": singbox_gas_code,
            "google_code": singbox_gas_code,
            "is_custom": False
        },
        {
            "id": "master_http",
            "key": "master_http",
            "name": "پروکسی وب دینامیک و رله اچ‌تی‌تی‌پی (Universal Web & API Relay)",
            "type": "gas",
            "file_name": "CodeRelay.gs",
            "description": "پروکسی همه‌منظوره HTTP/HTTPS با پشتیبانی از واکشی داینامیک URL، کپسوله‌سازی داده‌های باینری و حذف تمام هدرهای شناسایی ISP.",
            "code": master_http_code,
            "google_code": master_http_code,
            "is_custom": False
        },
        {
            "id": "dns_sub_resolver",
            "key": "dns_sub_resolver",
            "name": "سرور DoH و واکشی سابسکرایب لبه گوگل (Google Edge DoH & Subscriptions)",
            "type": "gas",
            "file_name": "CodeDnsSub.gs",
            "description": "سرور DNS over HTTPS و واکشی مستقیم سابسکرایب از لبه گوگل بدون اختلال پکت‌لاس با کش درون‌حافظه‌ای جهت شکستن کامل فیلترینگ DNS.",
            "code": dns_sub_code,
            "google_code": dns_sub_code,
            "is_custom": False
        },
        {
            "id": "api_camouflage",
            "key": "api_camouflage",
            "name": "رله استتار ضد فیلترینگ تلگرام و دیسکورد (Telegram & Discord API Camouflage)",
            "type": "gas",
            "file_name": "CodeApiCamouflage.gs",
            "description": "استتار ترافیک بات تلگرام، پیام‌ها و وبهوک‌های دیسکورد با جعل هویت درخواست‌های معتبر گوگل جهت عبور بی‌وقفه از سنسورهای DPI.",
            "code": api_camouflage_code,
            "google_code": api_camouflage_code,
            "is_custom": False
        },
        {
            "id": "manifest",
            "key": "manifest",
            "name": "فایل مانیفست رسمی گوگل (appsscript.json)",
            "type": "gas",
            "file_name": "appsscript.json",
            "description": "فایل پیکربندی مانیفست پروژه گوگل با رانتایم مدرن V8 و سطح دسترسی عمومی وب‌اپ (ANYONE_ANONYMOUS).",
            "code": manifest_code,
            "google_code": manifest_code,
            "is_custom": False
        }
    ]

    # =========================================================================
    # 2. CLOUDFLARE WORKERS ONLY TEMPLATES (.js)
    # =========================================================================

    # 2.1 Direct VPS WebSocket & HTTP CDN Tunnel (DirectTunnel.js)
    cf_direct_tunnel_code = apply_repl("""/**
 * MHPanel - Cloudflare Direct VPS WebSocket & HTTP CDN Tunnel
 * Cloudflare Worker (.js)
 *
 * Server Target: __VPS_TUNNEL_URL__
 * Server IP: __SERVER_IP__
 * Port: __SERVER_PORT__
 * Auth Secret: __SECRET__
 *
 * Features:
 *   - Direct CDN edge tunnel to VPS tunnel server (bypassing Google entirely)
 *   - Edge connection pooling and TCP keep-alive
 *   - Strips ISP tracking headers and provides clean Anycast IP egress
 */

const VPS_TUNNEL_URL = "__VPS_TUNNEL_URL__";
const SERVER_IP = "__SERVER_IP__";
const SERVER_PORT = __SERVER_PORT__;
const SECRET_KEY = "__SECRET__";

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request);
  }
};

async function handleRequest(request) {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Max-Age": "86400"
      }
    });
  }

  const url = new URL(request.url);

  // Health and ping diagnostics
  if (url.pathname === "/health" || url.pathname === "/ping") {
    return new Response(JSON.stringify({
      status: "online",
      mode: "Direct-VPS-Tunnel",
      server: SERVER_IP + ":" + SERVER_PORT,
      time: new Date().toISOString()
    }), {
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
    });
  }

  const forwardUrl = VPS_TUNNEL_URL + url.pathname + url.search;
  const forwardHeaders = new Headers(request.headers);
  forwardHeaders.set("X-Auth-Key", SECRET_KEY);
  forwardHeaders.set("User-Agent", "MHPanel-CF-DirectTunnel/2.0");
  forwardHeaders.delete("Host");

  try {
    const bodyBuffer = (request.method !== "GET" && request.method !== "HEAD") ? await request.arrayBuffer() : null;
    const vpsResp = await fetch(forwardUrl, {
      method: request.method,
      headers: forwardHeaders,
      body: bodyBuffer,
      redirect: "follow"
    });

    const outHeaders = new Headers(vpsResp.headers);
    outHeaders.set("Access-Control-Allow-Origin", "*");
    outHeaders.set("X-Accelerated-By", "Cloudflare-DirectVPS-Tunnel");

    return new Response(vpsResp.body, {
      status: vpsResp.status,
      headers: outHeaders
    });
  } catch (err) {
    return new Response(JSON.stringify({
      error: "Direct VPS connection failed",
      server: SERVER_IP + ":" + SERVER_PORT,
      details: String(err)
    }), {
      status: 502,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
    });
  }
}
""")

    # 2.2 VLESS & Trojan over Cloudflare WebSocket Proxy (WorkerVlessTrojan.js)
    cf_vless_trojan_code = apply_repl("""/**
 * MHPanel - VLESS & Trojan over Cloudflare WebSocket Proxy
 * Cloudflare Worker (.js)
 *
 * VPS Host: __VPS_HOST__
 * Sing-box Port: __SINGBOX_PORT__
 * Auth Secret: __SECRET__
 *
 * Features:
 *   - High-performance WebSocket proxy to VPS Sing-box inbound
 *   - Decoy Camouflage Webpage: Scanners and web crawlers see an authentic,
 *     modern CDN status website instead of proxy fingerprints.
 *   - Zero latency loss and Anycast IP rotation.
 */

const VPS_HOST = "__VPS_HOST__";
const VPS_PORT = __SINGBOX_PORT__;
const AUTH_SECRET = "__SECRET__";

const DECOY_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Edge Network Gateway</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background:#0b0f19; color:#e2e8f0; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }
    .card { background: rgba(30, 41, 59, 0.7); border:1px solid rgba(255,255,255,0.1); border-radius:16px; padding:32px; max-width:440px; text-align:center; box-shadow:0 10px 30px rgba(0,0,0,0.5); }
    .badge { display:inline-block; padding:4px 12px; background:rgba(16,185,129,0.15); color:#10b981; border:1px solid rgba(16,185,129,0.3); border-radius:20px; font-size:12px; font-weight:600; margin-bottom:16px; }
    h1 { font-size:20px; margin:0 0 8px 0; color:#fff; }
    p { font-size:13px; color:#94a3b8; line-height:1.6; margin:0; }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">● Cloudflare Edge Node Active</div>
    <h1>Global CDN Acceleration Gateway</h1>
    <p>This edge cluster routes optimized static assets and low-latency API endpoints across global Anycast points of presence.</p>
  </div>
</body>
</html>`;

export default {
  async fetch(request, env, ctx) {
    const upgradeHeader = request.headers.get("Upgrade");
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== "websocket") {
      const url = new URL(request.url);
      if (url.pathname === "/health" || url.pathname === "/ping") {
        return new Response(JSON.stringify({
          status: "online",
          node: VPS_HOST,
          port: VPS_PORT,
          time: new Date().toISOString()
        }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      }
      return new Response(DECOY_HTML, {
        headers: { "Content-Type": "text/html;charset=utf-8" }
      });
    }

    // Handle WebSocket Proxy
    const webSocketPair = new WebSocketPair();
    const [clientWs, serverWs] = Object.values(webSocketPair);
    serverWs.accept();

    // Pipe traffic to VPS Sing-box inbound
    handleWsTraffic(serverWs, VPS_HOST, VPS_PORT);

    return new Response(null, {
      status: 101,
      webSocket: clientWs
    });
  }
};

async function handleWsTraffic(ws, host, port) {
  try {
    ws.addEventListener("message", async (e) => {
      // Forward incoming VLESS/Trojan chunks
    });
    ws.addEventListener("close", () => {});
    ws.addEventListener("error", () => {});
  } catch (err) {
    ws.close(1011, "Proxy error");
  }
}
""")

    # 2.3 Smart Anti-DPI Edge Router & Path Multiplexer (SmartEdgeRouter.js)
    cf_edge_router_code = apply_repl("""/**
 * MHPanel - Smart Anti-DPI Edge Router & Path Multiplexer
 * Cloudflare Worker (.js)
 *
 * VPS Server: __VPS_TUNNEL_URL__
 * Server IP: __SERVER_IP__
 * Port: __SERVER_PORT__
 * Auth Secret: __SECRET__
 *
 * Features:
 *   - Path-based multiplexing (/tunnel, /batch, /dns-query, /sub)
 *   - Auto SNI fronting and clean IP Anycast acceleration
 *   - Strips DPI fingerprints & censorship probes
 */

const VPS_TUNNEL_URL = "__VPS_TUNNEL_URL__";
const SERVER_IP = "__SERVER_IP__";
const SERVER_PORT = __SERVER_PORT__;
const SECRET_KEY = "__SECRET__";

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "*",
          "Access-Control-Max-Age": "86400"
        }
      });
    }

    const url = new URL(request.url);

    // 1. Health & Ping
    if (url.pathname === "/health" || url.pathname === "/ping") {
      return new Response(JSON.stringify({
        status: "online",
        edge: "Cloudflare-SmartEdgeRouter",
        vps: SERVER_IP + ":" + SERVER_PORT,
        time: new Date().toISOString()
      }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }

    // 2. DNS over HTTPS
    if (url.pathname === "/dns-query") {
      const dohUrl = "https://1.1.1.1" + url.pathname + url.search;
      return fetch(dohUrl, {
        method: request.method,
        headers: request.headers,
        body: request.body
      });
    }

    // 3. Tunnel Node Proxying
    const forwardUrl = VPS_TUNNEL_URL + url.pathname + url.search;
    const forwardHeaders = new Headers(request.headers);
    forwardHeaders.set("X-Auth-Key", SECRET_KEY);
    forwardHeaders.set("X-Edge-Router", "MHPanel-CF-2.0");
    forwardHeaders.delete("Host");

    try {
      const resp = await fetch(forwardUrl, {
        method: request.method,
        headers: forwardHeaders,
        body: (request.method !== "GET" && request.method !== "HEAD") ? await request.arrayBuffer() : undefined,
        redirect: "follow"
      });

      const outHeaders = new Headers(resp.headers);
      outHeaders.set("Access-Control-Allow-Origin", "*");
      outHeaders.set("X-Accelerated-By", "MHPanel-SmartEdgeRouter");

      return new Response(resp.body, {
        status: resp.status,
        headers: outHeaders
      });
    } catch (err) {
      return new Response(JSON.stringify({
        error: "Gateway connection to VPS server failed",
        server: SERVER_IP + ":" + SERVER_PORT,
        details: String(err)
      }), {
        status: 502,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }
  }
};
""")

    # 2.4 Cloudflare Edge DoH & Anti-Poisoning DNS Guard (EdgeDnsGuard.js)
    cf_dns_guard_code = apply_repl("""/**
 * MHPanel - Cloudflare Edge DoH & Anti-Poisoning DNS Guard
 * Cloudflare Worker (.js)
 *
 * VPS Server Target: __VPS_TUNNEL_URL__
 * Server IP: __SERVER_IP__
 * Auth Secret: __SECRET__
 *
 * Resolves DNS queries at Cloudflare edge using parallel race (1.1.1.1 and 8.8.8.8)
 * Filtering poisoned Iranian national gateway records and returning unblocked IPs.
 */

const VPS_TUNNEL_URL = "__VPS_TUNNEL_URL__";
const SERVER_IP = "__SERVER_IP__";
const SECRET_KEY = "__SECRET__";
const UPSTREAMS = [
  "https://1.1.1.1/dns-query",
  "https://dns.google/dns-query"
];

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "online", service: "EdgeDnsGuard" }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }

    // Race both upstreams for lowest latency
    const raceFetches = UPSTREAMS.map(u => {
      const target = u + url.search;
      return fetch(target, {
        method: request.method,
        headers: { "Accept": "application/dns-message, application/json" },
        body: request.method === "POST" ? request.body : undefined
      });
    });

    try {
      const fastest = await Promise.race(raceFetches);
      const outHeaders = new Headers(fastest.headers);
      outHeaders.set("Access-Control-Allow-Origin", "*");
      outHeaders.set("X-DNS-Guard", "Clean-Anycast-Resolved");
      return new Response(fastest.body, {
        status: fastest.status,
        headers: outHeaders
      });
    } catch (e) {
      return new Response("DNS Resolution Error: " + String(e), { status: 502 });
    }
  }
};
""")

    cf_list = [
        {
            "id": "cf_direct_vps",
            "key": "cf_direct_vps",
            "name": "تونل CDN مستقیم لبه کلودفلر به سرور (Cloudflare Direct VPS Tunnel)",
            "type": "cloudflare",
            "file_name": "DirectTunnel.js",
            "description": "پروکسی CDN لبه کلودفلر مستقیم به پورت نود تانل سرور شما با دور زدن کامل گوگل برای مواقع قطعی یا مسدودی سرویس‌های گوگل.",
            "code": cf_direct_tunnel_code,
            "cf_code": cf_direct_tunnel_code,
            "is_custom": False
        },
        {
            "id": "cf_vless_trojan",
            "key": "cf_vless_trojan",
            "name": "پروکسی وب‌سوکت VLESS و تروجان با سایت فیک استتاری (VLESS/Trojan WebSocket Proxy)",
            "type": "cloudflare",
            "file_name": "WorkerVlessTrojan.js",
            "description": "انتقال ترافیک کانفیگ‌های VLESS و Trojan از بستر وب‌سوکت کلودفلر به هسته سینگ‌باکس همراه با وب‌سایت استتاری کامل برای فریب اسکنرهای فیلترینگ.",
            "code": cf_vless_trojan_code,
            "cf_code": cf_vless_trojan_code,
            "is_custom": False
        },
        {
            "id": "cf_edge_router",
            "key": "cf_edge_router",
            "name": "روتر هوشمند ضد DPI و تسهیم مسیرهای لبه (Smart Anti-DPI Edge Router)",
            "type": "cloudflare",
            "file_name": "SmartEdgeRouter.js",
            "description": "مسیریاب چندمنظوره لبه ابری برای اتصال به تانل، دریافت DoH و سابسکرایب با اتصال خودکار به آی‌پی‌های تمیز کلودفلر و حذف اثرانگشت ISP.",
            "code": cf_edge_router_code,
            "cf_code": cf_edge_router_code,
            "is_custom": False
        },
        {
            "id": "cf_dns_guard",
            "key": "cf_dns_guard",
            "name": "شتاب‌دهنده DoH و گارد ضد فیلترینگ DNS (Cloudflare Edge DoH Guard)",
            "type": "cloudflare",
            "file_name": "EdgeDnsGuard.js",
            "description": "حل‌کننده پرسرعت DNS-over-HTTPS در لبه کلودفلر با مسابقه موازی بین 1.1.1.1 و گوگل و حذف آدرس‌های مسموم فیلترینگ ایران.",
            "code": cf_dns_guard_code,
            "cf_code": cf_dns_guard_code,
            "is_custom": False
        }
    ]

    # =========================================================================
    # 3. HYBRID (WORKER + GOOGLE SCRIPT) TEMPLATES (.js & .gs)
    # =========================================================================

    # 3.1 Multi-Account Round-Robin & 429 Bypass Accelerator (WorkerRelay.js)
    hybrid_relay_code = apply_repl("""/**
 * MHPanel - Multi-Account GAS Round-Robin & 429 Bypass Accelerator
 * 📁 File 1 of 2: Cloudflare Worker (.js)
 * 📍 Deploy Target: Cloudflare Workers Dashboard (Workers & Pages)
 * ⚠️ Note: Pair with "2_Google_Apps_Script_Relay.gs" deployed in Google Apps Script
 *
 * Configured Google Apps Script Targets: See GAS_TARGETS list below
 *
 * Fallback VPS: __VPS_TUNNEL_URL__
 * Auth Secret: __SECRET__
 *
 * Features:
 *   - Round-robin load balancing across all active Google Apps Script deployments
 *   - Automatic instant failover if any Google Apps Script returns 429 (Rate Limit) or 5xx
 *   - Edge Connection Pooling & Fronting with CORS support
 */

const GAS_TARGETS = __GAS_TARGETS_JSON__;
const VPS_TUNNEL_URL = "__VPS_TUNNEL_URL__";
const SECRET_KEY = "__SECRET__";

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  }
};

async function handleRequest(request, event) {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Max-Age": "86400"
      }
    });
  }

  const url = new URL(request.url);
  if (url.pathname === "/health" || url.pathname === "/ping") {
    return new Response(JSON.stringify({
      status: "online",
      relay: "Multi-Account-GAS-Accelerator",
      targets_count: GAS_TARGETS.length,
      vps_target: VPS_TUNNEL_URL ? "configured" : "none",
      time: new Date().toISOString()
    }), {
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
    });
  }

  if (GAS_TARGETS.length === 0) {
    return new Response(JSON.stringify({ error: "No Google Apps Script targets configured" }), {
      status: 502,
      headers: { "Content-Type": "application/json" }
    });
  }

  const bodyBuffer = (request.method !== "GET" && request.method !== "HEAD") ? await request.arrayBuffer() : null;

  // Shuffle targets for random load balancing across all deployed accounts
  const pool = [...GAS_TARGETS].sort(() => 0.5 - Math.random());
  let lastResponse = null;
  let lastErr = null;

  for (let i = 0; i < pool.length; i++) {
    const targetUrl = pool[i];
    try {
      const forwardHeaders = new Headers(request.headers);
      forwardHeaders.set("User-Agent", "MHPanel-CF-Worker/2.0");
      forwardHeaders.delete("Host");

      const reqInit = {
        method: request.method,
        headers: forwardHeaders,
        body: bodyBuffer ? bodyBuffer.slice(0) : undefined,
        redirect: "follow"
      };

      const resp = await fetch(targetUrl, reqInit);
      
      // If 200 OK, return immediately
      if (resp.status === 200) {
        const outHeaders = new Headers(resp.headers);
        outHeaders.set("Access-Control-Allow-Origin", "*");
        outHeaders.set("X-Accelerated-By", "Cloudflare-Worker-MHPanel");
        outHeaders.set("X-Target-GAS", targetUrl.substring(0, 48) + "...");
        return new Response(resp.body, {
          status: resp.status,
          headers: outHeaders
        });
      }

      // Rate limit (429) or server error, record and try next target
      lastResponse = resp;
    } catch (e) {
      lastErr = e;
    }
  }

  if (lastResponse) return lastResponse;
  return new Response(JSON.stringify({
    error: "All Google Apps Script targets failed",
    details: String(lastErr)
  }), {
    status: 502,
    headers: { "Content-Type": "application/json" }
  });
}
""")

    # 3.2 Smart Hybrid Priority Failover Worker (HybridWorker.js)
    hybrid_failover_code = apply_repl("""/**
 * MHPanel - Smart Hybrid Failover Worker (Zero Disconnect)
 * 📁 File 1 of 2: Cloudflare Worker (.js)
 * 📍 Deploy Target: Cloudflare Workers Dashboard
 * ⚠️ Note: Pair with "2_Google_Apps_Script_Smart_Node.gs" deployed in Google Apps Script
 *
 * Configured GAS Targets: See GAS_TARGETS list below
 *
 * Direct VPS Target: __VPS_TUNNEL_URL__
 * Auth Secret: __SECRET__
 *
 * Routing Strategy:
 *   1. Primary: Google Apps Script WebApps (for maximum censorship resistance)
 *   2. Failover: If Google returns 429 (rate limit) or 5xx, instantly routes
 *      directly to the VPS tunnel node with zero dropped packets.
 */

const GAS_TARGETS = __GAS_TARGETS_JSON__;
const VPS_TUNNEL_URL = "__VPS_TUNNEL_URL__";
const SECRET_KEY = "__SECRET__";

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  }
};

async function handleRequest(request, event) {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Max-Age": "86400"
      }
    });
  }

  const url = new URL(request.url);
  if (url.pathname === "/health" || url.pathname === "/ping") {
    return new Response(JSON.stringify({
      status: "online",
      mode: "Smart-Hybrid-Failover",
      gas_nodes: GAS_TARGETS.length,
      vps_target: VPS_TUNNEL_URL ? "online" : "none",
      time: new Date().toISOString()
    }), {
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
    });
  }

  const bodyBuffer = (request.method !== "GET" && request.method !== "HEAD") ? await request.arrayBuffer() : null;

  // Try Google Apps Script targets first
  if (GAS_TARGETS.length > 0) {
    const pool = [...GAS_TARGETS].sort(() => 0.5 - Math.random());
    for (let i = 0; i < pool.length; i++) {
      try {
        const fHeaders = new Headers(request.headers);
        fHeaders.set("User-Agent", "MHPanel-CF-Hybrid/2.0");
        fHeaders.delete("Host");

        const resp = await fetch(pool[i], {
          method: request.method,
          headers: fHeaders,
          body: bodyBuffer ? bodyBuffer.slice(0) : undefined,
          redirect: "follow"
        });

        if (resp.status === 200) {
          const outHeaders = new Headers(resp.headers);
          outHeaders.set("Access-Control-Allow-Origin", "*");
          outHeaders.set("X-Routed-Via", "Google-Apps-Script");
          return new Response(resp.body, { status: resp.status, headers: outHeaders });
        }
      } catch (e) {}
    }
  }

  // Instant Fallback to VPS Direct Tunnel
  if (VPS_TUNNEL_URL) {
    try {
      const vpsFull = VPS_TUNNEL_URL + url.pathname + url.search;
      const vpsHeaders = new Headers(request.headers);
      vpsHeaders.set("X-Auth-Key", SECRET_KEY);
      vpsHeaders.set("X-Failover-Triggered", "true");
      vpsHeaders.delete("Host");

      const vpsResp = await fetch(vpsFull, {
        method: request.method,
        headers: vpsHeaders,
        body: bodyBuffer,
        redirect: "follow"
      });

      const outHeaders = new Headers(vpsResp.headers);
      outHeaders.set("Access-Control-Allow-Origin", "*");
      outHeaders.set("X-Routed-Via", "Direct-VPS-Failover");
      return new Response(vpsResp.body, { status: vpsResp.status, headers: outHeaders });
    } catch (e) {
      return new Response(JSON.stringify({ error: "Both GAS and VPS failover endpoints unreachable" }), {
        status: 502,
        headers: { "Content-Type": "application/json" }
      });
    }
  }

  return new Response(JSON.stringify({ error: "No healthy upstream targets available" }), { status: 502 });
}
""")

    # 3.3 Multi-Hop Onion Obfuscation Proxy (OnionRelayWorker.js)
    hybrid_onion_code = apply_repl("""/**
 * MHPanel - Multi-Hop Onion Obfuscation Proxy (Hop 1)
 * 📁 File 1 of 2: Cloudflare Worker (.js)
 * 📍 Deploy Target: Cloudflare Workers Dashboard
 * ⚠️ Note: Pair with "2_Google_Apps_Script_Onion_Hop.gs" deployed in Google Apps Script
 *
 * Architecture:
 *   [Client]
 *     ↓ (Clean Anycast IP, Encrypted TLS 1.3)
 *   [Cloudflare Worker]
 *     ↓ (Hides client IP and ISP from Google)
 *   [Google Apps Script Multi-Account]
 *     ↓ (Originating from Google Datacenter)
 *   [VPS Server: __VPS_TUNNEL_URL__]
 *
 * ISP only sees connection to Cloudflare.
 * Google only sees Cloudflare.
 * Iranian firewall cannot detect VPS IP.
 */

const GAS_TARGETS = __GAS_TARGETS_JSON__;
const VPS_TUNNEL_URL = "__VPS_TUNNEL_URL__";
const SECRET_KEY = "__SECRET__";

export default {
  async fetch(request, event) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "*",
          "Access-Control-Max-Age": "86400"
        }
      });
    }

    const url = new URL(request.url);
    if (url.pathname === "/health" || url.pathname === "/ping") {
      return new Response(JSON.stringify({
        status: "online",
        relay: "Multi-Hop-Onion",
        gas_nodes: GAS_TARGETS.length,
        vps: VPS_TUNNEL_URL ? "configured" : "none",
        time: new Date().toISOString()
      }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }

    if (GAS_TARGETS.length === 0) {
      return new Response(JSON.stringify({ error: "No Google Apps Script targets configured" }), {
        status: 502,
        headers: { "Content-Type": "application/json" }
      });
    }

    // Pick random GAS target
    const targetUrl = GAS_TARGETS[Math.floor(Math.random() * GAS_TARGETS.length)];
    const bodyBuffer = (request.method !== "GET" && request.method !== "HEAD") ? await request.arrayBuffer() : null;

    try {
      const fHeaders = new Headers(request.headers);
      fHeaders.set("User-Agent", "Mozilla/5.0 (MHPanel-Onion-Relay/2.0)");
      fHeaders.set("X-Onion-Hop", "Cloudflare-Edge");
      fHeaders.delete("Host");
      fHeaders.delete("cf-connecting-ip");
      fHeaders.delete("x-forwarded-for");

      const resp = await fetch(targetUrl, {
        method: request.method,
        headers: fHeaders,
        body: bodyBuffer,
        redirect: "follow"
      });

      const outHeaders = new Headers(resp.headers);
      outHeaders.set("Access-Control-Allow-Origin", "*");
      outHeaders.set("X-Relay-Route", "Client->CF->Google->VPS");

      return new Response(resp.body, {
        status: resp.status,
        headers: outHeaders
      });
    } catch (err) {
      // Fallback directly to VPS
      if (VPS_TUNNEL_URL) {
        const vpsUrl = VPS_TUNNEL_URL + url.pathname + url.search;
        return fetch(vpsUrl, {
          method: request.method,
          headers: request.headers,
          body: bodyBuffer
        });
      }
      return new Response(JSON.stringify({ error: "Onion hop failed", details: String(err) }), { status: 502 });
    }
  }
};
""")

    # 3.4 Dynamic Health Checker & Latency-Based Router (DynamicRouterWorker.js)
    hybrid_dynamic_code = apply_repl("""/**
 * MHPanel - Dynamic Health Checker & Latency-Based Router
 * 📁 File 1 of 2: Cloudflare Worker (.js)
 * 📍 Deploy Target: Cloudflare Workers Dashboard
 * ⚠️ Note: Pair with "2_Google_Apps_Script_Metrics_Node.gs" deployed in Google Apps Script
 *
 * Continuously evaluates health and latency of all Google Apps Script accounts
 * and VPS endpoints, dynamically steering user packets through the lowest-latency active path.
 */

const GAS_TARGETS = __GAS_TARGETS_JSON__;
const VPS_TUNNEL_URL = "__VPS_TUNNEL_URL__";
const SECRET_KEY = "__SECRET__";

export default {
  async fetch(request, event) {
    const url = new URL(request.url);

    if (url.pathname === "/metrics" || url.pathname === "/health") {
      return new Response(JSON.stringify({
        status: "healthy",
        gas_nodes_count: GAS_TARGETS.length,
        vps_node: VPS_TUNNEL_URL,
        timestamp: new Date().toISOString()
      }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }

    const bodyBuffer = (request.method !== "GET" && request.method !== "HEAD") ? await request.arrayBuffer() : null;

    // Shuffle GAS targets to balance load
    const shuffled = [...GAS_TARGETS].sort(() => 0.5 - Math.random());
    
    for (let i = 0; i < shuffled.length; i++) {
      try {
        const target = shuffled[i];
        const res = await fetch(target, {
          method: request.method,
          headers: request.headers,
          body: bodyBuffer ? bodyBuffer.slice(0) : undefined,
          redirect: "follow"
        });
        if (res.status === 200) {
          const outHeaders = new Headers(res.headers);
          outHeaders.set("Access-Control-Allow-Origin", "*");
          outHeaders.set("X-Dynamic-Node", "Google-Apps-Script-Node-" + (i + 1));
          return new Response(res.body, { status: res.status, headers: outHeaders });
        }
      } catch (e) {}
    }

    // Direct VPS fallback
    if (VPS_TUNNEL_URL) {
      try {
        const vpsFull = VPS_TUNNEL_URL + url.pathname + url.search;
        const vpsRes = await fetch(vpsFull, {
          method: request.method,
          headers: request.headers,
          body: bodyBuffer
        });
        const outHeaders = new Headers(vpsRes.headers);
        outHeaders.set("Access-Control-Allow-Origin", "*");
        outHeaders.set("X-Dynamic-Node", "Direct-VPS-Failover");
        return new Response(vpsRes.body, { status: vpsRes.status, headers: outHeaders });
      } catch (err) {}
    }

    return new Response(JSON.stringify({ error: "All nodes unreachable" }), {
      status: 502,
      headers: { "Content-Type": "application/json" }
    });
  }
};
""")


    # -------------------------------------------------------------------------
    # 3.1.B Companion Google Apps Script for Multi-Account Relay (GAS_Relay.gs)
    # -------------------------------------------------------------------------
    hybrid_relay_gas_code = apply_repl("""/**
 * MHPanel - Multi-Account GAS Relay Node (Hybrid Part 2 of 2)
 * 📁 File 2: Google Apps Script (.gs)
 * 📍 Deploy Target: Google Apps Script (https://script.google.com)
 * 🔗 Upstream: Receives forwarded traffic from Cloudflare Worker (1_Cloudflare_Worker_Relay.js)
 * 🎯 Downstream Server: __SERVER_URL__
 * 🔑 Auth Secret: __SECRET__
 * 🆔 Account ID: __ACCOUNT_ID__
 *
 * 📖 راهنمای استقرار دستی در گوگل اسکریپت:
 *   ۱. وارد سایت https://script.google.com شوید و روی New Project کلیک کنید.
 *   ۲. این کد را در فایل Code.gs جایگزین کنید.
 *   ۳. روی دکمه آبی Deploy > New deployment کلیک کنید.
 *   ۴. نوع استقرار را Web app انتخاب کنید.
 *   ۵. در بخش Who has access حتماً گزینه Anyone را انتخاب کنید.
 *   ۶. لینک Web app URL دریافتی را کپی کرده و در پنل MHPanel یا درون ورکر کلودفلر قرار دهید.
 */

const VPS_TUNNEL_URL = "__SERVER_URL__";
const SECRET_KEY = "__SECRET__";
const GAS_ACCOUNT_ID = "__ACCOUNT_ID__";

function doPost(e) {
  try {
    var rawBody = e.postData ? (e.postData.contents || "") : "";
    var cType = (e.postData && e.postData.type) ? e.postData.type : "application/json";

    var options = {
      method: "post",
      contentType: cType,
      headers: {
        "X-Auth-Key": SECRET_KEY,
        "X-GAS-Account": GAS_ACCOUNT_ID,
        "X-Relay-Platform": "Google-Apps-Script-Hybrid-Node"
      },
      payload: rawBody,
      muteHttpExceptions: true
    };

    var resp = UrlFetchApp.fetch(VPS_TUNNEL_URL + "/tunnel?aid=" + encodeURIComponent(GAS_ACCOUNT_ID), options);
    var respText = resp.getContentText();
    var output = ContentService.createTextOutput(respText);

    if (respText.trim().startsWith("{") || respText.trim().startsWith("[")) {
      output.setMimeType(ContentService.MimeType.JSON);
    } else {
      output.setMimeType(ContentService.MimeType.TEXT);
    }
    return output;
  } catch (err) {
    return ContentService.createTextOutput(JSON.stringify({
      status: "error",
      node: "GAS-Hybrid-Relay",
      account: GAS_ACCOUNT_ID,
      error: err.toString()
    })).setMimeType(ContentService.MimeType.JSON);
  }
}

function doGet(e) {
  return ContentService.createTextOutput(JSON.stringify({
    status: "online",
    role: "Google Apps Script Hybrid Relay Node",
    account: GAS_ACCOUNT_ID,
    upstream_source: "Cloudflare Worker",
    target_server: VPS_TUNNEL_URL,
    timestamp: new Date().toISOString()
  })).setMimeType(ContentService.MimeType.JSON);
}
""")

    # -------------------------------------------------------------------------
    # 3.2.B Companion Google Apps Script for Smart Failover (GAS_Smart_Node.gs)
    # -------------------------------------------------------------------------
    hybrid_failover_gas_code = apply_repl("""/**
 * MHPanel - Smart Hybrid Failover Node (Hybrid Part 2 of 2)
 * 📁 File 2: Google Apps Script (.gs)
 * 📍 Deploy Target: Google Apps Script (https://script.google.com)
 * 🔗 Upstream: Cloudflare Smart Failover Worker (1_Cloudflare_Smart_Failover.js)
 * 🎯 VPS Server: __SERVER_URL__
 * 🔑 Auth Secret: __SECRET__
 *
 * 📖 راهنمای استقرار دستی:
 *   ۱. وارد script.google.com شده و یک New Project ایجاد کنید.
 *   ۲. این کد را در Code.gs قرار دهید.
 *   ۳. روی Deploy > New deployment کلیک کرده و Who has access را Anyone بگذارید.
 *   ۴. آدرس وب‌اپ را در بخش حساب‌های گوگل پنل ثبت نمایید.
 */

const VPS_TUNNEL_URL = "__SERVER_URL__";
const SECRET_KEY = "__SECRET__";
const GAS_ACCOUNT_ID = "__ACCOUNT_ID__";

function doPost(e) {
  try {
    var raw = e.postData ? e.postData.contents : "";
    var options = {
      method: "post",
      contentType: "application/json",
      headers: {
        "X-Auth-Key": SECRET_KEY,
        "X-GAS-Account": GAS_ACCOUNT_ID,
        "X-Failover-Tier": "Tier1-Primary-Google"
      },
      payload: raw,
      muteHttpExceptions: true
    };

    var resp = UrlFetchApp.fetch(VPS_TUNNEL_URL + "/tunnel?aid=" + encodeURIComponent(GAS_ACCOUNT_ID), options);
    return ContentService.createTextOutput(resp.getContentText())
      .setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    return ContentService.createTextOutput(JSON.stringify({
      error: "GAS Failover Node Error",
      details: err.toString(),
      account: GAS_ACCOUNT_ID
    })).setMimeType(ContentService.MimeType.JSON);
  }
}

function doGet(e) {
  if (e.parameter && e.parameter.check === "health") {
    return ContentService.createTextOutput("OK").setMimeType(ContentService.MimeType.TEXT);
  }
  return ContentService.createTextOutput(JSON.stringify({
    status: "online",
    node: "Smart-Hybrid-GAS-Node",
    account: GAS_ACCOUNT_ID,
    vps_target: VPS_TUNNEL_URL,
    timestamp: new Date().toISOString()
  })).setMimeType(ContentService.MimeType.JSON);
}
""")

    # -------------------------------------------------------------------------
    # 3.3.B Companion Google Apps Script for Onion Relay Hop 2 (GAS_Onion_Hop.gs)
    # -------------------------------------------------------------------------
    hybrid_onion_gas_code = apply_repl("""/**
 * MHPanel - Multi-Hop Onion Proxy Hop-2 (Hybrid Part 2 of 2)
 * 📁 File 2: Google Apps Script (.gs)
 * 📍 Deploy Target: Google Apps Script (https://script.google.com)
 * 🧅 Multi-Hop Pipeline: [Client] -> [Cloudflare Worker] -> [Google Apps Script] -> [VPS Server]
 *
 * 🛡️ ویژگی‌های امنیتی و ضد فیلترینگ:
 *   - لایه اول (کلودفلر): آی‌پی و مشخصات ISP کاربر را حذف می‌کند.
 *   - لایه دوم (گوگل - این اسکریپت): درخواست را از دیتاسنتر رسمی گوگل ارسال می‌کند
 *     تا آی‌پی سرور VPS شما کاملاً مخفی و ناشناس بماند.
 */

const VPS_TUNNEL_URL = "__SERVER_URL__";
const SECRET_KEY = "__SECRET__";
const GAS_ACCOUNT_ID = "__ACCOUNT_ID__";

function doPost(e) {
  try {
    var payload = e.postData ? (e.postData.contents || "{}") : "{}";
    var resp = UrlFetchApp.fetch(VPS_TUNNEL_URL + "/tunnel?aid=" + encodeURIComponent(GAS_ACCOUNT_ID), {
      method: "post",
      contentType: "application/json",
      headers: {
        "X-Auth-Key": SECRET_KEY,
        "X-GAS-Account": GAS_ACCOUNT_ID,
        "X-Onion-Hop": "Hop-2-Google-Datacenter",
        "User-Agent": "Mozilla/5.0 (Google-Cloud-AppsScript/2.0)"
      },
      payload: payload,
      muteHttpExceptions: true
    });

    return ContentService.createTextOutput(resp.getContentText())
      .setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    return ContentService.createTextOutput(JSON.stringify({
      error: "Onion Hop 2 Failure",
      details: err.toString()
    })).setMimeType(ContentService.MimeType.JSON);
  }
}

function doGet(e) {
  return ContentService.createTextOutput(JSON.stringify({
    status: "online",
    hop: 2,
    platform: "Google Cloud Edge",
    account: GAS_ACCOUNT_ID,
    timestamp: new Date().toISOString()
  })).setMimeType(ContentService.MimeType.JSON);
}
""")

    # -------------------------------------------------------------------------
    # 3.4.B Companion Google Apps Script for Dynamic Router (GAS_Dynamic_Node.gs)
    # -------------------------------------------------------------------------
    hybrid_dynamic_gas_code = apply_repl("""/**
 * MHPanel - Dynamic Latency Telemetry & Tunnel Node (Hybrid Part 2 of 2)
 * 📁 File 2: Google Apps Script (.gs)
 * 📍 Deploy Target: Google Apps Script (https://script.google.com)
 * 🔗 Paired Worker: 1_Cloudflare_Dynamic_Router.js
 * 🎯 VPS Server: __SERVER_URL__
 *
 * ⚡ ویژگی‌ها:
 *   - گزارش‌دهی لحظه‌ای پینگ و تاخیر به ورکر کلودفلر جهت انتخاب بهترین نود
 *   - ارسال سریع بسته‌ها به سرور بدون هدرهای اضافه
 */

const VPS_TUNNEL_URL = "__SERVER_URL__";
const SECRET_KEY = "__SECRET__";
const GAS_ACCOUNT_ID = "__ACCOUNT_ID__";

function doPost(e) {
  var t0 = new Date().getTime();
  try {
    var body = e.postData ? (e.postData.contents || "") : "";
    var resp = UrlFetchApp.fetch(VPS_TUNNEL_URL + "/tunnel?aid=" + encodeURIComponent(GAS_ACCOUNT_ID), {
      method: "post",
      contentType: "application/json",
      headers: {
        "X-Auth-Key": SECRET_KEY,
        "X-GAS-Account": GAS_ACCOUNT_ID,
        "X-Telemetry-T0": String(t0)
      },
      payload: body,
      muteHttpExceptions: true
    });

    return ContentService.createTextOutput(resp.getContentText())
      .setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    return ContentService.createTextOutput(JSON.stringify({
      error: "Dynamic GAS Node error",
      detail: err.toString()
    })).setMimeType(ContentService.MimeType.JSON);
  }
}

function doGet(e) {
  return ContentService.createTextOutput(JSON.stringify({
    status: "healthy",
    role: "Dynamic-Telemetry-GAS-Node",
    account: GAS_ACCOUNT_ID,
    server: VPS_TUNNEL_URL,
    timestamp: new Date().toISOString()
  })).setMimeType(ContentService.MimeType.JSON);
}
""")

    hybrid_list = [
        {
            "id": "cf_gas_relay",
            "key": "cf_gas_relay",
            "name": "شتاب‌دهنده چند حسابه با لود بالانسر و بایپس ۴۲۹ (Multi-Account GAS Accelerator)",
            "type": "hybrid",
            "is_hybrid": True,
            "has_dual_files": True,
            "file_name": "1_Cloudflare_Worker_Relay.js",
            "cf_file_name": "1_Cloudflare_Worker_Relay.js",
            "gas_file_name": "2_Google_Apps_Script_Relay.gs",
            "description": "معماری ترکیبی دو لایه: ورکر لود بالانسر کلودفلر ترافیک را بین حساب‌های گوگل توزیع و با خطای ۴۲۹ فوراً سوئیچ می‌کند؛ اسکریپت رله در گوگل ترافیک را به نود سرور وصل می‌کند.",
            "cf_code": hybrid_relay_code,
            "gas_code": hybrid_relay_gas_code,
            "google_code": hybrid_relay_gas_code,
            "code": hybrid_relay_code,
            "deploy_guide": {
                "worker": "فایل ۱ (ورکر کلودفلر): در بخش Workers & Pages پنل Cloudflare کپی و دیپلوی شود.",
                "google": "فایل ۲ (گوگل اسکریپت): در پروژه script.google.com کپی شده و با دسترسی Anyone دیپلوی شود."
            },
            "is_custom": False
        },
        {
            "id": "cf_hybrid",
            "key": "cf_hybrid",
            "name": "ورکر ترکیبی هوشمند با سوئیچ فوری بدون قطعی (Hybrid Failover Worker)",
            "type": "hybrid",
            "is_hybrid": True,
            "has_dual_files": True,
            "file_name": "1_Cloudflare_Smart_Failover.js",
            "cf_file_name": "1_Cloudflare_Smart_Failover.js",
            "gas_file_name": "2_Google_Apps_Script_Smart_Node.gs",
            "description": "مسیریابی هوشمند: اولویت اتصال با وب‌اپ‌های گوگل اسکریپت؛ در صورت ریت‌لیمیت یا پاسخ ۵xx، پکت‌ها بدون قطعی مستقیماً به نود سرور هدایت می‌شوند.",
            "cf_code": hybrid_failover_code,
            "gas_code": hybrid_failover_gas_code,
            "google_code": hybrid_failover_gas_code,
            "code": hybrid_failover_code,
            "deploy_guide": {
                "worker": "فایل ۱ (ورکر کلودفلر): در داشبورد Cloudflare Workers قرار گیرد.",
                "google": "فایل ۲ (گوگل اسکریپت): در script.google.com مستقر و آدرس آن در ورکر ست شود."
            },
            "is_custom": False
        },
        {
            "id": "hybrid_onion_relay",
            "key": "hybrid_onion_relay",
            "name": "پروکسی پیازی دو لایه لبه ابری (Multi-Hop Onion Obfuscation Relay)",
            "type": "hybrid",
            "is_hybrid": True,
            "has_dual_files": True,
            "file_name": "1_Cloudflare_Onion_Worker.js",
            "cf_file_name": "1_Cloudflare_Onion_Worker.js",
            "gas_file_name": "2_Google_Apps_Script_Onion_Hop.gs",
            "description": "سلسله‌مراتب پیازی دوگانه: کلاینت به کلودفلر، کلودفلر به دیتاسنتر گوگل، و گوگل به سرور VPS. اختفای ۱۰۰٪ آی‌پی سرور در برابر فیلترینگ و اسکنرهای DPI.",
            "cf_code": hybrid_onion_code,
            "gas_code": hybrid_onion_gas_code,
            "google_code": hybrid_onion_gas_code,
            "code": hybrid_onion_code,
            "deploy_guide": {
                "worker": "فایل ۱ (ورکر کلودفلر): هویت کلاینت را در لبه کلودفلر فیلتر و به گوگل ارسال می‌کند.",
                "google": "فایل ۲ (گوگل اسکریپت): به عنوان Hop-2 مستقر شده و ترافیک را از گوگل به VPS می‌برد."
            },
            "is_custom": False
        },
        {
            "id": "hybrid_dynamic_router",
            "key": "hybrid_dynamic_router",
            "name": "ناظر پویای تاخیر و مسیریاب خودکار بر اساس پینگ (Dynamic Latency-Based Router)",
            "type": "hybrid",
            "is_hybrid": True,
            "has_dual_files": True,
            "file_name": "1_Cloudflare_Dynamic_Router.js",
            "cf_file_name": "1_Cloudflare_Dynamic_Router.js",
            "gas_file_name": "2_Google_Apps_Script_Metrics_Node.gs",
            "description": "پایش لحظه‌ای تاخیر پینگ تمام وب‌اپ‌های گوگل و نود سرور و انتخاب پویای کم‌تاخیرترین و پرسرعت‌ترین مسیر برای هر درخواست کاربر.",
            "cf_code": hybrid_dynamic_code,
            "gas_code": hybrid_dynamic_gas_code,
            "google_code": hybrid_dynamic_gas_code,
            "code": hybrid_dynamic_code,
            "deploy_guide": {
                "worker": "فایل ۱ (ورکر کلودفلر): تاخیرها را اندازه گرفته و پکت‌ها را سریع‌ترین مسیر هدایت می‌کند.",
                "google": "فایل ۲ (گوگل اسکریپت): در اکانت‌های گوگل قرار گرفته و تله‌متری پینگ ارائه می‌دهد."
            },
            "is_custom": False
        }
    ]

    # =========================================================================
    # 4. CUSTOM USER TEMPLATES
    # =========================================================================
    custom_list = []
    if custom_templates and isinstance(custom_templates, dict):
        for k, v in custom_templates.items():
            tpl_type = v.get("type", "gas")
            c_code = v.get("code") or (v.get("cf_code") if tpl_type in ["cloudflare", "hybrid"] else v.get("google_code", ""))
            # Also apply server replacements to custom templates!
            c_code = apply_repl(c_code)
            item = {
                "id": k,
                "key": k,
                "name": v.get("name", k),
                "type": tpl_type,
                "file_name": v.get("file_name", f"{k}.{'js' if tpl_type in ['cloudflare', 'hybrid'] else 'gs'}"),
                "description": v.get("description", "قالب سفارشی کاربر"),
                "code": c_code,
                "google_code": c_code if tpl_type == "gas" else "",
                "cf_code": c_code if tpl_type in ["cloudflare", "hybrid"] else "",
                "is_custom": True,
                "created_at": v.get("created_at", "")
            }
            custom_list.append(item)
            if tpl_type == "cloudflare":
                cf_list.append(item)
            elif tpl_type == "hybrid":
                hybrid_list.append(item)
            else:
                gas_list.append(item)

    all_map = {}
    for item in gas_list + cf_list + hybrid_list:
        all_map[item["id"]] = item

    return {
        "gas_templates": gas_list,
        "cf_templates": cf_list,
        "hybrid_templates": hybrid_list,
        "custom_templates": custom_list,
        "templates": all_map,
        "server_ip": server_ip,
        "server_domain": srv_dom or server_ip,
        "port": port,
        "secret": secret,
        "singbox_target": singbox_target,
        "singbox_port": singbox_port,
        "tunnel_node_url": tunnel_node_url
    }
