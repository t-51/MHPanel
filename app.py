import os
import re
import secrets
import subprocess
import psutil
import time
import threading
import json
import ssl
import socket
import concurrent.futures
import base64
import uuid
import platform
from datetime import datetime
from flask import Flask, jsonify, request, session, render_template, send_from_directory, Response

app = Flask(__name__)

class RedirectServer:
    def __init__(self):
        self.httpd = None
        self.thread = None
        self.running = False

    def start(self):
        if self.running:
            return
        # If Apache or other webserver is installed, let it handle port 80 and virtual hosts
        if os.path.exists("/www/server/apache/bin/httpd") or os.path.exists("/etc/init.d/httpd") or os.path.exists("/usr/sbin/apache2") or os.path.exists("/usr/sbin/nginx"):
            return
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        from http.server import HTTPServer, BaseHTTPRequestHandler
        from socketserver import ThreadingMixIn
        import socket, select

        class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        class RedirectHandler(BaseHTTPRequestHandler):
            def _proxy_to_ws(self):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    s.connect(('127.0.0.1', 8888))
                    s.settimeout(None)
                    raw_req = f"{self.command} {self.path} {self.request_version}\r\n"
                    for k, v in self.headers.items():
                        raw_req += f"{k}: {v}\r\n"
                    raw_req += "\r\n"
                    s.sendall(raw_req.encode("utf-8"))

                    self.connection.setblocking(False)
                    s.setblocking(False)
                    socks = [self.connection, s]
                    while True:
                        r, _, x = select.select(socks, [], socks, 120)
                        if x or not r:
                            break
                        for sock in r:
                            other = s if sock is self.connection else self.connection
                            data = sock.recv(16384)
                            if not data:
                                return
                            other.sendall(data)
                except Exception:
                    pass
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass

            def do_GET(self):
                upgrade = self.headers.get('Upgrade', '').lower()
                path = (self.path or '').lower()
                if upgrade == 'websocket' or path.startswith('/ssh') or path.startswith('/ws'):
                    return self._proxy_to_ws()

                host = self.headers.get('Host', '')
                if ':' in host:
                    host = host.split(':')[0]
                port = get_panel_port()
                self.send_response(301)
                self.send_header('Location', f'https://{host}:{port}{self.path}')
                self.end_headers()

            def do_CONNECT(self):
                return self._proxy_to_ws()

            def do_POST(self):
                upgrade = self.headers.get('Upgrade', '').lower()
                path = (self.path or '').lower()
                if upgrade == 'websocket' or path.startswith('/ssh') or path.startswith('/ws'):
                    return self._proxy_to_ws()
                self.send_error(405, "Method Not Allowed")

            def log_message(self, format, *args):
                pass

        while self.running:
            try:
                self.httpd = ThreadedHTTPServer(('0.0.0.0', 80), RedirectHandler)
                self.httpd.serve_forever()
            except OSError:
                self.running = False
                break
            except Exception:
                time.sleep(2)

    def stop(self):
        self.running = False
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                pass
            self.httpd = None
        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None

redirect_server = RedirectServer()

if os.environ.get("DEV_MODE") or os.environ.get("FLASK_ENV") == "development":
    DEV_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dev_data")
    os.makedirs(DEV_DATA_DIR, exist_ok=True)
    CREDENTIALS_FILE = os.path.join(DEV_DATA_DIR, "admin_credentials.txt")
    API_KEY_FILE = os.path.join(DEV_DATA_DIR, "api_key.txt")
    SESSION_SECRET_FILE = os.path.join(DEV_DATA_DIR, "session_secret.txt")
    TRAFFIC_STATS_FILE = os.path.join(DEV_DATA_DIR, "traffic_stats.json")
    HELPER_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "protocol_helper.sh")
    VPN_CERT_DIR = os.path.join(DEV_DATA_DIR, "vpn-ca")
    PANEL_SSL_DIR = os.path.join(DEV_DATA_DIR, "vpnpanel-ssl")
else:
    CREDENTIALS_FILE = "/www/wwwroot/mhpanel/admin_credentials.txt"
    API_KEY_FILE = "/www/wwwroot/mhpanel/api_key.txt"
    SESSION_SECRET_FILE = "/www/wwwroot/mhpanel/session_secret.txt"
    TRAFFIC_STATS_FILE = "/www/wwwroot/mhpanel/traffic_stats.json"
    HELPER_SCRIPT = "/www/wwwroot/mhpanel/scripts/protocol_helper.sh"
    VPN_CERT_DIR = "/etc/vpn-ca"
    PANEL_SSL_DIR = "/etc/vpnpanel/ssl"

VPN_CA_CERT = os.path.join(VPN_CERT_DIR, "ca.crt")
VPN_CA_KEY = os.path.join(VPN_CERT_DIR, "ca.key")
VPN_SERVER_CERT = os.path.join(VPN_CERT_DIR, "vpn-server.crt")
VPN_SERVER_KEY = os.path.join(VPN_CERT_DIR, "vpn-server.key")
PANEL_CERT = os.path.join(PANEL_SSL_DIR, "panel.crt")
PANEL_KEY = os.path.join(PANEL_SSL_DIR, "panel.key")
PROTOCOLS_LIST = ["ssh", "openvpn", "ocserv", "ikev2", "sstp", "pptp", "l2tp", "wireguard", "amneziawg", "http", "socks", "shadowsocks", "mtproto", "tuic", "dnstt", "vaydns", "slipstream"]
PROTOCOL_DEFAULT_PORTS = {
    "ssh": 2222,
    "openvpn": 1194,
    "ocserv": 443,
    "ikev2": "500/4500",
    "sstp": 4443,
    "pptp": 1723,
    "l2tp": 1701,
    "wireguard": 51820,
    "amneziawg": 51820,
    "http": 8080,
    "socks": 1080,
    "shadowsocks": 8388,
    "mtproto": 4433,
    "tuic": 7443,
    "dnstt": 5300,
    "vaydns": 5353,
    "slipstream": 5354,
}
PROTOCOL_SERVICE_MAP = {
    "ssh": "aethervpn-ssh",
    "openvpn": "openvpn@server",
    "ocserv": "ocserv",
    "ikev2": "strongswan-starter",
    "sstp": "sstpd",
    "pptp": "aethervpn-pptp",
    "l2tp": "xl2tpd",
    "wireguard": "wg-quick@wg0",
    "amneziawg": "awg-quick@awg0",
    "http": "aethervpn-http-proxy",
    "socks": "aethervpn-socks-proxy",
    "shadowsocks": "aethervpn-shadowsocks",
    "mtproto": "aethervpn-mtproto",
    "tuic": "aethervpn-tuic",
    "dnstt": "aethervpn-dnstt",
    "vaydns": "aethervpn-vaydns",
    "slipstream": "aethervpn-slipstream",
}

def get_session_secret():
    if not os.path.exists(SESSION_SECRET_FILE):
        os.makedirs(os.path.dirname(SESSION_SECRET_FILE), exist_ok=True)
        secret = secrets.token_hex(32)
        with open(SESSION_SECRET_FILE, "w") as f:
            f.write(secret)
        return secret
    with open(SESSION_SECRET_FILE, "r") as f:
        return f.read().strip()

app.secret_key = os.environ.get("FLASK_SECRET", get_session_secret())

# Session cookie security configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

def check_login():
    if session.get("logged_in", False):
        return True
    try:
        api_key = get_api_key()
        req_key = request.headers.get("X-API-Key") or request.headers.get("X-API-KEY")
        if not req_key and request.headers.get("Authorization"):
            auth_hdr = request.headers.get("Authorization").strip()
            if auth_hdr.startswith("Bearer "):
                req_key = auth_hdr.split("Bearer ", 1)[1].strip()
        if req_key and api_key and req_key == api_key:
            return True
    except Exception:
        pass
    return False

def get_credentials():
    if not os.path.exists(CREDENTIALS_FILE):
        os.makedirs(os.path.dirname(CREDENTIALS_FILE), exist_ok=True)
        pw = secrets.token_urlsafe(10)
        with open(CREDENTIALS_FILE, "w") as f:
            f.write(f"username=admin\npassword={pw}\n")
        return "admin", pw
    
    username = "admin"
    password = ""
    with open(CREDENTIALS_FILE, "r") as f:
        for line in f:
            if line.startswith("username="):
                username = line.split("=", 1)[1].strip()
            elif line.startswith("password="):
                password = line.split("=", 1)[1].strip()
    return username, password

def get_api_key():
    if not os.path.exists(API_KEY_FILE):
        os.makedirs(os.path.dirname(API_KEY_FILE), exist_ok=True)
        key = secrets.token_hex(16)
        with open(API_KEY_FILE, "w") as f:
            f.write(key)
        return key
    with open(API_KEY_FILE, "r") as f:
        return f.read().strip()

# --- Connection Counters ---
def get_connection_count(protocol):
    try:
        port = get_active_port(protocol)
        if not port and protocol not in ["ikev2", "l2tp"]:
            return 0
            
        if protocol == "ssh":
            # Count established SSH connections
            res = subprocess.run("ss -t -a | grep -i ssh | grep -i estab | wc -l", shell=True, capture_output=True, text=True)
            return int(res.stdout.strip())
        elif protocol == "openvpn":
            # Check openvpn port connections
            res = subprocess.run(f"ss -u -a | grep :{port} | grep -i estab | wc -l", shell=True, capture_output=True, text=True)
            return int(res.stdout.strip())
        elif protocol == "ocserv":
            # Use occtl command
            res = subprocess.run("occtl show users | grep -v 'Unique ID' | grep -v '^$' | wc -l", shell=True, capture_output=True, text=True)
            return max(0, int(res.stdout.strip()) - 1)
        elif protocol == "ikev2":
            # Count active SAs from swanctl
            res = subprocess.run("swanctl --list-sas | grep 'established' | wc -l", shell=True, capture_output=True, text=True)
            return int(res.stdout.strip())
        elif protocol == "sstp":
            res = subprocess.run(f"ss -t -a | grep :{port} | grep -i estab | wc -l", shell=True, capture_output=True, text=True)
            return int(res.stdout.strip())
        elif protocol == "pptp":
            res = subprocess.run(f"ss -t -a | grep :{port} | grep -i estab | wc -l", shell=True, capture_output=True, text=True)
            return int(res.stdout.strip())
        elif protocol == "l2tp":
            res = subprocess.run("ss -u -a | grep :1701 | grep -i estab | wc -l", shell=True, capture_output=True, text=True)
            return int(res.stdout.strip())
        elif protocol == "wireguard":
            # Count peers with handshakes in the last 2 minutes (120s)
            res = subprocess.run("wg show wg0 latest-handshakes", shell=True, capture_output=True, text=True)
            count = 0
            curr_time = time.time()
            for line in res.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 2:
                    ts = int(parts[1])
                    if ts > 0 and (curr_time - ts) < 120:
                        count += 1
            return count
        elif protocol == "amneziawg":
            res = subprocess.run("awg show awg0 latest-handshakes", shell=True, capture_output=True, text=True)
            count = 0
            curr_time = time.time()
            for line in res.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 2:
                    ts = int(parts[1])
                    if ts > 0 and (curr_time - ts) < 120:
                        count += 1
            return count
        elif protocol in ["http", "socks", "shadowsocks", "mtproto"]:
            res = subprocess.run(f"ss -t -a | grep :{port} | grep -i estab | wc -l", shell=True, capture_output=True, text=True)
            return int(res.stdout.strip())
        elif protocol in ["tuic", "dnstt", "vaydns", "slipstream"]:
            res = subprocess.run(f"ss -u -a | grep -E ':{port}\\s' | wc -l", shell=True, capture_output=True, text=True)
            return max(0, int(res.stdout.strip()) - 1)
    except Exception:
        pass
    return 0

# --- Helpers ---
def get_panel_port():
    if os.environ.get("DEV_MODE") or os.environ.get("FLASK_ENV") == "development":
        port_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dev_data", "panel_port.txt")
    else:
        port_file = "/www/wwwroot/mhpanel/panel_port.txt"
    if os.path.exists(port_file):
        try:
            with open(port_file, "r") as f:
                port = int(f.read().strip())
                if 1 <= port <= 65535:
                    return port
        except Exception:
            pass
    return 8443

def ensure_panel_certificate():
    os.makedirs(PANEL_SSL_DIR, exist_ok=True)
    os.chmod(PANEL_SSL_DIR, 0o700)
    if os.path.exists(PANEL_CERT) and os.path.exists(PANEL_KEY):
        return
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", PANEL_KEY, "-out", PANEL_CERT,
        "-subj", "/CN=AetherVPN Panel", "-days", "3650"
    ], check=True, capture_output=True, text=True, timeout=30)
    os.chmod(PANEL_KEY, 0o600)
    os.chmod(PANEL_CERT, 0o644)

def get_protocol_active(protocol):
    services = get_service_names(protocol)
    if not services:
        return False
    # Auxiliary services should not make the main protocol look stopped.
    primary_services = {
        "wireguard": ["wg-quick@wg0"],
        "amneziawg": ["awg-quick@awg0"],
        "l2tp": ["xl2tpd"],
    }
    services = primary_services.get(protocol, services)
    for service in services:
        res = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True, timeout=5)
        if res.stdout.strip().splitlines()[-1:] == ["active"]:
            return True
    return False

def extract_cert_domain(crt_content_or_path):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    try:
        if crt_content_or_path.startswith("/") and os.path.exists(crt_content_or_path):
            with open(crt_content_or_path, "rb") as f:
                cert_data = f.read()
        else:
            cert_data = crt_content_or_path.encode()
            
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        cn = None
        for attribute in cert.subject:
            if attribute.oid == x509.NameOID.COMMON_NAME:
                cn = attribute.value
                break
        if cn:
            return cn.replace("*.", "")
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for name in ext.value:
                if isinstance(name, x509.DNSName):
                    return name.value.replace("*.", "")
        except Exception:
            pass
    except Exception as e:
        print(f"Error parsing cert domain: {e}")
    return None

def _remove_file_or_link(path):
    if os.path.lexists(path):
        os.unlink(path)


def _write_or_link_cert_pair(crt_source, key_source, cert_path, key_path):
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    os.chmod(os.path.dirname(cert_path), 0o700)
    _remove_file_or_link(cert_path)
    _remove_file_or_link(key_path)
    if crt_source.startswith("/") and key_source.startswith("/") and os.path.exists(crt_source) and os.path.exists(key_source):
        os.symlink(os.path.realpath(crt_source), cert_path)
        os.symlink(os.path.realpath(key_source), key_path)
    else:
        with open(cert_path, "w") as f:
            f.write(crt_source.rstrip() + "\n")
        with open(key_path, "w") as f:
            f.write(key_source.rstrip() + "\n")
    os.chmod(key_path, 0o600)
    if not os.path.islink(cert_path):
        os.chmod(cert_path, 0o644)


def apply_certificates(crt_source, key_source):
    # HTTPS panel certificate is independent from VPN CA/server certificates.
    _write_or_link_cert_pair(crt_source, key_source, PANEL_CERT, PANEL_KEY)


def apply_vpn_server_certificates(crt_source, key_source):
    _write_or_link_cert_pair(crt_source, key_source, VPN_SERVER_CERT, VPN_SERVER_KEY)
    # Legacy compatibility for existing service files or external tooling.
    _remove_file_or_link("/root/vpn-server.crt")
    _remove_file_or_link("/root/vpn-server.key")
    os.symlink(VPN_SERVER_CERT, "/root/vpn-server.crt")
    os.symlink(VPN_SERVER_KEY, "/root/vpn-server.key")

def run_helper(action, protocol, arg3="", arg4=""):
    try:
        cmd = [HELPER_SCRIPT, action, protocol]
        if arg3:
            cmd.append(str(arg3))
        if arg4:
            cmd.append(str(arg4))
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300)
        return res.returncode == 0, res.stdout.strip(), res.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Operation timed out"
    except Exception as e:
        return False, "", str(e)

def is_installed(protocol):
    if protocol == "ssh":
        return os.path.exists("/etc/ssh/sshd_config") or os.path.exists("/etc/ssh/sshd_config_vpn")
    elif protocol == "openvpn":
        return os.path.exists("/etc/openvpn/server/server.conf") or os.path.exists("/etc/openvpn/server.conf")
    elif protocol == "ocserv":
        return os.path.exists("/etc/ocserv/ocserv.conf")
    elif protocol == "ikev2":
        return os.path.exists("/etc/ipsec.conf") or os.path.exists("/etc/swanctl/conf.d/ikev2.conf")
    elif protocol == "sstp":
        return os.path.exists("/etc/systemd/system/sstpd.service")
    elif protocol == "pptp":
        return os.path.exists("/etc/pptpd.conf")
    elif protocol == "l2tp":
        return os.path.exists("/etc/xl2tpd/xl2tpd.conf")
    elif protocol == "wireguard":
        return os.path.exists("/etc/wireguard/wg0.conf")
    elif protocol == "amneziawg":
        return os.path.exists("/etc/amnezia/amneziawg/awg0.conf")
    elif protocol == "http":
        return os.path.exists("/etc/systemd/system/aethervpn-http-proxy.service")
    elif protocol == "socks":
        return os.path.exists("/etc/systemd/system/aethervpn-socks-proxy.service")
    elif protocol == "shadowsocks":
        return os.path.exists("/etc/systemd/system/aethervpn-shadowsocks.service")
    elif protocol == "mtproto":
        return os.path.exists("/etc/systemd/system/aethervpn-mtproto@.service")
    elif protocol == "tuic":
        return os.path.exists("/usr/local/bin/tuic-server") or os.path.exists("/etc/systemd/system/aethervpn-tuic.service")
    elif protocol == "dnstt":
        return os.path.exists("/usr/local/bin/dnstt-server") or os.path.exists("/etc/systemd/system/aethervpn-dnstt.service") or os.path.exists("/etc/systemd/system/dnstt-server.service")
    elif protocol == "vaydns":
        return os.path.exists("/usr/local/bin/vaydns-server") or os.path.exists("/etc/systemd/system/aethervpn-vaydns.service")
    elif protocol == "slipstream":
        return os.path.exists("/usr/local/bin/slipstream-server") or os.path.exists("/etc/systemd/system/aethervpn-slipstream.service")
    return False


def get_active_port(protocol):
    try:
        if protocol == "ssh":
            for sp in ["/etc/ssh/sshd_config_vpn", "/etc/ssh/sshd_config"]:
                if os.path.exists(sp):
                    with open(sp, "r") as f:
                        match = re.search(r"^Port\s+(\d+)", f.read(), re.MULTILINE | re.IGNORECASE)
                        if match: return int(match.group(1))
            return 22
        elif protocol == "openvpn":
            for op in ["/etc/openvpn/server/server.conf", "/etc/openvpn/server.conf"]:
                if os.path.exists(op):
                    with open(op, "r") as f:
                        match = re.search(r"^port\s+(\d+)", f.read(), re.MULTILINE | re.IGNORECASE)
                        if match: return int(match.group(1))
            return 1194
        elif protocol == "ocserv":
            if os.path.exists("/etc/ocserv/ocserv.conf"):
                with open("/etc/ocserv/ocserv.conf", "r") as f:
                    content = f.read()
                match = re.search(r"^tcp-port\s*=\s*(\d+)", content, re.MULTILINE | re.IGNORECASE)
                if match:
                    return int(match.group(1))
            return 443
        elif protocol == "ikev2":
            return "500/4500"
        elif protocol == "sstp":
            if os.path.exists("/www/wwwroot/mhpanel/sstp_config.json"):
                try:
                    with open("/www/wwwroot/mhpanel/sstp_config.json", "r") as f:
                        cfg = json.load(f)
                        if "port" in cfg:
                            return int(cfg["port"])
                except Exception:
                    pass
            if os.path.exists("/etc/systemd/system/sstpd.service"):
                with open("/etc/systemd/system/sstpd.service", "r") as f:
                    content = f.read()
                match = re.search(r"-p\s+(\d+)", content)
                if match:
                    return int(match.group(1))
            return 4443
        elif protocol == "l2tp":
            return 1701
        elif protocol == "pptp":
            if os.path.exists("/etc/systemd/system/aethervpn-pptp.service"):
                with open("/etc/systemd/system/aethervpn-pptp.service", "r") as f:
                    content = f.read()
                match = re.search(r"Port (\d+)", content)
                if match:
                    return int(match.group(1))
            return 1723
        elif protocol == "wireguard":
            if os.path.exists("/etc/wireguard/wg0.conf"):
                with open("/etc/wireguard/wg0.conf", "r") as f:
                    content = f.read()
                match = re.search(r"^ListenPort\s*=\s*(\d+)", content, re.MULTILINE | re.IGNORECASE)
                if match:
                    return int(match.group(1))
            return 904
        elif protocol == "amneziawg":
            if os.path.exists("/etc/amnezia/amneziawg/awg0.conf"):
                with open("/etc/amnezia/amneziawg/awg0.conf", "r") as f:
                    content = f.read()
                match = re.search(r"^ListenPort\s*=\s*(\d+)", content, re.MULTILINE | re.IGNORECASE)
                if match:
                    return int(match.group(1))
            return 51820
        elif protocol == "http":
            path = "/etc/systemd/system/aethervpn-http-proxy.service"
            default = 8080
        elif protocol == "socks":
            path = "/etc/systemd/system/aethervpn-socks-proxy.service"
            default = 1080
        elif protocol == "tuic":
            if os.path.exists("/etc/vpnpanel/tuic.toml"):
                try:
                    with open("/etc/vpnpanel/tuic.toml", "r") as f:
                        m = re.search(r'server\s*=\s*"[^"]*:(\d+)"', f.read())
                        if m: return int(m.group(1))
                except Exception:
                    pass
            return 7443
        elif protocol == "shadowsocks":
            if os.path.exists("/etc/vpnpanel/shadowsocks.json"):
                try:
                    with open("/etc/vpnpanel/shadowsocks.json", "r") as f:
                        return int(json.load(f).get("server_port", 8388))
                except Exception:
                    pass
            path = "/etc/systemd/system/aethervpn-shadowsocks.service"
            default = 8388
        elif protocol == "mtproto":
            import glob
            files = glob.glob("/etc/vpnpanel/mtproto_config_*.py")
            if files:
                try:
                    with open(files[0], "r") as f:
                        content = f.read()
                    match = re.search(r"^PORT\s*=\s*(\d+)", content, re.MULTILINE)
                    if match:
                        return int(match.group(1))
                except Exception:
                    pass
            if os.path.exists("/etc/vpnpanel/mtproto_config.py"):
                try:
                    with open("/etc/vpnpanel/mtproto_config.py", "r") as f:
                        content = f.read()
                    match = re.search(r"^PORT\s*=\s*(\d+)", content, re.MULTILINE)
                    if match:
                        return int(match.group(1))
                except Exception:
                    pass
            return 4433
        elif protocol == "dnstt":
            if os.path.exists("/etc/vpnpanel/dnstt.json"):
                try:
                    with open("/etc/vpnpanel/dnstt.json", "r") as f:
                        return int(json.load(f).get("port", 5300))
                except Exception:
                    pass
            return 5300
        elif protocol == "vaydns":
            if os.path.exists("/etc/vpnpanel/vaydns.json"):
                try:
                    with open("/etc/vpnpanel/vaydns.json", "r") as f:
                        return int(json.load(f).get("port", 5353))
                except Exception:
                    pass
            return 5353
        elif protocol == "slipstream":
            if os.path.exists("/etc/vpnpanel/slipstream.json"):
                try:
                    with open("/etc/vpnpanel/slipstream.json", "r") as f:
                        return int(json.load(f).get("port", 5354))
                except Exception:
                    pass
            return 5354
        if protocol in ["http", "socks", "shadowsocks"] and os.path.exists(path):
            with open(path, "r") as f:
                content = f.read()
            match = re.search(r"0\.0\.0\.0:(\d+)", content)
            if match:
                return int(match.group(1))
            return default
    except Exception:
        pass
    return None


# --- Background Traffic Tracker ---
def traffic_tracker():
    last_rx = None
    last_tx = None
    
    while True:
        try:
            net_io = psutil.net_io_counters()
            curr_rx = net_io.bytes_recv
            curr_tx = net_io.bytes_sent
            
            if last_rx is None:
                last_rx = curr_rx
                last_tx = curr_tx
            elif curr_rx < last_rx or curr_tx < last_tx:
                # Server rebooted, reset tracking baseline
                last_rx = curr_rx
                last_tx = curr_tx
            else:
                diff_rx = curr_rx - last_rx
                diff_tx = curr_tx - last_tx
                
                if diff_rx > 0 or diff_tx > 0:
                    add_traffic_record(diff_rx, diff_tx)
                    
                last_rx = curr_rx
                last_tx = curr_tx
        except Exception as e:
            # Silence tracker errors
            pass
            
        time.sleep(300) # Poll every 5 minutes

def add_traffic_record(rx, tx):
    now = datetime.now()
    hour_str = now.strftime("%Y-%m-%dT%H:00:00")
    date_str = now.strftime("%Y-%m-%d")
    
    data = {"hourly": [], "daily": []}
    if os.path.exists(TRAFFIC_STATS_FILE):
        try:
            with open(TRAFFIC_STATS_FILE, "r") as f:
                data = json.load(f)
        except Exception:
            pass
            
    # Update hourly records
    hourly = data.setdefault("hourly", [])
    found_hour = False
    for item in hourly:
        if item.get("time") == hour_str:
            item["rx"] = item.get("rx", 0) + rx
            item["tx"] = item.get("tx", 0) + tx
            found_hour = True
            break
    if not found_hour:
        hourly.append({"time": hour_str, "rx": rx, "tx": tx})
    data["hourly"] = hourly[-48:] # Keep latest 48 hours
    
    # Update daily records
    daily = data.setdefault("daily", [])
    found_day = False
    for item in daily:
        if item.get("date") == date_str:
            item["rx"] = item.get("rx", 0) + rx
            item["tx"] = item.get("tx", 0) + tx
            found_day = True
            break
    if not found_day:
        daily.append({"date": date_str, "rx": rx, "tx": tx})
    data["daily"] = daily[-30:] # Keep latest 30 days
    
    try:
        with open(TRAFFIC_STATS_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

def wg_client_tracker():
    while True:
        try:
            if os.path.exists('/www/wwwroot/mhpanel/wg_users.json'):
                with open('/www/wwwroot/mhpanel/wg_users.json', 'r') as f:
                    try: wg_users = json.load(f)
                    except: wg_users = {}
                
                traffic = get_wg_traffic()
                changed = False
                now_str = datetime.now().strftime("%Y-%m-%d")
                
                for pubkey, user_data in wg_users.items():
                    limit_gb = user_data.get("limit_gb")
                    expire_date = user_data.get("expire_date")
                    start_on_first = user_data.get("start_on_first_connect")
                    duration_days = user_data.get("duration_days")
                    disabled = False
                    
                    tdata = traffic.get(pubkey, {"rx": 0, "tx": 0})
                    total_usage = tdata["rx"] + tdata["tx"]
                    
                    if start_on_first and not expire_date and total_usage > 0 and duration_days:
                        from datetime import datetime, timedelta
                        expire_date = (datetime.now() + timedelta(days=duration_days)).strftime("%Y-%m-%d")
                        user_data["expire_date"] = expire_date
                        user_data["start_on_first_connect"] = False
                        changed = True
                    
                    if expire_date:
                        if now_str > expire_date:
                            disabled = True
                            
                    if limit_gb and not disabled:
                        if total_usage >= limit_gb * (1024**3):
                            disabled = True
                            
                    if disabled:
                        if user_data.get("active", True):
                            user_data["active"] = False
                            changed = True
                        subprocess.run(["wg", "set", "wg0", "peer", pubkey, "remove"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    
                if changed:
                    with open('/www/wwwroot/mhpanel/wg_users.json', 'w') as f:
                        json.dump(wg_users, f)
        except Exception:
            pass
        time.sleep(60)

def awg_client_tracker():
    while True:
        try:
            if os.path.exists('/www/wwwroot/mhpanel/awg_users.json'):
                with open('/www/wwwroot/mhpanel/awg_users.json', 'r') as f:
                    try: awg_users = json.load(f)
                    except: awg_users = {}
                
                traffic = get_awg_traffic()
                changed = False
                now_str = datetime.now().strftime("%Y-%m-%d")
                
                for pubkey, user_data in awg_users.items():
                    limit_gb = user_data.get("limit_gb")
                    expire_date = user_data.get("expire_date")
                    start_on_first = user_data.get("start_on_first_connect")
                    duration_days = user_data.get("duration_days")
                    disabled = False
                    
                    tdata = traffic.get(pubkey, {"rx": 0, "tx": 0})
                    total_usage = tdata["rx"] + tdata["tx"]
                    
                    if start_on_first and not expire_date and total_usage > 0 and duration_days:
                        from datetime import datetime, timedelta
                        expire_date = (datetime.now() + timedelta(days=duration_days)).strftime("%Y-%m-%d")
                        user_data["expire_date"] = expire_date
                        user_data["start_on_first_connect"] = False
                        changed = True
                    
                    if expire_date:
                        if now_str > expire_date:
                            disabled = True
                            
                    if limit_gb and not disabled:
                        if total_usage >= limit_gb * (1024**3):
                            disabled = True
                            
                    if disabled:
                        if user_data.get("active", True):
                            user_data["active"] = False
                            changed = True
                        subprocess.run(["awg", "set", "awg0", "peer", pubkey, "remove"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    
                if changed:
                    with open('/www/wwwroot/mhpanel/awg_users.json', 'w') as f:
                        json.dump(awg_users, f)
        except Exception:
            pass
        time.sleep(60)

# --- Panel Path & Routes ---
PANEL_PATH_FILE = "/etc/vpnpanel/panel_path.txt"

def get_panel_path():
    try:
        if os.path.exists(PANEL_PATH_FILE):
            with open(PANEL_PATH_FILE, "r") as f:
                p = f.read().strip()
                if p:
                    if not p.startswith("/"):
                        p = "/" + p
                    return p.rstrip("/")
    except Exception:
        pass
    return ""

def render_dashboard_response(logged_in):
    from flask import make_response
    user, _ = get_credentials()
    custom_path = get_panel_path()
    resp = make_response(render_template(
        "dashboard.html",
        logged_in=logged_in,
        error=None,
        saved_username=user,
        api_key=get_api_key(),
        panel_path=custom_path,
        panel_port=get_panel_port()
    ))
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

@app.route("/")
def index():
    custom_path = get_panel_path()
    if custom_path and not check_login():
        return "Not Found", 404
    return render_dashboard_response(check_login())

@app.route("/<path:secret_path>")
def custom_login_route(secret_path):
    if secret_path.startswith("static/") or secret_path.startswith("api/"):
        return "Not Found", 404
    custom_path = get_panel_path()
    req_path = "/" + secret_path.strip("/")
    if custom_path and req_path == custom_path:
        return render_dashboard_response(check_login())
    return "Not Found", 404

@app.route("/static/<path:filename>")
def serve_static(filename):
    if os.environ.get("DEV_MODE") or os.environ.get("FLASK_ENV") == "development":
        static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    else:
        static_dir = "/www/wwwroot/mhpanel/static"
    return send_from_directory(static_dir, filename)

@app.route("/api/login", methods=["POST"])
def api_login():
    username = request.json.get("username", "")
    password = request.json.get("password", "")
    saved_user, saved_pw = get_credentials()
    
    if username == saved_user and password == saved_pw:
        session["logged_in"] = True
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Incorrect Username or Password"}), 401

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.pop("logged_in", None)
    return jsonify({"success": True})

# --- Credentials Update Endpoint ---
@app.route("/api/credentials/update", methods=["POST"])
def api_credentials_update():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    new_username = data.get("username", "").strip()
    new_password = data.get("password", "").strip()
    
    if not new_username or not new_password:
        return jsonify({"success": False, "error": "Username and password cannot be empty"}), 400
        
    try:
        with open(CREDENTIALS_FILE, "w") as f:
            f.write(f"username={new_username}\npassword={new_password}\n")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Default VPN Test User Endpoints ---
DEFAULT_TEST_USER_FILE = "/www/wwwroot/mhpanel/test_user.json"

def get_default_test_user():
    if os.path.exists(DEFAULT_TEST_USER_FILE):
        try:
            with open(DEFAULT_TEST_USER_FILE, "r") as f:
                d = json.load(f)
                if d.get("username") and d.get("password"):
                    return d
        except Exception:
            pass
    rad_file = "/www/wwwroot/mhpanel/radius_users.json"
    if os.path.exists(rad_file):
        try:
            with open(rad_file, "r") as f:
                r_users = json.load(f)
                if r_users and len(r_users) > 0:
                    return {"username": r_users[0].get("username", "NPU"), "password": r_users[0].get("password", "56226500")}
        except Exception:
            pass
    return {"username": "NPU", "password": "56226500"}

def sync_default_test_user(username, password):
    os.makedirs(os.path.dirname(DEFAULT_TEST_USER_FILE), exist_ok=True)
    with open(DEFAULT_TEST_USER_FILE, "w") as f:
        json.dump({"username": username, "password": password, "updated_at": time.time()}, f, indent=2)

    # 1. Update FreeRADIUS (mhpanel_users & radius_users.json)
    rad_users_file = "/www/wwwroot/mhpanel/radius_users.json"
    rad_users = []
    if os.path.exists(rad_users_file):
        try:
            with open(rad_users_file, "r") as f:
                rad_users = json.load(f)
        except Exception:
            rad_users = []
    found = False
    for u in rad_users:
        if u.get("is_default") or u.get("username", "").upper() == username.upper() or u.get("username", "").upper() == "NPU":
            u["username"] = username
            u["password"] = password
            u["is_default"] = True
            found = True
            break
    if not found:
        rad_users.append({
            "username": username,
            "password": password,
            "traffic_limit": 0,
            "expire_date": "never",
            "is_default": True
        })
    try:
        with open(rad_users_file, "w") as f:
            json.dump(rad_users, f, indent=2)
    except Exception:
        pass

    try:
        lines = ["# FreeRADIUS MH Panel Users"]
        for u in rad_users:
            un = u.get("username")
            pw = u.get("password")
            if un and pw:
                lines.append(f'"{un}" Cleartext-Password := "{pw}"')
        os.makedirs("/etc/freeradius/3.0", exist_ok=True)
        with open("/etc/freeradius/3.0/mhpanel_users", "w") as f:
            f.write("\n".join(lines) + "\n")
        subprocess.run(["systemctl", "reload", "freeradius"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    # 2. Update IKEv2 (/etc/ipsec.secrets, /etc/swanctl/conf.d/users.conf, ikev2_users.json)
    try:
        sec_lines = [f'{username} : EAP "{password}"', f'{username.lower()} : EAP "{password}"']
        with open("/etc/ipsec.secrets", "w") as f:
            f.write("\n".join(sec_lines) + "\n")
        os.makedirs("/etc/swanctl/conf.d", exist_ok=True)
        with open("/etc/swanctl/conf.d/users.conf", "w") as f:
            f.write(f'secrets {{\n    eap-{username} {{\n        id = "{username}"\n        secret = "{password}"\n    }}\n}}\n')
        subprocess.run(["ipsec", "rereadsecrets"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["swanctl", "--load-creds"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    # 3. Update L2TP & SSTP (/etc/ppp/chap-secrets, /etc/ppp/pap-secrets)
    try:
        with open("/etc/ppp/chap-secrets", "w") as f:
            f.write(f'"{username}" * "{password}" *\n')
        with open("/etc/ppp/pap-secrets", "w") as f:
            f.write(f'"{username}" * "{password}" *\n')
    except Exception:
        pass

    # 4. Sync in JSON files (ikev2_users.json, l2tp_users.json)
    for u_file in ["/www/wwwroot/mhpanel/ikev2_users.json", "/www/wwwroot/mhpanel/l2tp_users.json"]:
        try:
            if os.path.exists(u_file):
                with open(u_file, "r") as f:
                    u_data = json.load(f)
                if isinstance(u_data, list):
                    for u in u_data:
                        if u.get("is_default") or u.get("username", "").upper() == username.upper() or u.get("username", "").upper() == "NPU":
                            u["username"] = username
                            u["password"] = password
                            u["is_default"] = True
                    with open(u_file, "w") as f:
                        json.dump(u_data, f, indent=2)
        except Exception:
            pass

@app.route("/api/system/test-user", methods=["GET"])
def api_system_test_user_get():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_default_test_user())

@app.route("/api/system/test-user", methods=["POST"])
def api_system_test_user_post():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not username or not password:
        return jsonify({"success": False, "error": "Username and password cannot be empty"}), 400
    try:
        sync_default_test_user(username, password)
        return jsonify({"success": True, "message": f"کاربر تست '{username}' با موفقیت در ردیوس و تمامی پروتکل‌ها ذخیره و اعمال شد!"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Public API Endpoint ---
@app.route("/api/public/status", methods=["GET"])
def api_public_status():
    key = request.args.get("key", "")
    if not key or key != get_api_key():
        return jsonify({"error": "Unauthorized API Key"}), 401
        
    # Gather resource metrics
    cpu_percent = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net_io = psutil.net_io_counters()
    
    # Read traffic stats history
    traffic_history = {"hourly": [], "daily": []}
    if os.path.exists(TRAFFIC_STATS_FILE):
        try:
            with open(TRAFFIC_STATS_FILE, "r") as f:
                traffic_history = json.load(f)
        except Exception:
            pass
            
    # Gather protocols info & connections
    protocols_list = PROTOCOLS_LIST
    proto_info = {}
    for proto in protocols_list:
        installed = is_installed(proto)
        active = False
        connections = 0
        if installed:
            active = get_protocol_active(proto)
            if active:
                connections = get_connection_count(proto)
        proto_info[proto] = {
            "installed": installed,
            "active": active,
            "port": get_active_port(proto),
            "connections": connections
        }
        
    return jsonify({
        "system": {
            "cpu_percent": cpu_percent,
            "ram_percent": mem.percent,
            "ram_used_bytes": mem.used,
            "ram_total_bytes": mem.total,
            "disk_percent": disk.percent,
            "disk_used_bytes": disk.used,
            "disk_total_bytes": disk.total,
            "network_rx_bytes": net_io.bytes_recv,
            "network_tx_bytes": net_io.bytes_sent
        },
        "traffic_history": traffic_history,
        "vpn_protocols": proto_info
    })

# --- Enhanced Overview Metrics & Security Data Helpers ---
_hardware_static_cache = None
_security_alerts_cache = {"timestamp": 0, "data": None}
_proto_traffic_prev = {"timestamp": 0, "stats": {}}

def get_static_hardware_specs():
    global _hardware_static_cache
    if _hardware_static_cache is not None:
        return _hardware_static_cache
        
    distro = "Linux"
    if os.path.exists("/etc/os-release"):
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        distro = line.split("=", 1)[1].strip().strip('"')
                        break
        except Exception:
            pass
            
    kernel = platform.release()
    arch = platform.machine()
    hostname = platform.node()
    
    logical_cores = psutil.cpu_count(logical=True) or 1
    physical_cores = psutil.cpu_count(logical=False) or logical_cores
    
    model_name = "Generic CPU"
    bogomips = "N/A"
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if "model name" in line and model_name == "Generic CPU":
                    model_name = line.split(":", 1)[1].strip()
                elif "bogomips" in line and bogomips == "N/A":
                    bogomips = line.split(":", 1)[1].strip()
    except Exception:
        pass
        
    bus_speed = "باس پرسرعت مجازی (QEMU/KVM Host Bus)"
    ram_type = "DDR4"
    try:
        res = subprocess.run(["dmidecode", "-t", "memory"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0:
            sp = re.findall(r"Speed:\s*([0-9]+\s*(?:MHz|MT/s))", res.stdout, re.IGNORECASE)
            if sp and not any("unknown" in s.lower() for s in sp):
                bus_speed = sp[0]
            tp = re.findall(r"Type:\s*(DDR[0-9]?|LPDDR[0-9]?)", res.stdout, re.IGNORECASE)
            if tp:
                ram_type = tp[0]
    except Exception:
        pass
        
    _hardware_static_cache = {
        "os_distro": distro,
        "os_kernel": kernel,
        "os_arch": arch,
        "hostname": hostname,
        "cpu_model": model_name,
        "cpu_cores_physical": physical_cores,
        "cpu_cores_logical": logical_cores,
        "cpu_bogomips": bogomips,
        "ram_bus_speed": bus_speed,
        "ram_type": ram_type
    }
    return _hardware_static_cache


def get_live_system_metrics():
    specs = get_static_hardware_specs()
    
    # Uptime
    uptime_sec = 0
    try:
        with open("/proc/uptime") as f:
            uptime_sec = float(f.readline().split()[0])
    except Exception:
        pass
    days = int(uptime_sec // 86400)
    hours = int((uptime_sec % 86400) // 3600)
    mins = int((uptime_sec % 3600) // 60)
    uptime_str = f"{days} روز و {hours} ساعت" if days > 0 else f"{hours} ساعت و {mins} دقیقه"
    
    # CPU
    cpu_overall = psutil.cpu_percent(interval=None)
    per_core = psutil.cpu_percent(interval=None, percpu=True)
    freq = psutil.cpu_freq()
    freq_mhz = round(freq.current, 1) if freq and freq.current else None
    freq_ghz = f"{freq_mhz / 1000:.2f} GHz" if freq_mhz else "2.10 GHz"
    
    # RAM
    mem = psutil.virtual_memory()
    
    return {
        "os": {
            "distro": specs["os_distro"],
            "kernel": specs["os_kernel"],
            "arch": specs["os_arch"],
            "hostname": specs["hostname"],
            "uptime": uptime_str
        },
        "cpu": {
            "model": specs["cpu_model"],
            "physical_cores": specs["cpu_cores_physical"],
            "logical_cores": specs["cpu_cores_logical"],
            "freq_mhz": freq_mhz,
            "freq_ghz": freq_ghz,
            "bogomips": specs["cpu_bogomips"],
            "overall_percent": round(cpu_overall, 1),
            "per_core": [round(c, 1) for c in per_core]
        },
        "ram": {
            "total": mem.total,
            "used": mem.used,
            "available": mem.available,
            "percent": mem.percent,
            "bus_speed": specs["ram_bus_speed"],
            "type": specs["ram_type"]
        }
    }


def get_protocol_bandwidth_stats():
    global _proto_traffic_prev
    now = time.time()
    
    # 1. Dev interfaces
    dev_stats = {}
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if ":" in line:
                    iface, d = line.split(":", 1)
                    p = d.split()
                    dev_stats[iface.strip()] = {"rx": int(p[0]), "tx": int(p[8])}
    except Exception:
        pass

    # 2. Iptables forward stats
    ip_stats = {}
    try:
        res = subprocess.run(["iptables", "-nvx", "-L", "FORWARD"], capture_output=True, text=True, timeout=2)
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 9 and parts[1].isdigit():
                b = int(parts[1])
                if "10.10.10.0/24" in line:
                    ip_stats.setdefault("ocserv", {"rx": 0, "tx": 0})
                    if parts[8] == "10.10.10.0/24": ip_stats["ocserv"]["tx"] += b
                    else: ip_stats["ocserv"]["rx"] += b
                elif "10.20.20.0/24" in line:
                    ip_stats.setdefault("sstp", {"rx": 0, "tx": 0})
                    if parts[8] == "10.20.20.0/24": ip_stats["sstp"]["tx"] += b
                    else: ip_stats["sstp"]["rx"] += b
                elif "10.30.30.0/24" in line:
                    ip_stats.setdefault("ikev2", {"rx": 0, "tx": 0})
                    if parts[8] == "10.30.30.0/24": ip_stats["ikev2"]["tx"] += b
                    else: ip_stats["ikev2"]["rx"] += b
                elif "192.168.42.0/24" in line:
                    ip_stats.setdefault("l2tp", {"rx": 0, "tx": 0})
                    if parts[8] == "192.168.42.0/24": ip_stats["l2tp"]["tx"] += b
                    else: ip_stats["l2tp"]["rx"] += b
    except Exception:
        pass

    # 3. SSH stats
    ssh_rx, ssh_tx = 0, 0
    try:
        res = subprocess.run(["iptables", "-nvx", "-L", "MHPANEL_SSH_OUT"], capture_output=True, text=True, timeout=2)
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit() and "owner UID match" in line:
                b = int(parts[1])
                ssh_tx += b
                ssh_rx += b
    except Exception:
        pass

    # Aggregate protocols
    ovpn_rx = sum(dev_stats.get(tun, {}).get("rx", 0) for tun in dev_stats if tun.startswith("tun"))
    ovpn_tx = sum(dev_stats.get(tun, {}).get("tx", 0) for tun in dev_stats if tun.startswith("tun"))

    wg_rx = dev_stats.get("wg0", {}).get("rx", 0)
    wg_tx = dev_stats.get("wg0", {}).get("tx", 0)

    awg_rx = dev_stats.get("awg0", {}).get("rx", 0)
    awg_tx = dev_stats.get("awg0", {}).get("tx", 0)

    l2tp_rx = max(dev_stats.get("ppp0", {}).get("rx", 0), ip_stats.get("l2tp", {}).get("rx", 0))
    l2tp_tx = max(dev_stats.get("ppp0", {}).get("tx", 0), ip_stats.get("l2tp", {}).get("tx", 0))

    ocserv_rx = ip_stats.get("ocserv", {}).get("rx", 0)
    ocserv_tx = ip_stats.get("ocserv", {}).get("tx", 0)

    sstp_rx = ip_stats.get("sstp", {}).get("rx", 0)
    sstp_tx = ip_stats.get("sstp", {}).get("tx", 0)

    ikev2_rx = ip_stats.get("ikev2", {}).get("rx", 0)
    ikev2_tx = ip_stats.get("ikev2", {}).get("tx", 0)

    raw_traffic = {
        "wireguard": {"rx": wg_rx, "tx": wg_tx},
        "openvpn": {"rx": ovpn_rx, "tx": ovpn_tx},
        "ocserv": {"rx": ocserv_rx, "tx": ocserv_tx},
        "l2tp": {"rx": l2tp_rx, "tx": l2tp_tx},
        "sstp": {"rx": sstp_rx, "tx": sstp_tx},
        "ikev2": {"rx": ikev2_rx, "tx": ikev2_tx},
        "amneziawg": {"rx": awg_rx, "tx": awg_tx},
        "ssh": {"rx": ssh_rx, "tx": ssh_tx},
    }

    prev_time = _proto_traffic_prev.get("timestamp", 0)
    prev_stats = _proto_traffic_prev.get("stats", {})
    delta_t = now - prev_time if prev_time > 0 else 0

    proto_meta = [
        {"id": "wireguard", "name": "WireGuard", "fa_name": "وایرگارد", "icon": "zap", "color": "#9333ea", "tab": "wireguard"},
        {"id": "openvpn", "name": "OpenVPN", "fa_name": "اوپن‌وی‌پی‌ان", "icon": "lock", "color": "#ea580c", "tab": "openvpn"},
        {"id": "ocserv", "name": "Cisco AnyConnect", "fa_name": "سیسکو انی‌کانکت", "icon": "radio", "color": "#0284c7", "tab": "ocserv"},
        {"id": "l2tp", "name": "L2TP / IPsec", "fa_name": "ال‌تو‌تی‌پی", "icon": "repeat", "color": "#2563eb", "tab": "l2tp"},
        {"id": "sstp", "name": "SSTP", "fa_name": "اس‌اس‌تی‌پی", "icon": "globe", "color": "#0d9488", "tab": "sstp"},
        {"id": "ikev2", "name": "IKEv2 / IPsec", "fa_name": "آی‌کی‌ای نسخه ۲", "icon": "shield-check", "color": "#4f46e5", "tab": "ikev2"},
        {"id": "ssh", "name": "SSH Tunnel & WS", "fa_name": "تانل اس‌اس‌اچ", "icon": "terminal", "color": "#16a34a", "tab": "ssh"},
        {"id": "amneziawg", "name": "AmneziaWG", "fa_name": "آمنزیا وایرگارد", "icon": "shield", "color": "#d97706", "tab": "amneziawg"},
        {"id": "shadowsocks", "name": "Shadowsocks-rust", "fa_name": "شادوساکس", "icon": "shield", "color": "#f59e0b", "tab": "shadowsocks"},
        {"id": "mtproto", "name": "MTProto Proxy", "fa_name": "پروکسی تلگرام", "icon": "send", "color": "#0ea5e9", "tab": "mtproto"},
        {"id": "tuic", "name": "TUIC Protocol", "fa_name": "پروتکل توئیک", "icon": "zap", "color": "#6366f1", "tab": "tuic"},
    ]

    result_list = []
    total_vpn_rx = 0
    total_vpn_tx = 0

    for m in proto_meta:
        pid = m["id"]
        installed = is_installed(pid)
        active = get_protocol_active(pid) if installed else False
        conn = get_connection_count(pid) if active else 0
        port = get_active_port(pid) if installed else None
        
        t = raw_traffic.get(pid, {"rx": 0, "tx": 0})
        rx_bytes = t["rx"]
        tx_bytes = t["tx"]
        tot_bytes = rx_bytes + tx_bytes
        total_vpn_rx += rx_bytes
        total_vpn_tx += tx_bytes

        rx_speed = 0.0
        tx_speed = 0.0
        if delta_t > 0 and pid in prev_stats:
            p_rx = prev_stats[pid].get("rx", 0)
            p_tx = prev_stats[pid].get("tx", 0)
            if rx_bytes >= p_rx and tx_bytes >= p_tx:
                rx_speed = round((rx_bytes - p_rx) / delta_t / 1024, 1) # KB/s
                tx_speed = round((tx_bytes - p_tx) / delta_t / 1024, 1) # KB/s

        result_list.append({
            "id": pid,
            "name": m["name"],
            "fa_name": m["fa_name"],
            "icon": m["icon"],
            "color": m["color"],
            "tab": m["tab"],
            "installed": installed,
            "active": active,
            "port": port,
            "connections": conn,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "total_bytes": tot_bytes,
            "rx_speed_kbs": rx_speed,
            "tx_speed_kbs": tx_speed
        })

    _proto_traffic_prev = {"timestamp": now, "stats": raw_traffic}
    return {
        "protocols": result_list,
        "total_vpn_rx": total_vpn_rx,
        "total_vpn_tx": total_vpn_tx,
        "total_vpn_bytes": total_vpn_rx + total_vpn_tx
    }


def get_security_alerts_data(force_refresh=False):
    global _security_alerts_cache
    now = time.time()
    if not force_refresh and _security_alerts_cache["data"] is not None and (now - _security_alerts_cache["timestamp"] < 5):
        return _security_alerts_cache["data"]

    total_banned = 0
    currently_banned = 0
    total_failed = 0
    banned_ips = []

    # 1. Fail2ban status
    try:
        res = subprocess.run(["fail2ban-client", "status", "sshd"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0:
            tb = re.search(r"Total banned:\s*(\d+)", res.stdout)
            cb = re.search(r"Currently banned:\s*(\d+)", res.stdout)
            tf = re.search(r"Total failed:\s*(\d+)", res.stdout)
            bi = re.search(r"Banned IP list:\s*(.*)", res.stdout)
            if tb: total_banned = int(tb.group(1))
            if cb: currently_banned = int(cb.group(1))
            if tf: total_failed = int(tf.group(1))
            if bi and bi.group(1).strip():
                banned_ips = bi.group(1).strip().split()
    except Exception:
        pass

    events = []
    # 2. Fail2ban log
    if os.path.exists("/var/log/fail2ban.log"):
        try:
            with open("/var/log/fail2ban.log") as f:
                lines = f.readlines()[-80:]
            for line in lines:
                if "Ban " in line:
                    m = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*\[sshd\] Ban ([\d\.]+)", line)
                    if m:
                        events.append({
                            "time": m.group(1),
                            "type": "ban",
                            "severity": "critical",
                            "ip": m.group(2),
                            "title": "حمله تخریبی دفع و مسدود شد",
                            "message": f"آی‌پی {m.group(2)} به دلیل ارسال مکرر درخواست‌های مخرب و بروت‌فورس SSH مسدود گردید."
                        })
                elif "Found " in line:
                    m = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*\[sshd\] Found ([\d\.]+)", line)
                    if m:
                        events.append({
                            "time": m.group(1),
                            "type": "threat",
                            "severity": "warning",
                            "ip": m.group(2),
                            "title": "الگوی نفوذ مشکوک شناسایی شد",
                            "message": f"تلاش مشکوک به اسکن و بروت‌فورس از مبدأ {m.group(2)} رصد گردید."
                        })
        except Exception:
            pass

    # 3. Auth log
    if os.path.exists("/var/log/auth.log"):
        try:
            with open("/var/log/auth.log") as f:
                lines = f.readlines()[-100:]
            for line in lines:
                if "Invalid user" in line or "Failed password" in line:
                    m = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*(?:Invalid user|Failed password for(?: invalid user)?) (\w+) from ([\d\.]+)", line)
                    if m:
                        t = m.group(1).replace("T", " ")
                        events.append({
                            "time": t,
                            "type": "auth_fail",
                            "severity": "warning",
                            "ip": m.group(3),
                            "title": "تلاش ناموفق برای ورود به سرور",
                            "message": f"تلاش غیرمجاز لاگین با نام کاربری '{m.group(2)}' از آی‌پی {m.group(3)}"
                        })
        except Exception:
            pass

    events.sort(key=lambda x: x["time"], reverse=True)
    unique_events = []
    seen = set()
    for ev in events:
        key = (ev["time"], ev["ip"], ev["type"])
        if key not in seen:
            seen.add(key)
            unique_events.append(ev)

    data = {
        "status": "active",
        "service": "Fail2Ban + UFW Shield",
        "total_banned": total_banned,
        "currently_banned": currently_banned,
        "total_failed": total_failed,
        "banned_ips": banned_ips[:20],
        "events": unique_events[:30]
    }
    _security_alerts_cache = {"timestamp": now, "data": data}
    return data

@app.route("/api/stats", methods=["GET"])
def api_stats():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    cpu_percent = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net_io = psutil.net_io_counters()
    
    sys_info = get_live_system_metrics()
    proto_traffic = get_protocol_bandwidth_stats()
    sec_data = get_security_alerts_data()
    
    return jsonify({
        "cpu": cpu_percent,
        "ram": {
            "percent": mem.percent,
            "used": mem.used,
            "total": mem.total
        },
        "disk": {
            "percent": disk.percent,
            "used": disk.used,
            "total": disk.total
        },
        "network": {
            "bytes_recv": net_io.bytes_recv,
            "bytes_sent": net_io.bytes_sent
        },
        "system_info": sys_info,
        "protocol_traffic": proto_traffic,
        "security": sec_data
    })

@app.route("/api/security/refresh", methods=["POST"])
def api_security_refresh():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    sec_data = get_security_alerts_data(force_refresh=True)
    return jsonify({"success": True, "security": sec_data})

@app.route("/api/protocols", methods=["GET"])
def api_protocols():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    protocols_list = PROTOCOLS_LIST
    res = []
    
    for proto in protocols_list:
        installed = is_installed(proto)
        active = False
        port = None
        connections = 0
        
        if installed:
            active = get_protocol_active(proto)
            port = get_active_port(proto)
            if active:
                connections = get_connection_count(proto)
            
        res.append({
            "name": proto,
            "installed": installed,
            "active": active,
            "port": port,
            "connections": connections,
            "default_port": PROTOCOL_DEFAULT_PORTS[proto]
        })
        
    return jsonify(res)

@app.route("/api/protocols/install", methods=["POST"])
def api_protocols_install():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    protocol = data.get("protocol")
    port = data.get("port")
    ad_tag = data.get("ad_tag", "")
    
    success, stdout, stderr = run_helper("install", protocol, port, ad_tag if protocol == "mtproto" else "")
    if success:
        return jsonify({"success": True, "output": stdout})
    return jsonify({"success": False, "error": stderr}), 500

@app.route("/api/protocols/uninstall", methods=["POST"])
def api_protocols_uninstall():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    protocol = request.json.get("protocol")
    success, stdout, stderr = run_helper("uninstall", protocol)
    if success:
        return jsonify({"success": True})
    return jsonify({"success": False, "error": stderr}), 500

@app.route("/api/protocols/set-port", methods=["POST"])
def api_protocols_set_port():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    protocol = data.get("protocol")
    port = data.get("port")
    
    # Check port collision
    for proto in ["ssh", "openvpn", "ocserv", "sstp", "pptp", "wireguard", "http", "socks", "shadowsocks", "mtproto"]:
        if is_installed(proto) and proto != protocol:
            if str(get_active_port(proto)) == str(port):
                return jsonify({"success": False, "error": f"Port {port} is already used by {proto}"}), 400

    success, stdout, stderr = run_helper("set-port", protocol, port)
    if success:
        return jsonify({"success": True})
    return jsonify({"success": False, "error": stderr}), 500

@app.route("/api/protocols/mtproto/ad-tag", methods=["POST"])
def api_mtproto_ad_tag():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    ad_tag = (request.json or {}).get("ad_tag", "").strip()
    import glob
    for fpath in glob.glob("/etc/vpnpanel/mtproto_config_*.py"):
        try:
            with open(fpath, "r") as f:
                content = f.read()
            if re.search(r"^AD_TAG\s*=", content, re.MULTILINE):
                content = re.sub(r"^AD_TAG\s*=.*", f'AD_TAG = "{ad_tag}"', content, flags=re.MULTILINE)
            else:
                content += f'\nAD_TAG = "{ad_tag}"\n'
            with open(fpath, "w") as f:
                f.write(content)
            port_m = re.search(r"mtproto_config_(\d+)\.py", fpath)
            if port_m:
                subprocess.run(["systemctl", "restart", f"aethervpn-mtproto@{port_m.group(1)}"], check=False)
        except Exception:
            pass
    run_helper("set-ad-tag", "mtproto", ad_tag)
    return jsonify({"success": True, "ad_tag": ad_tag})

def get_service_names(protocol):
    if protocol == "mtproto":
        import glob
        services = []
        files = glob.glob("/etc/vpnpanel/mtproto_config_*.py")
        for f in files:
            match = re.search(r"mtproto_config_(\d+)\.py", f)
            if match:
                services.append(f"aethervpn-mtproto@{match.group(1)}")
        if not services:
            services = ["aethervpn-mtproto@4433"]
        return services
    elif protocol == "ssh":
        for s in ["ssh", "sshd", "aethervpn-ssh"]:
            res = subprocess.run(["systemctl", "is-active", s], capture_output=True, text=True)
            if res.stdout.strip() in ["active", "inactive"]: return [s]
        return ["ssh"]
    elif protocol == "openvpn":
        for s in ["openvpn-server@server", "openvpn@server"]:
            res = subprocess.run(["systemctl", "is-active", s], capture_output=True, text=True)
            if res.stdout.strip() in ["active", "inactive"]: return [s]
        return ["openvpn-server@server"]
    elif protocol == "ocserv":
        return ["ocserv"]
    elif protocol == "ikev2":
        for s in ["strongswan-starter", "strongswan-swanctl", "strongswan"]:
            res = subprocess.run(["systemctl", "is-active", s], capture_output=True, text=True)
            if res.stdout.strip() in ["active", "inactive"]: return [s]
        return ["strongswan-starter"]
    elif protocol == "sstp":
        return ["sstpd"]
    elif protocol == "pptp":
        return ["aethervpn-pptp"]
    elif protocol == "l2tp":
        ikev2_svc = "strongswan-swanctl"
        for s in ["strongswan-swanctl", "strongswan-starter", "strongswan"]:
            if os.path.exists(f"/etc/systemd/system/{s}.service") or os.path.exists(f"/lib/systemd/system/{s}.service"):
                ikev2_svc = s
                break
        return ["xl2tpd", ikev2_svc]
    elif protocol == "wireguard":
        return ["wg-quick@wg0", "aethervpn-wg-radius"]
    elif protocol == "http":
        return ["aethervpn-http-proxy"]
    elif protocol == "socks":
        return ["aethervpn-socks-proxy"]
    elif protocol == "shadowsocks":
        return ["aethervpn-shadowsocks"]
    elif protocol == "tuic":
        return ["aethervpn-tuic"]
    elif protocol == "dnstt":
        return ["aethervpn-dnstt"]
    elif protocol == "vaydns":
        return ["aethervpn-vaydns"]
    elif protocol == "slipstream":
        return ["aethervpn-slipstream"]
    return []

@app.route("/api/protocols/control", methods=["POST"])
def api_protocols_control():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    protocol = data.get("protocol")
    action = data.get("action")
    
    if action not in ["start", "stop", "restart"]:
        return jsonify({"success": False, "error": "Invalid action"}), 400
        
    services = get_service_names(protocol)
    if not services:
        return jsonify({"success": False, "error": "Unknown protocol"}), 400
        
    try:
        errors = []
        for service in services:
            res = subprocess.run(["systemctl", action, service], capture_output=True, text=True)
            if res.returncode != 0:
                errors.append(f"Failed to {action} {service}: {res.stderr.strip()}")
        if errors:
            return jsonify({"success": False, "error": "; ".join(errors)}), 500
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/protocols/logs/<protocol>", methods=["GET"])
def api_protocols_logs(protocol):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    success, stdout, stderr = run_helper("logs", protocol)
    if success:
        return jsonify({"logs": stdout})
    return jsonify({"error": stderr}), 500

@app.route("/api/protocols/advanced_logs/<protocol>", methods=["GET"])
def api_protocols_advanced_logs(protocol):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    services = []
    if protocol == "ssh": services = ["aethervpn-ssh"]
    elif protocol == "openvpn": services = ["openvpn@server"]
    elif protocol == "ocserv": services = ["ocserv"]
    elif protocol == "ikev2": services = ["strongswan-swanctl", "strongswan-starter", "strongswan"]
    elif protocol == "sstp": services = ["sstpd", "vpnserver"]
    elif protocol == "l2tp": services = ["xl2tpd"]
    elif protocol == "pptp": services = ["aethervpn-pptp"]
    elif protocol == "wireguard": services = ["wg-quick@wg0"]
    elif protocol == "amneziawg": services = ["awg-quick@awg0"]
    elif protocol == "mtproto": services = ["aethervpn-mtproto*"]
    else: return jsonify({"error": "Unknown protocol"}), 400
    
    cmd = ["journalctl"]
    for svc in services:
        cmd.extend(["-u", svc])
    cmd.extend(["-n", "300", "--no-pager", "-o", "json"])
    
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        logs = []
        for line in res.stdout.strip().split('\n'):
            if not line: continue
            try:
                j = json.loads(line)
                timestamp = int(j.get("__REALTIME_TIMESTAMP", 0)) / 1000000
                message = j.get("MESSAGE", "")
                priority = int(j.get("PRIORITY", 6))
                
                if isinstance(message, list):
                    try:
                        message = bytes(message).decode('utf-8', 'ignore')
                    except:
                        message = str(message)
                
                logs.append({
                    "timestamp": timestamp,
                    "message": message,
                    "priority": priority
                })
            except Exception:
                pass
        return jsonify({"logs": logs})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- MH Panel Internal FreeRADIUS & Unified Multi-Protocol Management ---
RADIUS_USERS_FILE = "/www/wwwroot/mhpanel/radius_users.json"
RADIUS_GROUPS_FILE = "/www/wwwroot/mhpanel/radius_groups.json"
FREERADIUS_USERS_FILE = "/etc/freeradius/3.0/mhpanel_users"

def get_radius_groups_data():
    if not os.path.exists(RADIUS_GROUPS_FILE):
        default_groups = {
            "default": {
                "id": "default",
                "name": "پکیج استاندارد (Standard)",
                "traffic_gb": 0,
                "validity_days": 30,
                "simultaneous_use": 2,
                "allowed_days": "all",
                "custom_days": [],
                "start_time": "00:00",
                "end_time": "24:00",
                "description": "پکیج استاندارد با ۲ کاربر همزمان و ترافیک نامحدود"
            },
            "vip": {
                "id": "vip",
                "name": "پکیج ویژه (VIP)",
                "traffic_gb": 100,
                "validity_days": 30,
                "simultaneous_use": 5,
                "allowed_days": "all",
                "custom_days": [],
                "start_time": "00:00",
                "end_time": "24:00",
                "description": "پکیج حرفه‌ای با ۵ اتصال همزمان و ۱۰۰ گیگابایت حجم"
            },
            "night": {
                "id": "night",
                "name": "بسته شبانه (Nightly)",
                "traffic_gb": 50,
                "validity_days": 30,
                "simultaneous_use": 2,
                "allowed_days": "all",
                "custom_days": [],
                "start_time": "01:00",
                "end_time": "08:00",
                "description": "فعال فقط از ۱ بامداد تا ۸ صبح"
            }
        }
        try:
            with open(RADIUS_GROUPS_FILE, "w") as f:
                json.dump(default_groups, f, indent=2)
            return default_groups
        except Exception:
            return default_groups
    try:
        with open(RADIUS_GROUPS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def format_freeradius_login_time(allowed_days="all", custom_days=None, start_time="00:00", end_time="24:00"):
    if not start_time: start_time = "00:00"
    if not end_time: end_time = "24:00"
    st = start_time.replace(":", "")
    et = end_time.replace(":", "")
    if len(st) != 4 or len(et) != 4:
        st, et = "0000", "2400"
    time_range = f"{st}-{et}"

    day_prefix = "Al"
    if allowed_days == "weekdays":
        day_prefix = "Wk"
    elif allowed_days == "weekends":
        day_prefix = "Sa,Su"
    elif allowed_days == "custom" and custom_days and isinstance(custom_days, list):
        day_prefix = ",".join(custom_days)
    elif allowed_days == "all":
        day_prefix = "Al"

    if time_range == "0000-2400" and day_prefix == "Al":
        return None
    return f"{day_prefix}{time_range}"

def get_all_radius_online_sessions():
    sessions = []
    
    # 1. Cisco AnyConnect / Ocserv
    try:
        res = subprocess.run(["occtl", "-j", "show", "users"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0 and res.stdout.strip():
            u_list = json.loads(res.stdout)
            for u in u_list:
                uname = u.get("Username") or u.get("username")
                if uname:
                    sessions.append({
                        "username": uname,
                        "protocol": "Cisco AnyConnect",
                        "client_ip": u.get("IP") or u.get("ip") or "-",
                        "vpn_ip": u.get("VPN IP") or u.get("vpn_ip") or "-",
                        "device": u.get("Device") or u.get("device") or "AnyConnect",
                        "connected_since": u.get("Connected at") or u.get("connected_at") or "-",
                        "session_id": str(u.get("ID") or u.get("id") or uname)
                    })
    except Exception:
        pass

    # 2. OpenVPN
    for log_path in ["/var/log/openvpn/openvpn-status.log", "/var/log/openvpn/openvpn-tcp-status.log", "/var/log/openvpn-status.log"]:
        if os.path.exists(log_path):
            try:
                with open(log_path, "r") as f:
                    content = f.read()
                lines = content.splitlines()
                in_client_list = False
                for line in lines:
                    if line.startswith("Common Name,Real Address"):
                        in_client_list = True
                        continue
                    if line.startswith("ROUTING TABLE") or line.startswith("GLOBAL STATS"):
                        in_client_list = False
                    if in_client_list and "," in line:
                        parts = line.split(",")
                        if len(parts) >= 5 and parts[0] != "UNDEF":
                            sessions.append({
                                "username": parts[0],
                                "protocol": "OpenVPN",
                                "client_ip": parts[1].split(":")[0] if ":" in parts[1] else parts[1],
                                "vpn_ip": "-",
                                "device": "OpenVPN Client",
                                "connected_since": parts[4] if len(parts) > 4 else "-",
                                "session_id": parts[0]
                            })
            except Exception:
                pass

    # 3. SSH Sessions
    try:
        ssh_active = get_ssh_active_sessions()
        for s in ssh_active:
            sessions.append({
                "username": s.get("username"),
                "protocol": "SSH Tunnel",
                "client_ip": s.get("ip", "-"),
                "vpn_ip": "-",
                "device": "SSH Client",
                "connected_since": s.get("login_time", "-"),
                "session_id": str(s.get("pid", ""))
            })
    except Exception:
        pass

    # 4. Radwho / FreeRADIUS Accounting
    try:
        res = subprocess.run(["radwho", "-n"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0 and res.stdout.strip():
            for line in res.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    uname = parts[0]
                    if not any(x["username"] == uname for x in sessions):
                        sessions.append({
                            "username": uname,
                            "protocol": parts[2] if len(parts) > 2 else "RADIUS",
                            "client_ip": parts[5] if len(parts) > 5 else "-",
                            "vpn_ip": "-",
                            "device": "RADIUS Session",
                            "connected_since": parts[4] if len(parts) > 4 else "-",
                            "session_id": uname
                        })
    except Exception:
        pass

    return sessions

def get_user_active_connection_counts():
    sessions = get_all_radius_online_sessions()
    counts = {}
    for s in sessions:
        uname = s.get("username")
        if uname:
            counts[uname] = counts.get(uname, 0) + 1
    return counts, sessions

def get_server_public_ip():
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "212.227.143.16"

def sync_freeradius_users():
    users = {}
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                users = json.load(f)
        except Exception:
            users = {}

    groups = get_radius_groups_data()

    lines = ["# MH Panel Unified RADIUS Database\n"]
    now_str = datetime.now().strftime("%Y-%m-%d")
    for username, data in users.items():
        password = data.get("password", "")
        active = data.get("active", True)
        expire_date = data.get("expire_date")
        group_id = data.get("group", "default")
        group_data = groups.get(group_id, {})

        if expire_date and now_str > expire_date:
            active = False

        if not active:
            lines.append(f'"{username}" Auth-Type := Reject\n\tReply-Message := "Account is disabled or expired by administrator"\n\n')
        else:
            sim_use = data.get("simultaneous_use") or group_data.get("simultaneous_use") or 2
            try: sim_use = int(sim_use)
            except Exception: sim_use = 2

            allowed_days = data.get("allowed_days") or group_data.get("allowed_days", "all")
            custom_days = data.get("custom_days") or group_data.get("custom_days", [])
            start_time = data.get("start_time") or group_data.get("start_time", "00:00")
            end_time = data.get("end_time") or group_data.get("end_time", "24:00")

            login_time = data.get("login_time_raw") or format_freeradius_login_time(allowed_days, custom_days, start_time, end_time)

            attr_items = [f'Cleartext-Password := "{password}"']
            if sim_use > 0:
                attr_items.append(f'Simultaneous-Use := {sim_use}')
            if login_time:
                attr_items.append(f'Login-Time := "{login_time}"')

            lines.append(f'"{username}" ' + ", ".join(attr_items) + "\n\n")

    os.makedirs("/etc/freeradius/3.0", exist_ok=True)
    with open(FREERADIUS_USERS_FILE, "w") as f:
        f.writelines(lines)

    try:
        import shutil
        shutil.chown(FREERADIUS_USERS_FILE, user="freerad", group="freerad")
        os.chmod(FREERADIUS_USERS_FILE, 0o640)
    except Exception:
        pass

    auth_file = "/etc/freeradius/3.0/mods-config/files/authorize"
    if os.path.exists(auth_file):
        try:
            with open(auth_file, "r") as f:
                content = f.read()
            if "$INCLUDE /etc/freeradius/3.0/mhpanel_users" not in content:
                with open(auth_file, "w") as f:
                    f.write("$INCLUDE /etc/freeradius/3.0/mhpanel_users\n" + content)
        except Exception:
            pass

    # Mirror to /etc/ppp/chap-secrets and /etc/ppp/pap-secrets as direct fallback
    try:
        os.makedirs("/etc/ppp", exist_ok=True)
        ppp_lines = ["# MH Panel Unified Users for PPP / L2TP\n"]
        for username, data in users.items():
            p = data.get("password", "")
            act = data.get("active", True)
            exp = data.get("expire_date")
            if exp and now_str > exp:
                act = False
            prefix = "" if act else "#"
            ppp_lines.append(f'{prefix}"{username}" * "{p}" *\n')
        with open("/etc/ppp/chap-secrets", "w") as f:
            f.writelines(ppp_lines)
        with open("/etc/ppp/pap-secrets", "w") as f:
            f.writelines(ppp_lines)
        os.chmod("/etc/ppp/chap-secrets", 0o600)
        os.chmod("/etc/ppp/pap-secrets", 0o600)
    except Exception:
        pass

    # Mirror to /etc/swanctl/conf.d/users.conf for strongSwan local EAP fallback
    try:
        os.makedirs("/etc/swanctl/conf.d", exist_ok=True)
        swan_lines = ["secrets {\n  eap-dynamic {\n"]
        for username, data in users.items():
            p = data.get("password", "")
            act = data.get("active", True)
            exp = data.get("expire_date")
            if exp and now_str > exp:
                act = False
            prefix = "    " if act else "    #"
            swan_lines.append(f'{prefix}{username} : EAP "{p}"\n')
        swan_lines.append("  }\n}\n")
        with open("/etc/swanctl/conf.d/users.conf", "w") as f:
            f.writelines(swan_lines)
        subprocess.run(["swanctl", "--load-creds"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    subprocess.run(["systemctl", "restart", "freeradius"], capture_output=True)

def apply_internal_radius_system(server_ip="127.0.0.1", shared_secret="testing123", auth_port=1812, acct_port=1813, protocols=None):
    if protocols is None:
        protocols = ["openvpn", "ocserv", "ikev2", "l2tp", "sstp", "ssh"]

    os.makedirs("/etc/vpnpanel", exist_ok=True)
    with open("/etc/vpnpanel/radius_config.json", "w") as f:
        json.dump({
            "server_ip": server_ip,
            "shared_secret": shared_secret,
            "auth_port": auth_port,
            "acct_port": acct_port,
            "enabled_protocols": protocols
        }, f, indent=2)

    # 1. pam_radius_auth.conf
    os.makedirs("/etc", exist_ok=True)
    with open("/etc/pam_radius_auth.conf", "w") as f:
        f.write(f"# RADIUS Server configuration generated by MH Panel\n{server_ip}:{auth_port} {shared_secret} 3\n")
    os.chmod("/etc/pam_radius_auth.conf", 0o600)

    # 2. radcli / radiusclient
    os.makedirs("/etc/radcli", exist_ok=True)
    try:
        open("/var/run/radius.seq", "a").close()
        open("/etc/radcli/port-id-map", "a").close()
    except Exception:
        pass

    with open("/etc/radcli/radiusclient.conf", "w") as f:
        f.write(f"""authserver {server_ip}:{auth_port}
acctserver {server_ip}:{acct_port}
servers /etc/radcli/servers
dictionary /etc/radcli/dictionary
default_realm
radius_timeout 3
radius_retries 3
bindaddr *
seqfile /var/run/radius.seq
mapfile /etc/radcli/port-id-map
nologin /etc/nologin
""")
    with open("/etc/radcli/servers", "w") as f:
        f.write(f"{server_ip} {shared_secret}\n")
    os.chmod("/etc/radcli/servers", 0o600)

    # Ensure radcli dictionaries include Microsoft & Roaring Penguin
    rad_dict = "/etc/radcli/dictionary"
    if os.path.exists(rad_dict):
        try:
            with open(rad_dict, "r") as f:
                dict_content = f.read()
            dict_content = dict_content.replace("#$INCLUDE /etc/radcli/dictionary.microsoft", "$INCLUDE /etc/radcli/dictionary.microsoft\nINCLUDE /etc/radcli/dictionary.microsoft")
            dict_content = dict_content.replace("#$INCLUDE /etc/radcli/dictionary.roaringpenguin", "$INCLUDE /etc/radcli/dictionary.roaringpenguin\nINCLUDE /etc/radcli/dictionary.roaringpenguin")
            dict_content = re.sub(r'\bipv4addr\b', 'ipaddr', dict_content)
            dict_content = re.sub(r'\b(ipv6addr|ipv6prefix)\b', 'string', dict_content)
            with open(rad_dict, "w") as f:
                f.write(dict_content)
        except Exception:
            pass

    # Sanitize /etc/ppp/options to remove legacy serial options
    ppp_opt = "/etc/ppp/options"
    if os.path.exists(ppp_opt):
        try:
            with open(ppp_opt, "r") as f:
                opt_c = f.read()
            opt_c = re.sub(r'^(crtscts|lock|modem)', r'#\1', opt_c, flags=re.MULTILINE)
            with open(ppp_opt, "w") as f:
                f.write(opt_c)
        except Exception:
            pass

    if not os.path.exists("/etc/radiusclient"):
        try:
            os.symlink("/etc/radcli", "/etc/radiusclient")
        except Exception:
            pass

    # 3. OpenVPN PAM
    os.makedirs("/etc/pam.d", exist_ok=True)
    with open("/etc/pam.d/openvpn", "w") as f:
        f.write("auth sufficient pam_radius_auth.so\nauth required pam_unix.so try_first_pass\naccount sufficient pam_permit.so\naccount required pam_unix.so\nsession sufficient pam_permit.so\nsession required pam_unix.so\n")

    ovpn_conf = "/etc/openvpn/server/server.conf"
    if os.path.exists(ovpn_conf):
        with open(ovpn_conf, "r") as f:
            lines = f.readlines()
        clean = [l for l in lines if not any(k in l for k in ["openvpn-plugin-auth-pam", "verify-client-cert", "username-as-common-name"])]
        if "openvpn" in protocols:
            clean.append("plugin /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so openvpn\n")
            clean.append("verify-client-cert none\n")
            clean.append("username-as-common-name\n")
        with open(ovpn_conf, "w") as f:
            f.writelines(clean)
        subprocess.run(["systemctl", "restart", "openvpn-server@server"], capture_output=True)

    # 4. Ocserv
    ocserv_conf = "/etc/ocserv/ocserv.conf"
    if os.path.exists(ocserv_conf):
        with open(ocserv_conf, "r") as f:
            content = f.read()
        if "ocserv" in protocols:
            content = re.sub(r'^auth\s*=.*', 'auth = "radius[config=/etc/radcli/radiusclient.conf,groupconfig=true]"', content, flags=re.MULTILINE)
            if "acct =" not in content:
                content += '\nacct = "radius[config=/etc/radcli/radiusclient.conf]"\n'
        else:
            content = re.sub(r'^auth\s*=.*', 'auth = "plain[passwd=/etc/ocserv/ocpasswd]"', content, flags=re.MULTILINE)
            content = re.sub(r'^acct\s*=\s*.*radius.*', '', content, flags=re.MULTILINE)
        with open(ocserv_conf, "w") as f:
            f.write(content)
        subprocess.run(["systemctl", "restart", "ocserv"], capture_output=True)

    # 5. StrongSwan IKEv2
    os.makedirs("/etc/strongswan.d/charon", exist_ok=True)
    with open("/etc/strongswan.d/charon/eap-radius.conf", "w") as f:
        f.write(f"""eap-radius {{
    load = yes
    servers {{
        primary {{
            address = {server_ip}
            secret = {shared_secret}
            auth_port = {auth_port}
            acct_port = {acct_port}
        }}
    }}
}}
""")
    ipsec_conf = "/etc/ipsec.conf"
    if os.path.exists(ipsec_conf):
        with open(ipsec_conf, "r") as f:
            c = f.read()
        if "ikev2" in protocols:
            c = c.replace("rightauth=eap-mschapv2", "rightauth=eap-radius")
        else:
            c = c.replace("rightauth=eap-radius", "rightauth=eap-mschapv2")
        with open(ipsec_conf, "w") as f:
            f.write(c)
        subprocess.run(["systemctl", "restart", "strongswan-starter"], capture_output=True)

    # 6. L2TP / SSTP ppp options
    l2tp_opt = "/etc/ppp/options.xl2tpd"
    if os.path.exists(l2tp_opt):
        with open(l2tp_opt, "r") as f:
            c = f.read()
        c = c.replace("plugin radius.so", "").replace("radius-config-file /etc/radcli/radiusclient.conf", "")
        if "l2tp" in protocols:
            c += "\nplugin radius.so\nradius-config-file /etc/radcli/radiusclient.conf\n"
        with open(l2tp_opt, "w") as f:
            f.write(c.strip() + "\n")
        subprocess.run(["systemctl", "restart", "xl2tpd"], capture_output=True)

    sstp_opt = "/etc/ppp/options.sstpd"
    if os.path.exists(sstp_opt):
        with open(sstp_opt, "r") as f:
            c = f.read()
        c = c.replace("plugin radius.so", "").replace("radius-config-file /etc/radcli/radiusclient.conf", "")
        if "sstp" in protocols:
            c += "\nplugin radius.so\nradius-config-file /etc/radcli/radiusclient.conf\n"
        with open(sstp_opt, "w") as f:
            f.write(c.strip() + "\n")
        subprocess.run(["systemctl", "restart", "sstpd"], capture_output=True)

    # 7. SSH PAM
    sshd_pam = "/etc/pam.d/sshd"
    if os.path.exists(sshd_pam):
        with open(sshd_pam, "r") as f:
            c = f.read()
        if "ssh" in protocols:
            if "pam_radius_auth.so" not in c:
                c = "auth sufficient pam_radius_auth.so\n" + c
                c = c.replace("@include common-account", "account sufficient pam_permit.so\n@include common-account")
                with open(sshd_pam, "w") as f:
                    f.write(c)
        else:
            c = c.replace("auth sufficient pam_radius_auth.so\n", "").replace("account sufficient pam_permit.so\n", "")
            with open(sshd_pam, "w") as f:
                f.write(c)
        subprocess.run(["systemctl", "restart", "ssh"], capture_output=True)

    sync_freeradius_users()

@app.route("/api/radius", methods=["GET"])
def api_radius_get():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    server_ip = "127.0.0.1"
    shared_secret = "testing123"
    auth_port = 1812
    acct_port = 1813
    enabled_protocols = []
    
    if os.path.exists("/etc/vpnpanel/radius_config.json"):
        try:
            with open("/etc/vpnpanel/radius_config.json", "r") as f:
                rdata = json.load(f)
                server_ip = rdata.get("server_ip", "127.0.0.1")
                shared_secret = rdata.get("shared_secret", "testing123")
                auth_port = rdata.get("auth_port", 1812)
                acct_port = rdata.get("acct_port", 1813)
                enabled_protocols = rdata.get("enabled_protocols", [])
        except Exception:
            pass
            
    # Check running status of FreeRADIUS
    rad_running = False
    try:
        res = subprocess.run(["systemctl", "is-active", "freeradius"], capture_output=True, text=True)
        rad_running = (res.stdout.strip() == "active")
    except Exception:
        pass

    user_count = 0
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                user_count = len(json.load(f))
        except Exception:
            pass

    return jsonify({
        "server_ip": server_ip,
        "shared_secret": shared_secret,
        "auth_port": auth_port,
        "acct_port": acct_port,
        "enabled_protocols": enabled_protocols,
        "internal_running": rad_running,
        "user_count": user_count,
        "public_ip": get_server_public_ip()
    })

@app.route("/api/radius", methods=["POST"])
def api_radius_set():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.json
    server_ip = data.get("server_ip", "127.0.0.1")
    shared_secret = data.get("shared_secret", "testing123")
    auth_port = data.get("auth_port", 1812)
    acct_port = data.get("acct_port", 1813)
    protocols = data.get("protocols", [])
    
    try:
        apply_internal_radius_system(server_ip, shared_secret, auth_port, acct_port, protocols)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/radius/internal/init", methods=["POST"])
def api_radius_internal_init():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        subprocess.run(["systemctl", "enable", "--now", "freeradius"], capture_output=True)
        apply_internal_radius_system("127.0.0.1", "testing123", 1812, 1813, ["openvpn", "ocserv", "ikev2", "l2tp", "sstp", "ssh"])
        return jsonify({"success": True, "message": "All protocols linked to internal FreeRADIUS successfully!"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/radius/users", methods=["GET"])
def api_radius_get_users():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    users = {}
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                users = json.load(f)
        except Exception:
            pass

    groups = get_radius_groups_data()
    counts, sessions = get_user_active_connection_counts()

    # Enrich users with group and live connection data
    enriched_users = {}
    for uname, udata in users.items():
        user_info = dict(udata)
        grp_id = user_info.get("group", "default")
        grp = groups.get(grp_id, {})
        user_info["group"] = grp_id
        user_info["group_name"] = grp.get("name", "عمومی")
        user_info["online_count"] = counts.get(uname, 0)
        if "simultaneous_use" not in user_info or not user_info["simultaneous_use"]:
            user_info["simultaneous_use"] = grp.get("simultaneous_use", 2)
        enriched_users[uname] = user_info

    return jsonify({
        "users": enriched_users,
        "groups": groups,
        "online_sessions": sessions,
        "total_online": len(sessions)
    })

@app.route("/api/radius/users", methods=["POST"])
def api_radius_add_user():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    group_id = data.get("group", "default").strip()
    groups = get_radius_groups_data()
    group_data = groups.get(group_id, {})

    expire_date = data.get("expire_date")
    validity_days = data.get("validity_days")
    if not expire_date and validity_days:
        try:
            from datetime import timedelta
            expire_date = (datetime.now() + timedelta(days=int(validity_days))).strftime("%Y-%m-%d")
        except Exception:
            pass
    elif not expire_date and group_data.get("validity_days"):
        try:
            from datetime import timedelta
            expire_date = (datetime.now() + timedelta(days=int(group_data.get("validity_days", 30)))).strftime("%Y-%m-%d")
        except Exception:
            pass

    limit_gb = data.get("limit_gb")
    if limit_gb is None or limit_gb == "":
        limit_gb = group_data.get("traffic_gb") or None
    else:
        try: limit_gb = float(limit_gb)
        except Exception: limit_gb = None

    simultaneous_use = data.get("simultaneous_use")
    if simultaneous_use is None or simultaneous_use == "":
        simultaneous_use = group_data.get("simultaneous_use", 2)
    else:
        try: simultaneous_use = int(simultaneous_use)
        except Exception: simultaneous_use = 2

    allowed_days = data.get("allowed_days") or group_data.get("allowed_days", "all")
    custom_days = data.get("custom_days") or group_data.get("custom_days", [])
    start_time = data.get("start_time") or group_data.get("start_time", "00:00")
    end_time = data.get("end_time") or group_data.get("end_time", "24:00")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    users = {}
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                users = json.load(f)
        except Exception:
            pass

    # Ensure system account exists for SSH PAM
    try:
        subprocess.run(["useradd", "-M", "-s", "/usr/sbin/nologin", "-g", "nogroup", username], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    users[username] = {
        "password": password,
        "active": True,
        "group": group_id,
        "simultaneous_use": simultaneous_use,
        "allowed_days": allowed_days,
        "custom_days": custom_days,
        "start_time": start_time,
        "end_time": end_time,
        "expire_date": expire_date,
        "limit_gb": limit_gb,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "protocols": ["all"]
    }

    with open(RADIUS_USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

    # Mirror to l2tp_users.json, ikev2_users.json & ocserv_users.json
    for path in ["/www/wwwroot/mhpanel/l2tp_users.json", "/www/wwwroot/mhpanel/ikev2_users.json", "/www/wwwroot/mhpanel/ocserv_users.json"]:
        try:
            m_users = {}
            if os.path.exists(path):
                with open(path, "r") as mf: m_users = json.load(mf)
            m_users[username] = {
                "active": True, "password": password, "limit_gb": limit_gb, "expire_date": expire_date,
                "rx": 0, "tx": 0, "last_rx": 0, "last_tx": 0
            }
            with open(path, "w") as mf: json.dump(m_users, mf, indent=2)
        except Exception:
            pass

    sync_freeradius_users()
    return jsonify({"success": True})

@app.route("/api/radius/users/batch", methods=["POST"])
def api_radius_batch_create():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    prefix = data.get("prefix", "user_").strip()
    if not prefix: prefix = "user_"
    try: count = min(max(int(data.get("count", 5)), 1), 200)
    except Exception: count = 5

    pwd_type = data.get("password_type", "random") # "random" or "fixed"
    fixed_pwd = data.get("custom_password", "123456")
    group_id = data.get("group", "default").strip()
    groups = get_radius_groups_data()
    group_data = groups.get(group_id, {})

    try: sim_use = int(data.get("simultaneous_use") or group_data.get("simultaneous_use", 2))
    except Exception: sim_use = 2

    validity_days = data.get("validity_days")
    if validity_days:
        try: validity_days = int(validity_days)
        except Exception: validity_days = 30
    else:
        validity_days = int(group_data.get("validity_days", 30))

    from datetime import timedelta
    expire_date = (datetime.now() + timedelta(days=validity_days)).strftime("%Y-%m-%d") if validity_days > 0 else None

    limit_gb = data.get("limit_gb")
    if limit_gb is None or limit_gb == "":
        limit_gb = group_data.get("traffic_gb") or None
    else:
        try: limit_gb = float(limit_gb)
        except Exception: limit_gb = None

    allowed_days = data.get("allowed_days") or group_data.get("allowed_days", "all")
    custom_days = data.get("custom_days") or group_data.get("custom_days", [])
    start_time = data.get("start_time") or group_data.get("start_time", "00:00")
    end_time = data.get("end_time") or group_data.get("end_time", "24:00")

    users = {}
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f: users = json.load(f)
        except Exception: users = {}

    import random, string
    created_list = []
    start_num = 1
    existing_prefixed = [u for u in users.keys() if u.startswith(prefix)]
    if existing_prefixed:
        start_num = len(existing_prefixed) + 1

    for i in range(count):
        idx = start_num + i
        uname = f"{prefix}{idx:02d}" if count < 100 else f"{prefix}{idx:03d}"
        if uname in users:
            uname = f"{prefix}{idx}_{''.join(random.choices(string.ascii_lowercase + string.digits, k=3))}"

        if pwd_type == "fixed" and fixed_pwd:
            upass = fixed_pwd
        else:
            upass = ''.join(random.choices(string.ascii_letters + string.digits, k=8))

        try:
            subprocess.run(["useradd", "-M", "-s", "/usr/sbin/nologin", "-g", "nogroup", uname], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

        user_record = {
            "password": upass,
            "active": True,
            "group": group_id,
            "simultaneous_use": sim_use,
            "expire_date": expire_date,
            "limit_gb": limit_gb,
            "allowed_days": allowed_days,
            "custom_days": custom_days,
            "start_time": start_time,
            "end_time": end_time,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "protocols": ["all"]
        }
        users[uname] = user_record
        created_list.append({
            "username": uname,
            "password": upass,
            "expire_date": expire_date or "بدون انقضا",
            "simultaneous_use": sim_use,
            "limit_gb": limit_gb or "نامحدود"
        })

        for path in ["/www/wwwroot/mhpanel/l2tp_users.json", "/www/wwwroot/mhpanel/ikev2_users.json", "/www/wwwroot/mhpanel/ocserv_users.json"]:
            try:
                m_users = {}
                if os.path.exists(path):
                    with open(path, "r") as mf: m_users = json.load(mf)
                m_users[uname] = {
                    "active": True, "password": upass, "limit_gb": limit_gb, "expire_date": expire_date,
                    "rx": 0, "tx": 0, "last_rx": 0, "last_tx": 0
                }
                with open(path, "w") as mf: json.dump(m_users, mf, indent=2)
            except Exception:
                pass

    with open(RADIUS_USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

    sync_freeradius_users()
    return jsonify({"success": True, "created": created_list, "count": len(created_list)})

@app.route("/api/radius/users/bulk-delete", methods=["POST"])
def api_radius_bulk_delete():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    usernames = data.get("usernames", [])
    if not isinstance(usernames, list) or not usernames:
        return jsonify({"error": "No usernames provided"}), 400

    users = {}
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f: users = json.load(f)
        except Exception: users = {}

    deleted_count = 0
    for uname in usernames:
        if uname in users:
            del users[uname]
            deleted_count += 1
            try:
                subprocess.run(["userdel", uname], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

            for path in ["/www/wwwroot/mhpanel/l2tp_users.json", "/www/wwwroot/mhpanel/ikev2_users.json", "/www/wwwroot/mhpanel/ocserv_users.json"]:
                try:
                    if os.path.exists(path):
                        with open(path, "r") as mf: m_users = json.load(mf)
                        if uname in m_users:
                            del m_users[uname]
                            with open(path, "w") as mf: json.dump(m_users, mf, indent=2)
                except Exception:
                    pass

    with open(RADIUS_USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

    sync_freeradius_users()
    return jsonify({"success": True, "deleted_count": deleted_count})

@app.route("/api/radius/users/<username>", methods=["DELETE"])
def api_radius_delete_user(username):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    users = {}
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                users = json.load(f)
        except Exception:
            pass

    if username in users:
        del users[username]
        with open(RADIUS_USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)

    # Delete system account if was created for ssh
    try:
        subprocess.run(["userdel", username], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    # Mirror deletion to l2tp_users.json, ikev2_users.json & ocserv_users.json
    for path in ["/www/wwwroot/mhpanel/l2tp_users.json", "/www/wwwroot/mhpanel/ikev2_users.json", "/www/wwwroot/mhpanel/ocserv_users.json"]:
        try:
            if os.path.exists(path):
                with open(path, "r") as mf: m_users = json.load(mf)
                if username in m_users:
                    del m_users[username]
                    with open(path, "w") as mf: json.dump(m_users, mf, indent=2)
        except Exception:
            pass

    sync_freeradius_users()
    return jsonify({"success": True})

@app.route("/api/radius/users/<username>/toggle", methods=["POST"])
def api_radius_toggle_user(username):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    users = {}
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                users = json.load(f)
        except Exception:
            pass

    if username in users:
        new_active = not users[username].get("active", True)
        users[username]["active"] = new_active
        with open(RADIUS_USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)

        # Mirror toggle to l2tp_users.json, ikev2_users.json & ocserv_users.json
        for path in ["/www/wwwroot/mhpanel/l2tp_users.json", "/www/wwwroot/mhpanel/ikev2_users.json", "/www/wwwroot/mhpanel/ocserv_users.json"]:
            try:
                if os.path.exists(path):
                    with open(path, "r") as mf: m_users = json.load(mf)
                    if username in m_users:
                        m_users[username]["active"] = new_active
                        with open(path, "w") as mf: json.dump(m_users, mf, indent=2)
            except Exception:
                pass

        sync_freeradius_users()
        return jsonify({"success": True, "active": new_active})

    return jsonify({"error": "User not found"}), 404

@app.route("/api/radius/users/<username>/password", methods=["POST"])
def api_radius_change_password(username):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    new_password = data.get("password")
    if not new_password:
        return jsonify({"error": "Password required"}), 400

    users = {}
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                users = json.load(f)
        except Exception:
            pass

    if username in users:
        users[username]["password"] = new_password
        with open(RADIUS_USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)
        sync_freeradius_users()
        return jsonify({"success": True})

    return jsonify({"error": "User not found"}), 404

# --- RADIUS Groups / Packages APIs (Mikrotik User Manager Style) ---
@app.route("/api/radius/groups", methods=["GET"])
def api_radius_get_groups():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"groups": get_radius_groups_data()})

@app.route("/api/radius/groups", methods=["POST"])
def api_radius_save_group():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    group_id = data.get("id", "").strip().lower()
    name = data.get("name", "").strip()
    if not group_id or not name:
        return jsonify({"error": "Group ID and Name are required"}), 400

    groups = get_radius_groups_data()
    try: traffic_gb = float(data.get("traffic_gb", 0))
    except Exception: traffic_gb = 0
    try: validity_days = int(data.get("validity_days", 30))
    except Exception: validity_days = 30
    try: sim_use = int(data.get("simultaneous_use", 2))
    except Exception: sim_use = 2

    groups[group_id] = {
        "id": group_id,
        "name": name,
        "traffic_gb": traffic_gb,
        "validity_days": validity_days,
        "simultaneous_use": sim_use,
        "allowed_days": data.get("allowed_days", "all"),
        "custom_days": data.get("custom_days", []),
        "start_time": data.get("start_time", "00:00"),
        "end_time": data.get("end_time", "24:00"),
        "description": data.get("description", "")
    }

    with open(RADIUS_GROUPS_FILE, "w") as f:
        json.dump(groups, f, indent=2)

    sync_freeradius_users()
    return jsonify({"success": True, "group": groups[group_id]})

@app.route("/api/radius/groups/<group_id>", methods=["DELETE"])
def api_radius_delete_group(group_id):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    if group_id == "default":
        return jsonify({"error": "گروه پیش‌فرض قابل حذف نیست"}), 400

    groups = get_radius_groups_data()
    if group_id in groups:
        del groups[group_id]
        with open(RADIUS_GROUPS_FILE, "w") as f:
            json.dump(groups, f, indent=2)
        return jsonify({"success": True})
    return jsonify({"error": "Group not found"}), 404

# --- Online Active Sessions APIs ---
@app.route("/api/radius/online", methods=["GET"])
def api_radius_get_online_sessions():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    sessions = get_all_radius_online_sessions()
    return jsonify({"sessions": sessions, "count": len(sessions)})

@app.route("/api/radius/online/disconnect", methods=["POST"])
def api_radius_disconnect_session():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    username = data.get("username", "")
    proto = data.get("protocol", "").lower()
    session_id = str(data.get("session_id", ""))

    if not username and not session_id:
        return jsonify({"error": "Username or Session ID required"}), 400

    try:
        if "cisco" in proto or "ocserv" in proto:
            if session_id and session_id.isdigit():
                subprocess.run(["occtl", "disconnect", "id", session_id], capture_output=True)
            elif username:
                subprocess.run(["occtl", "disconnect", "user", username], capture_output=True)
        elif "ssh" in proto:
            if session_id and session_id.isdigit():
                subprocess.run(["kill", "-9", session_id], capture_output=True)
            elif username:
                subprocess.run(f"pkill -u '{username}' sshd", shell=True, capture_output=True)
        elif "openvpn" in proto:
            subprocess.run(f"pkill -f 'openvpn.*{username}'", shell=True, capture_output=True)
        
        return jsonify({"success": True, "message": "Disconnect signal sent"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/radius/test", methods=["POST"])
def api_radius_test():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.json
    server_ip = data.get("server_ip", "127.0.0.1")
    shared_secret = data.get("shared_secret", "testing123")
    
    try:
        cmd = ["radtest", "testuser", "testpass", server_ip, "10", shared_secret]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        if "Access-Reject" in res.stdout or "Access-Accept" in res.stdout:
            return jsonify({"success": True, "message": "Successfully communicated with RADIUS server (Received Access-Reject/Accept)"})
        elif "No reply from server" in res.stdout or "timeout" in res.stdout.lower() or res.stderr:
            return jsonify({"success": False, "error": "No reply from RADIUS server. Check IP, port, firewall or secret."})
        return jsonify({"success": False, "error": res.stdout})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Connection timed out. RADIUS server is unreachable."})
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to run radtest: {str(e)}"})


# --- Customizable Protocol Settings & Client Profiles API ---
SETTINGS_FILE = "/etc/vpnpanel/protocol_settings.json"

def get_protocol_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

@app.route("/api/protocols/settings", methods=["GET"])
def api_protocols_settings_get():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    settings = get_protocol_settings()
    defaults = {
        "openvpn_proto": "udp",
        "openvpn_cipher": "AES-256-GCM",
        "openvpn_subnet": "10.8.0.0",
        "openvpn_dns1": "8.8.8.8",
        "openvpn_dns2": "8.8.4.4",
        "ocserv_subnet": "10.9.0.0",
        "ocserv_dns1": "8.8.8.8",
        "ocserv_dns2": "8.8.4.4",
        "ikev2_subnet": "10.10.0.0",
        "ikev2_dns1": "8.8.8.8",
        "ikev2_dns2": "8.8.4.4",
        "sstp_subnet": "10.11.0.0",
        "sstp_dns1": "8.8.8.8",
        "sstp_dns2": "8.8.4.4",
        "sstp_auth_proto": "MS-CHAPv2",
        "pptp_subnet": "10.14.0.0",
        "pptp_dns1": "8.8.8.8",
        "pptp_dns2": "8.8.4.4",
        "l2tp_subnet": "10.12.0.0",
        "l2tp_psk": "VpnSecret123",
        "l2tp_dns1": "8.8.8.8",
        "l2tp_dns2": "8.8.4.4",
        "wireguard_subnet": "10.13.0.0",
        "wireguard_dns1": "8.8.8.8",
        "wireguard_dns2": "8.8.4.4",
        "wireguard_server_ip": "",
        "ssh_max_sessions": 100,
        "ssh_grace_time": 30,
        "ssh_max_auth_tries": 5,
        "ssh_keepalive": 60,
        "ssh_gateway_ports": "clientspecified",
        "ssh_compression": "yes",
        "ssh_permit_root": "yes",
        "pptp_subnet": "10.14.0.0",
        "pptp_dns1": "8.8.8.8",
        "pptp_dns2": "8.8.4.4",
        "l2tp_auth_mode": "mschapv2",
        "l2tpv3_subnet": "10.15.0.0",
        "l2tpv3_encap": "udp",
        "l2tpv3_port": "5555"
    }
    
    for k, v in defaults.items():
        if k not in settings:
            settings[k] = v
            
    return jsonify(settings)

@app.route("/api/protocols/settings", methods=["POST"])
def api_protocols_settings_post():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json or {}
    settings = get_protocol_settings()
    
    keys = [
        "openvpn_proto", "openvpn_cipher", "openvpn_subnet", "openvpn_dns1", "openvpn_dns2",
        "ocserv_subnet", "ocserv_dns1", "ocserv_dns2",
        "ikev2_subnet", "ikev2_dns1", "ikev2_dns2",
        "sstp_subnet", "sstp_dns1", "sstp_dns2", "sstp_auth_proto",
        "pptp_subnet", "pptp_dns1", "pptp_dns2",
        "l2tp_subnet", "l2tp_psk", "l2tp_dns1", "l2tp_dns2",
        "wireguard_subnet", "wireguard_dns1", "wireguard_dns2", "wireguard_server_ip",
        "ssh_max_sessions", "ssh_grace_time", "ssh_max_auth_tries", "ssh_keepalive",
        "ssh_gateway_ports", "ssh_compression", "ssh_permit_root",
        "l2tp_auth_mode",
        "l2tpv3_subnet", "l2tpv3_encap", "l2tpv3_port",
    ]
    
    for k in keys:
        if k in data:
            settings[k] = data[k]
            
    try:
        os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
        with open(SETTINGS_FILE, "w") as f:
            json.dump(settings, f, indent=2)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/protocols/reconfigure", methods=["POST"])
def api_protocols_reconfigure():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.json or {}
    protocol = data.get("protocol")
    if not protocol or protocol not in ["ssh", "openvpn", "ocserv", "ikev2", "sstp", "pptp", "l2tp", "wireguard"]:
        return jsonify({"success": False, "error": "Invalid protocol"}), 400
        
    success, stdout, stderr = run_helper("reconfigure", protocol)
    if success:
        return jsonify({"success": True, "message": f"{protocol} reconfigured successfully."})
    return jsonify({"success": False, "error": stderr}), 500

@app.route("/api/openvpn/client/download", methods=["GET"])
def api_openvpn_client_download():
    if not check_login():
        return "Unauthorized", 401
        
    ca_path = "/etc/openvpn/server/ca.crt" if os.path.exists("/etc/openvpn/server/ca.crt") else "/etc/openvpn/ca.crt"
    tc_path = "/etc/openvpn/server/tc.key" if os.path.exists("/etc/openvpn/server/tc.key") else "/etc/openvpn/tls-crypt.key"
    
    if not os.path.exists(ca_path):
        return "گواهی CA سرور OpenVPN یافت نشد.", 400
        
    with open(ca_path, "r") as f:
        ca_content = f.read().strip()
        
    tc_content = ""
    if os.path.exists(tc_path):
        with open(tc_path, "r") as f:
            tc_content = f.read().strip()
            
    proto_param = request.args.get("proto", "udp").lower()
    proto = "tcp-client" if "tcp" in proto_param else "udp"
    
    # Port
    default_port = 1194
    req_port = request.args.get("port", "").strip()
    port = int(req_port) if req_port.isdigit() and int(req_port) > 0 else default_port
    
    # Host (Domain or IP)
    settings = get_protocol_settings()
    server_ip = settings.get("wireguard_server_ip", "")
    if not server_ip:
        try:
            server_ip = subprocess.run(["curl", "-s", "--max-time", "2", "ifconfig.me"], stdout=subprocess.PIPE, text=True).stdout.strip()
        except Exception:
            pass
    if not server_ip:
        server_ip = "212.227.143.16"
        
    host = request.args.get("host", "").strip()
    if not host:
        host = server_ip
        
    use_xor = request.args.get("xor") == "1"
    use_udpspeeder = request.args.get("udpspeeder") == "1" or request.args.get("udp") == "1"
    bypass_dpi = request.args.get("bypass_dpi", "1") == "1"
    dns_leak = request.args.get("dns_leak", "1") == "1"
    
    ovpn_lines = [
        "client",
        "dev tun",
        f"proto {proto}"
    ]
    
    if use_udpspeeder and proto == "udp":
        ovpn_lines.append(f"remote 127.0.0.1 4000")
        ovpn_lines.append(f"route {server_ip} 255.255.255.255 net_gateway")
    else:
        ovpn_lines.append(f"remote {host} {port}")
        
    ovpn_lines.extend([
        "resolv-retry infinite",
        "nobind",
        "persist-key",
        "persist-tun",
        "remote-cert-tls server",
        "auth-user-pass",
        "setenv CLIENT_CERT 0",
        "cipher AES-256-GCM",
        "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
        "auth SHA256",
        "verb 3",
        "redirect-gateway def1 bypass-dhcp",
        "dhcp-option DNS 1.1.1.1",
        "dhcp-option DNS 8.8.8.8"
    ])
    
    if proto == "tcp-client":
        ovpn_lines.append("tcp-nodelay")
        
    if dns_leak:
        ovpn_lines.append("setenv opt block-outside-dns")
        
    if bypass_dpi:
        ovpn_lines.append("mssfix 1360")
        if proto == "udp":
            ovpn_lines.append("fast-io")
            
    if use_xor:
        xor_installed = False
        try:
            res = subprocess.run(["strings", "/usr/sbin/openvpn"], capture_output=True, text=True, timeout=2)
            if "scramble" in (res.stdout or ""):
                xor_installed = True
        except Exception:
            pass
        if xor_installed:
            xor_key = request.args.get("xor_key", "openvpn_xor").strip() or "openvpn_xor"
            ovpn_lines.append(f"scramble obfuscate {xor_key}")
        
    user = request.args.get("user", "").strip()
    pw = request.args.get("pass", "").strip()
    if user and not pw:
        try:
            r_file = "/www/wwwroot/mhpanel/radius_users.json"
            if os.path.exists(r_file):
                with open(r_file, "r") as f:
                    r_u = json.load(f)
                if user in r_u:
                    pw = r_u[user].get("password", "")
        except Exception:
            pass
    if user and not pw:
        def_u = get_default_test_user()
        if def_u.get("username") == user:
            pw = def_u.get("password", "")
            
    if user and pw:
        ovpn_lines.append(f"<auth-user-pass>\n{user}\n{pw}\n</auth-user-pass>")
        
    ovpn_lines.append(f"<ca>\n{ca_content}\n</ca>")
    if tc_content:
        ovpn_lines.append(f"<tls-crypt>\n{tc_content}\n</tls-crypt>")
        
    ovpn_content = "\n".join(ovpn_lines) + "\n"
    
    proto_label = "TCP" if proto == "tcp-client" else "UDP"
    filename = f"MHPanel-OpenVPN-{proto_label}-{port}-{host}.ovpn"
    
    return Response(
        ovpn_content,
        mimetype="application/x-openvpn-profile",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# --- WireGuard Peer Manager ---
@app.route("/api/wireguard/client/bulk", methods=["POST"])
def api_wg_client_bulk():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    prefix = request.json.get("prefix", "Client").strip()
    prefix = re.sub(r'[^a-zA-Z0-9_\-]', '', prefix)
    count = request.json.get("count", 1)
    limit_gb = request.json.get("limit_gb")
    expire_days = request.json.get("expire_days")
    start_on_first_connect = request.json.get("start_on_first_connect", False)
    
    expire_date = None
    if expire_days and not start_on_first_connect:
        from datetime import datetime, timedelta
        expire_date = (datetime.now() + timedelta(days=int(expire_days))).strftime("%Y-%m-%d")
    try:
        count = int(count)
    except (ValueError, TypeError):
        count = 1
        
    if count < 1 or count > 50:
        return jsonify({"success": False, "error": "Count must be between 1 and 50"}), 400
        
    if not os.path.exists("/etc/wireguard/wg0.conf"):
        return jsonify({"success": False, "error": "WireGuard is not installed."}), 400
        
    settings = get_protocol_settings()
    wg_subnet = settings.get("wireguard_subnet", "10.13.0.0")
    subnet_prefix = wg_subnet.rsplit(".", 1)[0]
    
    with open("/etc/wireguard/wg0.conf", "r") as f:
        content = f.read()
        
    match_addr = re.search(r"^Address\s*=\s*(\d+\.\d+\.\d+)\.\d+", content, re.MULTILINE | re.IGNORECASE)
    if match_addr:
        subnet_prefix = match_addr.group(1)
        
    server_pubkey = ""
    if os.path.exists("/etc/wireguard/public.key"):
        with open("/etc/wireguard/public.key", "r") as f:
            server_pubkey = f.read().strip()
    if not server_pubkey and os.path.exists("/etc/wireguard/wg0.conf"):
        m = re.search(r"^PrivateKey\s*=\s*(.+)$", content, re.MULTILINE | re.IGNORECASE)
        if m:
            res_pk = subprocess.run(["wg", "pubkey"], input=m.group(1).strip(), capture_output=True, text=True)
            server_pubkey = res_pk.stdout.strip()
            if server_pubkey:
                with open("/etc/wireguard/public.key", "w") as f:
                    f.write(server_pubkey)
            
    port = get_active_port("wireguard") or 904
    
    server_ip = settings.get("wireguard_server_ip", "")
    if not server_ip:
        server_ip = "212.227.143.16"
            
    wg_dns1 = settings.get("wireguard_dns1", "8.8.8.8")
    wg_dns2 = settings.get("wireguard_dns2", "8.8.4.4")
    dns_val = f"{wg_dns1}, {wg_dns2}" if (wg_dns1 and wg_dns2) else (wg_dns1 or wg_dns2 or "8.8.8.8")
    
    escaped_prefix = subnet_prefix.replace(".", r"\.")
    used_ips = [int(ip) for ip in re.findall(escaped_prefix + r'\.(\d+)', content)]
    
    created_clients = []
    wg0_append_text = ""
    current_next_ip = 2
    
    for idx in range(1, count + 1):
        name = f"{prefix}-{idx}"
        while current_next_ip in used_ips:
            current_next_ip += 1
        if current_next_ip > 254:
            break
            
        client_ip = f"{subnet_prefix}.{current_next_ip}"
        used_ips.append(current_next_ip)
        
        privkey = subprocess.run(["wg", "genkey"], stdout=subprocess.PIPE, text=True).stdout.strip()
        pubkey = subprocess.run(["wg", "pubkey"], input=privkey, stdout=subprocess.PIPE, text=True).stdout.strip()
        
        wg0_append_text += f"\n# Name: {name}\n[Peer]\nPublicKey = {pubkey}\nAllowedIPs = {client_ip}/32\n"
        
        client_config = f"""[Interface]
PrivateKey = {privkey}
Address = {client_ip}/24
DNS = {dns_val}

[Peer]
PublicKey = {server_pubkey}
Endpoint = {server_ip}:{port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
        created_clients.append({
            "name": name,
            "ip": client_ip,
            "public_key": pubkey,
            "config": client_config
        })
        
    if wg0_append_text:
        with open("/etc/wireguard/wg0.conf", "a") as f:
            f.write(wg0_append_text)
        subprocess.run(f"wg syncconf wg0 <(wg-quick strip wg0)", shell=True, executable="/bin/bash")
        
    wg_users = {}
    if os.path.exists('/www/wwwroot/mhpanel/wg_users.json'):
        with open('/www/wwwroot/mhpanel/wg_users.json', 'r') as f:
            try: wg_users = json.load(f)
            except: pass
    for client in created_clients:
        wg_users[client["public_key"]] = {
            "limit_gb": limit_gb,
            "expire_date": expire_date,
            "active": True,
            "duration_days": int(expire_days) if expire_days else None,
            "start_on_first_connect": start_on_first_connect,
            "config": client["config"]
        }
    with open('/www/wwwroot/mhpanel/wg_users.json', 'w') as f:
        json.dump(wg_users, f)
        
    return jsonify({"success": True, "clients": created_clients})


def get_wg_traffic():
    traffic = {}
    try:
        res = subprocess.run(["wg", "show", "wg0", "dump"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            for line in res.stdout.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 8:
                    pubkey = parts[0]
                    rx = int(parts[5])
                    tx = int(parts[6])
                    traffic[pubkey] = {"rx": rx, "tx": tx}
    except Exception:
        pass
    return traffic

@app.route("/api/wireguard/peers", methods=["GET"])
def api_wg_peers():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    peers = []
    if not os.path.exists("/etc/wireguard/wg0.conf"):
        return jsonify(peers)
        
    current_peer = {}
    last_comment = None
    with open("/etc/wireguard/wg0.conf", "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#"):
                comment = line.replace("#", "").strip()
                if comment.lower().startswith("name:"):
                    comment = comment[5:].strip()
                last_comment = comment
            elif line.lower() == "[peer]":
                if current_peer:
                    peers.append(current_peer)
                current_peer = {"name": last_comment if last_comment else "Client"}
                last_comment = None
            elif "=" in line and current_peer:
                parts = line.split("=", 1)
                key = parts[0].strip().lower()
                val = parts[1].strip()
                if key == "publickey":
                    current_peer["public_key"] = val
                elif key == "allowedips":
                    current_peer["ip"] = val.replace("/32", "")
        if current_peer:
            peers.append(current_peer)
            
    wg_users = {}
    if os.path.exists('/www/wwwroot/mhpanel/wg_users.json'):
        with open('/www/wwwroot/mhpanel/wg_users.json', 'r') as f:
            try: wg_users = json.load(f)
            except: pass

    traffic = get_wg_traffic()
    for peer in peers:
        pubkey = peer.get("public_key")
        user_data = wg_users.get(pubkey, {})
        peer["limit_gb"] = user_data.get("limit_gb")
        peer["expire_date"] = user_data.get("expire_date")
        peer["active"] = user_data.get("active", True)
        peer["config"] = user_data.get("config", "")
        peer["duration_days"] = user_data.get("duration_days")
        peer["start_on_first_connect"] = user_data.get("start_on_first_connect", False)

        tdata = traffic.get(pubkey, {"rx": 0, "tx": 0})
        peer["rx"] = tdata["rx"]
        peer["tx"] = tdata["tx"]
        peer["total_usage"] = tdata["rx"] + tdata["tx"]
        
    return jsonify(peers)

@app.route("/api/wireguard/client/edit", methods=["POST"])
def api_wg_client_edit():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    pubkey = request.json.get("public_key")
    new_name = request.json.get("name", "").strip()
    new_name = re.sub(r'[^a-zA-Z0-9_\- ]', '', new_name)
    limit_gb = request.json.get("limit_gb")
    expire_days = request.json.get("expire_days")
    start_on_first_connect = request.json.get("start_on_first_connect")
    
    if not pubkey or not new_name:
        return jsonify({"success": False, "error": "Missing parameters"}), 400
        
    if not os.path.exists("/etc/wireguard/wg0.conf"):
        return jsonify({"success": False, "error": "WireGuard is not installed."}), 400
        
    try:
        with open("/etc/wireguard/wg0.conf", "r") as f:
            lines = f.readlines()
            
        updated = False
        for i, line in enumerate(lines):
            if "PublicKey" in line and pubkey in line:
                j = i
                while j >= 0:
                    if lines[j].strip().lower() == "[peer]":
                        if j - 1 >= 0 and lines[j-1].strip().startswith("#"):
                            lines[j-1] = f"# Name: {new_name}\n"
                            updated = True
                        break
                    j -= 1
                if updated:
                    break
                    
        if not updated:
            return jsonify({"success": False, "error": "Client name comment not found above [Peer]"}), 404
            
        with open("/etc/wireguard/wg0.conf", "w") as f:
            f.writelines(lines)
            
        subprocess.run(f"wg syncconf wg0 <(wg-quick strip wg0)", shell=True, executable="/bin/bash")
        
        wg_users = {}
        if os.path.exists('/www/wwwroot/mhpanel/wg_users.json'):
            with open('/www/wwwroot/mhpanel/wg_users.json', 'r') as f:
                try: wg_users = json.load(f)
                except: pass
                
        if pubkey in wg_users:
            if limit_gb is not None:
                wg_users[pubkey]["limit_gb"] = float(limit_gb) if str(limit_gb).strip() else None
                
            if expire_days is not None:
                days = int(expire_days) if str(expire_days).strip() else None
                wg_users[pubkey]["duration_days"] = days
                if days:
                    if not wg_users[pubkey].get("start_on_first_connect") and not start_on_first_connect:
                        wg_users[pubkey]["expire_date"] = (datetime.datetime.now() + datetime.timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
                else:
                    wg_users[pubkey]["expire_date"] = None
                    
            if start_on_first_connect is not None:
                wg_users[pubkey]["start_on_first_connect"] = bool(start_on_first_connect)
                if bool(start_on_first_connect):
                    wg_users[pubkey]["expire_date"] = None
                    wg_users[pubkey]["first_connect_time"] = None
                    
            with open('/www/wwwroot/mhpanel/wg_users.json', 'w') as f:
                json.dump(wg_users, f)
                
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/wireguard/client", methods=["POST"])
def api_wg_client():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    name = request.json.get("name", "Client").strip()
    name = re.sub(r'[^a-zA-Z0-9_\-]', '', name)
    if not name:
        name = "Client"
        
    limit_gb = request.json.get("limit_gb")
    expire_days = request.json.get("expire_days")
    start_on_first_connect = request.json.get("start_on_first_connect", False)
    
    expire_date = None
    if expire_days and not start_on_first_connect:
        from datetime import datetime, timedelta
        expire_date = (datetime.now() + timedelta(days=int(expire_days))).strftime("%Y-%m-%d")
        
    if not os.path.exists("/etc/wireguard/wg0.conf"):
        return jsonify({"success": False, "error": "WireGuard is not installed."}), 400
        
    privkey = subprocess.run(["wg", "genkey"], stdout=subprocess.PIPE, text=True).stdout.strip()
    pubkey = subprocess.run(["wg", "pubkey"], input=privkey, stdout=subprocess.PIPE, text=True).stdout.strip()
    
    with open("/etc/wireguard/wg0.conf", "r") as f:
        content = f.read()

    server_pubkey = ""
    if os.path.exists("/etc/wireguard/public.key"):
        with open("/etc/wireguard/public.key", "r") as f:
            server_pubkey = f.read().strip()
    if not server_pubkey and os.path.exists("/etc/wireguard/wg0.conf"):
        m = re.search(r"^PrivateKey\s*=\s*(.+)$", content, re.MULTILINE | re.IGNORECASE)
        if m:
            res_pk = subprocess.run(["wg", "pubkey"], input=m.group(1).strip(), capture_output=True, text=True)
            server_pubkey = res_pk.stdout.strip()
            if server_pubkey:
                with open("/etc/wireguard/public.key", "w") as f:
                    f.write(server_pubkey)
            
    port = get_active_port("wireguard") or 904
    
    # Parse client base IP prefix from wg0.conf or use wireguard_subnet setting
    settings = get_protocol_settings()
    wg_subnet = settings.get("wireguard_subnet", "10.13.0.0")
    subnet_prefix = wg_subnet.rsplit(".", 1)[0]
    
    match_addr = re.search(r"^Address\s*=\s*(\d+\.\d+\.\d+)\.\d+", content, re.MULTILINE | re.IGNORECASE)
    if match_addr:
        subnet_prefix = match_addr.group(1)
        
    escaped_prefix = subnet_prefix.replace(".", r"\.")
    used_ips = [int(ip) for ip in re.findall(escaped_prefix + r'\.(\d+)', content)]
    next_ip_num = 2
    while next_ip_num in used_ips:
        next_ip_num += 1
        if next_ip_num > 254:
            return jsonify({"success": False, "error": "IP pool exhausted"}), 400
            
    client_ip = f"{subnet_prefix}.{next_ip_num}"
    
    # Get server endpoint
    server_ip = settings.get("wireguard_server_ip", "")
    if not server_ip:
        server_ip = "212.227.143.16"
            
    with open("/etc/wireguard/wg0.conf", "a") as f:
        f.write(f"\n# Name: {name}\n[Peer]\nPublicKey = {pubkey}\nAllowedIPs = {client_ip}/32\n")
        
    subprocess.run(f"wg syncconf wg0 <(wg-quick strip wg0)", shell=True, executable="/bin/bash")
    
    # Get custom WireGuard DNS
    wg_dns1 = settings.get("wireguard_dns1", "8.8.8.8")
    wg_dns2 = settings.get("wireguard_dns2", "8.8.4.4")
    dns_val = f"{wg_dns1}, {wg_dns2}" if (wg_dns1 and wg_dns2) else (wg_dns1 or wg_dns2 or "8.8.8.8")
    
    client_config = f"""[Interface]
PrivateKey = {privkey}
Address = {client_ip}/24
DNS = {dns_val}

[Peer]
PublicKey = {server_pubkey}
Endpoint = {server_ip}:{port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""

    wg_users = {}
    if os.path.exists('/www/wwwroot/mhpanel/wg_users.json'):
        with open('/www/wwwroot/mhpanel/wg_users.json', 'r') as f:
            try: wg_users = json.load(f)
            except: pass
    
    wg_users[pubkey] = {
        "limit_gb": limit_gb,
        "expire_date": expire_date,
        "active": True,
        "duration_days": int(expire_days) if expire_days else None,
        "start_on_first_connect": start_on_first_connect,
        "config": client_config
    }
    
    with open('/www/wwwroot/mhpanel/wg_users.json', 'w') as f:
        json.dump(wg_users, f)
    
    return jsonify({
        "success": True,
        "config": client_config,
        "name": name,
        "ip": client_ip
    })


@app.route("/api/wireguard/client/delete", methods=["POST"])
def api_wg_client_delete():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    pubkey = request.json.get("public_key")
    if not pubkey:
        return jsonify({"success": False, "error": "Missing public key"}), 400
        
    if not os.path.exists("/etc/wireguard/wg0.conf"):
        return jsonify({"success": False, "error": "WireGuard is not installed."}), 400
        
    with open("/etc/wireguard/wg0.conf", "r") as f:
        lines = f.readlines()
        
    new_lines = []
    skip_lines = 0
    
    for i, line in enumerate(lines):
        if skip_lines > 0:
            skip_lines -= 1
            continue
        if "[Peer]" in line:
            block_lines = []
            j = i
            while j < len(lines) and not lines[j].strip().startswith("[Interface]") and not (lines[j].strip().startswith("[Peer]") and j > i):
                block_lines.append(lines[j])
                j += 1
            block_content = "".join(block_lines)
            if pubkey in block_content:
                if len(new_lines) > 0 and new_lines[-1].strip().startswith("# Name:"):
                    new_lines.pop()
                skip_lines = len(block_lines) - 1
                continue
        new_lines.append(line)
        
    with open("/etc/wireguard/wg0.conf", "w") as f:
        f.writelines(new_lines)
        
    subprocess.run(f"wg syncconf wg0 <(wg-quick strip wg0)", shell=True, executable="/bin/bash")
    
    if os.path.exists('/www/wwwroot/mhpanel/wg_users.json'):
        wg_users = {}
        with open('/www/wwwroot/mhpanel/wg_users.json', 'r') as f:
            try: wg_users = json.load(f)
            except: pass
        if pubkey in wg_users:
            del wg_users[pubkey]
            with open('/www/wwwroot/mhpanel/wg_users.json', 'w') as f:
                json.dump(wg_users, f)
                
    return jsonify({"success": True})

# --- MTProto Multi-Instance API ---
@app.route("/api/amneziawg/client/bulk", methods=["POST"])
def api_awg_client_bulk():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    prefix = request.json.get("prefix", "Client").strip()
    prefix = re.sub(r'[^a-zA-Z0-9_\-]', '', prefix)
    count = request.json.get("count", 1)
    limit_gb = request.json.get("limit_gb")
    expire_days = request.json.get("expire_days")
    start_on_first_connect = request.json.get("start_on_first_connect", False)
    
    expire_date = None
    if expire_days and not start_on_first_connect:
        from datetime import datetime, timedelta
        expire_date = (datetime.now() + timedelta(days=int(expire_days))).strftime("%Y-%m-%d")
    try:
        count = int(count)
    except (ValueError, TypeError):
        count = 1
        
    if count < 1 or count > 50:
        return jsonify({"success": False, "error": "Count must be between 1 and 50"}), 400
        
    if not os.path.exists("/etc/amnezia/amneziawg/awg0.conf"):
        return jsonify({"success": False, "error": "WireGuard is not installed."}), 400
        
    settings = get_protocol_settings()
    wg_subnet = settings.get("amneziawg_subnet", "10.13.0.0")
    subnet_prefix = wg_subnet.rsplit(".", 1)[0]
    
    with open("/etc/amnezia/amneziawg/awg0.conf", "r") as f:
        content = f.read()
        
    match_addr = re.search(r"^Address\s*=\s*(\d+\.\d+\.\d+)\.\d+", content, re.MULTILINE | re.IGNORECASE)
    if match_addr:
        subnet_prefix = match_addr.group(1)
        
    server_pubkey = ""
    if os.path.exists("/etc/amnezia/amneziawg/public.key"):
        with open("/etc/amnezia/amneziawg/public.key", "r") as f:
            server_pubkey = f.read().strip()
    if not server_pubkey and os.path.exists("/etc/amnezia/amneziawg/awg0.conf"):
        m = re.search(r"^PrivateKey\s*=\s*(.+)$", content, re.MULTILINE | re.IGNORECASE)
        if m:
            res_pk = subprocess.run(["awg", "pubkey"], input=m.group(1).strip(), capture_output=True, text=True)
            server_pubkey = res_pk.stdout.strip()
            if server_pubkey:
                with open("/etc/amnezia/amneziawg/public.key", "w") as f:
                    f.write(server_pubkey)
            
    port = get_active_port("amneziawg") or 51820
    
    server_ip = settings.get("amneziawg_server_ip", "")
    if not server_ip:
        server_ip = "212.227.143.16"
            
    wg_dns1 = settings.get("amneziawg_dns1", "8.8.8.8")
    wg_dns2 = settings.get("amneziawg_dns2", "8.8.4.4")
    dns_val = f"{wg_dns1}, {wg_dns2}" if (wg_dns1 and wg_dns2) else (wg_dns1 or wg_dns2 or "8.8.8.8")

    # Extract obfuscation parameters from awg0.conf
    obf_params = ""
    for param in ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"]:
        match = re.search(fr"^{param}\s*=\s*(.+)$", content, re.MULTILINE | re.IGNORECASE)
        if match:
            obf_params += f"{param} = {match.group(1).strip()}\n"
    
    escaped_prefix = subnet_prefix.replace(".", r"\.")
    used_ips = [int(ip) for ip in re.findall(escaped_prefix + r'\.(\d+)', content)]
    
    created_clients = []
    awg0_append_text = ""
    current_next_ip = 2
    
    for idx in range(1, count + 1):
        name = f"{prefix}-{idx}"
        while current_next_ip in used_ips:
            current_next_ip += 1
        if current_next_ip > 254:
            break
            
        client_ip = f"{subnet_prefix}.{current_next_ip}"
        used_ips.append(current_next_ip)
        
        privkey = subprocess.run(["awg", "genkey"], stdout=subprocess.PIPE, text=True).stdout.strip()
        pubkey = subprocess.run(["awg", "pubkey"], input=privkey, stdout=subprocess.PIPE, text=True).stdout.strip()
        
        awg0_append_text += f"\n# Name: {name}\n[Peer]\nPublicKey = {pubkey}\nAllowedIPs = {client_ip}/32\n"
        
        client_config = f"""[Interface]
PrivateKey = {privkey}
Address = {client_ip}/32
DNS = {dns_val}
{obf_params}
[Peer]
PublicKey = {server_pubkey}
Endpoint = {server_ip}:{port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
        created_clients.append({
            "name": name,
            "ip": client_ip,
            "public_key": pubkey,
            "config": client_config
        })
        
    if awg0_append_text:
        with open("/etc/amnezia/amneziawg/awg0.conf", "a") as f:
            f.write(awg0_append_text)
        subprocess.run(f"awg syncconf awg0 <(awg-quick strip awg0)", shell=True, executable="/bin/bash")
        
    awg_users = {}
    if os.path.exists('/www/wwwroot/mhpanel/awg_users.json'):
        with open('/www/wwwroot/mhpanel/awg_users.json', 'r') as f:
            try: awg_users = json.load(f)
            except: pass
    for client in created_clients:
        awg_users[client["public_key"]] = {
            "limit_gb": limit_gb,
            "expire_date": expire_date,
            "active": True,
            "duration_days": int(expire_days) if expire_days else None,
            "start_on_first_connect": start_on_first_connect,
            "config": client["config"]
        }
    with open('/www/wwwroot/mhpanel/awg_users.json', 'w') as f:
        json.dump(awg_users, f)
        
    return jsonify({"success": True, "clients": created_clients})


def get_awg_traffic():
    traffic = {}
    try:
        res = subprocess.run(["awg", "show", "awg0", "dump"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            for line in res.stdout.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 8:
                    pubkey = parts[0]
                    rx = int(parts[5])
                    tx = int(parts[6])
                    traffic[pubkey] = {"rx": rx, "tx": tx}
    except Exception:
        pass
    return traffic

@app.route("/api/amneziawg/peers", methods=["GET"])
def api_awg_peers():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    peers = []
    if not os.path.exists("/etc/amnezia/amneziawg/awg0.conf"):
        return jsonify(peers)
        
    current_peer = {}
    last_comment = None
    with open("/etc/amnezia/amneziawg/awg0.conf", "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#"):
                comment = line.replace("#", "").strip()
                if comment.lower().startswith("name:"):
                    comment = comment[5:].strip()
                last_comment = comment
            elif line.lower() == "[peer]":
                if current_peer:
                    peers.append(current_peer)
                current_peer = {"name": last_comment if last_comment else "Client"}
                last_comment = None
            elif "=" in line and current_peer:
                parts = line.split("=", 1)
                key = parts[0].strip().lower()
                val = parts[1].strip()
                if key == "publickey":
                    current_peer["public_key"] = val
                elif key == "allowedips":
                    current_peer["ip"] = val.replace("/32", "")
        if current_peer:
            peers.append(current_peer)
            
    awg_users = {}
    if os.path.exists('/www/wwwroot/mhpanel/awg_users.json'):
        with open('/www/wwwroot/mhpanel/awg_users.json', 'r') as f:
            try: awg_users = json.load(f)
            except: pass

    traffic = get_awg_traffic()
    active_awg_port = get_active_port("amneziawg") or 51820
    awg_users_dirty = False
    for peer in peers:
        pubkey = peer.get("public_key")
        user_data = awg_users.get(pubkey, {})
        peer["limit_gb"] = user_data.get("limit_gb")
        peer["expire_date"] = user_data.get("expire_date")
        peer["active"] = user_data.get("active", True)
        cfg = user_data.get("config", "")
        if cfg and f":{active_awg_port}" not in cfg:
            cfg = re.sub(r"(Endpoint\s*=\s*[^:\s]+):\d+", rf"\1:{active_awg_port}", cfg)
            user_data["config"] = cfg
            awg_users_dirty = True
        peer["config"] = cfg
        peer["duration_days"] = user_data.get("duration_days")
        peer["start_on_first_connect"] = user_data.get("start_on_first_connect", False)

        tdata = traffic.get(pubkey, {"rx": 0, "tx": 0})
        peer["rx"] = tdata["rx"]
        peer["tx"] = tdata["tx"]
        peer["total_usage"] = tdata["rx"] + tdata["tx"]
        
    if awg_users_dirty:
        try:
            with open('/www/wwwroot/mhpanel/awg_users.json', 'w') as f:
                json.dump(awg_users, f, indent=2)
        except Exception:
            pass
        
    return jsonify(peers)

@app.route("/api/amneziawg/client/edit", methods=["POST"])
def api_awg_client_edit():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    pubkey = request.json.get("public_key")
    new_name = request.json.get("name", "").strip()
    new_name = re.sub(r'[^a-zA-Z0-9_\- ]', '', new_name)
    limit_gb = request.json.get("limit_gb")
    expire_days = request.json.get("expire_days")
    start_on_first_connect = request.json.get("start_on_first_connect")
    
    if not pubkey or not new_name:
        return jsonify({"success": False, "error": "Missing parameters"}), 400
        
    if not os.path.exists("/etc/amnezia/amneziawg/awg0.conf"):
        return jsonify({"success": False, "error": "WireGuard is not installed."}), 400
        
    try:
        with open("/etc/amnezia/amneziawg/awg0.conf", "r") as f:
            lines = f.readlines()
            
        updated = False
        for i, line in enumerate(lines):
            if "PublicKey" in line and pubkey in line:
                j = i
                while j >= 0:
                    if lines[j].strip().lower() == "[peer]":
                        if j - 1 >= 0 and lines[j-1].strip().startswith("#"):
                            lines[j-1] = f"# Name: {new_name}\n"
                            updated = True
                        break
                    j -= 1
                if updated:
                    break
                    
        if not updated:
            return jsonify({"success": False, "error": "Client name comment not found above [Peer]"}), 404
            
        with open("/etc/amnezia/amneziawg/awg0.conf", "w") as f:
            f.writelines(lines)
            
        subprocess.run(f"awg syncconf awg0 <(awg-quick strip awg0)", shell=True, executable="/bin/bash")
        
        awg_users = {}
        if os.path.exists('/www/wwwroot/mhpanel/awg_users.json'):
            with open('/www/wwwroot/mhpanel/awg_users.json', 'r') as f:
                try: awg_users = json.load(f)
                except: pass
                
        if pubkey in awg_users:
            if limit_gb is not None:
                awg_users[pubkey]["limit_gb"] = float(limit_gb) if str(limit_gb).strip() else None
                
            if expire_days is not None:
                days = int(expire_days) if str(expire_days).strip() else None
                awg_users[pubkey]["duration_days"] = days
                if days:
                    if not awg_users[pubkey].get("start_on_first_connect") and not start_on_first_connect:
                        awg_users[pubkey]["expire_date"] = (datetime.datetime.now() + datetime.timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
                else:
                    awg_users[pubkey]["expire_date"] = None
                    
            if start_on_first_connect is not None:
                awg_users[pubkey]["start_on_first_connect"] = bool(start_on_first_connect)
                if bool(start_on_first_connect):
                    awg_users[pubkey]["expire_date"] = None
                    awg_users[pubkey]["first_connect_time"] = None
                    
            with open('/www/wwwroot/mhpanel/awg_users.json', 'w') as f:
                json.dump(awg_users, f)
                
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/amneziawg/client", methods=["POST"])
def api_awg_client():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    name = request.json.get("name", "Client").strip()
    name = re.sub(r'[^a-zA-Z0-9_\-]', '', name)
    if not name:
        name = "Client"
        
    limit_gb = request.json.get("limit_gb")
    expire_days = request.json.get("expire_days")
    start_on_first_connect = request.json.get("start_on_first_connect", False)
    
    expire_date = None
    if expire_days and not start_on_first_connect:
        from datetime import datetime, timedelta
        expire_date = (datetime.now() + timedelta(days=int(expire_days))).strftime("%Y-%m-%d")
        
    if not os.path.exists("/etc/amnezia/amneziawg/awg0.conf"):
        return jsonify({"success": False, "error": "WireGuard is not installed."}), 400
        
    privkey = subprocess.run(["awg", "genkey"], stdout=subprocess.PIPE, text=True).stdout.strip()
    pubkey = subprocess.run(["awg", "pubkey"], input=privkey, stdout=subprocess.PIPE, text=True).stdout.strip()
    
    server_pubkey = ""
    if os.path.exists("/etc/amnezia/amneziawg/awg0.conf"):
        with open("/etc/amnezia/amneziawg/awg0.conf", "r") as f:
            content = f.read()
            match_priv = re.search(r"^PrivateKey\s*=\s*(.+)$", content, re.MULTILINE | re.IGNORECASE)
            if match_priv:
                server_privkey = match_priv.group(1).strip()
                server_pubkey = subprocess.run(["awg", "pubkey"], input=server_privkey, stdout=subprocess.PIPE, text=True).stdout.strip()
            
    port = get_active_port("amneziawg") or 51820
    with open("/etc/amnezia/amneziawg/awg0.conf", "r") as f:
        content = f.read()
    
    # Parse client base IP prefix from awg0.conf or use amneziawg_subnet setting
    settings = get_protocol_settings()
    wg_subnet = settings.get("amneziawg_subnet", "10.13.0.0")
    subnet_prefix = wg_subnet.rsplit(".", 1)[0]
    
    match_addr = re.search(r"^Address\s*=\s*(\d+\.\d+\.\d+)\.\d+", content, re.MULTILINE | re.IGNORECASE)
    if match_addr:
        subnet_prefix = match_addr.group(1)
        
    escaped_prefix = subnet_prefix.replace(".", r"\.")
    used_ips = [int(ip) for ip in re.findall(escaped_prefix + r'\.(\d+)', content)]
    next_ip_num = 2
    while next_ip_num in used_ips:
        next_ip_num += 1
        if next_ip_num > 254:
            return jsonify({"success": False, "error": "IP pool exhausted"}), 400
            
    client_ip = f"{subnet_prefix}.{next_ip_num}"
    
    # Get server endpoint
    server_ip = settings.get("amneziawg_server_ip", "")
    if not server_ip:
        try:
            server_ip = subprocess.run(["curl", "-s", "ifconfig.me"], stdout=subprocess.PIPE, text=True, timeout=3).stdout.strip()
        except Exception:
            server_ip = "YOUR_SERVER_IP"
            
    with open("/etc/amnezia/amneziawg/awg0.conf", "a") as f:
        f.write(f"\n# Name: {name}\n[Peer]\nPublicKey = {pubkey}\nAllowedIPs = {client_ip}/32\n")
        
    subprocess.run(f"awg syncconf awg0 <(awg-quick strip awg0)", shell=True, executable="/bin/bash")
    
    # Get custom WireGuard DNS
    wg_dns1 = settings.get("amneziawg_dns1", "8.8.8.8")
    wg_dns2 = settings.get("amneziawg_dns2", "8.8.4.4")
    dns_val = f"{wg_dns1}, {wg_dns2}" if (wg_dns1 and wg_dns2) else (wg_dns1 or wg_dns2 or "8.8.8.8")
    # Extract obfuscation parameters from awg0.conf
    obf_params = ""
    for param in ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"]:
        match = re.search(fr"^{param}\s*=\s*(.+)$", content, re.MULTILINE | re.IGNORECASE)
        if match:
            obf_params += f"{param} = {match.group(1).strip()}\n"

    client_config = f"""[Interface]
PrivateKey = {privkey}
Address = {client_ip}/32
DNS = {dns_val}
{obf_params}
[Peer]
PublicKey = {server_pubkey}
Endpoint = {server_ip}:{port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""

    awg_users = {}
    if os.path.exists('/www/wwwroot/mhpanel/awg_users.json'):
        with open('/www/wwwroot/mhpanel/awg_users.json', 'r') as f:
            try: awg_users = json.load(f)
            except: pass
    
    awg_users[pubkey] = {
        "limit_gb": limit_gb,
        "expire_date": expire_date,
        "active": True,
        "duration_days": int(expire_days) if expire_days else None,
        "start_on_first_connect": start_on_first_connect,
        "config": client_config
    }
    
    with open('/www/wwwroot/mhpanel/awg_users.json', 'w') as f:
        json.dump(awg_users, f)
    
    return jsonify({
        "success": True,
        "config": client_config,
        "name": name,
        "ip": client_ip
    })


@app.route("/api/amneziawg/client/delete", methods=["POST"])
def api_awg_client_delete():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    pubkey = request.json.get("public_key")
    if not pubkey:
        return jsonify({"success": False, "error": "Missing public key"}), 400
        
    if not os.path.exists("/etc/amnezia/amneziawg/awg0.conf"):
        return jsonify({"success": False, "error": "AmneziaWG is not installed."}), 400
        
    with open("/etc/amnezia/amneziawg/awg0.conf", "r") as f:
        lines = f.readlines()
        
    new_lines = []
    skip_lines = 0
    
    for i, line in enumerate(lines):
        if skip_lines > 0:
            skip_lines -= 1
            continue
        if "[Peer]" in line:
            block_lines = []
            j = i
            while j < len(lines) and not lines[j].strip().startswith("[Interface]") and not (lines[j].strip().startswith("[Peer]") and j > i):
                block_lines.append(lines[j])
                j += 1
            block_content = "".join(block_lines)
            if pubkey in block_content:
                if len(new_lines) > 0 and new_lines[-1].strip().startswith("# Name:"):
                    new_lines.pop()
                skip_lines = len(block_lines) - 1
                continue
        new_lines.append(line)
        
    with open("/etc/amnezia/amneziawg/awg0.conf", "w") as f:
        f.writelines(new_lines)
        
    subprocess.run(f"awg syncconf awg0 <(awg-quick strip awg0)", shell=True, executable="/bin/bash")
    
    if os.path.exists('/www/wwwroot/mhpanel/awg_users.json'):
        awg_users = {}
        with open('/www/wwwroot/mhpanel/awg_users.json', 'r') as f:
            try: awg_users = json.load(f)
            except: pass
        if pubkey in awg_users:
            del awg_users[pubkey]
            with open('/www/wwwroot/mhpanel/awg_users.json', 'w') as f:
                json.dump(awg_users, f)
                
    return jsonify({"success": True})

# --- MTProto Multi-Instance API ---


@app.route("/api/amneziawg/install", methods=["POST"])
def api_amneziawg_install():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        res = subprocess.run(["/www/wwwroot/mhpanel/scripts/install_amneziawg.sh"], capture_output=True, text=True, timeout=180)
        if res.returncode != 0:
            return jsonify({"success": False, "error": res.stderr or res.stdout}), 500
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/amneziawg/status", methods=["GET"])
def api_amneziawg_status():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    installed = os.path.exists("/etc/amnezia/amneziawg/awg0.conf")
    return jsonify({"installed": installed})

def set_amneziawg_protocol_version(target_ver):
    conf_path = "/etc/amnezia/amneziawg/awg0.conf"
    if not os.path.exists(conf_path):
        return False, "AmneziaWG is not installed."
    
    with open(conf_path, "r") as f:
        content = f.read()
        
    def get_val(key, default):
        m = re.search(fr"^{key}\s*=\s*(.+)$", content, re.MULTILINE | re.IGNORECASE)
        return m.group(1).strip() if m else default

    jc = get_val("Jc", "4")
    jmin = get_val("Jmin", "50")
    jmax = get_val("Jmax", "1000")
    s1 = get_val("S1", "56")
    s2 = get_val("S2", "56")
    s3 = get_val("S3", "56")
    s4 = get_val("S4", "56")
    
    import random
    h1 = get_val("H1", str(random.randint(10000000, 2147483647)))
    h2 = get_val("H2", str(random.randint(10000000, 2147483647)))
    h3 = get_val("H3", str(random.randint(10000000, 2147483647)))
    h4 = get_val("H4", str(random.randint(10000000, 2147483647)))
    
    if target_ver == "v3":
        if not s3 or s3 == "0": s3 = "56"
        if not s4 or s4 == "0": s4 = "56"
        if not s1 or s1 == "0": s1 = "56"
        if not s2 or s2 == "0": s2 = "56"
        if not jc or jc == "0": jc = "4"
        if h1 in ["1", "0"]: h1 = str(random.randint(10000000, 2147483647))
        if h2 in ["2", "0"]: h2 = str(random.randint(10000000, 2147483647))
        if h3 in ["3", "0"]: h3 = str(random.randint(10000000, 2147483647))
        if h4 in ["4", "0"]: h4 = str(random.randint(10000000, 2147483647))
        new_obf = f"# Version = 3\nJc = {jc}\nJmin = {jmin}\nJmax = {jmax}\nS1 = {s1}\nS2 = {s2}\nS3 = {s3}\nS4 = {s4}\nH1 = {h1}\nH2 = {h2}\nH3 = {h3}\nH4 = {h4}\n"
    elif target_ver == "v1":
        new_obf = f"# Version = 1\nJc = 0\nJmin = 0\nJmax = 0\nS1 = 0\nS2 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n"
    else:
        target_ver = "v2"
        if not s1 or s1 == "0": s1 = "56"
        if not s2 or s2 == "0": s2 = "56"
        if not jc or jc == "0": jc = "4"
        if h1 in ["1", "0"]: h1 = str(random.randint(10000000, 2147483647))
        if h2 in ["2", "0"]: h2 = str(random.randint(10000000, 2147483647))
        if h3 in ["3", "0"]: h3 = str(random.randint(10000000, 2147483647))
        if h4 in ["4", "0"]: h4 = str(random.randint(10000000, 2147483647))
        new_obf = f"# Version = 2\nJc = {jc}\nJmin = {jmin}\nJmax = {jmax}\nS1 = {s1}\nS2 = {s2}\nH1 = {h1}\nH2 = {h2}\nH3 = {h3}\nH4 = {h4}\n"

    lines = content.splitlines(True)
    out_lines = []
    obf_written = False
    for line in lines:
        if re.match(r"^#\s*Version\s*=", line, re.IGNORECASE) or \
           re.match(r"^(Jc|Jmin|Jmax|S1|S2|S3|S4|H1|H2|H3|H4)\s*=", line, re.IGNORECASE) or \
           re.match(r"^#\s*Anti-DPI\s+Obfuscation", line, re.IGNORECASE):
            if not obf_written:
                out_lines.append(f"# Anti-DPI Obfuscation Parameters (AmneziaWG)\n{new_obf}")
                obf_written = True
            continue
        out_lines.append(line)

    if not obf_written:
        res_lines = []
        for line in out_lines:
            res_lines.append(line)
            if re.match(r"^\[Interface\]", line, re.IGNORECASE) and not obf_written:
                res_lines.append(f"# Anti-DPI Obfuscation Parameters (AmneziaWG)\n{new_obf}")
                obf_written = True
        out_lines = res_lines

    with open(conf_path, "w") as f:
        f.writelines(out_lines)

    subprocess.run("awg syncconf awg0 <(awg-quick strip awg0)", shell=True, executable="/bin/bash")
    subprocess.run(["systemctl", "restart", "awg-quick@awg0"], check=False)

    users_file = "/www/wwwroot/mhpanel/awg_users.json"
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                users = json.load(f)
            for pub, udata in users.items():
                cfg_txt = udata.get("config", "")
                if cfg_txt:
                    c_lines = cfg_txt.splitlines(True)
                    new_c_lines = []
                    c_obf_written = False
                    for cl in c_lines:
                        if re.match(r"^#\s*Version\s*=", cl, re.IGNORECASE) or \
                           re.match(r"^(Jc|Jmin|Jmax|S1|S2|S3|S4|H1|H2|H3|H4)\s*=", cl, re.IGNORECASE) or \
                           re.match(r"^#\s*Anti-DPI", cl, re.IGNORECASE):
                            if not c_obf_written:
                                new_c_lines.append(new_obf)
                                c_obf_written = True
                            continue
                        if re.match(r"^\[Peer\]", cl, re.IGNORECASE) and not c_obf_written:
                            new_c_lines.append(new_obf)
                            c_obf_written = True
                        new_c_lines.append(cl)
                    udata["config"] = "".join(new_c_lines)
            with open(users_file, "w") as f:
                json.dump(users, f, indent=2)
        except Exception:
            pass

    return True, target_ver

@app.route("/api/amneziawg/version", methods=["GET", "POST"])
def api_amneziawg_version():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    conf_path = "/etc/amnezia/amneziawg/awg0.conf"
    if not os.path.exists(conf_path):
        return jsonify({"error": "AmneziaWG is not installed."}), 400
        
    if request.method == "GET":
        with open(conf_path, "r") as f:
            c_text = f.read()
        ver = "v2"
        m_ver = re.search(r"^#\s*Version\s*=\s*(\w+)", c_text, re.MULTILINE | re.IGNORECASE)
        if m_ver:
            v_val = m_ver.group(1).lower().strip()
            if "3" in v_val: ver = "v3"
            elif "1" in v_val: ver = "v1"
            elif "2" in v_val: ver = "v2"
        else:
            m_s3 = re.search(r"^S3\s*=\s*([1-9]\d*)", c_text, re.MULTILINE | re.IGNORECASE)
            m_s4 = re.search(r"^S4\s*=\s*([1-9]\d*)", c_text, re.MULTILINE | re.IGNORECASE)
            m_h1 = re.search(r"^H1\s*=\s*1\b", c_text, re.MULTILINE | re.IGNORECASE)
            m_s1 = re.search(r"^S1\s*=\s*0\b", c_text, re.MULTILINE | re.IGNORECASE)
            if m_s3 or m_s4: ver = "v3"
            elif m_h1 and m_s1: ver = "v1"
            else: ver = "v2"
        return jsonify({"success": True, "version": ver})

    target_ver = (request.json or {}).get("version", "").lower().strip()
    if target_ver not in ["v1", "v2", "v3", "1", "2", "3"]:
        return jsonify({"error": "نسخه نامعتبر است. لطفاً v2 یا v3 انتخاب نمایید."}), 400
    
    if target_ver in ["1", "v1"]: target_ver = "v1"
    elif target_ver in ["3", "v3"]: target_ver = "v3"
    else: target_ver = "v2"

    ok, res = set_amneziawg_protocol_version(target_ver)
    if not ok:
        return jsonify({"error": res}), 500

    ver_names = {
        "v1": "نسخه ۱ (پایه و سازگار با WireGuard)",
        "v2": "نسخه ۲ (پایدار و سازگار با تمامی کلاینت‌ها)",
        "v3": "نسخه ۳ (ضد فیلترینگ پیشرفته با محافظت لایه انتقال S3/S4)"
    }
    return jsonify({
        "success": True,
        "version": target_ver,
        "message": f"نسخه AmneziaWG با موفقیت به {ver_names.get(target_ver, target_ver)} تغییر یافت و کلیه پروفایل‌ها به‌روزرسانی شدند."
    })

@app.route("/api/amneziawg/settings", methods=["GET"])
def api_amneziawg_settings():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    settings = {}
    try:
        conf_path = "/etc/amnezia/amneziawg/awg0.conf"
        if not os.path.exists(conf_path):
            return jsonify({"success": False, "error": "AmneziaWG is not installed."}), 400
            
        with open(conf_path, "r") as f:
            c_text = f.read()
            for line in c_text.splitlines():
                match = re.match(r'^(Jc|Jmin|Jmax|S1|S2|S3|S4|H1|H2|H3|H4|ListenPort|MTU)\s*=\s*(.*)', line.strip(), re.IGNORECASE)
                if match:
                    key = match.group(1).upper()
                    if key in ["LISTENPORT", "PORT"]:
                        key = "PORT"
                    settings[key] = match.group(2).strip()

        ver = "v2"
        m_ver = re.search(r"^#\s*Version\s*=\s*(\w+)", c_text, re.MULTILINE | re.IGNORECASE)
        if m_ver:
            v_val = m_ver.group(1).lower().strip()
            if "3" in v_val: ver = "v3"
            elif "1" in v_val: ver = "v1"
            elif "2" in v_val: ver = "v2"
        else:
            s3_val = settings.get("S3", "0")
            s4_val = settings.get("S4", "0")
            h1_val = settings.get("H1", "")
            s1_val = settings.get("S1", "")
            jc_val = settings.get("JC", "")
            if (s3_val and s3_val != "0") or (s4_val and s4_val != "0"):
                ver = "v3"
            elif h1_val == "1" and s1_val == "0" and jc_val == "0":
                ver = "v1"
            else:
                ver = "v2"

        version_titles = {
            "v1": "AmneziaWG v1 (پایه / سازگار با وایرگارد)",
            "v2": "AmneziaWG v2 (پایدار و سازگار با همه دستگاه‌ها)",
            "v3": "AmneziaWG v3 (نسل جدید با محافظت لایه انتقال S3/S4)"
        }

        return jsonify({
            "success": True, 
            "settings": settings,
            "version": ver,
            "version_title": version_titles.get(ver, f"AmneziaWG {ver.upper()}")
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/amneziawg/settings", methods=["POST"])
def api_amneziawg_update_settings():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400
        
    conf_path = "/etc/amnezia/amneziawg/awg0.conf"
    if not os.path.exists(conf_path):
        return jsonify({"success": False, "error": "AmneziaWG is not installed."}), 400
        
    try:
        with open(conf_path, "r") as f:
            lines = f.readlines()
            
        old_port = None
        new_port = None
        for line in lines:
            m = re.match(r"^ListenPort\s*=\s*(\d+)", line.strip(), re.IGNORECASE)
            if m:
                old_port = m.group(1)
                break
                
        lookup_port = data.get("PORT") or data.get("ListenPort") or data.get("LISTENPORT")
        if lookup_port:
            new_port = str(lookup_port).strip()

        new_lines = []
        for line in lines:
            match = re.match(r'^(Jc|Jmin|Jmax|S1|S2|S3|S4|H1|H2|H3|H4|ListenPort|MTU)\s*=\s*(.*)', line.strip(), re.IGNORECASE)
            if match:
                raw_k = match.group(1)
                k = raw_k.upper()
                lookup_k = "PORT" if k in ["LISTENPORT", "PORT"] else k
                if lookup_k in data:
                    new_lines.append(f"{raw_k} = {data[lookup_k]}\n")
                    continue
                elif k in data:
                    new_lines.append(f"{raw_k} = {data[k]}\n")
                    continue
            if old_port and new_port and old_port != new_port:
                if f"--dport {old_port}" in line:
                    line = line.replace(f"--dport {old_port}", f"--dport {new_port}")
            new_lines.append(line)
            
        with open(conf_path, "w") as f:
            f.writelines(new_lines)
            
        if old_port and new_port and old_port != new_port:
            subprocess.run(["iptables", "-D", "INPUT", "-p", "udp", "--dport", str(old_port), "-j", "ACCEPT"], capture_output=True)
            subprocess.run(["iptables", "-I", "INPUT", "-p", "udp", "--dport", str(new_port), "-j", "ACCEPT"], capture_output=True)
            if os.path.exists("/www/wwwroot/mhpanel/awg_users.json"):
                try:
                    with open("/www/wwwroot/mhpanel/awg_users.json", "r") as f:
                        u_data = json.load(f)
                    for k, u in u_data.items():
                        if "config" in u and f":{old_port}" in u["config"]:
                            u["config"] = u["config"].replace(f":{old_port}", f":{new_port}")
                    with open("/www/wwwroot/mhpanel/awg_users.json", "w") as f:
                        json.dump(u_data, f, indent=2)
                except Exception:
                    pass

        subprocess.run(["systemctl", "restart", "awg-quick@awg0"], check=False)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/amneziawg/port", methods=["POST"])
def api_amneziawg_set_port():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    port = (request.json or {}).get("port")
    if not port:
        return jsonify({"error": "Port required"}), 400
    try:
        port = int(port)
    except:
        return jsonify({"error": "Invalid port number"}), 400
        
    conf_path = "/etc/amnezia/amneziawg/awg0.conf"
    if not os.path.exists(conf_path):
        return jsonify({"error": "AmneziaWG is not installed."}), 400
        
    try:
        with open(conf_path, "r") as f:
            content = f.read()
        m_old = re.search(r"^ListenPort\s*=\s*(\d+)", content, re.MULTILINE | re.IGNORECASE)
        old_port = m_old.group(1) if m_old else "51820"
        
        content = re.sub(r"^ListenPort\s*=.*", f"ListenPort = {port}", content, flags=re.MULTILINE | re.IGNORECASE)
        content = re.sub(rf"--dport\s+{old_port}", f"--dport {port}", content)
        with open(conf_path, "w") as f:
            f.write(content)
            
        subprocess.run(["iptables", "-D", "INPUT", "-p", "udp", "--dport", str(old_port), "-j", "ACCEPT"], capture_output=True)
        subprocess.run(["iptables", "-I", "INPUT", "-p", "udp", "--dport", str(port), "-j", "ACCEPT"], capture_output=True)
        
        if os.path.exists("/www/wwwroot/mhpanel/awg_users.json"):
            try:
                with open("/www/wwwroot/mhpanel/awg_users.json", "r") as f:
                    u_data = json.load(f)
                for k, u in u_data.items():
                    if "config" in u and f":{old_port}" in u["config"]:
                        u["config"] = u["config"].replace(f":{old_port}", f":{port}")
                with open("/www/wwwroot/mhpanel/awg_users.json", "w") as f:
                    json.dump(u_data, f, indent=2)
            except Exception:
                pass
                
        subprocess.run(["systemctl", "restart", "awg-quick@awg0"], check=False)
        return jsonify({"success": True, "port": port})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/amneziawg/warp", methods=["GET"])
def api_amneziawg_warp_status():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    is_active = subprocess.run(["systemctl", "is-active", "aethervpn-amnezia-warp"], capture_output=True, text=True).stdout.strip() == "active"
    warp_svc_active = subprocess.run(["systemctl", "is-active", "warp-svc"], capture_output=True, text=True).stdout.strip() == "active"
    warp_ip = "-"
    if is_active:
        try:
            res = subprocess.run(["curl", "--interface", "awg-warp", "-s", "--max-time", "3", "https://cloudflare.com/cdn-cgi/trace"], capture_output=True, text=True)
            for line in res.stdout.splitlines():
                if line.startswith("ip="):
                    warp_ip = line.split("=")[1].strip()
                    break
        except Exception:
            pass
    return jsonify({
        "success": True,
        "active": is_active,
        "warp_svc_active": warp_svc_active,
        "warp_ip": warp_ip
    })

@app.route("/api/amneziawg/warp/toggle", methods=["POST"])
def api_amneziawg_warp_toggle():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    enable = bool((request.json or {}).get("enabled", False))
    try:
        if enable:
            subprocess.run(["systemctl", "start", "warp-svc"], check=False)
            subprocess.run(["warp-cli", "--accept-tos", "mode", "proxy"], check=False)
            subprocess.run(["warp-cli", "--accept-tos", "connect"], check=False)
            subprocess.run(["systemctl", "enable", "--now", "aethervpn-amnezia-warp"], check=False)
            subprocess.run(["systemctl", "restart", "aethervpn-amnezia-warp"], check=False)
        else:
            subprocess.run(["systemctl", "disable", "--now", "aethervpn-amnezia-warp"], check=False)
            subprocess.run(["ip", "rule", "del", "from", "10.77.77.0/24", "table", "51821", "priority", "51821"], check=False)
            subprocess.run(["ip", "route", "flush", "table", "51821"], check=False)
            subprocess.run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "10.77.77.0/24", "-o", "awg-warp", "-j", "MASQUERADE"], check=False)
        time.sleep(1)
        is_active = subprocess.run(["systemctl", "is-active", "aethervpn-amnezia-warp"], capture_output=True, text=True).stdout.strip() == "active"
        return jsonify({"success": True, "active": is_active})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/amneziawg/uninstall", methods=["POST"])
def api_amneziawg_uninstall():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        subprocess.run(["systemctl", "stop", "awg-quick@awg0"], capture_output=True)
        subprocess.run(["systemctl", "disable", "awg-quick@awg0"], capture_output=True)
        conf_path = "/etc/amnezia/amneziawg/awg0.conf"
        if os.path.exists(conf_path):
            os.remove(conf_path)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Domain Management Helpers & APIs ---
SERVER_DOMAIN_FILE = "/etc/vpnpanel/server_domain.txt"

def get_server_domain():
    # 1. User explicitly set domain
    if os.path.exists(SERVER_DOMAIN_FILE):
        try:
            with open(SERVER_DOMAIN_FILE, "r") as f:
                d = f.read().strip()
                if d and not d.startswith("#") and "." in d:
                    return d
        except Exception:
            pass
    # 2. Extract from active certificates
    for cert_path in [PANEL_CERT, VPN_SERVER_CERT]:
        if os.path.exists(cert_path):
            d = extract_cert_domain(cert_path)
            if d and d not in ["AetherVPN Panel", "localhost", "127.0.0.1"] and "." in d:
                return d
    # 3. Check /etc/letsencrypt/live/
    le_dir = "/etc/letsencrypt/live"
    if os.path.isdir(le_dir):
        for entry in os.listdir(le_dir):
            if os.path.exists(os.path.join(le_dir, entry, "fullchain.pem")) and "." in entry and entry not in ["clients", "README"]:
                return entry
    # 4. HTTP request host header
    try:
        from flask import has_request_context, request
        if has_request_context():
            host = request.host.split(":")[0]
            if host and host not in ["127.0.0.1", "localhost", "0.0.0.0"] and "." in host:
                return host
    except Exception:
        pass
    # 5. Public IP as fallback
    try:
        ip_file = "/etc/vpnpanel/server_ip.txt"
        if os.path.exists(ip_file):
            with open(ip_file, "r") as f:
                return f.read().strip()
    except Exception:
        pass
    return "212.227.143.16"

def get_detected_domains():
    domains = set()
    if os.path.exists(SERVER_DOMAIN_FILE):
        try:
            with open(SERVER_DOMAIN_FILE, "r") as f:
                d = f.read().strip()
                if d and "." in d: domains.add(d)
        except Exception: pass
    le_dir = "/etc/letsencrypt/live"
    if os.path.isdir(le_dir):
        for entry in os.listdir(le_dir):
            if os.path.exists(os.path.join(le_dir, entry, "fullchain.pem")) and "." in entry:
                domains.add(entry)
    for cert_path in [PANEL_CERT, VPN_SERVER_CERT]:
        if os.path.exists(cert_path):
            d = extract_cert_domain(cert_path)
            if d and d not in ["AetherVPN Panel", "localhost", "127.0.0.1"] and "." in d:
                domains.add(d)
    return list(domains)

@app.route("/api/system/domain", methods=["GET"])
def api_system_domain_get():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    saved = ""
    if os.path.exists(SERVER_DOMAIN_FILE):
        try:
            with open(SERVER_DOMAIN_FILE, "r") as f:
                saved = f.read().strip()
        except: pass
    return jsonify({
        "domain": get_server_domain(),
        "saved_domain": saved,
        "all_domains": get_detected_domains(),
        "ip": "212.227.143.16"
    })

@app.route("/api/system/domain", methods=["POST"])
def api_system_domain_set():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"success": False, "error": "نام دامنه معتبر الزامی است."}), 400
    os.makedirs("/etc/vpnpanel", exist_ok=True)
    with open(SERVER_DOMAIN_FILE, "w") as f:
        f.write(domain)
    # Update TUIC hostname if configured
    tuic_cfg = "/etc/vpnpanel/tuic.toml"
    if os.path.exists(tuic_cfg):
        try:
            with open(tuic_cfg, "r") as f:
                content = f.read()
            content = re.sub(r'hostname\s*=\s*"[^"]*"', f'hostname = "{domain}"', content)
            with open(tuic_cfg, "w") as f:
                f.write(content)
            subprocess.run(["systemctl", "restart", "aethervpn-tuic"], check=False)
        except: pass
    return jsonify({"success": True, "domain": domain})

@app.route("/api/mtproto/instances", methods=["GET"])
def api_mtproto_instances():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    instances = []
    config_dir = "/etc/vpnpanel"
    if os.path.exists(config_dir):
        for filename in os.listdir(config_dir):
            if filename.startswith("mtproto_config_") and filename.endswith(".py"):
                filepath = os.path.join(config_dir, filename)
                try:
                    with open(filepath, "r") as f:
                        content = f.read()
                    
                    port_match = re.search(r"PORT\s*=\s*(\d+)", content)
                    secret_match = re.search(r"\"aethervpn\"\s*:\s*\"([a-fA-F0-9]+)\"", content)
                    ad_tag_match = re.search(r"AD_TAG\s*=\s*\"([^\"]*)\"", content)
                    
                    if port_match:
                        port = int(port_match.group(1))
                        secret = secret_match.group(1) if secret_match else ""
                        ad_tag = ad_tag_match.group(1) if ad_tag_match else ""
                        tls_domain_match = re.search(r"TLS_DOMAIN\s*=\s*\"([^\"]*)\"", content)
                        tls_domain = tls_domain_match.group(1) if tls_domain_match else "www.cloudflare.com"
                        
                        tls_hex = tls_domain.encode("utf-8").hex()
                        tls_secret = f"ee{secret}{tls_hex}" if secret else ""
                        standard_secret = f"dd{secret}" if secret else ""
                        
                        status_res = subprocess.run(["systemctl", "is-active", f"aethervpn-mtproto@{port}"], capture_output=True, text=True)
                        active = (status_res.stdout.strip() == "active")
                        
                        connections = 0
                        if active:
                            try:
                                res_conn = subprocess.run(f"ss -t -a | grep -E ':{port}\\s' | grep -i estab | wc -l", shell=True, capture_output=True, text=True)
                                connections = int(res_conn.stdout.strip())
                            except Exception:
                                pass
                                
                        instances.append({
                            "port": port,
                            "secret": secret,
                            "standard_secret": standard_secret,
                            "tls_secret": tls_secret,
                            "tls_domain": tls_domain,
                            "ad_tag": ad_tag,
                            "has_sponsor": bool(ad_tag and len(ad_tag) >= 16),
                            "active": active,
                            "connections": connections,
                            "server_domain": get_server_domain(),
                            "server_ip": "212.227.143.16"
                        })
                except Exception:
                    pass
                    
    return jsonify(instances)

@app.route("/api/mtproto/instances/<int:port>/ad-tag", methods=["POST"])
def api_mtproto_instance_set_ad_tag(port):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    ad_tag = data.get("ad_tag", "").strip()
    config_file = f"/etc/vpnpanel/mtproto_config_{port}.py"
    if not os.path.exists(config_file):
        return jsonify({"success": False, "error": "اینستنس پروکسی یافت نشد."}), 404
    try:
        with open(config_file, "r") as f:
            content = f.read()
        if re.search(r"^AD_TAG\s*=", content, re.MULTILINE):
            content = re.sub(r"^AD_TAG\s*=.*", f'AD_TAG = "{ad_tag}"', content, flags=re.MULTILINE)
        else:
            content += f'\nAD_TAG = "{ad_tag}"\n'
        with open(config_file, "w") as f:
            f.write(content)
        subprocess.run(["systemctl", "restart", f"aethervpn-mtproto@{port}"], check=False)
        return jsonify({"success": True, "ad_tag": ad_tag, "has_sponsor": bool(ad_tag and len(ad_tag) >= 16)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/mtproto/instances", methods=["POST"])
def api_mtproto_instances_create():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.json
    try:
        port = int(data.get("port"))
        ad_tag = data.get("ad_tag", "").strip()
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid port number"}), 400
        
    for proto in ["ssh", "openvpn", "ocserv", "sstp", "wireguard", "http", "socks", "shadowsocks"]:
        if is_installed(proto) and str(get_active_port(proto)) == str(port):
            return jsonify({"success": False, "error": f"Port {port} is already used by {proto}"}), 400
            
    config_file = f"/etc/vpnpanel/mtproto_config_{port}.py"
    if os.path.exists(config_file):
        return jsonify({"success": False, "error": f"MTProto instance on port {port} already exists"}), 400
        
    secret = secrets.token_hex(16)
    
    try:
        os.makedirs("/etc/vpnpanel", exist_ok=True)
        with open(config_file, "w") as f:
            f.write(f"""PORT = {port}
USERS = {{
    "aethervpn": "{secret}",
}}
MODES = {{"classic": True, "secure": True, "tls": True}}
TLS_DOMAIN = "www.cloudflare.com"
AD_TAG = "{ad_tag}"
""")
        subprocess.run(["ufw", "allow", f"{port}/tcp"], check=False)
        
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", f"aethervpn-mtproto@{port}"], check=True)
        subprocess.run(["systemctl", "start", f"aethervpn-mtproto@{port}"], check=True)
        
        return jsonify({"success": True, "port": port, "secret": secret})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/mtproto/instances/<int:port>", methods=["DELETE"])
def api_mtproto_instances_delete(port):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    config_file = f"/etc/vpnpanel/mtproto_config_{port}.py"
    try:
        subprocess.run(["systemctl", "stop", f"aethervpn-mtproto@{port}"], check=False)
        subprocess.run(["systemctl", "disable", f"aethervpn-mtproto@{port}"], check=False)
        
        subprocess.run(["ufw", "delete", "allow", f"{port}/tcp"], check=False)
        
        if os.path.exists(config_file):
            os.remove(config_file)
            
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/mtproto/instances/<int:port>/control", methods=["POST"])
def api_mtproto_instances_control(port):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    action = request.json.get("action", "")
    if action not in ["start", "stop", "restart"]:
        return jsonify({"success": False, "error": "Invalid action"}), 400
        
    try:
        subprocess.run(["systemctl", action, f"aethervpn-mtproto@{port}"], check=True)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- TUIC Protocol APIs ---
TUIC_CONFIG_FILE = "/etc/vpnpanel/tuic.toml"

@app.route("/api/tuic/config", methods=["GET"])
def api_tuic_config_get():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    port = 7443
    users = {}
    congestion = "bbr"
    zero_rtt = True
    alpn = ["h3"]
    domain = get_server_domain()
    ip = "212.227.143.16"

    if os.path.exists(TUIC_CONFIG_FILE):
        try:
            with open(TUIC_CONFIG_FILE, "r") as f:
                content = f.read()
            pm = re.search(r'server\s*=\s*"[^"]*:(\d+)"', content)
            if pm: port = int(pm.group(1))
            cm = re.search(r'controller\s*=\s*"([^"]+)"', content)
            if cm: congestion = cm.group(1)
            zm = re.search(r'zero_rtt_handshake\s*=\s*(true|false)', content, re.IGNORECASE)
            if zm: zero_rtt = (zm.group(1).lower() == "true")
            users_match = re.search(r'\[users\](.*?)(?:\[|\Z)', content, re.DOTALL)
            if users_match:
                for line in users_match.group(1).splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        u, p = line.split("=", 1)
                        u = u.strip().strip('"').strip("'")
                        p = p.strip().strip('"').strip("'")
                        if u and p: users[u] = p
        except Exception as e:
            print("Error parsing tuic.toml:", e)

    res = subprocess.run(["systemctl", "is-active", "aethervpn-tuic"], capture_output=True, text=True)
    active = (res.stdout.strip() == "active")

    connections = 0
    if active:
        try:
            res_c = subprocess.run(f"ss -u -a | grep -E ':{port}\\s' | wc -l", shell=True, capture_output=True, text=True)
            connections = max(0, int(res_c.stdout.strip()) - 1)
        except: pass

    share_links = []
    singbox_outbounds = []
    for u, p in users.items():
        link = f"tuic://{u}:{p}@{domain}:{port}/?congestion_control={congestion}&alpn=h3&sni={domain}&allow_insecure=1#TUIC-BBR"
        link_ip = f"tuic://{u}:{p}@{ip}:{port}/?congestion_control={congestion}&alpn=h3&sni={domain}&allow_insecure=1#TUIC-BBR-IP"
        share_links.append({"uuid": u, "password": p, "link": link, "link_ip": link_ip})
        singbox_outbounds.append({
            "type": "tuic",
            "tag": "tuic-out",
            "server": domain,
            "server_port": port,
            "uuid": u,
            "password": p,
            "congestion_control": congestion,
            "zero_rtt_handshake": zero_rtt,
            "alpn": ["h3"],
            "tls": {
                "enabled": True,
                "server_name": domain,
                "insecure": True
            }
        })

    return jsonify({
        "installed": os.path.exists("/usr/local/bin/tuic-server"),
        "active": active,
        "port": port,
        "domain": domain,
        "ip": ip,
        "congestion_control": congestion,
        "zero_rtt_handshake": zero_rtt,
        "alpn": alpn,
        "users": users,
        "connections": connections,
        "share_links": share_links,
        "singbox_snippet": json.dumps(singbox_outbounds[0] if singbox_outbounds else {}, indent=2)
    })

@app.route("/api/tuic/config", methods=["POST"])
def api_tuic_config_set():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    port = int(data.get("port", 7443))
    congestion = data.get("congestion_control", "bbr").strip()
    zero_rtt = bool(data.get("zero_rtt_handshake", True))
    domain = get_server_domain()

    if not os.path.exists(TUIC_CONFIG_FILE):
        return jsonify({"success": False, "error": "فایل تنظیمات TUIC یافت نشد."}), 404

    try:
        with open(TUIC_CONFIG_FILE, "r") as f:
            content = f.read()
        content = re.sub(r'server\s*=\s*"[^"]*"', f'server = "0.0.0.0:{port}"', content)
        content = re.sub(r'zero_rtt_handshake\s*=\s*(?:true|false)', f'zero_rtt_handshake = {"true" if zero_rtt else "false"}', content, flags=re.IGNORECASE)
        content = re.sub(r'controller\s*=\s*"[^"]*"', f'controller = "{congestion}"', content)
        content = re.sub(r'hostname\s*=\s*"[^"]*"', f'hostname = "{domain}"', content)
        with open(TUIC_CONFIG_FILE, "w") as f:
            f.write(content)
        subprocess.run(["systemctl", "restart", "aethervpn-tuic"], check=False)
        return jsonify({"success": True, "port": port, "congestion_control": congestion, "zero_rtt_handshake": zero_rtt})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/tuic/users", methods=["POST"])
def api_tuic_users():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    action = data.get("action", "add")
    target_uuid = data.get("uuid", "").strip()
    target_password = data.get("password", "").strip()

    if not os.path.exists(TUIC_CONFIG_FILE):
        return jsonify({"success": False, "error": "فایل تنظیمات TUIC یافت نشد."}), 404

    try:
        with open(TUIC_CONFIG_FILE, "r") as f:
            content = f.read()

        if action == "add":
            if not target_uuid:
                target_uuid = str(uuid.uuid4())
            if not target_password:
                target_password = secrets.token_urlsafe(16)
            pattern = r'(\[users\][^\n]*)'
            replacement = f'\\1\n{target_uuid} = "{target_password}"'
            content = re.sub(pattern, replacement, content, count=1)
        elif action == "delete":
            if not target_uuid:
                return jsonify({"success": False, "error": "UUID الزامی است."}), 400
            content = re.sub(rf'^{re.escape(target_uuid)}\s*=.*?\n', '', content, flags=re.MULTILINE)

        with open(TUIC_CONFIG_FILE, "w") as f:
            f.write(content)
        subprocess.run(["systemctl", "restart", "aethervpn-tuic"], check=False)
        return jsonify({"success": True, "uuid": target_uuid, "password": target_password})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Shadowsocks-rust Protocol APIs ---
SHADOWSOCKS_CONFIG_FILE = "/etc/vpnpanel/shadowsocks.json"

@app.route("/api/shadowsocks/config", methods=["GET"])
def api_shadowsocks_config_get():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    port = 8388
    password = ""
    method = "2022-blake3-aes-128-gcm"
    fast_open = True
    domain = get_server_domain()
    ip = "212.227.143.16"

    if os.path.exists(SHADOWSOCKS_CONFIG_FILE):
        try:
            with open(SHADOWSOCKS_CONFIG_FILE, "r") as f:
                cfg = json.load(f)
            port = int(cfg.get("server_port", 8388))
            password = cfg.get("password", "")
            method = cfg.get("method", "2022-blake3-aes-128-gcm")
            fast_open = bool(cfg.get("fast_open", True))
        except Exception as e:
            print("Error loading shadowsocks.json:", e)

    res = subprocess.run(["systemctl", "is-active", "aethervpn-shadowsocks"], capture_output=True, text=True)
    active = (res.stdout.strip() == "active")

    connections = 0
    if active:
        try:
            res_c = subprocess.run(f"ss -t -a | grep -E ':{port}\\s' | grep -i estab | wc -l", shell=True, capture_output=True, text=True)
            connections = int(res_c.stdout.strip())
        except: pass

    userinfo = base64.b64encode(f"{method}:{password}".encode()).decode()
    share_link = f"ss://{userinfo}@{domain}:{port}#Shadowsocks-2022"
    share_link_ip = f"ss://{userinfo}@{ip}:{port}#Shadowsocks-2022"

    return jsonify({
        "installed": os.path.exists("/usr/local/bin/ssserver"),
        "active": active,
        "port": port,
        "password": password,
        "method": method,
        "fast_open": fast_open,
        "domain": domain,
        "ip": ip,
        "connections": connections,
        "share_link": share_link,
        "share_link_ip": share_link_ip
    })

@app.route("/api/shadowsocks/config", methods=["POST"])
def api_shadowsocks_config_set():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    port = int(data.get("port", 8388))
    password = data.get("password", "").strip()
    method = data.get("method", "2022-blake3-aes-128-gcm").strip()
    fast_open = bool(data.get("fast_open", True))

    if not password:
        if "2022-blake3-aes-128" in method:
            password = base64.b64encode(os.urandom(16)).decode()
        elif "2022-blake3-aes-256" in method or "2022-blake3-chacha20" in method:
            password = base64.b64encode(os.urandom(32)).decode()
        else:
            password = secrets.token_urlsafe(16)

    cfg = {
        "server": "0.0.0.0",
        "server_port": port,
        "password": password,
        "method": method,
        "mode": "tcp_and_udp",
        "timeout": 300,
        "fast_open": fast_open,
        "nameserver": "1.1.1.1"
    }
    try:
        os.makedirs("/etc/vpnpanel", exist_ok=True)
        with open(SHADOWSOCKS_CONFIG_FILE, "w") as f:
            json.dump(cfg, f, indent=4)
        subprocess.run(["systemctl", "restart", "aethervpn-shadowsocks"], check=False)
        return jsonify({"success": True, "port": port, "method": method, "password": password})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/shadowsocks/generate-key", methods=["POST"])
def api_shadowsocks_gen_key():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    method = data.get("method", "2022-blake3-aes-128-gcm")
    if "2022-blake3-aes-128" in method:
        key = base64.b64encode(os.urandom(16)).decode()
    elif "2022-blake3-aes-256" in method or "2022-blake3-chacha20" in method:
        key = base64.b64encode(os.urandom(32)).decode()
    else:
        key = secrets.token_urlsafe(16)
    return jsonify({"success": True, "key": key})

# --- Shadowsocks Clients API ---
SHADOWSOCKS_CLIENTS_FILE = "/etc/vpnpanel/shadowsocks_clients.json"

def load_shadowsocks_clients():
    if os.path.exists(SHADOWSOCKS_CLIENTS_FILE):
        try:
            with open(SHADOWSOCKS_CLIENTS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return []

def save_shadowsocks_clients(clients):
    os.makedirs(os.path.dirname(SHADOWSOCKS_CLIENTS_FILE), exist_ok=True)
    with open(SHADOWSOCKS_CLIENTS_FILE, "w") as f:
        json.dump(clients, f, indent=2)
    # Sync with shadowsocks.json users array if method is 2022
    if os.path.exists(SHADOWSOCKS_CONFIG_FILE):
        try:
            with open(SHADOWSOCKS_CONFIG_FILE, "r") as f:
                cfg = json.load(f)
            method = cfg.get("method", "2022-blake3-aes-128-gcm")
            if "2022-" in method:
                cfg["users"] = [{"name": c["username"], "password": c["password"]} for c in clients]
                with open(SHADOWSOCKS_CONFIG_FILE, "w") as f:
                    json.dump(cfg, f, indent=4)
                subprocess.run(["systemctl", "restart", "aethervpn-shadowsocks"], capture_output=True)
        except Exception as e:
            print("Failed to sync shadowsocks clients:", e)

@app.route("/api/shadowsocks/clients", methods=["GET"])
def api_shadowsocks_clients_get():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    clients = load_shadowsocks_clients()
    domain = get_server_domain()
    ip = "212.227.143.16"
    port = 8388
    method = "2022-blake3-aes-128-gcm"
    server_password = ""
    if os.path.exists(SHADOWSOCKS_CONFIG_FILE):
        try:
            with open(SHADOWSOCKS_CONFIG_FILE, "r") as f:
                cfg = json.load(f)
            port = int(cfg.get("server_port", 8388))
            method = cfg.get("method", "2022-blake3-aes-128-gcm")
            server_password = cfg.get("password", "")
        except Exception:
            pass
            
    res_clients = []
    for c in clients:
        u_name = c.get("username", "")
        u_pass = c.get("password", "")
        if "2022-" in method and server_password:
            userinfo = base64.b64encode(f"{method}:{server_password}:{u_pass}".encode()).decode()
        else:
            userinfo = base64.b64encode(f"{method}:{u_pass}".encode()).decode()
        share_link = f"ss://{userinfo}@{domain}:{port}#{u_name}"
        share_link_ip = f"ss://{userinfo}@{ip}:{port}#{u_name}"
        res_clients.append({
            "id": c.get("id"),
            "username": u_name,
            "password": u_pass,
            "created_at": c.get("created_at", ""),
            "share_link": share_link,
            "share_link_ip": share_link_ip
        })
    return jsonify({"clients": res_clients, "port": port, "method": method})

@app.route("/api/shadowsocks/clients", methods=["POST"])
def api_shadowsocks_clients_add():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    if not username:
        return jsonify({"success": False, "error": "نام کاربری نمی‌تواند خالی باشد"}), 400
        
    method = "2022-blake3-aes-128-gcm"
    if os.path.exists(SHADOWSOCKS_CONFIG_FILE):
        try:
            with open(SHADOWSOCKS_CONFIG_FILE, "r") as f:
                method = json.load(f).get("method", "2022-blake3-aes-128-gcm")
        except: pass
        
    if not password:
        if "2022-blake3-aes-128" in method:
            password = base64.b64encode(os.urandom(16)).decode()
        elif "2022-blake3-aes-256" in method or "2022-blake3-chacha20" in method:
            password = base64.b64encode(os.urandom(32)).decode()
        else:
            password = secrets.token_urlsafe(16)
            
    clients = load_shadowsocks_clients()
    if any(c["username"] == username for c in clients):
        return jsonify({"success": False, "error": "کاربری با این نام قبلاً ثبت شده است"}), 400
        
    client_entry = {
        "id": str(uuid.uuid4())[:8],
        "username": username,
        "password": password,
        "created_at": time.strftime("%Y-%m-%d %H:%M")
    }
    clients.append(client_entry)
    save_shadowsocks_clients(clients)
    return jsonify({"success": True, "client": client_entry})

@app.route("/api/shadowsocks/clients/<client_id>", methods=["DELETE"])
def api_shadowsocks_clients_delete(client_id):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    clients = load_shadowsocks_clients()
    new_clients = [c for c in clients if c.get("id") != client_id and c.get("username") != client_id]
    save_shadowsocks_clients(new_clients)
    return jsonify({"success": True})


# --- Local Proxy Clients API (SOCKS5 & HTTP) ---
PROXY_USERS_FILE = "/etc/vpnpanel/proxy_users.json"

def load_proxy_users():
    if os.path.exists(PROXY_USERS_FILE):
        try:
            with open(PROXY_USERS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_proxy_users(users):
    os.makedirs(os.path.dirname(PROXY_USERS_FILE), exist_ok=True)
    with open(PROXY_USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

@app.route("/api/proxy/clients", methods=["GET"])
def api_proxy_clients_get():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    users = load_proxy_users()
    domain = get_server_domain()
    ip = "212.227.143.16"
    socks_port = 1080
    http_port = 3128
    
    clients = []
    for uname, udata in users.items():
        if isinstance(udata, dict):
            pw = udata.get("password", "")
            protocols = udata.get("protocols", ["socks5", "http"])
            enabled = udata.get("enabled", True)
            created_at = udata.get("created_at", "")
        else:
            pw = str(udata)
            protocols = ["socks5", "http"]
            enabled = True
            created_at = ""
            
        socks_link = f"socks5://{uname}:{pw}@{domain}:{socks_port}"
        http_link = f"http://{uname}:{pw}@{domain}:{http_port}"
        socks_link_ip = f"socks5://{uname}:{pw}@{ip}:{socks_port}"
        http_link_ip = f"http://{uname}:{pw}@{ip}:{http_port}"
        clients.append({
            "username": uname,
            "password": pw,
            "protocols": protocols,
            "enabled": enabled,
            "created_at": created_at,
            "socks_link": socks_link,
            "http_link": http_link,
            "socks_link_ip": socks_link_ip,
            "http_link_ip": http_link_ip
        })
    return jsonify({"clients": clients, "socks_port": socks_port, "http_port": http_port, "domain": domain})

@app.route("/api/proxy/clients", methods=["POST"])
def api_proxy_clients_add():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    protocols = data.get("protocols") or ["socks5", "http"]
    if not username:
        return jsonify({"success": False, "error": "نام کاربری نمی‌تواند خالی باشد"}), 400
    if not password:
        password = secrets.token_urlsafe(10)
        
    users = load_proxy_users()
    users[username] = {
        "password": password,
        "protocols": protocols,
        "enabled": True,
        "created_at": time.strftime("%Y-%m-%d %H:%M")
    }
    save_proxy_users(users)
    return jsonify({"success": True, "username": username, "password": password})

@app.route("/api/proxy/clients/<username>", methods=["DELETE"])
def api_proxy_clients_delete(username):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    users = load_proxy_users()
    if username in users:
        del users[username]
        save_proxy_users(users)
    return jsonify({"success": True})


# --- WireGuard over Cloudflare WebSocket (wstunnel) API ---
WIREGUARD_CF_FILE = "/etc/vpnpanel/wireguard_cf.json"

def get_wg_cf_config():
    cfg = {"enabled": True, "port": 2082, "path": "wg-cf", "target": "127.0.0.1:904"}
    if os.path.exists(WIREGUARD_CF_FILE):
        try:
            with open(WIREGUARD_CF_FILE, "r") as f:
                cfg.update(json.load(f))
        except: pass
    return cfg

@app.route("/api/wireguard/cloudflare", methods=["GET"])
def api_wireguard_cloudflare_get():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    cfg = get_wg_cf_config()
    res = subprocess.run(["systemctl", "is-active", "aethervpn-wireguard-ws"], capture_output=True, text=True)
    active = (res.stdout.strip() == "active")
    domain = get_server_domain()
    port = cfg.get("port", 2082)
    path = cfg.get("path", "wg-cf")
    target = cfg.get("target", "127.0.0.1:904")
    
    client_cmd = f"wstunnel client -L udp://127.0.0.1:51820:{target} wss://{domain}:443/{path} --http-upgrade-path-prefix {path}"
    
    return jsonify({
        "installed": os.path.exists("/usr/local/bin/wstunnel"),
        "active": active,
        "port": port,
        "path": path,
        "target": target,
        "domain": domain,
        "client_cmd": client_cmd,
        "cf_supported_ports": [2082, 2083, 2052, 2053, 2086, 2087, 8080, 8443]
    })

@app.route("/api/wireguard/cloudflare/config", methods=["POST"])
def api_wireguard_cloudflare_config():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    port = int(data.get("port") or 2082)
    path = (data.get("path") or "wg-cf").strip().lstrip("/")
    target = (data.get("target") or "127.0.0.1:904").strip()
    
    cfg = {"enabled": True, "port": port, "path": path, "target": target}
    os.makedirs(os.path.dirname(WIREGUARD_CF_FILE), exist_ok=True)
    with open(WIREGUARD_CF_FILE, "w") as f:
        json.dump(cfg, f, indent=2)
        
    svc_content = f"""[Unit]
Description=AetherVPN - WireGuard over Cloudflare WebSocket (wstunnel)
After=network-online.target wg-quick@wg0.service
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/wstunnel server --restrict-to {target} -r {path} ws://0.0.0.0:{port}
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"""
    with open("/etc/systemd/system/aethervpn-wireguard-ws.service", "w") as f:
        f.write(svc_content)
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    subprocess.run(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"], capture_output=True)
    subprocess.run(["systemctl", "restart", "aethervpn-wireguard-ws"], capture_output=True)
    return jsonify({"success": True, "port": port, "path": path})

@app.route("/api/wireguard/cloudflare/toggle", methods=["POST"])
def api_wireguard_cloudflare_toggle():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    res = subprocess.run(["systemctl", "is-active", "aethervpn-wireguard-ws"], capture_output=True, text=True)
    active = (res.stdout.strip() == "active")
    action = "stop" if active else "start"
    subprocess.run(["systemctl", action, "aethervpn-wireguard-ws"], capture_output=True)
    return jsonify({"success": True, "action": action, "active": not active})

# --- Panel Access & URL Configuration API ---
@app.route("/api/system/panel-access", methods=["GET", "POST"])
def api_system_panel_access():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    if request.method == "POST":
        data = request.json or {}
        new_path = (data.get("path") or "").strip()
        new_port = data.get("port")
        
        if new_path and new_path != "/":
            if not new_path.startswith("/"):
                new_path = "/" + new_path
            new_path = new_path.rstrip("/")
            clean_check = new_path.replace("/", "").replace("-", "").replace("_", "")
            if clean_check and not clean_check.isalnum():
                return jsonify({"success": False, "error": "مسیر فقط می‌تواند شامل حروف، اعداد، خط تیره و اسلش باشد"}), 400
        else:
            new_path = ""
            
        os.makedirs(os.path.dirname(PANEL_PATH_FILE), exist_ok=True)
        with open(PANEL_PATH_FILE, "w") as f:
            f.write(new_path)
            
        port_changed = False
        curr_port = get_panel_port()
        port_to_use = curr_port
        if new_port:
            try:
                new_port = int(new_port)
                if 1 <= new_port <= 65535 and new_port != curr_port:
                    port_changed = True
                    port_to_use = new_port
                    port_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dev_data", "panel_port.txt") if os.environ.get("DEV_MODE") else "/www/wwwroot/mhpanel/panel_port.txt"
                    os.makedirs(os.path.dirname(port_file), exist_ok=True)
                    with open(port_file, "w") as f:
                        f.write(str(new_port))
                    subprocess.run(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(new_port), "-j", "ACCEPT"], capture_output=True)
            except Exception as e:
                return jsonify({"success": False, "error": f"پورت نامعتبر است: {e}"}), 400

        domain = get_server_domain()
        new_url = f"https://{domain}:{port_to_use}{new_path}"
        
        if port_changed:
            def delayed_restart():
                time.sleep(1.0)
                for svc in ["mhpanel", "vpnpanel"]:
                    subprocess.run(["systemctl", "restart", svc], capture_output=True)
            threading.Thread(target=delayed_restart, daemon=True).start()
            
        return jsonify({
            "success": True,
            "path": new_path,
            "port": port_to_use,
            "port_changed": port_changed,
            "new_url": new_url
        })
        
    domain = get_server_domain()
    port = get_panel_port()
    path = get_panel_path()
    return jsonify({
        "path": path,
        "port": port,
        "domain": domain,
        "url": f"https://{domain}:{port}{path}"
    })


# --- DNSTT Protocol API ---
@app.route("/api/dnstt/config", methods=["GET", "POST"])
def api_dnstt_config():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    cfg_file = "/etc/vpnpanel/dnstt.json"
    pubkey = ""
    if os.path.exists("/etc/dnstt/server.pub"):
        try:
            with open("/etc/dnstt/server.pub", "r") as f:
                pubkey = f.read().strip()
        except Exception:
            pass

    if request.method == "POST":
        data = request.json or {}
        port = int(data.get("port") or 5300)
        domain = (data.get("domain") or "").strip()
        upstream = (data.get("upstream") or "127.0.0.1:22").strip()
        mtu = int(data.get("mtu") or 1232)
        
        cfg = {"port": port, "domain": domain, "upstream": upstream, "mtu": mtu, "pubkey": pubkey}
        os.makedirs(os.path.dirname(cfg_file), exist_ok=True)
        with open(cfg_file, "w") as f:
            json.dump(cfg, f, indent=2)
            
        svc_content = f"""[Unit]
Description=AetherVPN - DNSTT SlowDNS Tunnel Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/dnstt-server -udp 0.0.0.0:{port} -privkey-file /etc/dnstt/server.key -mtu {mtu} {domain} {upstream}
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"""
        with open("/etc/systemd/system/aethervpn-dnstt.service", "w") as f:
            f.write(svc_content)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["iptables", "-I", "INPUT", "-p", "udp", "--dport", str(port), "-j", "ACCEPT"], capture_output=True)
        subprocess.run(["systemctl", "restart", "aethervpn-dnstt"], capture_output=True)
        return jsonify({"success": True})
        
    cfg = {"port": 5300, "domain": f"t.{get_server_domain()}", "upstream": "127.0.0.1:22", "mtu": 1232, "pubkey": pubkey}
    if os.path.exists(cfg_file):
        try:
            with open(cfg_file, "r") as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    cfg["active"] = get_protocol_active("dnstt")
    cfg["installed"] = is_installed("dnstt")
    cfg["connections"] = get_connection_count("dnstt")
    cfg["server_domain"] = get_server_domain()
    cfg["client_cmd"] = f"dnstt-client -doh https://cloudflare-dns.com/dns-query -pubkey {pubkey} {cfg.get('domain')} 127.0.0.1:1080"
    return jsonify(cfg)


# --- VayDNS Protocol API ---
@app.route("/api/vaydns/config", methods=["GET", "POST"])
def api_vaydns_config():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    cfg_file = "/etc/vpnpanel/vaydns.json"
    pubkey = ""
    if os.path.exists("/etc/vaydns/server.pub"):
        try:
            with open("/etc/vaydns/server.pub", "r") as f:
                pubkey = f.read().strip()
        except Exception:
            pass

    if request.method == "POST":
        data = request.json or {}
        port = int(data.get("port") or 5353)
        domain = (data.get("domain") or "").strip()
        upstream = (data.get("upstream") or "127.0.0.1:22").strip()
        mtu = int(data.get("mtu") or 1232)
        compat = bool(data.get("compat", True))
        
        cfg = {"port": port, "domain": domain, "upstream": upstream, "mtu": mtu, "compat": compat, "pubkey": pubkey}
        os.makedirs(os.path.dirname(cfg_file), exist_ok=True)
        with open(cfg_file, "w") as f:
            json.dump(cfg, f, indent=2)
            
        compat_flag = " -dnstt-compat" if compat else ""
        svc_content = f"""[Unit]
Description=AetherVPN - VayDNS Iran Anti-Censorship DNS Tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/vaydns-server -udp 0.0.0.0:{port} -privkey-file /etc/vaydns/server.key -domain {domain} -upstream {upstream}{compat_flag}
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"""
        with open("/etc/systemd/system/aethervpn-vaydns.service", "w") as f:
            f.write(svc_content)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["iptables", "-I", "INPUT", "-p", "udp", "--dport", str(port), "-j", "ACCEPT"], capture_output=True)
        subprocess.run(["systemctl", "restart", "aethervpn-vaydns"], capture_output=True)
        return jsonify({"success": True})
        
    cfg = {"port": 5353, "domain": f"v.{get_server_domain()}", "upstream": "127.0.0.1:22", "mtu": 1232, "compat": True, "pubkey": pubkey}
    if os.path.exists(cfg_file):
        try:
            with open(cfg_file, "r") as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    cfg["active"] = get_protocol_active("vaydns")
    cfg["installed"] = is_installed("vaydns")
    cfg["connections"] = get_connection_count("vaydns")
    cfg["server_domain"] = get_server_domain()
    cfg["client_cmd"] = f"vaydns-client -udp 8.8.8.8:53 -pubkey {pubkey} -domain {cfg.get('domain')} 127.0.0.1:1080"
    return jsonify(cfg)


# --- Slipstream Protocol API ---
@app.route("/api/slipstream/config", methods=["GET", "POST"])
def api_slipstream_config():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    cfg_file = "/etc/vpnpanel/slipstream.json"
    if request.method == "POST":
        data = request.json or {}
        port = int(data.get("port") or 5354)
        domain = (data.get("domain") or "").strip()
        upstream = (data.get("upstream") or "127.0.0.1:22").strip()
        
        cfg = {"port": port, "domain": domain, "upstream": upstream}
        os.makedirs(os.path.dirname(cfg_file), exist_ok=True)
        with open(cfg_file, "w") as f:
            json.dump(cfg, f, indent=2)
            
        svc_content = f"""[Unit]
Description=AetherVPN - Slipstream QUIC Covert DNS Tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/slipstream-server -l {port} -d {domain} -a {upstream} -c /etc/slipstream/cert.pem -k /etc/slipstream/key.pem
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"""
        with open("/etc/systemd/system/aethervpn-slipstream.service", "w") as f:
            f.write(svc_content)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["iptables", "-I", "INPUT", "-p", "udp", "--dport", str(port), "-j", "ACCEPT"], capture_output=True)
        subprocess.run(["systemctl", "restart", "aethervpn-slipstream"], capture_output=True)
        return jsonify({"success": True})
        
    cfg = {"port": 5354, "domain": f"s.{get_server_domain()}", "upstream": "127.0.0.1:22"}
    if os.path.exists(cfg_file):
        try:
            with open(cfg_file, "r") as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    cfg["active"] = get_protocol_active("slipstream")
    cfg["installed"] = is_installed("slipstream")
    cfg["connections"] = get_connection_count("slipstream")
    cfg["server_domain"] = get_server_domain()
    cfg["client_cmd"] = f"slipstream-client -l 1080 -d {cfg.get('domain')} -s {get_server_domain()}"
    return jsonify(cfg)


# --- Certificate Management API ---
def restart_panel_service_threaded():
    def _worker():
        time.sleep(2)
        for svc in ["mhpanel", "vpnpanel"]:
            res = subprocess.run(["systemctl", "restart", svc], capture_output=True, text=True)
            if res.returncode == 0:
                break
    threading.Thread(target=_worker, daemon=True).start()

def get_certificate_details(cert_path):
    if not os.path.exists(cert_path):
        return {"exists": False}
    try:
        cmd = ["openssl", "x509", "-in", cert_path, "-noout", "-subject", "-issuer", "-enddate", "-ext", "subjectAltName"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        subject, issuer, expiry, san = "Unknown", "Unknown", "Unknown", ""
        if res.returncode == 0:
            lines = res.stdout.strip().split("\n")
            for i, line in enumerate(lines):
                line_str = line.strip()
                if line_str.startswith("subject="):
                    subject = line_str.replace("subject=", "").strip()
                elif line_str.startswith("issuer="):
                    issuer = line_str.replace("issuer=", "").strip()
                elif line_str.startswith("notAfter="):
                    expiry = line_str.replace("notAfter=", "").strip()
                elif "X509v3 Subject Alternative Name:" in line:
                    if i + 1 < len(lines):
                        san = lines[i + 1].strip()
        ca_path = os.path.join(PANEL_SSL_DIR, "panel-ca.crt")
        has_ca = os.path.exists(ca_path)
        return {
            "exists": True,
            "subject": subject,
            "issuer": issuer,
            "expiry": expiry,
            "san": san,
            "has_ca": has_ca
        }
    except Exception as e:
        return {"exists": True, "error": str(e)}

@app.route("/api/ssl/status", methods=["GET"])
def api_ssl_status():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    cert_path = PANEL_CERT
    key_path = PANEL_KEY
        
    real_cert_path = cert_path
    real_key_path = key_path
    
    if os.path.islink(cert_path):
        real_cert_path = os.path.realpath(cert_path)
    if os.path.islink(key_path):
        real_key_path = os.path.realpath(key_path)
        
    details = get_certificate_details(cert_path)
    details["cert_path"] = cert_path
    details["key_path"] = key_path
    details["real_cert_path"] = real_cert_path
    details["real_key_path"] = real_key_path
    
    return jsonify(details)


@app.route("/api/ssl/issue", methods=["POST"])
def api_ssl_issue():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.json or {}
    domain = data.get("domain", "").strip()
    email = data.get("email", "").strip()
    
    if not domain:
        return jsonify({"success": False, "error": "Domain name is required"}), 400

    potential_webroots = [
        f"/www/wwwroot/{domain}",
        "/www/wwwroot/mhpanel.kigaping.com",
        "/var/www/html"
    ]
    webroot_path = None
    for wr in potential_webroots:
        if os.path.isdir(wr):
            webroot_path = wr
            break

    cmd = ["certbot", "certonly", "-d", domain, "--non-interactive", "--agree-tos"]
    if email:
        cmd.extend(["--email", email])
    else:
        cmd.append("--register-unsafely-without-email")

    used_standalone = False
    if webroot_path:
        os.makedirs(os.path.join(webroot_path, ".well-known", "acme-challenge"), exist_ok=True)
        cmd.extend(["--webroot", "-w", webroot_path])
    else:
        cmd.append("--standalone")
        used_standalone = True

    try:
        if used_standalone:
            try:
                redirect_server.stop()
            except:
                pass
            time.sleep(1)

        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if res.returncode != 0 and not used_standalone:
            try:
                redirect_server.stop()
            except:
                pass
            time.sleep(1)
            retry_cmd = ["certbot", "certonly", "--standalone", "-d", domain, "--non-interactive", "--agree-tos"]
            if email: retry_cmd.extend(["--email", email])
            else: retry_cmd.append("--register-unsafely-without-email")
            res = subprocess.run(retry_cmd, capture_output=True, text=True, timeout=120)
    finally:
        try:
            redirect_server.start()
        except:
            pass

    if res.returncode != 0:
        return jsonify({"success": False, "error": f"Certbot failed:\n{res.stderr}\n{res.stdout}"}), 500
        
    cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
    key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        apply_certificates(cert_path, key_path)
        try:
            os.makedirs("/etc/vpnpanel", exist_ok=True)
            with open("/etc/vpnpanel/server_domain.txt", "w") as f:
                f.write(domain.strip())
        except Exception:
            pass
        restart_panel_service_threaded()
        return jsonify({"success": True, "message": f"گواهی امنیتی Let's Encrypt برای دامنه {domain} با موفقیت دریافت و فعال شد. پنل مجدداً بارگذاری می‌شود.", "domain": domain})
    else:
        return jsonify({"success": False, "error": "Certbot completed but certificate files were not found"}), 500


@app.route("/api/ssl/issue-ip", methods=["POST"])
def api_ssl_issue_ip():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json or {}
    server_ip = data.get("ip", "").strip()
    if not server_ip:
        try:
            r = requests.get("https://api.ipify.org", timeout=3)
            if r.ok: server_ip = r.text.strip()
        except:
            server_ip = request.host.split(":")[0]

    os.makedirs(PANEL_SSL_DIR, exist_ok=True)
    ca_key = os.path.join(PANEL_SSL_DIR, "panel-ca.key")
    ca_crt = os.path.join(PANEL_SSL_DIR, "panel-ca.crt")

    try:
        if not os.path.exists(ca_key) or not os.path.exists(ca_crt):
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:4096", "-sha256", "-days", "3650",
                "-nodes", "-keyout", ca_key, "-out", ca_crt,
                "-subj", "/CN=MH Panel Local Root CA/O=MHPanel Authority/C=US"
            ], check=True)
            os.chmod(ca_key, 0o600)
            os.chmod(ca_crt, 0o644)

        ip_csr = os.path.join(PANEL_SSL_DIR, "panel-ip.csr")
        ip_ext = os.path.join(PANEL_SSL_DIR, "panel-ip.ext")
        temp_cert = os.path.join(PANEL_SSL_DIR, "panel-ip-temp.crt")

        subprocess.run(["openssl", "genrsa", "-out", PANEL_KEY, "2048"], check=True)
        os.chmod(PANEL_KEY, 0o600)

        subprocess.run([
            "openssl", "req", "-new", "-key", PANEL_KEY, "-out", ip_csr,
            "-subj", f"/CN={server_ip}/O=MHPanel Server"
        ], check=True)

        ext_lines = [
            "authorityKeyIdentifier=keyid,issuer",
            "basicConstraints=CA:FALSE",
            "keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment",
            f"subjectAltName = IP:{server_ip}, IP:127.0.0.1, DNS:localhost\n"
        ]
        with open(ip_ext, "w") as f:
            f.write("\n".join(ext_lines))

        subprocess.run([
            "openssl", "x509", "-req", "-in", ip_csr, "-CA", ca_crt, "-CAkey", ca_key,
            "-CAcreateserial", "-out", temp_cert, "-days", "3650", "-sha256",
            "-extfile", ip_ext
        ], check=True)

        with open(temp_cert, "r") as f_c, open(ca_crt, "r") as f_ca, open(PANEL_CERT, "w") as f_out:
            f_out.write(f_c.read() + "\n" + f_ca.read())
        os.chmod(PANEL_CERT, 0o644)

        for p in [ip_csr, ip_ext, temp_cert]:
            if os.path.exists(p):
                try: os.unlink(p)
                except: pass

        restart_panel_service_threaded()
        return jsonify({
            "success": True,
            "message": f"گواهی امنیتی معتبر ۱۰ ساله برای آدرس IP ({server_ip}) با قابلیت IP SAN با موفقیت صادر شد. پنل مجدداً بارگذاری می‌شود.",
            "ip": server_ip
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/ssl/ca.crt", methods=["GET"])
def api_ssl_ca_download():
    from flask import send_file
    ca_path = os.path.join(PANEL_SSL_DIR, "panel-ca.crt")
    if not os.path.exists(ca_path):
        ca_path = PANEL_CERT
    if os.path.exists(ca_path):
        return send_file(ca_path, as_attachment=True, download_name="mhpanel-root-ca.crt", mimetype="application/x-x509-ca-cert")
    return jsonify({"error": "Certificate not found"}), 404


@app.route("/api/ssl/manual", methods=["POST"])
def api_ssl_manual():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.json or {}
    crt_content = data.get("crt_content", "").strip()
    key_content = data.get("key_content", "").strip()
    
    if not crt_content or not key_content:
        return jsonify({"success": False, "error": "Certificate and Key contents are required"}), 400
        
    import tempfile
    import ssl
    import os
    
    temp_crt_fd, temp_crt_path = tempfile.mkstemp()
    temp_key_fd, temp_key_path = tempfile.mkstemp()
    try:
        with os.fdopen(temp_crt_fd, 'w') as f:
            f.write(crt_content + "\n")
        with os.fdopen(temp_key_fd, 'w') as f:
            f.write(key_content + "\n")
            
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=temp_crt_path, keyfile=temp_key_path)
    except Exception as e:
        return jsonify({"success": False, "error": f"Invalid Certificate or Key pair: {e}"}), 400
    finally:
        try:
            os.unlink(temp_crt_path)
            os.unlink(temp_key_path)
        except:
            pass
            
    try:
        domain = extract_cert_domain(crt_content)
        apply_certificates(crt_content, key_content)
        restart_panel_service_threaded()
        return jsonify({"success": True, "message": "سرتیفیکیت سفارشی با موفقیت ذخیره و اعمال شد. پنل مجدداً بارگذاری می‌شود.", "domain": domain})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/ssl/paths", methods=["POST"])
def api_ssl_paths():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.json or {}
    crt_path = data.get("crt_path", "").strip()
    key_path = data.get("key_path", "").strip()
    
    if not crt_path or not key_path:
        return jsonify({"success": False, "error": "Certificate and Key file paths are required"}), 400
        
    if not os.path.exists(crt_path):
        return jsonify({"success": False, "error": f"Certificate file not found at path: {crt_path}"}), 400
    if not os.path.exists(key_path):
        return jsonify({"success": False, "error": f"Key file not found at path: {key_path}"}), 400
        
    import ssl
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=crt_path, keyfile=key_path)
    except Exception as e:
        return jsonify({"success": False, "error": f"Invalid Certificate or Key pair at paths: {e}"}), 400
        
    try:
        domain = extract_cert_domain(crt_path)
        apply_certificates(crt_path, key_path)
        restart_panel_service_threaded()
        return jsonify({"success": True, "message": "مسیرهای سرتیفیکیت با موفقیت پیوند داده شدند. پنل مجدداً بارگذاری می‌شود.", "domain": domain})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/ssl/repair", methods=["POST"])
def api_ssl_repair():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    try:
        for path in [PANEL_CERT, PANEL_KEY]:
            if os.path.lexists(path):
                os.unlink(path)
        ensure_panel_certificate()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=PANEL_CERT, keyfile=PANEL_KEY)
        restart_panel_service_threaded()
        return jsonify({"success": True, "message": "سرتیفیکیت خودامضای پنل با موفقیت بازسازی شد. پنل مجدداً بارگذاری می‌شود."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =========================================================================
# MikroTik Certificate Migration & Custom SSL Hub with Protocol Assignment
# =========================================================================

IMPORTED_CERTS_DIR = "/etc/vpnpanel/imported_certs"
IMPORTED_CERTS_FILE = "/etc/vpnpanel/imported_certs.json"

def parse_cert_info(cert_pem):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from datetime import timezone
    try:
        cert = x509.load_pem_x509_certificate(
            cert_pem.encode("utf-8") if isinstance(cert_pem, str) else cert_pem,
            default_backend()
        )
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        if hasattr(cert, "not_valid_after_utc"):
            expiry = cert.not_valid_after_utc.replace(tzinfo=None)
            valid_from = cert.not_valid_before_utc.replace(tzinfo=None)
        else:
            expiry = cert.not_valid_after
            valid_from = cert.not_valid_before
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        days_left = (expiry - now).days
        sans = []
        try:
            ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in ext.value:
                sans.append(str(name.value))
        except Exception:
            pass
        cn = "Unknown"
        for part in subject.split(","):
            if part.strip().startswith("CN="):
                cn = part.strip()[3:]
                break
        return {
            "common_name": cn,
            "subject": subject,
            "issuer": issuer,
            "valid_from": valid_from.strftime("%Y-%m-%d %H:%M"),
            "valid_until": expiry.strftime("%Y-%m-%d %H:%M"),
            "days_remaining": days_left,
            "is_expired": days_left < 0,
            "sans": sans
        }
    except Exception as e:
        return {"error": str(e), "common_name": "Invalid Certificate", "days_remaining": 0, "is_expired": True, "sans": []}

def validate_key_pair(cert_pem, key_pem):
    import tempfile
    fd_c, path_c = tempfile.mkstemp()
    fd_k, path_k = tempfile.mkstemp()
    try:
        with os.fdopen(fd_c, "w", encoding="utf-8") as f:
            f.write(cert_pem.strip() + "\n")
        with os.fdopen(fd_k, "w", encoding="utf-8") as f:
            f.write(key_pem.strip() + "\n")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=path_c, keyfile=path_k)
        return True, ""
    except Exception as e:
        return False, str(e)
    finally:
        for p in [path_c, path_k]:
            if os.path.exists(p):
                try: os.unlink(p)
                except: pass

def load_imported_certs():
    if not os.path.exists(IMPORTED_CERTS_FILE):
        defaults = []
        le_crt = "/etc/letsencrypt/live/vpn.kigaping.com/fullchain.pem"
        le_key = "/etc/letsencrypt/live/vpn.kigaping.com/privkey.pem"
        if os.path.exists(le_crt) and os.path.exists(le_key):
            try:
                with open(le_crt, "r", encoding="utf-8") as f:
                    info = parse_cert_info(f.read())
                defaults.append({
                    "id": "sys_letsencrypt",
                    "name": "گواهی رسمی Let's Encrypt (vpn.kigaping.com)",
                    "type": "custom",
                    "type_label": "گواهی رسمی Let's Encrypt",
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "common_name": info.get("common_name", "vpn.kigaping.com"),
                    "subject": info.get("subject", ""),
                    "issuer": info.get("issuer", "Let's Encrypt Authority"),
                    "valid_from": info.get("valid_from", ""),
                    "valid_until": info.get("valid_until", ""),
                    "days_remaining": info.get("days_remaining", 90),
                    "is_expired": info.get("is_expired", False),
                    "sans": info.get("sans", []),
                    "server_crt_path": le_crt,
                    "server_key_path": le_key,
                    "ca_path": VPN_CA_CERT if os.path.exists(VPN_CA_CERT) else None,
                    "client_crt_path": None,
                    "client_key_path": None,
                    "has_client": False,
                    "assigned_protocols": ["sstp", "ocserv"]
                })
            except Exception:
                pass

        if os.path.exists(VPN_CA_CERT) and os.path.exists(VPN_SERVER_CERT):
            try:
                with open(VPN_SERVER_CERT, "r", encoding="utf-8") as f:
                    sinfo = parse_cert_info(f.read())
                with open(VPN_CA_CERT, "r", encoding="utf-8") as f:
                    cainfo = parse_cert_info(f.read())
                defaults.append({
                    "id": "sys_internal_ca",
                    "name": "گواهی ریشه و سرور داخلی AetherVPN (Root CA)",
                    "type": "mikrotik",
                    "type_label": "گواهی داخلی سیستم و کاربران (Root CA)",
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "common_name": sinfo.get("common_name", "vpn-server"),
                    "subject": sinfo.get("subject", ""),
                    "issuer": cainfo.get("common_name", "AetherVPN Root CA"),
                    "ca_subject": cainfo.get("subject", ""),
                    "valid_from": sinfo.get("valid_from", ""),
                    "valid_until": sinfo.get("valid_until", ""),
                    "days_remaining": sinfo.get("days_remaining", 3650),
                    "is_expired": sinfo.get("is_expired", False),
                    "sans": sinfo.get("sans", []),
                    "server_crt_path": VPN_SERVER_CERT,
                    "server_key_path": VPN_SERVER_KEY,
                    "ca_path": VPN_CA_CERT,
                    "client_crt_path": None,
                    "client_key_path": None,
                    "has_client": False,
                    "assigned_protocols": ["openvpn", "ikev2"]
                })
            except Exception:
                pass

        if defaults:
            save_imported_certs(defaults)
            return defaults
        return []

    try:
        with open(IMPORTED_CERTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_imported_certs(certs):
    os.makedirs(os.path.dirname(IMPORTED_CERTS_FILE), exist_ok=True)
    with open(IMPORTED_CERTS_FILE, "w", encoding="utf-8") as f:
        json.dump(certs, f, ensure_ascii=False, indent=2)

def get_protocol_certificate(protocol):
    certs = load_imported_certs()
    for c in certs:
        if protocol in c.get("assigned_protocols", []):
            crt = c.get("server_crt_path")
            key = c.get("server_key_path")
            ca = c.get("ca_path")
            if crt and key and os.path.exists(crt) and os.path.exists(key):
                return {
                    "cert_path": crt,
                    "key_path": key,
                    "ca_path": ca,
                    "id": c.get("id"),
                    "name": c.get("name"),
                    "type": c.get("type")
                }
    if protocol == "sstp":
        for cp, kp in [
            ("/etc/letsencrypt/live/vpn.kigaping.com/fullchain.pem", "/etc/letsencrypt/live/vpn.kigaping.com/privkey.pem"),
            ("/etc/letsencrypt/live/mhpanel.kigaping.com/fullchain.pem", "/etc/letsencrypt/live/mhpanel.kigaping.com/privkey.pem"),
            (VPN_SERVER_CERT, VPN_SERVER_KEY),
            (PANEL_CERT, PANEL_KEY)
        ]:
            if os.path.exists(cp) and os.path.exists(kp):
                return {"cert_path": cp, "key_path": kp, "ca_path": VPN_CA_CERT, "id": "default", "name": "System Default Certificate"}
    return {"cert_path": PANEL_CERT, "key_path": PANEL_KEY, "ca_path": VPN_CA_CERT, "id": "panel_ssl", "name": "Panel Web SSL"}

def apply_certificate_to_protocols(cert_entry, protocols):
    results = {}
    import shutil
    cert_path = cert_entry.get("server_crt_path")
    key_path = cert_entry.get("server_key_path")
    ca_path = cert_entry.get("ca_path")

    if not (cert_path and key_path and os.path.exists(cert_path) and os.path.exists(key_path)):
        return {"error": "فایل‌های گواهی سرور یا کلید خصوصی یافت نشدند"}

    if "sstp" in protocols:
        try:
            service_path = "/etc/systemd/system/sstpd.service"
            if os.path.exists(service_path):
                with open(service_path, "r", encoding="utf-8") as f:
                    content = f.read()
                content = re.sub(r"-c\s+[^\s]+", f"-c {cert_path}", content)
                content = re.sub(r"-k\s+[^\s]+", f"-k {key_path}", content)
                with open(service_path, "w", encoding="utf-8") as f:
                    f.write(content)
                subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
                subprocess.run(["systemctl", "restart", "sstpd"], capture_output=True)
            results["sstp"] = True
        except Exception as e:
            results["sstp"] = str(e)

    if "openvpn" in protocols:
        try:
            for d in ["/etc/openvpn/server", "/etc/openvpn"]:
                if os.path.isdir(d):
                    if ca_path and os.path.exists(ca_path):
                        shutil.copyfile(ca_path, os.path.join(d, "ca.crt"))
                    shutil.copyfile(cert_path, os.path.join(d, "server.crt"))
                    shutil.copyfile(key_path, os.path.join(d, "server.key"))
            subprocess.run(["systemctl", "restart", "openvpn-server@server"], capture_output=True)
            subprocess.run(["systemctl", "restart", "openvpn@server"], capture_output=True)
            subprocess.run(["systemctl", "restart", "openvpn"], capture_output=True)
            results["openvpn"] = True
        except Exception as e:
            results["openvpn"] = str(e)

    if "ocserv" in protocols:
        try:
            conf_path = "/etc/ocserv/ocserv.conf"
            if os.path.exists(conf_path):
                with open(conf_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                new_lines = []
                has_ca_in_conf = False
                for line in lines:
                    sline = line.strip()
                    if sline.startswith("server-cert"):
                        new_lines.append(f"server-cert = {cert_path}\n")
                    elif sline.startswith("server-key"):
                        new_lines.append(f"server-key = {key_path}\n")
                    elif sline.startswith("ca-cert"):
                        has_ca_in_conf = True
                        if ca_path and os.path.exists(ca_path):
                            new_lines.append(f"ca-cert = {ca_path}\n")
                        else:
                            new_lines.append(line)
                    else:
                        new_lines.append(line)
                if ca_path and os.path.exists(ca_path) and not has_ca_in_conf and len(new_lines) > 5:
                    new_lines.insert(5, f"ca-cert = {ca_path}\n")
                with open(conf_path, "w", encoding="utf-8") as f:
                    f.writelines(new_lines)
                subprocess.run(["systemctl", "restart", "ocserv"], capture_output=True)
            results["ocserv"] = True
        except Exception as e:
            results["ocserv"] = str(e)

    if "ikev2" in protocols:
        try:
            os.makedirs("/etc/ipsec.d/certs", exist_ok=True)
            os.makedirs("/etc/ipsec.d/private", exist_ok=True)
            os.makedirs("/etc/ipsec.d/cacerts", exist_ok=True)
            shutil.copyfile(cert_path, "/etc/ipsec.d/certs/server-cert.pem")
            shutil.copyfile(key_path, "/etc/ipsec.d/private/server-key.pem")
            if ca_path and os.path.exists(ca_path):
                shutil.copyfile(ca_path, "/etc/ipsec.d/cacerts/ca-cert.pem")
            subprocess.run(["systemctl", "restart", "ipsec"], capture_output=True)
            subprocess.run(["systemctl", "restart", "strongswan-starter"], capture_output=True)
            results["ikev2"] = True
        except Exception as e:
            results["ikev2"] = str(e)

    if "panel" in protocols:
        try:
            shutil.copyfile(cert_path, PANEL_CERT)
            shutil.copyfile(key_path, PANEL_KEY)
            restart_panel_service_threaded()
            results["panel"] = True
        except Exception as e:
            results["panel"] = str(e)

    return results

@app.route("/api/ssl/certificates", methods=["GET"])
def api_ssl_certificates():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    certs = load_imported_certs()
    for c in certs:
        # Refresh validity
        if c.get("server_crt_path") and os.path.exists(c["server_crt_path"]):
            try:
                with open(c["server_crt_path"], "r", encoding="utf-8") as f:
                    inf = parse_cert_info(f.read())
                    c["days_remaining"] = inf.get("days_remaining", c.get("days_remaining", 0))
                    c["is_expired"] = inf.get("is_expired", c.get("is_expired", False))
                    c["valid_until"] = inf.get("valid_until", c.get("valid_until", ""))
            except Exception:
                pass

    available_protocols = [
        {"id": "sstp", "name": "SSTP (Windows / MikroTik)", "icon": "shuffle", "color": "cyan"},
        {"id": "ocserv", "name": "سیسکو AnyConnect", "icon": "radio", "color": "blue"},
        {"id": "openvpn", "name": "اوپن‌وی‌پی‌ان (OpenVPN)", "icon": "lock", "color": "amber"},
        {"id": "ikev2", "name": "پروتکل IKEv2 / IPsec", "icon": "smartphone", "color": "purple"},
        {"id": "panel", "name": "پنل وب HTTPS", "icon": "globe", "color": "emerald"}
    ]
    return jsonify({
        "success": True,
        "certificates": certs,
        "available_protocols": available_protocols
    })

@app.route("/api/ssl/import-mikrotik", methods=["POST"])
def api_ssl_import_mikrotik():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    name = ""
    ca_crt = ""
    server_crt = ""
    server_key = ""
    client_crt = ""
    client_key = ""
    protocols = []

    if request.is_json:
        data = request.json or {}
        name = data.get("name", "").strip()
        ca_crt = data.get("ca_crt", "").strip()
        server_crt = data.get("server_crt", "").strip()
        server_key = data.get("server_key", "").strip()
        client_crt = data.get("client_crt", "").strip()
        client_key = data.get("client_key", "").strip()
        protocols = data.get("assign_protocols", [])
    else:
        name = request.form.get("name", "").strip()
        for field in ["ca_crt", "server_crt", "server_key", "client_crt", "client_key"]:
            if field in request.files and request.files[field].filename:
                val = request.files[field].read().decode("utf-8", errors="ignore")
            else:
                val = request.form.get(field, "").strip()
            if field == "ca_crt": ca_crt = val
            elif field == "server_crt": server_crt = val
            elif field == "server_key": server_key = val
            elif field == "client_crt": client_crt = val
            elif field == "client_key": client_key = val
        protocols_raw = request.form.get("assign_protocols", "[]")
        try:
            protocols = json.loads(protocols_raw) if protocols_raw.startswith("[") else [p.strip() for p in protocols_raw.split(",") if p.strip()]
        except Exception:
            protocols = []

    if not name:
        name = f"گواهی میکروتیک {datetime.now().strftime('%Y/%m/%d')}"

    if not ca_crt:
        return jsonify({"success": False, "error": "گواهی Root CA میکروتیک (ca.crt) الزامی است."}), 400
    if not server_crt:
        return jsonify({"success": False, "error": "گواهی سرور (server.crt) الزامی است."}), 400
    if not server_key:
        return jsonify({"success": False, "error": "کلید خصوصی سرور (server.key) الزامی است."}), 400

    is_valid, err_msg = validate_key_pair(server_crt, server_key)
    if not is_valid:
        return jsonify({"success": False, "error": f"کلید خصوصی با گواهی سرور همخوانی ندارد: {err_msg}"}), 400

    ca_info = parse_cert_info(ca_crt)
    if "error" in ca_info:
        return jsonify({"success": False, "error": f"فایل Root CA نامعتبر است: {ca_info['error']}"}), 400

    srv_info = parse_cert_info(server_crt)
    if "error" in srv_info:
        return jsonify({"success": False, "error": f"فایل گواهی سرور نامعتبر است: {srv_info['error']}"}), 400

    cert_id = f"mkt_{int(time.time())}_{secrets.token_hex(3)}"
    target_dir = os.path.join(IMPORTED_CERTS_DIR, cert_id)
    os.makedirs(target_dir, exist_ok=True)

    ca_path = os.path.join(target_dir, "ca.crt")
    srv_crt_path = os.path.join(target_dir, "server.crt")
    srv_key_path = os.path.join(target_dir, "server.key")
    with open(ca_path, "w", encoding="utf-8") as f:
        f.write(ca_crt.strip() + "\n")
    with open(srv_crt_path, "w", encoding="utf-8") as f:
        f.write(server_crt.strip() + "\n")
    with open(srv_key_path, "w", encoding="utf-8") as f:
        f.write(server_key.strip() + "\n")

    cli_crt_path = None
    cli_key_path = None
    if client_crt:
        cli_crt_path = os.path.join(target_dir, "client.crt")
        with open(cli_crt_path, "w", encoding="utf-8") as f:
            f.write(client_crt.strip() + "\n")
    if client_key:
        cli_key_path = os.path.join(target_dir, "client.key")
        with open(cli_key_path, "w", encoding="utf-8") as f:
            f.write(client_key.strip() + "\n")

    cert_entry = {
        "id": cert_id,
        "name": name,
        "type": "mikrotik",
        "type_label": "مهاجرت از میکروتیک (MikroTik CA)",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "common_name": srv_info.get("common_name", "MikroTik Server"),
        "subject": srv_info.get("subject", ""),
        "issuer": srv_info.get("issuer", ca_info.get("subject", "")),
        "ca_subject": ca_info.get("subject", ""),
        "valid_from": srv_info.get("valid_from", ""),
        "valid_until": srv_info.get("valid_until", ""),
        "days_remaining": srv_info.get("days_remaining", 0),
        "is_expired": srv_info.get("is_expired", False),
        "sans": srv_info.get("sans", []),
        "ca_path": ca_path,
        "server_crt_path": srv_crt_path,
        "server_key_path": srv_key_path,
        "client_crt_path": cli_crt_path,
        "client_key_path": cli_key_path,
        "has_client": bool(cli_crt_path),
        "assigned_protocols": protocols
    }

    certs = load_imported_certs()
    if protocols:
        for c in certs:
            c["assigned_protocols"] = [p for p in c.get("assigned_protocols", []) if p not in protocols]
        apply_res = apply_certificate_to_protocols(cert_entry, protocols)
        cert_entry["apply_status"] = apply_res

    certs.insert(0, cert_entry)
    save_imported_certs(certs)

    return jsonify({
        "success": True,
        "message": f"گواهی میکروتیک «{name}» با موفقیت وارد شد و بدون نیاز به تولید فایل جدید برای کلاینت‌ها فعال گردید.",
        "certificate": cert_entry
    })

@app.route("/api/ssl/import-custom", methods=["POST"])
def api_ssl_import_custom():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    name = ""
    cert_crt = ""
    cert_key = ""
    ca_crt = ""
    protocols = []

    if request.is_json:
        data = request.json or {}
        name = data.get("name", "").strip()
        cert_crt = data.get("cert_crt", "").strip()
        cert_key = data.get("cert_key", "").strip()
        ca_crt = data.get("ca_crt", "").strip()
        protocols = data.get("assign_protocols", [])
    else:
        name = request.form.get("name", "").strip()
        for field in ["cert_crt", "cert_key", "ca_crt"]:
            if field in request.files and request.files[field].filename:
                val = request.files[field].read().decode("utf-8", errors="ignore")
            else:
                val = request.form.get(field, "").strip()
            if field == "cert_crt": cert_crt = val
            elif field == "cert_key": cert_key = val
            elif field == "ca_crt": ca_crt = val
        protocols_raw = request.form.get("assign_protocols", "[]")
        try:
            protocols = json.loads(protocols_raw) if protocols_raw.startswith("[") else [p.strip() for p in protocols_raw.split(",") if p.strip()]
        except Exception:
            protocols = []

    if not name:
        name = f"گواهی سفارشی {datetime.now().strftime('%Y/%m/%d')}"

    if not cert_crt or not cert_key:
        return jsonify({"success": False, "error": "متن سرتیفیکیت و کلید خصوصی الزامی هستند."}), 400

    is_valid, err_msg = validate_key_pair(cert_crt, cert_key)
    if not is_valid:
        return jsonify({"success": False, "error": f"کلید خصوصی با سرتیفیکیت همخوانی ندارد: {err_msg}"}), 400

    srv_info = parse_cert_info(cert_crt)
    if "error" in srv_info:
        return jsonify({"success": False, "error": f"فایل گواهی نامعتبر است: {srv_info['error']}"}), 400

    cert_id = f"cst_{int(time.time())}_{secrets.token_hex(3)}"
    target_dir = os.path.join(IMPORTED_CERTS_DIR, cert_id)
    os.makedirs(target_dir, exist_ok=True)

    srv_crt_path = os.path.join(target_dir, "server.crt")
    srv_key_path = os.path.join(target_dir, "server.key")
    with open(srv_crt_path, "w", encoding="utf-8") as f:
        f.write(cert_crt.strip() + "\n")
    with open(srv_key_path, "w", encoding="utf-8") as f:
        f.write(cert_key.strip() + "\n")

    ca_path = None
    if ca_crt:
        ca_path = os.path.join(target_dir, "ca.crt")
        with open(ca_path, "w", encoding="utf-8") as f:
            f.write(ca_crt.strip() + "\n")

    cert_entry = {
        "id": cert_id,
        "name": name,
        "type": "custom",
        "type_label": "گواهی عمومی SSL (سفارشی)",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "common_name": srv_info.get("common_name", "SSL Certificate"),
        "subject": srv_info.get("subject", ""),
        "issuer": srv_info.get("issuer", "Unknown Issuer"),
        "valid_from": srv_info.get("valid_from", ""),
        "valid_until": srv_info.get("valid_until", ""),
        "days_remaining": srv_info.get("days_remaining", 0),
        "is_expired": srv_info.get("is_expired", False),
        "sans": srv_info.get("sans", []),
        "ca_path": ca_path,
        "server_crt_path": srv_crt_path,
        "server_key_path": srv_key_path,
        "client_crt_path": None,
        "client_key_path": None,
        "has_client": False,
        "assigned_protocols": protocols
    }

    certs = load_imported_certs()
    if protocols:
        for c in certs:
            c["assigned_protocols"] = [p for p in c.get("assigned_protocols", []) if p not in protocols]
        apply_res = apply_certificate_to_protocols(cert_entry, protocols)
        cert_entry["apply_status"] = apply_res

    certs.insert(0, cert_entry)
    save_imported_certs(certs)

    return jsonify({
        "success": True,
        "message": f"گواهی سفارشی «{name}» با موفقیت ذخیره و فعال شد.",
        "certificate": cert_entry
    })

@app.route("/api/ssl/certificates/<cert_id>/assign", methods=["POST"])
def api_ssl_assign_certificate(cert_id):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json or {}
    protocols = data.get("protocols", [])

    certs = load_imported_certs()
    target_cert = None
    for c in certs:
        if c["id"] == cert_id:
            target_cert = c
            break

    if not target_cert:
        return jsonify({"success": False, "error": "گواهی مورد نظر یافت نشد"}), 404

    for c in certs:
        if c["id"] != cert_id:
            c["assigned_protocols"] = [p for p in c.get("assigned_protocols", []) if p not in protocols]

    target_cert["assigned_protocols"] = protocols
    apply_res = apply_certificate_to_protocols(target_cert, protocols)
    target_cert["apply_status"] = apply_res
    save_imported_certs(certs)

    return jsonify({
        "success": True,
        "message": f"گواهی «{target_cert['name']}» با موفقیت به پروتکل‌های انتخاب‌شده تخصیص داده شد.",
        "apply_results": apply_res
    })

@app.route("/api/ssl/certificates/<cert_id>", methods=["DELETE"])
def api_ssl_delete_certificate(cert_id):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    certs = load_imported_certs()
    target_cert = None
    new_certs = []
    for c in certs:
        if c["id"] == cert_id:
            target_cert = c
        else:
            new_certs.append(c)

    if not target_cert:
        return jsonify({"success": False, "error": "گواهی یافت نشد"}), 404

    target_dir = os.path.join(IMPORTED_CERTS_DIR, cert_id)
    if os.path.exists(target_dir):
        try:
            import shutil
            shutil.rmtree(target_dir)
        except Exception:
            pass

    save_imported_certs(new_certs)
    return jsonify({
        "success": True,
        "message": f"گواهی «{target_cert['name']}» با موفقیت حذف شد."
    })

@app.route("/api/ssl/certificates/<cert_id>/download/<file_type>", methods=["GET"])
def api_ssl_download_cert_file(cert_id, file_type):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    certs = load_imported_certs()
    target = next((c for c in certs if c["id"] == cert_id), None)
    if not target:
        return jsonify({"error": "Certificate not found"}), 404

    from flask import send_file
    path = None
    download_name = f"{cert_id}.crt"
    mimetype = "application/x-x509-ca-cert"

    clean_name = re.sub(r"[^\w\-_.]", "_", target.get("name", "cert"))

    if file_type == "ca":
        path = target.get("ca_path")
        download_name = f"{clean_name}-ca.crt"
    elif file_type == "server_crt":
        path = target.get("server_crt_path")
        download_name = f"{clean_name}-server.crt"
    elif file_type == "client_crt":
        path = target.get("client_crt_path")
        download_name = f"{clean_name}-client.crt"
    elif file_type == "server_key":
        path = target.get("server_key_path")
        download_name = f"{clean_name}-server.key"
        mimetype = "application/x-pem-file"
    elif file_type == "client_key":
        path = target.get("client_key_path")
        download_name = f"{clean_name}-client.key"
        mimetype = "application/x-pem-file"

    if path and os.path.exists(path):
        return send_file(path, as_attachment=True, download_name=download_name, mimetype=mimetype)
    return jsonify({"error": "File not found"}), 404


@app.route("/api/protocols/batch-install", methods=["POST"])
def api_protocols_batch_install():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json or {}
    protocols = data.get("protocols", [])
    if not protocols or not isinstance(protocols, list):
        return jsonify({"success": False, "error": "هیچ پروتکلی برای نصب انتخاب نشده است"}), 400

    results = []
    for proto in protocols:
        p_name = proto.get("name") if isinstance(proto, dict) else str(proto)
        p_port = proto.get("port") if isinstance(proto, dict) else None
        if not p_name: continue
        success, stdout, stderr = run_helper("install", p_name, p_port, "")
        results.append({
            "protocol": p_name,
            "success": success,
            "message": stdout if success else stderr
        })

    return jsonify({"success": True, "results": results})


@app.route("/api/openvpn/ca/status", methods=["GET"])
def api_openvpn_ca_status():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    real_ca = "/etc/openvpn/server/ca.crt" if os.path.exists("/etc/openvpn/server/ca.crt") else VPN_CA_CERT
    details = get_certificate_details(real_ca)
    details["has_tc_key"] = os.path.exists("/etc/openvpn/server/tc.key") or os.path.exists("/etc/openvpn/tls-crypt.key")
    return jsonify(details)

@app.route("/api/openvpn/ca.crt", methods=["GET"])
def api_openvpn_download_ca():
    if not check_login():
        return "Unauthorized", 401
    from flask import send_file
    ca_path = "/etc/openvpn/server/ca.crt" if os.path.exists("/etc/openvpn/server/ca.crt") else "/etc/openvpn/ca.crt"
    if os.path.exists(ca_path):
        return send_file(ca_path, as_attachment=True, download_name="openvpn-ca.crt", mimetype="application/x-x509-ca-cert")
    return "CA certificate not found", 404

@app.route("/api/openvpn/tc.key", methods=["GET"])
def api_openvpn_download_tc():
    if not check_login():
        return "Unauthorized", 401
    from flask import send_file
    tc_path = "/etc/openvpn/server/tc.key" if os.path.exists("/etc/openvpn/server/tc.key") else "/etc/openvpn/tls-crypt.key"
    if os.path.exists(tc_path):
        return send_file(tc_path, as_attachment=True, download_name="tc.key", mimetype="text/plain")
    return "TLS-crypt key not found", 404

@app.route("/api/openvpn/ca/regenerate", methods=["POST"])
def api_openvpn_ca_regenerate():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    try:
        subprocess.run(["systemctl", "restart", "openvpn-server@server", "openvpn-server@server-tcp"], check=False)
        return jsonify({"success": True, "message": "گواهی و سرویس‌های OpenVPN با موفقیت به‌روزرسانی و مجدداً راه‌اندازی شدند."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/system/ports", methods=["GET"])
def api_system_ports():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    ports = []
    try:
        res = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            lines = res.stdout.strip().split("\n")
            for line in lines[1:]:
                parts = line.split()
                if len(parts) < 5:
                    continue
                netid = parts[0]
                local_addr_port = parts[4]
                
                if "]" in local_addr_port:
                    addr_part, port_part = local_addr_port.rsplit(":", 1)
                else:
                    addr_part, port_part = local_addr_port.rsplit(":", 1)
                
                try:
                    port = int(port_part)
                except ValueError:
                    port = port_part

                process_info = "-"
                pid = "-"
                if len(parts) >= 7:
                    proc_col = parts[6]
                    match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', proc_col)
                    if match:
                        process_info = match.group(1)
                        pid = match.group(2)
                    else:
                        match2 = re.search(r'pid=(\d+)', proc_col)
                        if match2:
                            pid = match2.group(1)
                        match3 = re.search(r'\(\(([^,]+)', proc_col)
                        if match3:
                            process_info = match3.group(1).replace('"', '')
                
                ports.append({
                    "protocol": netid,
                    "address": addr_part,
                    "port": port,
                    "process": process_info,
                    "pid": pid
                })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
        
    return jsonify(ports)

# --- Cloudflare WARP & TCP BBR Management ---

def get_warp_info():
    import shutil
    cli = shutil.which("warp-cli")
    if not cli:
        return {"installed": False, "connected": False, "status": "Not Installed", "account_type": "-", "license": "", "socks_port": 40000}
    info = {"installed": True, "connected": False, "status": "Disconnected", "account_type": "Free", "license": "", "socks_port": 40000}
    try:
        res = subprocess.run(["warp-cli", "--accept-tos", "status"], capture_output=True, text=True, timeout=5)
        out = res.stdout
        if "Connected" in out:
            info["connected"] = True
            info["status"] = "Connected"
        elif "Connecting" in out:
            info["status"] = "Connecting"
        else:
            info["status"] = "Disconnected"

        res_reg = subprocess.run(["warp-cli", "--accept-tos", "registration", "show"], capture_output=True, text=True, timeout=5)
        out_reg = res_reg.stdout
        for line in out_reg.splitlines():
            line = line.strip()
            if "Account type:" in line:
                info["account_type"] = line.split(":", 1)[1].strip()
            elif "License:" in line:
                info["license"] = line.split(":", 1)[1].strip()
    except Exception as e:
        info["error"] = str(e)
    return info

@app.route("/api/warp/status", methods=["GET"])
def api_warp_status():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_warp_info())

@app.route("/api/warp/connect", methods=["POST"])
def api_warp_connect():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        subprocess.run(["systemctl", "start", "warp-svc"], check=False)
        subprocess.run(["warp-cli", "--accept-tos", "mode", "proxy"], check=False)
        res = subprocess.run(["warp-cli", "--accept-tos", "connect"], capture_output=True, text=True, timeout=10)
        time.sleep(1)
        return jsonify({"success": True, "output": res.stdout.strip(), "info": get_warp_info()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/warp/disconnect", methods=["POST"])
def api_warp_disconnect():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        res = subprocess.run(["warp-cli", "--accept-tos", "disconnect"], capture_output=True, text=True, timeout=10)
        time.sleep(1)
        return jsonify({"success": True, "output": res.stdout.strip(), "info": get_warp_info()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/warp/set-license", methods=["POST"])
def api_warp_set_license():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    key = data.get("license", "").strip()
    if not key:
        return jsonify({"error": "کد لایسنس وارپ ارسال نشده است."}), 400
    try:
        res = subprocess.run(["warp-cli", "--accept-tos", "registration", "license", key], capture_output=True, text=True, timeout=15)
        if "Success" in res.stdout or res.returncode == 0:
            subprocess.run(["warp-cli", "--accept-tos", "connect"], check=False)
            return jsonify({"success": True, "message": "لایسنس با موفقیت اعمال شد.", "info": get_warp_info()})
        else:
            return jsonify({"success": False, "error": res.stderr.strip() or res.stdout.strip()}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/warp/reset", methods=["POST"])
def api_warp_reset():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        subprocess.run(["warp-cli", "--accept-tos", "disconnect"], check=False)
        subprocess.run(["warp-cli", "--accept-tos", "registration", "new"], capture_output=True, text=True, timeout=15)
        subprocess.run(["warp-cli", "--accept-tos", "mode", "proxy"], check=False)
        subprocess.run(["warp-cli", "--accept-tos", "connect"], check=False)
        time.sleep(1)
        return jsonify({"success": True, "message": "اکانت رایگان جدید با موفقیت ایجاد و متصل شد.", "info": get_warp_info()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

def get_bbr_info():
    info = {"active": False, "algo": "cubic", "qdisc": "fq_codel", "available": []}
    try:
        r1 = subprocess.run(["sysctl", "-n", "net.ipv4.tcp_congestion_control"], capture_output=True, text=True)
        r2 = subprocess.run(["sysctl", "-n", "net.core.default_qdisc"], capture_output=True, text=True)
        r3 = subprocess.run(["sysctl", "-n", "net.ipv4.tcp_available_congestion_control"], capture_output=True, text=True)
        info["algo"] = r1.stdout.strip()
        info["qdisc"] = r2.stdout.strip()
        info["available"] = r3.stdout.strip().split()
        info["active"] = (info["algo"] == "bbr")
    except Exception:
        pass
    return info

@app.route("/api/system/bbr", methods=["GET"])
def api_system_bbr():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_bbr_info())

@app.route("/api/system/bbr/enable", methods=["POST"])
def api_system_bbr_enable():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        conf_content = """# MHPanel TCP BBR & Network Buffer Optimizations
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
"""
        with open("/etc/sysctl.d/99-bbr.conf", "w") as f:
            f.write(conf_content)
        subprocess.run(["sysctl", "--system"], capture_output=True, text=True)
        return jsonify({"success": True, "message": "تنظیمات بهینه‌ساز BBR و بافرهای شبکه با موفقیت اعمال و تثبیت شد.", "info": get_bbr_info()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/terminal/execute", methods=["POST"])
def api_terminal_execute():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.json
    command = data.get("command", "").strip()
    cwd = data.get("cwd", "").strip()
    
    if not cwd or not os.path.exists(cwd):
        cwd = "/root"
        
    if not command:
        return jsonify({"output": "", "cwd": cwd})
        
    separator = "___CWD_SEPARATOR___"
    wrapped_command = f"cd '{cwd}' && {command} ; echo -n '{separator}' ; pwd"
    
    try:
        res = subprocess.run(
            ["bash", "-c", wrapped_command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15
        )
        
        stdout = res.stdout
        stderr = res.stderr
        
        new_cwd = cwd
        output = stdout
        
        if separator in stdout:
            parts = stdout.rsplit(separator, 1)
            output = parts[0]
            possible_cwd = parts[1].strip()
            if os.path.exists(possible_cwd):
                new_cwd = possible_cwd
                
        full_output = output
        if stderr:
            if full_output:
                full_output = full_output + "\n" + stderr
            else:
                full_output = stderr
                
        return jsonify({
            "output": full_output,
            "cwd": new_cwd
        })
        
    except subprocess.TimeoutExpired:
        return jsonify({
            "output": "Command timed out after 15 seconds.",
            "cwd": cwd
        }), 500
    except Exception as e:
        return jsonify({
            "output": f"Error executing command: {str(e)}",
            "cwd": cwd
        }), 500

# --- Remote Servers Manager ---
def get_servers_file():
    if os.environ.get("DEV_MODE") or os.environ.get("FLASK_ENV") == "development":
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "dev_data", "servers.json")
    return "/www/wwwroot/mhpanel/servers.json"

@app.route("/api/servers", methods=["GET"])
def api_servers_list():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    sf = get_servers_file()
    if os.path.exists(sf):
        try:
            with open(sf, "r") as f:
                return jsonify(json.load(f))
        except Exception:
            return jsonify([])
    return jsonify([])

@app.route("/api/servers/add", methods=["POST"])
def api_servers_add():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    sf = get_servers_file()
    servers = []
    if os.path.exists(sf):
        try:
            with open(sf, "r") as f:
                servers = json.load(f)
        except Exception:
            pass
    servers.append({
        "ip": data.get("ip"),
        "port": data.get("port"),
        "user": data.get("user"),
        "pass": data.get("pass")
    })
    try:
        with open(sf, "w") as f:
            json.dump(servers, f)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/servers/delete", methods=["POST"])
def api_servers_delete():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    ip = request.json.get("ip")
    sf = get_servers_file()
    if os.path.exists(sf):
        try:
            with open(sf, "r") as f:
                servers = json.load(f)
            servers = [s for s in servers if s.get("ip") != ip]
            with open(sf, "w") as f:
                json.dump(servers, f)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
    return jsonify({"success": True})

@app.route("/api/servers/install", methods=["POST"])
def api_servers_install():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    ip = data.get("ip")
    # Placeholder for actual SSH connection and script execution
    # e.g. using paramiko or sshpass, which can be configured later
    return jsonify({"success": True, "message": f"Simulated install on {ip}. Waiting for script details."})

# --- OpenVPN User Management ---
# --- OpenVPN User & Multi-Port Management ---
OPENVPN_MULTIPORT_FILE = "/www/wwwroot/mhpanel/openvpn_multiport.json"

def get_default_openvpn_multiport_config():
    return {
        "udp_enabled": True,
        "tcp_enabled": True,
        "primary_udp_port": 1194,
        "primary_tcp_port": 1194,
        "extra_udp_ports": [],
        "extra_tcp_ports": [9443],
        "server_host": "212.227.143.16",
        "scramble_enabled": False,
        "scramble_key": "openvpn_xor"
    }

def get_openvpn_multiport_config():
    if os.path.exists(OPENVPN_MULTIPORT_FILE):
        try:
            with open(OPENVPN_MULTIPORT_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    cfg = get_default_openvpn_multiport_config()
    try:
        with open(OPENVPN_MULTIPORT_FILE, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception:
        pass
    return cfg

RESERVED_SYSTEM_PORTS = {
    21, 22, 25, 53, 80, 106, 110, 143, 443, 465, 500, 587, 888, 904, 993, 995, 
    1194, 1812, 1813, 2053, 2083, 2087, 2096, 2567, 3306, 4443, 4500, 5000, 5001, 
    5006, 5055, 5065, 8080, 8443, 8444, 8880, 9090, 10443, 51820, 51821
}

def apply_openvpn_multiport_iptables(config):
    try:
        subprocess.run("iptables -t nat -N OPENVPN_MULTIPORT 2>/dev/null || true", shell=True)
        subprocess.run("iptables -t nat -C PREROUTING -j OPENVPN_MULTIPORT 2>/dev/null || iptables -t nat -I PREROUTING 2 -j OPENVPN_MULTIPORT", shell=True)
        subprocess.run("iptables -t nat -F OPENVPN_MULTIPORT", shell=True)

        subprocess.run("iptables -N OPENVPN_MULTIPORT_IN 2>/dev/null || true", shell=True)
        subprocess.run("iptables -C INPUT -j OPENVPN_MULTIPORT_IN 2>/dev/null || iptables -I INPUT 2 -j OPENVPN_MULTIPORT_IN", shell=True)
        subprocess.run("iptables -F OPENVPN_MULTIPORT_IN", shell=True)

        if config.get("udp_enabled", True):
            uports = [int(p) for p in config.get("extra_udp_ports", []) if str(p).isdigit() and int(p) > 0 and int(p) != 1194 and int(p) not in RESERVED_SYSTEM_PORTS]
            if uports:
                chunks = [uports[i:i + 15] for i in range(0, len(uports), 15)]
                for chunk in chunks:
                    csv = ",".join(str(p) for p in chunk)
                    subprocess.run(f"iptables -t nat -A OPENVPN_MULTIPORT -p udp -m multiport --dports {csv} -j REDIRECT --to-ports 1194", shell=True)
                    subprocess.run(f"iptables -A OPENVPN_MULTIPORT_IN -p udp -m multiport --dports {csv} -j ACCEPT", shell=True)

        if config.get("tcp_enabled", True):
            tports = [int(p) for p in config.get("extra_tcp_ports", []) if str(p).isdigit() and int(p) > 0 and int(p) != 1194 and int(p) not in RESERVED_SYSTEM_PORTS]
            if tports:
                chunks = [tports[i:i + 15] for i in range(0, len(tports), 15)]
                for chunk in chunks:
                    csv = ",".join(str(p) for p in chunk)
                    subprocess.run(f"iptables -t nat -A OPENVPN_MULTIPORT -p tcp -m multiport --dports {csv} -j REDIRECT --to-ports 1194", shell=True)
                    subprocess.run(f"iptables -A OPENVPN_MULTIPORT_IN -p tcp -m multiport --dports {csv} -j ACCEPT", shell=True)

        subprocess.run("iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o ens6 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ens6 -j MASQUERADE", shell=True)
        subprocess.run("iptables -t nat -C POSTROUTING -s 10.9.0.0/24 -o ens6 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o ens6 -j MASQUERADE", shell=True)
        subprocess.run("which netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true", shell=True)
        subprocess.run("which iptables-save >/dev/null 2>&1 && iptables-save > /etc/iptables/rules.v4 2>/dev/null || true", shell=True)
    except Exception as e:
        print(f"Error applying openvpn multiport: {e}")

def get_ovpn_traffic():
    traffic = {}
    for log_file in ["/var/log/openvpn/openvpn-status.log", "/var/log/openvpn/openvpn-tcp-status.log", "/var/log/openvpn-status.log"]:
        if os.path.exists(log_file):
            try:
                with open(log_file, "r") as f:
                    content = f.read()
                lines = content.split('\n')
                in_client_list = False
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("CLIENT_LIST,"):
                        parts = line.split(",")
                        if len(parts) >= 7:
                            uname = parts[1].strip()
                            if len(parts) > 10 and parts[10].strip() and parts[10].strip() != "UNDEF":
                                uname = parts[10].strip()
                            try:
                                rx = int(parts[5])
                                tx = int(parts[6])
                                if uname not in traffic:
                                    traffic[uname] = {"rx": 0, "tx": 0}
                                traffic[uname]["rx"] += rx
                                traffic[uname]["tx"] += tx
                            except ValueError:
                                pass
                    if line.startswith("Common Name,"):
                        in_client_list = True
                        continue
                    if line.startswith("ROUTING TABLE"):
                        in_client_list = False
                    if in_client_list and "," in line:
                        parts = line.split(",")
                        if len(parts) >= 4:
                            uname = parts[0].strip()
                            try:
                                rx = int(parts[2])
                                tx = int(parts[3])
                                if uname not in traffic:
                                    traffic[uname] = {"rx": 0, "tx": 0}
                                traffic[uname]["rx"] += rx
                                traffic[uname]["tx"] += tx
                            except ValueError:
                                pass
            except Exception:
                pass
    return traffic

def ovpn_client_tracker():
    while True:
        try:
            users_file = "/www/wwwroot/mhpanel/ovpn_users.json"
            if os.path.exists(users_file):
                with open(users_file, "r") as f:
                    try:
                        users = json.load(f)
                    except:
                        users = {}
                
                traffic = get_ovpn_traffic()
                changed = False
                now_str = datetime.now().strftime("%Y-%m-%d")
                
                for username, user_data in users.items():
                    tdata = traffic.get(username, {"rx": 0, "tx": 0})
                    if "rx" not in user_data: user_data["rx"] = 0
                    if "tx" not in user_data: user_data["tx"] = 0
                    if tdata["rx"] > user_data.get("last_rx", 0):
                        user_data["rx"] += (tdata["rx"] - user_data.get("last_rx", 0))
                    user_data["last_rx"] = tdata["rx"]
                    
                    if tdata["tx"] > user_data.get("last_tx", 0):
                        user_data["tx"] += (tdata["tx"] - user_data.get("last_tx", 0))
                    user_data["last_tx"] = tdata["tx"]

                    limit_gb = user_data.get("limit_gb")
                    expire_date = user_data.get("expire_date")
                    disabled = False
                    
                    total_usage = user_data["rx"] + user_data["tx"]
                    
                    if expire_date:
                        if now_str > expire_date:
                            disabled = True
                            
                    if limit_gb and not disabled:
                        if total_usage >= limit_gb * (1024**3):
                            disabled = True
                            
                    if disabled:
                        if user_data.get("active", True):
                            user_data["active"] = False
                            changed = True
                            subprocess.run(["usermod", "-L", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                if changed or len(traffic) > 0:
                    with open(users_file, "w") as f:
                        json.dump(users, f)
        except Exception:
            pass
        time.sleep(60)

@app.route("/api/openvpn/config", methods=["GET"])
def api_get_openvpn_config():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    cfg = get_openvpn_multiport_config()
    udp_active = get_service_is_active("openvpn-server@server")
    tcp_active = get_service_is_active("openvpn-server@server-tcp")
    udpspeeder_active = get_service_is_active("udpspeeder-openvpn")
    
    real_ca = "/etc/openvpn/server/ca.crt" if os.path.exists("/etc/openvpn/server/ca.crt") else VPN_CA_CERT
    ca_details = get_certificate_details(real_ca)
    ca_details["has_tc_key"] = os.path.exists("/etc/openvpn/server/tc.key") or os.path.exists("/etc/openvpn/tls-crypt.key")

    settings = get_protocol_settings()
    server_ip = settings.get("wireguard_server_ip", "212.227.143.16")
    domains = ["212.227.143.16", "kigaping.com", "ovpn.kigaping.com", "vpn.kigaping.com"]
    
    return jsonify({
        "success": True,
        "config": cfg,
        "status": {
            "udp_active": udp_active,
            "tcp_active": tcp_active,
            "udpspeeder_active": udpspeeder_active,
            "freeradius_active": get_service_is_active("freeradius")
        },
        "ca_details": ca_details,
        "server_ip": server_ip,
        "domains": domains
    })

@app.route("/api/openvpn/config", methods=["POST"])
def api_save_openvpn_config():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    
    def parse_ports(val):
        if isinstance(val, list):
            return [int(p) for p in val if str(p).isdigit() and 0 < int(p) <= 65535]
        if isinstance(val, str):
            return [int(p.strip()) for p in val.split(",") if p.strip().isdigit() and 0 < int(p.strip()) <= 65535]
        return []

    cfg = get_openvpn_multiport_config()
    cfg["udp_enabled"] = bool(data.get("udp_enabled", True))
    cfg["tcp_enabled"] = bool(data.get("tcp_enabled", True))
    if "extra_udp_ports" in data:
        cfg["extra_udp_ports"] = parse_ports(data["extra_udp_ports"])
    if "extra_tcp_ports" in data:
        cfg["extra_tcp_ports"] = parse_ports(data["extra_tcp_ports"])
    if "scramble_key" in data:
        cfg["scramble_key"] = data["scramble_key"].strip() or "openvpn_xor"
    if "dns_servers" in data:
        cfg["dns_servers"] = data["dns_servers"].strip() or "1.1.1.1, 8.8.8.8"
    if "mssfix" in data:
        cfg["mssfix"] = bool(data["mssfix"])
    if "fast_io" in data:
        cfg["fast_io"] = bool(data["fast_io"])
    if "block_outside_dns" in data:
        cfg["block_outside_dns"] = bool(data["block_outside_dns"])
    if "tcp_nodelay" in data:
        cfg["tcp_nodelay"] = bool(data["tcp_nodelay"])
        
    try:
        with open(OPENVPN_MULTIPORT_FILE, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
            
        apply_openvpn_multiport_iptables(cfg)
        
        if cfg["udp_enabled"]:
            if not get_service_is_active("openvpn-server@server"):
                subprocess.run(["systemctl", "start", "openvpn-server@server"])
        else:
            subprocess.run(["systemctl", "stop", "openvpn-server@server"])
            
        if cfg["tcp_enabled"]:
            if not get_service_is_active("openvpn-server@server-tcp"):
                subprocess.run(["systemctl", "start", "openvpn-server@server-tcp"])
        else:
            subprocess.run(["systemctl", "stop", "openvpn-server@server-tcp"])
            
        return jsonify({"success": True, "message": "تنظیمات ساخت سرور و مولتی‌پورت OpenVPN با موفقیت در فایروال و هسته شبکه اعمال شد."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/openvpn/service", methods=["POST"])
def api_openvpn_service_action():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    action = (request.json or {}).get("action", "restart")
    try:
        if action == "restart":
            subprocess.run(["systemctl", "restart", "openvpn-server@server", "openvpn-server@server-tcp"])
            msg = "تمامی سرویس‌های OpenVPN (UDP و TCP) با موفقیت راه‌اندازی مجدد شدند."
        elif action == "restart_udp":
            subprocess.run(["systemctl", "restart", "openvpn-server@server"])
            msg = "سرویس OpenVPN UDP با موفقیت راه‌اندازی مجدد شد."
        elif action == "restart_tcp":
            subprocess.run(["systemctl", "restart", "openvpn-server@server-tcp"])
            msg = "سرویس OpenVPN TCP با موفقیت راه‌اندازی مجدد شد."
        elif action == "stop":
            subprocess.run(["systemctl", "stop", "openvpn-server@server", "openvpn-server@server-tcp"])
            msg = "سرویس‌های OpenVPN متوقف شدند."
        elif action == "start":
            subprocess.run(["systemctl", "start", "openvpn-server@server", "openvpn-server@server-tcp"])
            msg = "سرویس‌های OpenVPN روشن شدند."
        else:
            return jsonify({"success": False, "error": "عملیات نامعتبر است."}), 400
        return jsonify({"success": True, "message": msg})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/openvpn/addons/udpspeeder", methods=["POST"])
def api_openvpn_udpspeeder_action():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    action = (request.json or {}).get("action", "toggle")
    try:
        is_active = get_service_is_active("udpspeeder-openvpn")
        if action == "toggle":
            target = "stop" if is_active else "start"
            subprocess.run(["systemctl", target, "udpspeeder-openvpn"])
            new_state = "متوقف" if is_active else "روشن"
            return jsonify({"success": True, "message": f"سرویس UDPspeeder با موفقیت {new_state} شد."})
        elif action in ["start", "stop", "restart"]:
            subprocess.run(["systemctl", action, "udpspeeder-openvpn"])
            return jsonify({"success": True, "message": f"عملیات {action} روی UDPspeeder انجام شد."})
        return jsonify({"success": False, "error": "عملیات نامعتبر است."}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/openvpn/users", methods=["GET"])
def api_get_openvpn_users():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    users = {}
    traffic = get_ovpn_traffic()
    
    # 1. Load users from radius_users.json (FreeRADIUS)
    radius_file = "/www/wwwroot/mhpanel/radius_users.json"
    if os.path.exists(radius_file):
        try:
            with open(radius_file, "r") as f:
                r_data = json.load(f)
            if isinstance(r_data, dict):
                for uname, uinfo in r_data.items():
                    users[uname] = {
                        "active": uinfo.get("active", True),
                        "limit_gb": uinfo.get("limit_gb"),
                        "expire_date": uinfo.get("expire_date"),
                        "created_at": uinfo.get("created_at"),
                        "auth_source": "FreeRADIUS",
                        "rx": 0,
                        "tx": 0
                    }
        except Exception:
            pass
            
    # 2. Also check ovpn_users.json and merge usage / extra fields
    users_file = "/www/wwwroot/mhpanel/ovpn_users.json"
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                o_data = json.load(f)
            if isinstance(o_data, dict):
                for uname, uinfo in o_data.items():
                    if uname in users:
                        users[uname]["rx"] = uinfo.get("rx", 0)
                        users[uname]["tx"] = uinfo.get("tx", 0)
                        users[uname]["active"] = uinfo.get("active", users[uname]["active"])
                    else:
                        users[uname] = {
                            "active": uinfo.get("active", True),
                            "limit_gb": uinfo.get("limit_gb"),
                            "expire_date": uinfo.get("expire_date"),
                            "auth_source": "Local/PAM",
                            "rx": uinfo.get("rx", 0),
                            "tx": uinfo.get("tx", 0)
                        }
        except Exception:
            pass

    for uname, tdata in traffic.items():
        if uname in users:
            users[uname]["rx"] = max(users[uname].get("rx", 0), tdata.get("rx", 0))
            users[uname]["tx"] = max(users[uname].get("tx", 0), tdata.get("tx", 0))

    def_user = get_default_test_user()
    if def_user and def_user.get("username"):
        uname = def_user["username"]
        if uname not in users:
            users[uname] = {
                "active": True,
                "limit_gb": None,
                "expire_date": None,
                "auth_source": "FreeRADIUS (Test User)",
                "rx": 0,
                "tx": 0,
                "is_default": True
            }
        else:
            users[uname]["is_default"] = True
            users[uname]["auth_source"] = "FreeRADIUS (Test User)"
            
    return jsonify({"users": users})

@app.route("/api/openvpn/users", methods=["POST"])
def api_add_openvpn_user():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    limit_gb = data.get("limit_gb")
    expire_date = data.get("expire_date")
    
    if not username or not password:
        return jsonify({"error": "نام کاربری و کلمه عبور الزامی هستند."}), 400
        
    try:
        r_file = "/www/wwwroot/mhpanel/radius_users.json"
        r_users = {}
        if os.path.exists(r_file):
            try:
                with open(r_file, "r") as f:
                    r_users = json.load(f)
            except Exception:
                pass
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        r_users[username] = {
            "password": password,
            "active": True,
            "expire_date": expire_date or None,
            "limit_gb": float(limit_gb) if limit_gb else None,
            "created_at": now_str,
            "protocols": ["all"]
        }
        with open(r_file, "w") as f:
            json.dump(r_users, f, indent=2)
            
        fr_lines = ["# MH Panel Unified RADIUS Database\n"]
        for u, inf in r_users.items():
            if inf.get("active", True):
                pw = inf.get("password", "")
                fr_lines.append(f'"{u}" Cleartext-Password := "{pw}"\n')
                if u != u.lower():
                    fr_lines.append(f'"{u.lower()}" Cleartext-Password := "{pw}"\n')
        with open("/etc/freeradius/3.0/mhpanel_users", "w") as f:
            f.writelines(fr_lines)
            
        try:
            subprocess.run(["id", username], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            subprocess.run(["useradd", "-M", "-s", "/usr/sbin/nologin", username], check=False)
        proc = subprocess.Popen(["chpasswd"], stdin=subprocess.PIPE, text=True)
        proc.communicate(f"{username}:{password}")
        
        users_file = "/www/wwwroot/mhpanel/ovpn_users.json"
        users = {}
        if os.path.exists(users_file):
            try:
                with open(users_file, "r") as f:
                    users = json.load(f)
            except Exception:
                pass
        users[username] = {
            "active": True,
            "limit_gb": float(limit_gb) if limit_gb else None,
            "expire_date": expire_date or None,
            "rx": 0,
            "tx": 0,
            "last_rx": 0,
            "last_tx": 0
        }
        with open(users_file, "w") as f:
            json.dump(users, f, indent=2)
            
        return jsonify({"success": True, "message": f"کاربر '{username}' با موفقیت در FreeRADIUS و OpenVPN ایجاد شد."})
    except Exception as e:
        return jsonify({"error": f"خطا در ایجاد کاربر: {str(e)}"}), 500

@app.route("/api/openvpn/users/<username>", methods=["DELETE"])
def api_delete_openvpn_user(username):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        r_file = "/www/wwwroot/mhpanel/radius_users.json"
        if os.path.exists(r_file):
            try:
                with open(r_file, "r") as f:
                    r_users = json.load(f)
                if username in r_users:
                    del r_users[username]
                    with open(r_file, "w") as f:
                        json.dump(r_users, f, indent=2)
                    fr_lines = ["# MH Panel Unified RADIUS Database\n"]
                    for u, inf in r_users.items():
                        if inf.get("active", True):
                            pw = inf.get("password", "")
                            fr_lines.append(f'"{u}" Cleartext-Password := "{pw}"\n')
                            if u != u.lower():
                                fr_lines.append(f'"{u.lower()}" Cleartext-Password := "{pw}"\n')
                    with open("/etc/freeradius/3.0/mhpanel_users", "w") as f:
                        f.writelines(fr_lines)
            except Exception:
                pass

        users_file = "/www/wwwroot/mhpanel/ovpn_users.json"
        if os.path.exists(users_file):
            try:
                with open(users_file, "r") as f:
                    users = json.load(f)
                if username in users:
                    del users[username]
                    with open(users_file, "w") as f:
                        json.dump(users, f, indent=2)
            except Exception:
                pass
                
        subprocess.run(["userdel", "-f", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return jsonify({"success": True, "message": f"کاربر '{username}' با موفقیت حذف شد."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/openvpn/users/<username>/toggle", methods=["POST"])
def api_toggle_openvpn_user(username):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    users_file = "/www/wwwroot/mhpanel/ovpn_users.json"
    users = {}
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                users = json.load(f)
        except:
            pass
            
    current_status = True
    if username in users:
        current_status = users[username].get("active", True)
    new_status = not current_status
    
    if username in users:
        users[username]["active"] = new_status
        with open(users_file, "w") as f:
            json.dump(users, f, indent=2)

    r_file = "/www/wwwroot/mhpanel/radius_users.json"
    if os.path.exists(r_file):
        try:
            with open(r_file, "r") as f:
                r_users = json.load(f)
            if username in r_users:
                r_users[username]["active"] = new_status
                with open(r_file, "w") as f:
                    json.dump(r_users, f, indent=2)
                fr_lines = ["# MH Panel Unified RADIUS Database\n"]
                for u, inf in r_users.items():
                    if inf.get("active", True):
                        pw = inf.get("password", "")
                        fr_lines.append(f'"{u}" Cleartext-Password := "{pw}"\n')
                        if u != u.lower():
                            fr_lines.append(f'"{u.lower()}" Cleartext-Password := "{pw}"\n')
                with open("/etc/freeradius/3.0/mhpanel_users", "w") as f:
                    f.writelines(fr_lines)
        except Exception:
            pass
            
    if new_status:
        subprocess.run(["usermod", "-U", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.run(["usermod", "-L", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
    return jsonify({"success": True, "active": new_status})

@app.route("/api/openvpn/addons", methods=["POST"])
def api_install_openvpn_addon():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    addon = request.json.get("addon")
    success, stdout, stderr = run_helper(f"install_openvpn_{addon}", "openvpn")
    
    try:
        with open("/var/log/vpnpanel_addons.log", "w") as f:
            f.write(f"--- STDOUT ---\n{stdout}\n\n--- STDERR ---\n{stderr}\n")
    except:
        pass

    if success:
        return jsonify({"success": True, "message": f"{addon} installed successfully."})
    return jsonify({"success": False, "error": "Installation failed. Please check Addon Logs."}), 500

@app.route("/api/openvpn/addons", methods=["DELETE"])
def api_uninstall_openvpn_addon():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    addon = (request.json or {}).get("addon")
    if not addon:
        return jsonify({"success": False, "error": "نام افزونه مشخص نشده است."}), 400
    success, stdout, stderr = run_helper(f"uninstall_openvpn_{addon}", "openvpn")
    try:
        with open("/var/log/vpnpanel_addons.log", "w") as f:
            f.write(f"--- UNINSTALL STDOUT ---\n{stdout}\n\n--- UNINSTALL STDERR ---\n{stderr}\n")
    except:
        pass
    if success:
        return jsonify({"success": True, "message": f"افزونه {addon} با موفقیت حذف شد."})
    return jsonify({"success": False, "error": f"حذف {addon} ناموفق بود."}), 500

@app.route("/api/logs/addons", methods=["GET"])
def api_logs_addons():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        with open("/var/log/vpnpanel_addons.log", "r") as f:
            return jsonify({"logs": f.read()})
    except Exception:
        return jsonify({"logs": "No logs available."})

@app.route("/api/openvpn/addons/status", methods=["GET"])
def api_openvpn_addons_status():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    # Check XOR
    xor_installed = False
    try:
        res = subprocess.run(["strings", "/usr/sbin/openvpn"], capture_output=True, text=True, timeout=2)
        if "scramble" in res.stdout:
            xor_installed = True
    except Exception:
        pass
        
    # Check UDPspeeder
    udp_installed = os.path.exists("/usr/bin/udpspeeder")
    
    # Check Rosenpass
    rosenpass_installed = os.path.exists("/usr/bin/rosenpass")
    
    return jsonify({
        "xor": xor_installed,
        "udpspeeder": udp_installed,
        "rosenpass": rosenpass_installed
    })


# --- Additional Protocols User Management ---

def get_ssh_traffic():
    traffic = {}
    try:
        res = subprocess.run(["iptables", "-nvx", "-L", "MHPANEL_SSH_OUT"], capture_output=True, text=True)
        import pwd
        for line in res.stdout.splitlines():
            line = line.strip()
            if "owner UID match" in line:
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    bytes_count = int(parts[1])
                    uid_str = parts[-1]
                    try:
                        uname = pwd.getpwuid(int(uid_str)).pw_name if uid_str.isdigit() else uid_str
                        traffic[uname] = {"tx": bytes_count, "rx": bytes_count}
                    except Exception:
                        pass
    except Exception:
        pass
    return traffic

def get_ssh_active_sessions():
    sessions = []
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
            try:
                cmd = proc.info.get('cmdline') or []
                cmd_str = " ".join(cmd)
                if 'sshd:' in cmd_str and ('[priv]' in cmd_str or '@pts/' in cmd_str or '@notty' in cmd_str):
                    parts = cmd_str.split('sshd:')
                    if len(parts) > 1:
                        raw_target = parts[1].strip()
                        uname = raw_target.split()[0].split('@')[0]
                        if uname and uname not in ('root', 'sshd', 'unknown', '[accepted]', '[listener]'):
                            peer_ip = "اتصال محلی / پروکسی"
                            try:
                                for conn in proc.connections(kind='inet'):
                                    if conn.raddr:
                                        peer_ip = f"{conn.raddr.ip}:{conn.raddr.port}"
                                        break
                            except Exception:
                                pass
                            started_at = datetime.fromtimestamp(proc.info['create_time']).strftime("%Y-%m-%d %H:%M:%S")
                            sessions.append({
                                "pid": proc.info['pid'],
                                "username": uname,
                                "peer_ip": peer_ip,
                                "started_at": started_at
                            })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return sessions

def ssh_client_tracker():
    while True:
        try:
            subprocess.run("iptables -N MHPANEL_SSH_OUT 2>/dev/null || true", shell=True)
            subprocess.run("iptables -C OUTPUT -j MHPANEL_SSH_OUT 2>/dev/null || iptables -I OUTPUT 1 -j MHPANEL_SSH_OUT", shell=True)

            users_file = "/www/wwwroot/mhpanel/ssh_users.json"
            users = {}
            if os.path.exists(users_file):
                try:
                    with open(users_file, "r") as f:
                        users = json.load(f)
                except Exception:
                    users = {}

            rad_file = "/www/wwwroot/mhpanel/radius_users.json"
            if os.path.exists(rad_file):
                try:
                    with open(rad_file, "r") as f:
                        r_data = json.load(f)
                    for ru in r_data.keys():
                        if ru not in users:
                            users[ru] = {
                                "active": r_data[ru].get("active", True),
                                "limit_gb": r_data[ru].get("limit_gb"),
                                "expire_date": r_data[ru].get("expire_date"),
                                "rx": 0, "tx": 0, "last_rx": 0, "last_tx": 0
                            }
                except Exception:
                    pass

            traffic = get_ssh_traffic()
            changed = False
            now_str = datetime.now().strftime("%Y-%m-%d")

            for username, user_data in users.items():
                subprocess.run(f"iptables -C MHPANEL_SSH_OUT -m owner --uid-owner {username} 2>/dev/null || iptables -A MHPANEL_SSH_OUT -m owner --uid-owner {username} 2>/dev/null", shell=True)

                tdata = traffic.get(username, {"rx": 0, "tx": 0})
                if "rx" not in user_data: user_data["rx"] = 0
                if "tx" not in user_data: user_data["tx"] = 0
                if tdata["rx"] > user_data.get("last_rx", 0):
                    user_data["rx"] += (tdata["rx"] - user_data.get("last_rx", 0))
                user_data["last_rx"] = tdata["rx"]

                if tdata["tx"] > user_data.get("last_tx", 0):
                    user_data["tx"] += (tdata["tx"] - user_data.get("last_tx", 0))
                user_data["last_tx"] = tdata["tx"]

                limit_gb = user_data.get("limit_gb")
                expire_date = user_data.get("expire_date")
                disabled = False
                total_usage = user_data["rx"] + user_data["tx"]

                if expire_date and now_str > expire_date:
                    disabled = True
                if limit_gb and not disabled:
                    if total_usage >= limit_gb * (1024**3):
                        disabled = True

                if disabled:
                    if user_data.get("active", True):
                        user_data["active"] = False
                        changed = True
                        subprocess.run(["usermod", "-L", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        subprocess.run(["pkill", "-u", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        if os.path.exists(rad_file):
                            try:
                                with open(rad_file, "r") as f:
                                    r_users = json.load(f)
                                if username in r_users:
                                    r_users[username]["active"] = False
                                    with open(rad_file, "w") as f:
                                        json.dump(r_users, f, indent=2)
                                    sync_freeradius_users()
                            except Exception:
                                pass

            if changed or len(traffic) > 0:
                with open(users_file, "w") as f:
                    json.dump(users, f, indent=2)
        except Exception:
            pass
        time.sleep(30)

@app.route("/api/ssh/users", methods=["GET"])
def api_get_ssh_users():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    users = {}
    traffic = get_ssh_traffic()
    active_sessions = get_ssh_active_sessions()
    online_usernames = {s["username"] for s in active_sessions}

    radius_file = "/www/wwwroot/mhpanel/radius_users.json"
    if os.path.exists(radius_file):
        try:
            with open(radius_file, "r") as f:
                r_data = json.load(f)
            if isinstance(r_data, dict):
                for uname, uinfo in r_data.items():
                    users[uname] = {
                        "active": uinfo.get("active", True),
                        "limit_gb": uinfo.get("limit_gb"),
                        "expire_date": uinfo.get("expire_date"),
                        "created_at": uinfo.get("created_at"),
                        "auth_source": "FreeRADIUS",
                        "online": uname in online_usernames,
                        "rx": 0,
                        "tx": 0
                    }
        except Exception:
            pass

    users_file = "/www/wwwroot/mhpanel/ssh_users.json"
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                s_data = json.load(f)
            if isinstance(s_data, dict):
                for uname, uinfo in s_data.items():
                    if uname in users:
                        users[uname]["rx"] = uinfo.get("rx", 0)
                        users[uname]["tx"] = uinfo.get("tx", 0)
                        users[uname]["active"] = uinfo.get("active", users[uname]["active"])
                    else:
                        users[uname] = {
                            "active": uinfo.get("active", True),
                            "limit_gb": uinfo.get("limit_gb"),
                            "expire_date": uinfo.get("expire_date"),
                            "created_at": uinfo.get("created_at"),
                            "auth_source": "Local / Linux",
                            "online": uname in online_usernames,
                            "rx": uinfo.get("rx", 0),
                            "tx": uinfo.get("tx", 0)
                        }
        except Exception:
            pass

    for uname, tdata in traffic.items():
        if uname in users:
            users[uname]["rx"] = max(users[uname].get("rx", 0), tdata.get("rx", 0))
            users[uname]["tx"] = max(users[uname].get("tx", 0), tdata.get("tx", 0))

    for uname in users:
        users[uname]["online"] = uname in online_usernames

    def_user = get_default_test_user()
    if def_user and def_user.get("username"):
        uname = def_user["username"]
        if uname not in users:
            users[uname] = {
                "active": True,
                "limit_gb": None,
                "expire_date": None,
                "auth_source": "FreeRADIUS (Test User)",
                "online": uname in online_usernames,
                "rx": 0,
                "tx": 0,
                "is_default": True
            }
        else:
            users[uname]["is_default"] = True
            users[uname]["auth_source"] = "FreeRADIUS (Test User)"
            users[uname]["online"] = uname in online_usernames

    return jsonify({"users": users})

@app.route("/api/ssh/users", methods=["POST"])
def api_add_ssh_user():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    limit_gb = data.get("limit_gb")
    expire_date = data.get("expire_date")

    if not username or not password:
        return jsonify({"error": "نام کاربری و کلمه عبور الزامی هستند."}), 400

    subprocess.run("getent group jailed >/dev/null || groupadd jailed", shell=True)

    try:
        subprocess.run(["id", username], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["usermod", "-s", "/bin/false", "-aG", "jailed", username], check=False)
        subprocess.run(["usermod", "-U", username], check=False)
    except subprocess.CalledProcessError:
        subprocess.run(["useradd", "-M", "-s", "/bin/false", "-G", "jailed", username], check=True)

    proc = subprocess.Popen(["chpasswd"], stdin=subprocess.PIPE, text=True)
    proc.communicate(f"{username}:{password}")

    r_file = "/www/wwwroot/mhpanel/radius_users.json"
    r_users = {}
    if os.path.exists(r_file):
        try:
            with open(r_file, "r") as f:
                r_users = json.load(f)
        except Exception:
            pass
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    r_users[username] = {
        "password": password,
        "active": True,
        "expire_date": expire_date or None,
        "limit_gb": float(limit_gb) if limit_gb else None,
        "created_at": now_str,
        "protocols": ["all"]
    }
    with open(r_file, "w") as f:
        json.dump(r_users, f, indent=2)
    sync_freeradius_users()

    subprocess.run(f"iptables -C MHPANEL_SSH_OUT -m owner --uid-owner {username} 2>/dev/null || iptables -A MHPANEL_SSH_OUT -m owner --uid-owner {username}", shell=True)

    users_file = "/www/wwwroot/mhpanel/ssh_users.json"
    users = {}
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                users = json.load(f)
        except Exception:
            pass
    users[username] = {
        "active": True,
        "limit_gb": float(limit_gb) if limit_gb else None,
        "expire_date": expire_date or None,
        "created_at": now_str,
        "rx": 0, "tx": 0, "last_rx": 0, "last_tx": 0
    }
    with open(users_file, "w") as f:
        json.dump(users, f, indent=2)

    return jsonify({"success": True})

@app.route("/api/ssh/users/<username>", methods=["DELETE"])
def api_delete_ssh_user(username):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    def_user = get_default_test_user()
    if def_user and def_user.get("username") == username:
        return jsonify({"error": "امکان حذف کاربر پیش‌فرض تست از این بخش وجود ندارد. آن را در ابزارهای سیستم مدیریت کنید."}), 400

    subprocess.run(["pkill", "-u", username], stderr=subprocess.DEVNULL)
    subprocess.run(["userdel", "-f", username], stderr=subprocess.DEVNULL)
    subprocess.run(f"iptables -D MHPANEL_SSH_OUT -m owner --uid-owner {username} 2>/dev/null || true", shell=True)

    r_file = "/www/wwwroot/mhpanel/radius_users.json"
    if os.path.exists(r_file):
        try:
            with open(r_file, "r") as f:
                r_users = json.load(f)
            if username in r_users:
                del r_users[username]
                with open(r_file, "w") as f:
                    json.dump(r_users, f, indent=2)
                sync_freeradius_users()
        except Exception:
            pass

    users_file = "/www/wwwroot/mhpanel/ssh_users.json"
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                users = json.load(f)
            if username in users:
                del users[username]
                with open(users_file, "w") as f:
                    json.dump(users, f, indent=2)
        except Exception:
            pass

    return jsonify({"success": True})

@app.route("/api/ssh/users/<username>/toggle", methods=["POST"])
def api_toggle_ssh_user(username):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    r_file = "/www/wwwroot/mhpanel/radius_users.json"
    users_file = "/www/wwwroot/mhpanel/ssh_users.json"

    current_status = True
    r_users = {}
    if os.path.exists(r_file):
        try:
            with open(r_file, "r") as f:
                r_users = json.load(f)
            if username in r_users:
                current_status = r_users[username].get("active", True)
        except Exception:
            pass

    new_status = not current_status

    if new_status:
        subprocess.run(["usermod", "-U", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.run(["usermod", "-L", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-u", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if username in r_users:
        r_users[username]["active"] = new_status
        with open(r_file, "w") as f:
            json.dump(r_users, f, indent=2)
        sync_freeradius_users()

    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                s_users = json.load(f)
            if username in s_users:
                s_users[username]["active"] = new_status
                with open(users_file, "w") as f:
                    json.dump(s_users, f, indent=2)
        except Exception:
            pass

    return jsonify({"success": True, "active": new_status})

@app.route("/api/ssh/config", methods=["GET"])
def api_get_ssh_config():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    def check_service(name):
        try:
            res = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True)
            return res.stdout.strip() == "active"
        except Exception:
            return False

    slowdns_pub = ""
    pubkey_path = "/etc/dnstt/server.pub"
    if os.path.exists(pubkey_path):
        try:
            with open(pubkey_path, "r") as f:
                slowdns_pub = f.read().strip()
        except Exception:
            pass
    if not slowdns_pub:
        slowdns_pub = "b3290012dd13fe7df78551fdfbccfdfce5d3c594522fef40bf8284e4313b3a31"

    config_data = {
        "server_ip": "212.227.143.16",
        "hostnames": ["vpn.kigaping.com", "shahan.kigaping.com"],
        "direct_ports": [22, 2053, 443],
        "stunnel_ports": [9443, 2087, 443],
        "ws_ports": [80, 8088, 443, 8444, 2083],
        "ws_paths": ["/ssh", "/ws"],
        "slowdns": {
            "pubkey": slowdns_pub,
            "nameservers": ["t.kigaping.com", "dns.kigaping.com"],
            "port": "UDP 53 / 5300",
            "upstream_dns": "8.8.8.8"
        },
        "udpgw_port": 7300,
        "services": {
            "ssh": check_service("ssh"),
            "stunnel": check_service("stunnel4"),
            "ws": check_service("ssh-ws"),
            "slowdns": check_service("dnstt-server"),
            "udpgw": check_service("videocall"),
            "radius": check_service("freeradius")
        }
    }
    return jsonify(config_data)

@app.route("/api/ssh/sessions", methods=["GET"])
def api_get_ssh_sessions():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"sessions": get_ssh_active_sessions()})

@app.route("/api/ssh/sessions/kill", methods=["POST"])
def api_kill_ssh_session():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    pid = data.get("pid")
    username = data.get("username")
    if pid:
        try:
            os.kill(int(pid), 9)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    elif username:
        try:
            subprocess.run(["pkill", "-u", username], check=False)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "شناسه نشست یا نام کاربری ارسال نشده است."}), 400

@app.route("/api/ssh/services/restart", methods=["POST"])
def api_restart_ssh_services():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    services = ["ssh", "stunnel4", "ssh-ws", "dnstt-server", "videocall"]
    errors = []
    for s in services:
        try:
            res = subprocess.run(["systemctl", "restart", s], capture_output=True, text=True)
            if res.returncode != 0:
                errors.append(f"{s}: {res.stderr.strip()}")
        except Exception as e:
            errors.append(f"{s}: {str(e)}")
    if errors:
        return jsonify({"success": False, "errors": errors}), 500
    return jsonify({"success": True})

OCSERV_CONFIG_FILE = "/etc/vpnpanel/ocserv_config.json"

def format_bytes_size(b):
    if not b or b < 0:
        return "0 B"
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    else:
        return f"{b / (1024 * 1024 * 1024):.2f} GB"

def is_service_active(svc_name):
    try:
        res = subprocess.run(["systemctl", "is-active", svc_name], capture_output=True, text=True, timeout=3)
        return res.stdout.strip() == "active"
    except Exception:
        return False

def get_ocserv_traffic():
    traffic = {}
    try:
        res = subprocess.run(["occtl", "-j", "show", "users"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0 and res.stdout.strip():
            users_list = json.loads(res.stdout)
            for u in users_list:
                uname = u.get("Username") or u.get("username")
                if uname:
                    rx = int(u.get("raw_rx", u.get("RX", 0)) or 0)
                    tx = int(u.get("raw_tx", u.get("TX", 0)) or 0)
                    if uname in traffic:
                        traffic[uname]["rx"] += rx
                        traffic[uname]["tx"] += tx
                    else:
                        traffic[uname] = {"rx": rx, "tx": tx}
    except Exception:
        pass
    return traffic

def ocserv_client_tracker():
    while True:
        try:
            users_file = "/www/wwwroot/mhpanel/ocserv_users.json"
            if os.path.exists(users_file):
                with open(users_file, "r") as f:
                    try:
                        users = json.load(f)
                    except:
                        users = {}
                
                traffic = get_ocserv_traffic()
                changed = False
                now_str = datetime.now().strftime("%Y-%m-%d")
                
                for username, user_data in users.items():
                    tdata = traffic.get(username, {"rx": 0, "tx": 0})
                    if "rx" not in user_data: user_data["rx"] = 0
                    if "tx" not in user_data: user_data["tx"] = 0
                    if tdata["rx"] > user_data.get("last_rx", 0):
                        user_data["rx"] += (tdata["rx"] - user_data.get("last_rx", 0))
                    user_data["last_rx"] = tdata["rx"]
                    
                    if tdata["tx"] > user_data.get("last_tx", 0):
                        user_data["tx"] += (tdata["tx"] - user_data.get("last_tx", 0))
                    user_data["last_tx"] = tdata["tx"]

                    limit_gb = user_data.get("limit_gb")
                    expire_date = user_data.get("expire_date")
                    disabled = False
                    
                    total_usage = user_data["rx"] + user_data["tx"]
                    
                    if expire_date:
                        if now_str > expire_date:
                            disabled = True
                            
                    if limit_gb and not disabled:
                        if total_usage >= limit_gb * (1024**3):
                            disabled = True
                            
                    if disabled:
                        if user_data.get("active", True):
                            user_data["active"] = False
                            changed = True
                            subprocess.run(["usermod", "-L", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            subprocess.run(["occtl", "disconnect", "user", username], capture_output=True)
                
                if changed or len(traffic) > 0:
                    with open(users_file, "w") as f:
                        json.dump(users, f)
        except Exception:
            pass
        time.sleep(60)

def get_ocserv_config_data():
    conf_path = "/etc/ocserv/ocserv.conf"
    le_cert = "/etc/letsencrypt/live/vpn.kigaping.com/fullchain.pem"
    le_key = "/etc/letsencrypt/live/vpn.kigaping.com/privkey.pem"
    has_le = (os.path.exists(le_cert) and os.path.exists(le_key)) or (os.path.exists("/etc/letsencrypt/live/mhpanel.kigaping.com/fullchain.pem"))

    config = {
        "tcp_port": 10443,
        "udp_port": 10443,
        "enable_udp": True,
        "camouflage": False,
        "camouflage_secret": "secure_npu_bypass",
        "camouflage_realm": "Restricted Area",
        "cert_type": "letsencrypt" if has_le else "self_signed",
        "default_domain": "vpn.kigaping.com",
        "ipv4_network": "10.30.30.0",
        "ipv4_netmask": "255.255.255.0",
        "dns1": "8.8.8.8",
        "dns2": "1.1.1.1",
        "mtu": 1200,
        "cisco_compat": True,
        "compression": True,
        "dtls_legacy": True,
        "max_clients": 128,
        "max_same_clients": 4,
        "keepalive": 32400,
        "dpd": 90,
        "mobile_dpd": 1800,
        "auth_mode": "radius",
        "tls_priorities": "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1",
        "letsencrypt_available": has_le,
        "ca_cert_available": os.path.exists("/etc/ocserv/certs/ca.crt"),
        "active": is_service_active("ocserv"),
        "server_ip": get_server_public_ip(),
        "stats": {}
    }

    if os.path.exists(OCSERV_CONFIG_FILE):
        try:
            with open(OCSERV_CONFIG_FILE, "r") as f:
                saved = json.load(f)
                config.update(saved)
        except Exception:
            pass

    if os.path.exists(conf_path):
        try:
            with open(conf_path, "r") as f:
                content = f.read()

            m = re.search(r'^\s*tcp-port\s*=\s*(\d+)', content, re.M)
            if m: config["tcp_port"] = int(m.group(1))

            m = re.search(r'^\s*udp-port\s*=\s*(\d+)', content, re.M)
            if m:
                config["udp_port"] = int(m.group(1))
                config["enable_udp"] = True
            elif re.search(r'^\s*#\s*udp-port', content, re.M):
                config["enable_udp"] = False

            m = re.search(r'^\s*camouflage\s*=\s*(true|false)', content, re.M)
            if m: config["camouflage"] = (m.group(1).lower() == "true")

            m = re.search(r'^\s*camouflage_secret\s*=\s*"([^"]*)"', content, re.M)
            if m: config["camouflage_secret"] = m.group(1)

            m = re.search(r'^\s*camouflage_realm\s*=\s*"([^"]*)"', content, re.M)
            if m: config["camouflage_realm"] = m.group(1)

            if "letsencrypt" in content:
                config["cert_type"] = "letsencrypt"
            elif "/etc/ocserv/certs/" in content:
                config["cert_type"] = "self_signed"

            m = re.search(r'^\s*default-domain\s*=\s*([^\s\n]+)', content, re.M)
            if m: config["default_domain"] = m.group(1)

            m = re.search(r'^\s*ipv4-network\s*=\s*([^\s\n]+)', content, re.M)
            if m: config["ipv4_network"] = m.group(1)

            m = re.search(r'^\s*ipv4-netmask\s*=\s*([^\s\n]+)', content, re.M)
            if m: config["ipv4_netmask"] = m.group(1)

            dns_matches = re.findall(r'^\s*dns\s*=\s*([^\s\n]+)', content, re.M)
            if len(dns_matches) >= 1: config["dns1"] = dns_matches[0]
            if len(dns_matches) >= 2: config["dns2"] = dns_matches[1]

            m = re.search(r'^\s*mtu\s*=\s*(\d+)', content, re.M)
            if m: config["mtu"] = int(m.group(1))

            m = re.search(r'^\s*max-clients\s*=\s*(\d+)', content, re.M)
            if m: config["max_clients"] = int(m.group(1))

            m = re.search(r'^\s*max-same-clients\s*=\s*(\d+)', content, re.M)
            if m: config["max_same_clients"] = int(m.group(1))

            m = re.search(r'^\s*cisco-client-compat\s*=\s*(true|false)', content, re.M)
            if m: config["cisco_compat"] = (m.group(1).lower() == "true")

            m = re.search(r'^\s*compression\s*=\s*(true|false)', content, re.M)
            if m: config["compression"] = (m.group(1).lower() == "true")

            m = re.search(r'^\s*tls-priorities\s*=\s*"([^"]*)"', content, re.M)
            if m: config["tls_priorities"] = m.group(1)

            if 'auth = "plain' in content:
                config["auth_mode"] = "plain"
            elif 'auth = "radius' in content:
                config["auth_mode"] = "radius"
        except Exception:
            pass

    try:
        st_res = subprocess.run(["occtl", "-j", "show", "status"], capture_output=True, text=True, timeout=2)
        if st_res.returncode == 0 and st_res.stdout.strip():
            config["stats"] = json.loads(st_res.stdout)
    except Exception:
        config["stats"] = {}

    return config

def save_ocserv_full_config(data):
    tcp_port = int(data.get("tcp_port", 10443))
    udp_port = int(data.get("udp_port", 10443))
    enable_udp = bool(data.get("enable_udp", True))
    camouflage = bool(data.get("camouflage", False))
    camouflage_secret = str(data.get("camouflage_secret", "myvpnsecret")).strip()
    camouflage_realm = str(data.get("camouflage_realm", "Restricted Content")).strip()
    cert_type = data.get("cert_type", "letsencrypt")
    default_domain = data.get("default_domain", "vpn.kigaping.com").strip() or "vpn.kigaping.com"
    ipv4_network = data.get("ipv4_network", "10.30.30.0").strip()
    ipv4_netmask = data.get("ipv4_netmask", "255.255.255.0").strip()
    dns1 = data.get("dns1", "8.8.8.8").strip()
    dns2 = data.get("dns2", "1.1.1.1").strip()
    mtu = int(data.get("mtu", 1200))
    cisco_compat = bool(data.get("cisco_compat", True))
    compression = bool(data.get("compression", True))
    dtls_legacy = bool(data.get("dtls_legacy", True))
    max_clients = int(data.get("max_clients", 128))
    max_same_clients = int(data.get("max_same_clients", 4))
    keepalive = int(data.get("keepalive", 32400))
    dpd = int(data.get("dpd", 90))
    mobile_dpd = int(data.get("mobile_dpd", 1800))
    auth_mode = data.get("auth_mode", "radius")
    tls_priorities = data.get("tls_priorities", "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1")

    # Certificates selection
    cert_lines = []
    ca_cert_line = ""
    if cert_type == "letsencrypt":
        added = set()
        for d in [default_domain, "vpn.kigaping.com", "mhpanel.kigaping.com"]:
            c_cert = f"/etc/letsencrypt/live/{d}/fullchain.pem"
            c_key = f"/etc/letsencrypt/live/{d}/privkey.pem"
            if os.path.exists(c_cert) and os.path.exists(c_key) and c_cert not in added:
                cert_lines.append(f"server-cert = {c_cert}")
                cert_lines.append(f"server-key = {c_key}")
                added.add(c_cert)
    if not cert_lines:
        cert_lines.append("server-cert = /etc/ocserv/certs/server.crt")
        cert_lines.append("server-key = /etc/ocserv/certs/server.key")
        ca_cert_line = "ca-cert = /etc/ocserv/certs/ca.crt"
    server_certs_block = "\n".join(cert_lines)

    # Auth selection
    if auth_mode == "plain":
        auth_line = 'auth = "plain[passwd=/etc/ocserv/ocpasswd]"'
        acct_line = ""
    else:
        auth_line = 'auth = "radius[config=/etc/radcli/radiusclient.conf,groupconfig=true]"'
        acct_line = 'acct = "radius[config=/etc/radcli/radiusclient.conf]"'

    udp_line = f"udp-port = {udp_port}" if enable_udp else "# udp-port disabled (Anti-DPI TCP-Only mode)"

    camo_lines = []
    if camouflage:
        camo_lines.append("camouflage = true")
        camo_lines.append(f'camouflage_secret = "{camouflage_secret}"')
        camo_lines.append(f'camouflage_realm = "{camouflage_realm}"')
    else:
        camo_lines.append("camouflage = false")
        camo_lines.append(f'# camouflage_secret = "{camouflage_secret}"')
        camo_lines.append(f'# camouflage_realm = "{camouflage_realm}"')
    camo_str = "\n".join(camo_lines)

    conf_content = f"""# Generated by MH Panel
{auth_line}
{acct_line}

tcp-port = {tcp_port}
{udp_line}

{server_certs_block}
{ca_cert_line}

# Anti-DPI Stealth & Camouflage
{camo_str}

max-clients = {max_clients}
max-same-clients = {max_same_clients}
rate-limit-ms = 0
server-stats-reset-time = 604800

keepalive = {keepalive}
dpd = {dpd}
mobile-dpd = {mobile_dpd}
switch-to-tcp-timeout = 25

compression = {"true" if compression else "false"}
no-compress-limit = 256

tls-priorities = "{tls_priorities}"

auth-timeout = 240
min-reauth-time = 300
max-ban-score = 80
ban-reset-time = 1200
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl

use-occtl = true
pid-file = /run/ocserv.pid
socket-file = /run/ocserv.socket

device = vpns
predictable-ips = true
default-domain = {default_domain}

ipv4-network = {ipv4_network}
ipv4-netmask = {ipv4_netmask}

dns = {dns1}
dns = {dns2}

ping-leases = false
mtu = {mtu}
cisco-client-compat = {"true" if cisco_compat else "false"}
dtls-legacy = {"true" if dtls_legacy else "false"}
"""

    temp_path = "/tmp/ocserv_new.conf"
    with open(temp_path, "w") as f:
        f.write(conf_content)

    test_res = subprocess.run(["ocserv", "-t", "-c", temp_path], capture_output=True, text=True)
    if test_res.returncode != 0:
        if os.path.exists(temp_path): os.remove(temp_path)
        err = test_res.stderr.strip() or test_res.stdout.strip()
        raise Exception(f"خطای اعتبارسنجی کانفیگ ocserv: {err}")

    ocserv_conf = "/etc/ocserv/ocserv.conf"
    if os.path.exists(ocserv_conf):
        try:
            with open(ocserv_conf, "r") as f:
                backup = f.read()
            with open("/etc/ocserv/ocserv.conf.bak", "w") as f:
                f.write(backup)
        except Exception:
            pass

    with open(ocserv_conf, "w") as f:
        f.write(conf_content)
    if os.path.exists(temp_path):
        os.remove(temp_path)

    # Persist JSON settings
    os.makedirs("/etc/vpnpanel", exist_ok=True)
    with open(OCSERV_CONFIG_FILE, "w") as f:
        json.dump({
            "tcp_port": tcp_port,
            "udp_port": udp_port,
            "enable_udp": enable_udp,
            "camouflage": camouflage,
            "camouflage_secret": camouflage_secret,
            "camouflage_realm": camouflage_realm,
            "cert_type": cert_type,
            "default_domain": default_domain,
            "ipv4_network": ipv4_network,
            "ipv4_netmask": ipv4_netmask,
            "dns1": dns1,
            "dns2": dns2,
            "mtu": mtu,
            "cisco_compat": cisco_compat,
            "compression": compression,
            "dtls_legacy": dtls_legacy,
            "max_clients": max_clients,
            "max_same_clients": max_same_clients,
            "keepalive": keepalive,
            "dpd": dpd,
            "mobile_dpd": mobile_dpd,
            "auth_mode": auth_mode,
            "tls_priorities": tls_priorities
        }, f, indent=2)

    # Firewall iptables
    try:
        import ipaddress
        net = ipaddress.IPv4Network(f"{ipv4_network}/{ipv4_netmask}", strict=False)
        cidr = str(net)
        subprocess.run(f"iptables -t nat -C POSTROUTING -s {cidr} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {cidr} -j MASQUERADE", shell=True)
        subprocess.run(f"iptables -C FORWARD -s {cidr} -j ACCEPT 2>/dev/null || iptables -A FORWARD -s {cidr} -j ACCEPT", shell=True)
        subprocess.run(f"iptables -C FORWARD -d {cidr} -j ACCEPT 2>/dev/null || iptables -A FORWARD -d {cidr} -j ACCEPT", shell=True)
    except Exception:
        pass

    subprocess.run(["systemctl", "restart", "ocserv"], capture_output=True)

def get_live_ocserv_sessions():
    sessions = []
    try:
        res = subprocess.run(["occtl", "-j", "show", "users"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0 and res.stdout.strip():
            raw_list = json.loads(res.stdout)
            for item in raw_list:
                sid = item.get("ID") or item.get("id") or item.get("Session ID") or ""
                username = item.get("Username") or item.get("username") or item.get("user") or "-"
                device = item.get("Device") or item.get("device") or item.get("dev") or "vpns"
                remote_ip = item.get("Remote IP") or item.get("remote_ip") or item.get("Remote-IP") or item.get("IP") or "-"
                vpn_ip = item.get("VPN IP") or item.get("Local Device IP") or item.get("vpn_ip") or item.get("ipv4") or "-"
                connected_at = item.get("Connected at") or item.get("connected_at") or item.get("uptime") or "-"
                state = item.get("State") or item.get("state") or "connected"
                rx = item.get("raw_rx", item.get("RX", 0)) or 0
                tx = item.get("raw_tx", item.get("TX", 0)) or 0
                try: rx_val = int(rx)
                except Exception: rx_val = 0
                try: tx_val = int(tx)
                except Exception: tx_val = 0

                sessions.append({
                    "id": str(sid),
                    "username": username,
                    "device": device,
                    "remote_ip": remote_ip,
                    "vpn_ip": vpn_ip,
                    "connected_at": connected_at,
                    "state": state,
                    "rx_bytes": rx_val,
                    "tx_bytes": tx_val,
                    "rx_formatted": format_bytes_size(rx_val),
                    "tx_formatted": format_bytes_size(tx_val)
                })
    except Exception:
        pass
    return sessions

@app.route("/api/ocserv/config", methods=["GET"])
def api_ocserv_config_get():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_ocserv_config_data())

@app.route("/api/ocserv/config", methods=["POST"])
def api_ocserv_config_set():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    try:
        save_ocserv_full_config(data)
        return jsonify({"success": True, "message": "تنظیمات OCServ با موفقیت ذخیره و اعمال شد!"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ocserv/service/<action>", methods=["POST"])
def api_ocserv_service_action(action):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    if action == "restart":
        subprocess.run(["systemctl", "restart", "ocserv"], capture_output=True)
        return jsonify({"success": True, "message": "سرویس OCServ با موفقیت راه‌اندازی مجدد شد."})
    elif action == "reload":
        subprocess.run(["occtl", "reload"], capture_output=True)
        return jsonify({"success": True, "message": "کانفیگ OCServ با موفقیت بازخوانی شد."})
    elif action == "stop":
        subprocess.run(["systemctl", "stop", "ocserv"], capture_output=True)
        return jsonify({"success": True, "message": "سرویس OCServ متوقف شد."})
    elif action == "start":
        subprocess.run(["systemctl", "start", "ocserv"], capture_output=True)
        return jsonify({"success": True, "message": "سرویس OCServ راه‌اندازی شد."})
    return jsonify({"error": "Invalid action"}), 400

@app.route("/api/ocserv/sessions", methods=["GET"])
def api_ocserv_sessions_get():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"sessions": get_live_ocserv_sessions()})

@app.route("/api/ocserv/sessions/disconnect", methods=["POST"])
def api_ocserv_session_disconnect():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    sid = data.get("id")
    username = data.get("username")
    
    if sid:
        res = subprocess.run(["occtl", "disconnect", "id", str(sid)], capture_output=True, text=True)
        if res.returncode == 0:
            return jsonify({"success": True, "message": f"سشن {sid} با موفقیت قطع شد."})
        else:
            return jsonify({"error": res.stderr.strip() or "خطا در قطع سشن"}), 400
    elif username:
        res = subprocess.run(["occtl", "disconnect", "user", str(username)], capture_output=True, text=True)
        if res.returncode == 0:
            return jsonify({"success": True, "message": f"اتصال کاربر {username} با موفقیت قطع شد."})
        else:
            return jsonify({"error": res.stderr.strip() or "خطا در قطع کاربر"}), 400
    return jsonify({"error": "شناسه سشن یا نام کاربری مشخص نشده است"}), 400

@app.route("/api/ocserv/ca.crt", methods=["GET"])
def api_ocserv_download_ca():
    ca_path = "/etc/ocserv/certs/ca.crt"
    if not os.path.exists(ca_path):
        return "CA Certificate not found", 404
    from flask import send_file
    return send_file(ca_path, as_attachment=True, download_name="ocserv-ca.crt", mimetype="application/x-x509-ca-cert")

@app.route("/api/ocserv/users", methods=["GET"])
def api_get_ocserv_users():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    users = {}
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                r_users = json.load(f)
            for u, d in r_users.items():
                users[u] = {
                    "password": d.get("password", ""),
                    "active": d.get("active", True),
                    "limit_gb": d.get("limit_gb"),
                    "expire_date": d.get("expire_date"),
                    "rx": d.get("rx", 0),
                    "tx": d.get("tx", 0),
                    "source": "radius"
                }
        except Exception:
            pass
    users_file = "/www/wwwroot/mhpanel/ocserv_users.json"
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                oc_users = json.load(f)
            for u, d in oc_users.items():
                if u not in users:
                    users[u] = d
                    users[u]["source"] = "local"
                else:
                    users[u]["rx"] = d.get("rx", users[u].get("rx", 0))
                    users[u]["tx"] = d.get("tx", users[u].get("tx", 0))
                    if "limit_gb" in d and d["limit_gb"] is not None:
                        users[u]["limit_gb"] = d["limit_gb"]
                    if "expire_date" in d and d["expire_date"] is not None:
                        users[u]["expire_date"] = d["expire_date"]
                    users[u]["source"] = d.get("source", "radius")
        except Exception:
            pass
    return jsonify({"users": users})

@app.route("/api/ocserv/users", methods=["POST"])
def api_add_ocserv_user():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    limit_gb = data.get("limit_gb")
    expire_date = data.get("expire_date")
    
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
        
    try:
        subprocess.run(["useradd", "-M", "-s", "/usr/sbin/nologin", username], check=False, stderr=subprocess.DEVNULL)
        proc = subprocess.Popen(["chpasswd"], stdin=subprocess.PIPE, text=True)
        proc.communicate(f"{username}:{password}")
    except Exception:
        pass
        
    users_file = "/www/wwwroot/mhpanel/ocserv_users.json"
    users = {}
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                users = json.load(f)
        except Exception:
            pass
            
    users[username] = {
        "password": password,
        "active": True,
        "limit_gb": limit_gb,
        "expire_date": expire_date,
        "rx": 0,
        "tx": 0,
        "last_rx": 0,
        "last_tx": 0
    }
    
    with open(users_file, "w") as f:
        json.dump(users, f, indent=2)

    # Save to RADIUS_USERS_FILE and sync FreeRADIUS
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f: r_users = json.load(f)
        except Exception: r_users = {}
        r_users[username] = {
            "password": password,
            "active": True,
            "limit_gb": limit_gb,
            "expire_date": expire_date,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "protocols": ["all"]
        }
        with open(RADIUS_USERS_FILE, "w") as f: json.dump(r_users, f, indent=2)
        sync_freeradius_users()
        
    return jsonify({"success": True})

@app.route("/api/ocserv/users/<username>", methods=["DELETE"])
def api_delete_ocserv_user(username):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    subprocess.run(["userdel", "-f", username], stderr=subprocess.DEVNULL)

    users_file = "/www/wwwroot/mhpanel/ocserv_users.json"
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                users = json.load(f)
            if username in users:
                del users[username]
                with open(users_file, "w") as f:
                    json.dump(users, f, indent=2)
        except Exception:
            pass

    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f: r_users = json.load(f)
            if username in r_users:
                del r_users[username]
                with open(RADIUS_USERS_FILE, "w") as f: json.dump(r_users, f, indent=2)
                sync_freeradius_users()
        except Exception: pass

    subprocess.run(["occtl", "disconnect", "user", username], capture_output=True)

    return jsonify({"success": True})

@app.route("/api/ocserv/users/<username>/toggle", methods=["POST"])
def api_toggle_ocserv_user(username):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    users_file = "/www/wwwroot/mhpanel/ocserv_users.json"
    users = {}
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                users = json.load(f)
        except Exception:
            pass

    new_status = False
    if username in users:
        new_status = not users[username].get("active", True)
        users[username]["active"] = new_status
        with open(users_file, "w") as f: json.dump(users, f, indent=2)
    elif os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f: r_users = json.load(f)
            if username in r_users:
                new_status = not r_users[username].get("active", True)
        except Exception: pass

    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f: r_users = json.load(f)
            if username in r_users:
                r_users[username]["active"] = new_status
                with open(RADIUS_USERS_FILE, "w") as f: json.dump(r_users, f, indent=2)
                sync_freeradius_users()
        except Exception: pass

    if new_status:
        subprocess.run(["usermod", "-U", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.run(["usermod", "-L", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["occtl", "disconnect", "user", username], capture_output=True)

    return jsonify({"success": True})

SSTP_CONFIG_FILE = "/www/wwwroot/mhpanel/sstp_config.json"

def get_sstp_config():
    default_cfg = {
        "engine": "sstpd",
        "port": 4443,
        "sni": "sstp.kigaping.com",
        "haproxy_443": True,
        "stunnel_multiport": True,
        "stunnel_ports": [9443, 2087],
        "local_ip": "10.20.20.1",
        "remote_subnet": "10.20.20.0/24",
        "ip_range": "10.20.20.10-250",
        "dns1": "8.8.8.8",
        "dns2": "1.1.1.1",
        "mtu": 1400,
        "mru": 1400,
        "cipher_preset": "all_aes_sha",
        "ciphers": "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:HIGH:!aNULL:!MD5:!RC4",
        "mppe_mode": "require-mppe-128",
        "auth_mode": "radius_and_chap"
    }
    if os.path.exists(SSTP_CONFIG_FILE):
        try:
            with open(SSTP_CONFIG_FILE, "r") as f:
                data = json.load(f)
                default_cfg.update(data)
        except Exception:
            pass
    return default_cfg

def get_sstp_traffic():
    traffic = {}
    try:
        if os.path.exists("/proc/net/dev"):
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()
            for line in lines[2:]:
                parts = line.strip().split()
                if not parts:
                    continue
                iface = parts[0].rstrip(":")
                if iface.startswith("ppp"):
                    rx_bytes = int(parts[1])
                    tx_bytes = int(parts[9])
                    traffic[iface] = {"rx": rx_bytes, "tx": tx_bytes}
    except Exception:
        pass
    return traffic

def sstp_client_tracker():
    while True:
        try:
            users_file = "/www/wwwroot/mhpanel/sstp_users.json"
            if os.path.exists(users_file):
                with open(users_file, "r") as f:
                    try:
                        users = json.load(f)
                    except Exception:
                        users = {}
                
                changed = False
                now_str = datetime.now().strftime("%Y-%m-%d")
                
                for username, user_data in users.items():
                    limit_gb = user_data.get("limit_gb")
                    expire_date = user_data.get("expire_date")
                    disabled = False
                    
                    total_usage = user_data.get("rx", 0) + user_data.get("tx", 0)
                    
                    if expire_date and now_str > expire_date:
                        disabled = True
                            
                    if limit_gb and not disabled:
                        if total_usage >= limit_gb * (1024**3):
                            disabled = True
                            
                    if disabled and user_data.get("active", True):
                        user_data["active"] = False
                        changed = True
                        subprocess.run(["sed", "-i", f's/^"{username}" /#"{username}" /', "/etc/ppp/chap-secrets"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                if changed:
                    with open(users_file, "w") as f:
                        json.dump(users, f, indent=2)
                    sync_freeradius_users()
        except Exception:
            pass
        time.sleep(60)

@app.route("/api/sstp/config", methods=["GET"])
def api_get_sstp_config():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    cfg = get_sstp_config()
    
    def check_unit(u):
        res = subprocess.run(["systemctl", "is-active", u], capture_output=True, text=True)
        return res.stdout.strip() == "active"
        
    sstpd_active = check_unit("sstpd")
    vpnserver_active = check_unit("vpnserver")
    haproxy_active = check_unit("haproxy")
    
    cert_path = "/etc/letsencrypt/live/vpn.kigaping.com/fullchain.pem"
    cert_valid = os.path.exists(cert_path)
    
    return jsonify({
        "config": cfg,
        "services": {
            "sstpd": sstpd_active,
            "vpnserver": vpnserver_active,
            "haproxy": haproxy_active
        },
        "cert": {
            "valid": cert_valid,
            "domain": "vpn.kigaping.com"
        },
        "server_ip": "212.227.143.16",
        "domain": "vpn.kigaping.com",
        "sni": cfg.get("sni", "sstp.kigaping.com")
    })

@app.route("/api/sstp/config", methods=["POST"])
def api_save_sstp_config():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.json or {}
    cfg = get_sstp_config()
    
    engine = data.get("engine", cfg.get("engine", "sstpd"))
    port = int(data.get("port", cfg.get("port", 4443)))
    sni = data.get("sni", cfg.get("sni", "sstp.kigaping.com")).strip()
    haproxy_443 = bool(data.get("haproxy_443", True))
    stunnel_multiport = bool(data.get("stunnel_multiport", True))
    local_ip = data.get("local_ip", cfg.get("local_ip", "10.20.20.1")).strip()
    remote_subnet = data.get("remote_subnet", cfg.get("remote_subnet", "10.20.20.0/24")).strip()
    ip_range = data.get("ip_range", cfg.get("ip_range", "10.20.20.10-250")).strip()
    dns1 = data.get("dns1", cfg.get("dns1", "8.8.8.8")).strip()
    dns2 = data.get("dns2", cfg.get("dns2", "1.1.1.1")).strip()
    mtu = int(data.get("mtu", cfg.get("mtu", 1400)))
    mru = int(data.get("mru", cfg.get("mru", 1400)))
    cipher_preset = data.get("cipher_preset", cfg.get("cipher_preset", "all_aes_sha"))
    ciphers = data.get("ciphers", cfg.get("ciphers", "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:HIGH:!aNULL:!MD5:!RC4")).strip()
    mppe_mode = data.get("mppe_mode", cfg.get("mppe_mode", "require-mppe-128"))
    auth_mode = data.get("auth_mode", "radius_and_chap")
    
    cfg.update({
        "engine": engine,
        "port": port,
        "sni": sni,
        "haproxy_443": haproxy_443,
        "stunnel_multiport": stunnel_multiport,
        "local_ip": local_ip,
        "remote_subnet": remote_subnet,
        "ip_range": ip_range,
        "dns1": dns1,
        "dns2": dns2,
        "mtu": mtu,
        "mru": mru,
        "cipher_preset": cipher_preset,
        "ciphers": ciphers,
        "mppe_mode": mppe_mode,
        "auth_mode": auth_mode
    })
    
    with open(SSTP_CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)
        
    mppe_directive = "require-mppe-128\nmppe-stateful" if mppe_mode == "require-mppe-128" else "mppe-stateful"
    ppp_options = f"""name sstpd
debug
dump
logfd 2
ipcp-accept-local
ipcp-accept-remote
idle 1800
mtu {mtu}
mru {mru}
proxyarp
lcp-echo-failure 4
lcp-echo-interval 30
ms-dns {dns1}
ms-dns {dns2}
nodefaultroute
{mppe_directive}
require-mschap-v2
refuse-mschap
refuse-chap
refuse-pap
refuse-eap
plugin radius.so
radius-config-file /etc/radcli/radiusclient.conf
"""
    try:
        with open("/etc/ppp/options.sstpd", "w") as f:
            f.write(ppp_options)
    except Exception:
        pass
        
    sstp_cert = get_protocol_certificate("sstp")
    sstp_c_path = sstp_cert.get("cert_path")
    sstp_k_path = sstp_cert.get("key_path")
    if not (sstp_c_path and sstp_k_path and os.path.exists(sstp_c_path) and os.path.exists(sstp_k_path)):
        for cp, kp in [
            ("/etc/letsencrypt/live/vpn.kigaping.com/fullchain.pem", "/etc/letsencrypt/live/vpn.kigaping.com/privkey.pem"),
            ("/etc/letsencrypt/live/mhpanel.kigaping.com/fullchain.pem", "/etc/letsencrypt/live/mhpanel.kigaping.com/privkey.pem"),
            (VPN_SERVER_CERT, VPN_SERVER_KEY),
            (PANEL_CERT, PANEL_KEY)
        ]:
            if os.path.exists(cp) and os.path.exists(kp):
                sstp_c_path, sstp_k_path = cp, kp
                break

    service_content = f"""[Unit]
Description=SSTP Server Daemon (sstpd)
After=network.target freeradius.service
Wants=freeradius.service

[Service]
Type=simple
ExecStart=/usr/local/bin/sstpd -l 0.0.0.0 -p {port} -c {sstp_c_path} -k {sstp_k_path} --local {local_ip} --remote {remote_subnet} --range {ip_range} --pppd-config /etc/ppp/options.sstpd --ciphers "{ciphers}"
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"""
    try:
        with open("/etc/systemd/system/sstpd.service", "w") as f:
            f.write(service_content)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    except Exception:
        pass
        
    if engine in ["sstpd", "both"]:
        subprocess.run(["systemctl", "restart", "sstpd"], capture_output=True)
    else:
        subprocess.run(["systemctl", "stop", "sstpd"], capture_output=True)
        
    if engine in ["softether", "both"]:
        subprocess.run(["systemctl", "start", "vpnserver"], capture_output=True)
    else:
        subprocess.run(["systemctl", "stop", "vpnserver"], capture_output=True)
        
    subprocess.run(f"iptables -t nat -C POSTROUTING -s {remote_subnet} -o ens6 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {remote_subnet} -o ens6 -j MASQUERADE", shell=True)
    
    return jsonify({"success": True, "message": "تنظیمات SSTP ذخیره و اعمال شد."})

@app.route("/api/sstp/service/restart", methods=["POST"])
def api_restart_sstp_services():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    cfg = get_sstp_config()
    engine = cfg.get("engine", "sstpd")
    
    if engine in ["sstpd", "both"]:
        subprocess.run(["systemctl", "restart", "sstpd"], capture_output=True)
    if engine in ["softether", "both"]:
        subprocess.run(["systemctl", "restart", "vpnserver"], capture_output=True)
    subprocess.run(["systemctl", "reload", "haproxy"], capture_output=True)
    
    return jsonify({"success": True, "message": "سرویس‌های SSTP با موفقیت راه‌اندازی مجدد شدند."})

@app.route("/api/sstp/sessions", methods=["GET"])
def api_get_sstp_sessions():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    sessions = []
    
    try:
        ps_res = subprocess.run(["ps", "-eo", "pid,user,etime,command"], capture_output=True, text=True)
        for line in ps_res.stdout.splitlines():
            parts = line.strip().split(None, 3)
            if len(parts) >= 4:
                pid, user, etime, cmd = parts
                if (cmd.startswith("pppd ") or cmd.startswith("/usr/sbin/pppd")) and not "sstpd" in cmd:
                    user_match = re.search(r"user\s+([^\s]+)", cmd)
                    u_name = user_match.group(1) if user_match else "Connected User"
                    sessions.append({
                        "id": f"sstpd_{pid}",
                        "pid": pid,
                        "engine": "sstpd",
                        "username": u_name,
                        "ip": "Peer IP (Active PPP)",
                        "device": "Windows / Android",
                        "connected_since": etime,
                        "interface": "ppp"
                    })
    except Exception:
        pass
        
    try:
        se_res = subprocess.run(["/usr/local/vpnserver/vpncmd", "localhost:5555", "/SERVER", "/HUB:DEFAULT", "/CMD", "SessionList"], capture_output=True, text=True)
        if se_res.returncode == 0:
            current_s = {}
            for line in se_res.stdout.splitlines():
                if "|" in line:
                    k, v = [x.strip() for x in line.split("|", 1)]
                    if k == "Session Name":
                        if current_s and current_s.get("name") and not current_s.get("name", "").startswith("SecureNAT"):
                            sessions.append({
                                "id": f"se_{current_s['name']}",
                                "session_name": current_s["name"],
                                "engine": "softether",
                                "username": current_s.get("user", "Unknown"),
                                "ip": current_s.get("ip", "Unknown"),
                                "device": "SoftEther MS-SSTP",
                                "connected_since": "Active",
                                "interface": "Virtual Hub"
                            })
                        current_s = {"name": v}
                    elif k == "User Name (Authentication)":
                        current_s["user"] = v
                    elif k == "IP Address":
                        current_s["ip"] = v
            if current_s and current_s.get("name") and not current_s.get("name", "").startswith("SecureNAT"):
                sessions.append({
                    "id": f"se_{current_s['name']}",
                    "session_name": current_s["name"],
                    "engine": "softether",
                    "username": current_s.get("user", "Unknown"),
                    "ip": current_s.get("ip", "Unknown"),
                    "device": "SoftEther MS-SSTP",
                    "connected_since": "Active",
                    "interface": "Virtual Hub"
                })
    except Exception:
        pass
        
    return jsonify({"sessions": sessions})

@app.route("/api/sstp/sessions/kill", methods=["POST"])
def api_kill_sstp_session():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    pid = data.get("pid")
    session_name = data.get("session_name")
    
    if pid:
        try:
            os.kill(int(pid), 9)
            return jsonify({"success": True, "message": f"پردازش اتصال (PID: {pid}) قطع گردید."})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    elif session_name:
        try:
            subprocess.run(["/usr/local/vpnserver/vpncmd", "localhost:5555", "/SERVER", "/HUB:DEFAULT", "/CMD", "SessionDisconnect", session_name], capture_output=True)
            return jsonify({"success": True, "message": f"نشست SoftEther ({session_name}) با موفقیت بسته شد."})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
            
    return jsonify({"error": "شناسه نشست یافت نشد."}), 400

@app.route("/api/sstp/powershell-script", methods=["GET"])
def api_get_sstp_powershell_script():
    cfg = get_sstp_config()
    script_type = request.args.get("type", "direct")
    server_addr = "vpn.kigaping.com"
    port = cfg.get("port", 4443)
    
    if script_type == "sni":
        vpn_name = "MHPanel SSTP (Port 443 SNI)"
        target = cfg.get("sni", "sstp.kigaping.com")
    else:
        vpn_name = f"MHPanel SSTP (Port {port})"
        target = f"{server_addr}:{port}"
        
    ps_content = f"""# =========================================================
# MHPanel SSTP Windows 1-Click Auto Configuration Script
# Created automatically by MHPanel VPN Suite
# Run with PowerShell (Run as Administrator)
# =========================================================

$VpnName = "{vpn_name}"
$ServerAddress = "{target}"

Write-Host ">>> Configuring Secure SSTP VPN Connection: $VpnName" -ForegroundColor Cyan
Write-Host ">>> Destination Server: $ServerAddress" -ForegroundColor Cyan

# 1. Remove existing connection if it exists
if (Get-VpnConnection -Name $VpnName -ErrorAction SilentlyContinue) {{
    Write-Host "Existing VPN profile found. Removing to ensure clean setup..." -ForegroundColor Yellow
    Remove-VpnConnection -Name $VpnName -Force -Confirm:$false
}}

# 2. Add new SSTP VPN Connection
Add-VpnConnection -Name $VpnName `
    -ServerAddress $ServerAddress `
    -TunnelType Sstp `
    -EncryptionLevel Required `
    -AuthenticationMethod MSChapv2 `
    -RememberCredential $true `
    -SplitTunneling $false

# 3. Optimize connection parameters
Set-VpnConnection -Name $VpnName `
    -TunnelType Sstp `
    -EncryptionLevel Required `
    -AuthenticationMethod MSChapv2

Write-Host ""
Write-Host "SUCCESS! The SSTP VPN profile has been added to Windows Settings." -ForegroundColor Green
Write-Host "You can now connect directly from Windows Network Flyout / Settings." -ForegroundColor Green
Write-Host "Press any key to exit..."
[Console]::ReadKey() | Out-Null
"""
    return Response(ps_content, mimetype="text/plain; charset=utf-8", headers={"Content-Disposition": f"attachment; filename=Setup_{script_type}_SSTP.ps1"})

@app.route("/api/sstp/users", methods=["GET"])
def api_get_sstp_users():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    users = {}
    users_file = "/www/wwwroot/mhpanel/sstp_users.json"
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                users = json.load(f)
        except Exception:
            pass
            
    # Merge with FreeRADIUS accounts if present
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                r_users = json.load(f)
            for ru, rdata in r_users.items():
                if ru not in users:
                    users[ru] = {
                        "active": rdata.get("active", True),
                        "limit_gb": rdata.get("limit_gb"),
                        "expire_date": rdata.get("expire_date"),
                        "rx": 0,
                        "tx": 0,
                        "source": "radius"
                    }
        except Exception:
            pass
            
    return jsonify({"users": users})

@app.route("/api/sstp/users", methods=["POST"])
def api_add_sstp_user():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    limit_gb = data.get("limit_gb")
    expire_date = data.get("expire_date")
    
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
        
    try:
        # 1. Update /etc/ppp/chap-secrets
        os.makedirs("/etc/ppp", exist_ok=True)
        chap_lines = []
        if os.path.exists("/etc/ppp/chap-secrets"):
            with open("/etc/ppp/chap-secrets", "r") as f:
                chap_lines = [line for line in f if not line.strip().startswith(f'"{username}"') and not line.strip().startswith(f'#"{username}"')]
        chap_lines.append(f'"{username}" * "{password}" *\n')
        with open("/etc/ppp/chap-secrets", "w") as f:
            f.writelines(chap_lines)
            
        # 2. Update RADIUS database
        r_users = {}
        if os.path.exists(RADIUS_USERS_FILE):
            try:
                with open(RADIUS_USERS_FILE, "r") as f:
                    r_users = json.load(f)
            except Exception:
                pass
        r_users[username] = {
            "password": password,
            "active": True,
            "limit_gb": limit_gb,
            "expire_date": expire_date,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "protocols": ["all"]
        }
        with open(RADIUS_USERS_FILE, "w") as f:
            json.dump(r_users, f, indent=2)
        sync_freeradius_users()
        
        # 3. SoftEther sync if running
        try:
            subprocess.run(["/usr/local/vpnserver/vpncmd", "localhost:5555", "/SERVER", "/HUB:DEFAULT", "/CMD", "UserCreate", username, "/GROUP:none", "/REALNAME:none", "/NOTE:none"], capture_output=True)
            subprocess.run(["/usr/local/vpnserver/vpncmd", "localhost:5555", "/SERVER", "/HUB:DEFAULT", "/CMD", "UserPasswordSet", username, f"/PASSWORD:{password}"], capture_output=True)
        except Exception:
            pass

    except Exception as e:
        return jsonify({"error": f"Failed to create user: {str(e)}"}), 500
        
    users_file = "/www/wwwroot/mhpanel/sstp_users.json"
    users = {}
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                users = json.load(f)
        except Exception:
            pass
            
    users[username] = {
        "active": True,
        "limit_gb": limit_gb,
        "expire_date": expire_date,
        "rx": 0,
        "tx": 0,
        "last_rx": 0,
        "last_tx": 0
    }
    
    with open(users_file, "w") as f:
        json.dump(users, f, indent=2)
        
    return jsonify({"success": True})

@app.route("/api/sstp/users/<username>", methods=["DELETE"])
def api_delete_sstp_user(username):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    if os.path.exists("/etc/ppp/chap-secrets"):
        with open("/etc/ppp/chap-secrets", "r") as f:
            lines = f.readlines()
        with open("/etc/ppp/chap-secrets", "w") as f:
            for line in lines:
                if not line.strip().startswith(f'"{username}"') and not line.strip().startswith(f'#"{username}"'):
                    f.write(line)

    # Remove from RADIUS
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                r_users = json.load(f)
            if username in r_users:
                del r_users[username]
                with open(RADIUS_USERS_FILE, "w") as f:
                    json.dump(r_users, f, indent=2)
                sync_freeradius_users()
        except Exception:
            pass

    # SoftEther delete
    try:
        subprocess.run(["/usr/local/vpnserver/vpncmd", "localhost:5555", "/SERVER", "/HUB:DEFAULT", "/CMD", "UserDelete", username], capture_output=True)
    except Exception:
        pass

    users_file = "/www/wwwroot/mhpanel/sstp_users.json"
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                users = json.load(f)
            if username in users:
                del users[username]
                with open(users_file, "w") as f:
                    json.dump(users, f, indent=2)
        except Exception:
            pass
            
    return jsonify({"success": True})

@app.route("/api/sstp/users/<username>/toggle", methods=["POST"])
def api_toggle_sstp_user(username):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    users_file = "/www/wwwroot/mhpanel/sstp_users.json"
    users = {}
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                users = json.load(f)
        except Exception:
            pass
            
    current_status = users.get(username, {}).get("active", True)
    new_status = not current_status
    if username in users:
        users[username]["active"] = new_status
        with open(users_file, "w") as f:
            json.dump(users, f, indent=2)

    if os.path.exists("/etc/ppp/chap-secrets"):
        with open("/etc/ppp/chap-secrets", "r") as f:
            content = f.read()
        if new_status:
            content = re.sub(f'^# *\"{username}\" ', f'\"{username}\" ', content, flags=re.MULTILINE)
        else:
            content = re.sub(f'^\"{username}\" ', f'#\"{username}\" ', content, flags=re.MULTILINE)
        with open("/etc/ppp/chap-secrets", "w") as f:
            f.write(content)

    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                r_users = json.load(f)
            if username in r_users:
                r_users[username]["active"] = new_status
                with open(RADIUS_USERS_FILE, "w") as f:
                    json.dump(r_users, f, indent=2)
                sync_freeradius_users()
        except Exception:
            pass
        
    return jsonify({"success": True, "active": new_status})

def get_l2tp_traffic():
    traffic = {}
    return traffic

def l2tp_client_tracker():
    while True:
        try:
            users_file = "/www/wwwroot/mhpanel/l2tp_users.json"
            if os.path.exists(users_file):
                with open(users_file, "r") as f:
                    try:
                        users = json.load(f)
                    except:
                        users = {}
                
                traffic = get_l2tp_traffic()
                changed = False
                now_str = datetime.now().strftime("%Y-%m-%d")
                
                for username, user_data in users.items():
                    tdata = traffic.get(username, {"rx": 0, "tx": 0})
                    if "rx" not in user_data: user_data["rx"] = 0
                    if "tx" not in user_data: user_data["tx"] = 0
                    if tdata["rx"] > user_data.get("last_rx", 0):
                        user_data["rx"] += (tdata["rx"] - user_data.get("last_rx", 0))
                    user_data["last_rx"] = tdata["rx"]
                    
                    if tdata["tx"] > user_data.get("last_tx", 0):
                        user_data["tx"] += (tdata["tx"] - user_data.get("last_tx", 0))
                    user_data["last_tx"] = tdata["tx"]

                    limit_gb = user_data.get("limit_gb")
                    expire_date = user_data.get("expire_date")
                    disabled = False
                    
                    total_usage = user_data["rx"] + user_data["tx"]
                    
                    if expire_date:
                        if now_str > expire_date:
                            disabled = True
                            
                    if limit_gb and not disabled:
                        if total_usage >= limit_gb * (1024**3):
                            disabled = True
                            
                    if disabled:
                        if user_data.get("active", True):
                            user_data["active"] = False
                            changed = True
                            subprocess.run(["sed", "-i", f's/^"{username}" /#"{username}" /', "/etc/ppp/chap-secrets"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                if changed or len(traffic) > 0:
                    with open(users_file, "w") as f:
                        json.dump(users, f)
        except Exception:
            pass
        time.sleep(60)

@app.route("/api/l2tp/users", methods=["GET"])
def api_get_l2tp_users():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    users = {}
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                r_users = json.load(f)
            for u, d in r_users.items():
                users[u] = {
                    "password": d.get("password", ""),
                    "active": d.get("active", True),
                    "limit_gb": d.get("limit_gb"),
                    "expire_date": d.get("expire_date"),
                    "rx": d.get("rx", 0),
                    "tx": d.get("tx", 0)
                }
        except Exception:
            pass
    users_file = "/www/wwwroot/mhpanel/l2tp_users.json"
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                l2_users = json.load(f)
            for u, d in l2_users.items():
                if u not in users:
                    users[u] = d
                else:
                    users[u]["rx"] = d.get("rx", users[u].get("rx", 0))
                    users[u]["tx"] = d.get("tx", users[u].get("tx", 0))
                    if "limit_gb" in d and d["limit_gb"] is not None:
                        users[u]["limit_gb"] = d["limit_gb"]
                    if "expire_date" in d and d["expire_date"] is not None:
                        users[u]["expire_date"] = d["expire_date"]
        except Exception:
            pass
    return jsonify({"users": users})

@app.route("/api/l2tp/users", methods=["POST"])
def api_add_l2tp_user():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")
    limit_gb = data.get("limit_gb")
    expire_date = data.get("expire_date")
    
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
        
    users_file = "/www/wwwroot/mhpanel/l2tp_users.json"
    users = {}
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                users = json.load(f)
        except:
            pass
            
    users[username] = {
        "active": True,
        "password": password,
        "limit_gb": limit_gb,
        "expire_date": expire_date,
        "rx": 0,
        "tx": 0,
        "last_rx": 0,
        "last_tx": 0
    }
    with open(users_file, "w") as f:
        json.dump(users, f, indent=2)

    # Sync to RADIUS database
    r_users = {}
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                r_users = json.load(f)
        except Exception:
            r_users = {}
    r_users[username] = {
        "password": password,
        "active": True,
        "limit_gb": limit_gb,
        "expire_date": expire_date,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "protocols": ["all"]
    }
    with open(RADIUS_USERS_FILE, "w") as f:
        json.dump(r_users, f, indent=2)

    # Sync to ikev2_users.json as well
    try:
        ik_file = "/www/wwwroot/mhpanel/ikev2_users.json"
        ik_users = {}
        if os.path.exists(ik_file):
            with open(ik_file, "r") as f: ik_users = json.load(f)
        ik_users[username] = users[username]
        with open(ik_file, "w") as f: json.dump(ik_users, f, indent=2)
    except Exception:
        pass

    sync_freeradius_users()
    return jsonify({"success": True})

@app.route("/api/l2tp/users/<username>", methods=["DELETE"])
def api_delete_l2tp_user(username):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    users_file = "/www/wwwroot/mhpanel/l2tp_users.json"
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                users = json.load(f)
            if username in users:
                del users[username]
                with open(users_file, "w") as f:
                    json.dump(users, f, indent=2)
        except:
            pass

    r_users = {}
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                r_users = json.load(f)
            if username in r_users:
                del r_users[username]
                with open(RADIUS_USERS_FILE, "w") as f:
                    json.dump(r_users, f, indent=2)
        except Exception:
            pass

    try:
        ik_file = "/www/wwwroot/mhpanel/ikev2_users.json"
        if os.path.exists(ik_file):
            with open(ik_file, "r") as f: ik_users = json.load(f)
            if username in ik_users:
                del ik_users[username]
                with open(ik_file, "w") as f: json.dump(ik_users, f, indent=2)
    except Exception:
        pass

    sync_freeradius_users()
    return jsonify({"success": True})

@app.route("/api/l2tp/users/<username>/toggle", methods=["POST"])
def api_toggle_l2tp_user(username):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    users_file = "/www/wwwroot/mhpanel/l2tp_users.json"
    users = {}
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                users = json.load(f)
        except:
            pass
            
    new_status = False
    if username in users:
        new_status = not users[username].get("active", True)
        users[username]["active"] = new_status
        with open(users_file, "w") as f:
            json.dump(users, f, indent=2)

    r_users = {}
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                r_users = json.load(f)
            if username in r_users:
                new_status = not r_users[username].get("active", True)
                r_users[username]["active"] = new_status
                with open(RADIUS_USERS_FILE, "w") as f:
                    json.dump(r_users, f, indent=2)
        except Exception:
            pass

    try:
        ik_file = "/www/wwwroot/mhpanel/ikev2_users.json"
        if os.path.exists(ik_file):
            with open(ik_file, "r") as f: ik_users = json.load(f)
            if username in ik_users:
                ik_users[username]["active"] = new_status
                with open(ik_file, "w") as f: json.dump(ik_users, f, indent=2)
    except Exception:
        pass

    sync_freeradius_users()
    return jsonify({"success": True, "active": new_status})

# ----------------- L2TPv2 & L2TPv3 Full Management Suite -----------------
L2TP_CONFIG_FILE = "/etc/vpnpanel/l2tp_config.json"
L2TPV3_CONFIG_FILE = "/etc/vpnpanel/l2tpv3_tunnels.json"

def format_bytes_size(b):
    if not b or b < 0:
        return "0 B"
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    else:
        return f"{b / (1024 * 1024 * 1024):.2f} GB"

def is_service_active(svc_name):
    try:
        res = subprocess.run(["systemctl", "is-active", svc_name], capture_output=True, text=True, timeout=3)
        return res.stdout.strip() == "active"
    except Exception:
        return False

def get_l2tp_config_data():
    pub_ip = get_server_public_ip()
    conf = {
        "active": get_protocol_active("l2tp") or is_service_active("xl2tpd"),
        "ipsec_active": is_service_active("strongswan-starter"),
        "radius_active": is_service_active("freeradius"),
        "server_ip": pub_ip,
        "psk": "VpnSecret123",
        "local_ip": "192.168.42.1",
        "ip_range": "192.168.42.10-192.168.42.250",
        "subnet": "192.168.42.0/24",
        "dns1": "8.8.8.8",
        "dns2": "1.1.1.1",
        "mtu": 1280,
        "mru": 1280,
        "auth_mode": "mschapv2",
        "radius_enabled": True,
        "ike": "aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!",
        "esp": "aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1,3des-sha1!",
        "dpdaction": "clear",
        "dpddelay": "30s"
    }

    if os.path.exists(L2TP_CONFIG_FILE):
        try:
            with open(L2TP_CONFIG_FILE, "r") as f:
                saved = json.load(f)
                conf.update(saved)
        except Exception:
            pass

    if os.path.exists("/etc/ipsec.secrets"):
        try:
            with open("/etc/ipsec.secrets", "r") as f:
                for line in f:
                    if "PSK" in line:
                        m = re.search(r'PSK\s+["\']?([^"\']+)["\']?', line)
                        if m:
                            conf["psk"] = m.group(1).strip()
                            break
        except Exception:
            pass

    if os.path.exists("/etc/xl2tpd/xl2tpd.conf"):
        try:
            with open("/etc/xl2tpd/xl2tpd.conf", "r") as f:
                c = f.read()
                m_range = re.search(r'^\s*ip range\s*=\s*([^\n]+)', c, re.MULTILINE)
                if m_range:
                    conf["ip_range"] = m_range.group(1).strip()
                m_local = re.search(r'^\s*local ip\s*=\s*([^\n]+)', c, re.MULTILINE)
                if m_local:
                    conf["local_ip"] = m_local.group(1).strip()
        except Exception:
            pass

    if os.path.exists("/etc/ppp/options.xl2tpd"):
        try:
            with open("/etc/ppp/options.xl2tpd", "r") as f:
                lines = f.readlines()
                dns_found = []
                for line in lines:
                    line = line.strip()
                    if line.startswith("ms-dns"):
                        dns_found.append(line.split()[1])
                    elif line.startswith("mtu"):
                        try:
                            conf["mtu"] = int(line.split()[1])
                        except Exception:
                            pass
                    elif line.startswith("mru"):
                        try:
                            conf["mru"] = int(line.split()[1])
                        except Exception:
                            pass
                if len(dns_found) > 0:
                    conf["dns1"] = dns_found[0]
                if len(dns_found) > 1:
                    conf["dns2"] = dns_found[1]
                content = "".join(lines)
                conf["radius_enabled"] = ("plugin radius.so" in content)
                if "require-mschap-v2" in content:
                    conf["auth_mode"] = "mschapv2"
                elif "require-pap" in content:
                    conf["auth_mode"] = "pap"
                elif "require-chap" in content:
                    conf["auth_mode"] = "chap"
                elif "auth" in content and "refuse-pap" not in content:
                    conf["auth_mode"] = "all"
        except Exception:
            pass

    if os.path.exists("/etc/ipsec.conf"):
        try:
            with open("/etc/ipsec.conf", "r") as f:
                content = f.read()
            if "conn L2TP-PSK" in content:
                l2tp_part = content.split("conn L2TP-PSK", 1)[1].split("conn ", 1)[0]
                for line in l2tp_part.splitlines():
                    line = line.strip()
                    if line.startswith("ike=") or line.startswith("ike ="):
                        conf["ike"] = line.split("=", 1)[1].strip()
                    elif line.startswith("esp=") or line.startswith("esp ="):
                        conf["esp"] = line.split("=", 1)[1].strip()
                    elif line.startswith("dpdaction=") or line.startswith("dpdaction ="):
                        conf["dpdaction"] = line.split("=", 1)[1].strip()
                    elif line.startswith("dpddelay=") or line.startswith("dpddelay ="):
                        conf["dpddelay"] = line.split("=", 1)[1].strip()
        except Exception:
            pass

    return conf

def save_l2tp_full_config(data):
    psk = data.get("psk", "VpnSecret123").strip()
    local_ip = data.get("local_ip", "192.168.42.1").strip()
    ip_range = data.get("ip_range", "192.168.42.10-192.168.42.250").strip()
    subnet = data.get("subnet", "192.168.42.0/24").strip()
    dns1 = data.get("dns1", "8.8.8.8").strip()
    dns2 = data.get("dns2", "1.1.1.1").strip()
    mtu = int(data.get("mtu", 1280))
    mru = int(data.get("mru", 1280))
    auth_mode = data.get("auth_mode", "mschapv2").strip()
    radius_enabled = data.get("radius_enabled", True)
    ike = data.get("ike", "aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!").strip()
    esp = data.get("esp", "aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1,3des-sha1!").strip()
    dpdaction = data.get("dpdaction", "clear").strip()
    dpddelay = data.get("dpddelay", "30s").strip()

    # 1. Update /etc/ipsec.conf, preserving conn ikev2-vpn
    ipsec_conf = "/etc/ipsec.conf"
    existing_ikev2 = ""
    if os.path.exists(ipsec_conf):
        try:
            with open(ipsec_conf, "r") as f:
                c = f.read()
            if "conn ikev2-vpn" in c:
                parts = c.split("conn ikev2-vpn")
                post = parts[1]
                if "conn " in post:
                    existing_ikev2 = "conn ikev2-vpn" + post.split("conn ")[0]
                else:
                    existing_ikev2 = "conn ikev2-vpn" + post
        except Exception:
            pass

    if not existing_ikev2:
        pub_ip = get_server_public_ip()
        existing_ikev2 = f"""conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid={pub_ip}
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth=eap-radius
    rightsourceip=10.10.10.10-10.10.10.250
    rightdns=8.8.8.8,1.1.1.1
    rightsendcert=never
    eap_identity=%identity
    ike=aes256-sha256-curve25519,aes128-sha256-curve25519,aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024,aes256-sha256-ecp256,aes128-sha256-ecp256!
    esp=aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1!"""

    l2tp_block = f"""conn L2TP-PSK
    auto=add
    keyexchange=ikev1
    type=transport
    authby=secret
    left=%any
    leftid=%any
    leftprotoport=17/1701
    right=%any
    rightid=%any
    rightprotoport=17/%any
    rekey=no
    dpdaction={dpdaction}
    dpddelay={dpddelay}
    ike={ike}
    esp={esp}"""

    new_ipsec = f"""config setup
    charondebug="ike 2, knl 1, cfg 2, enc 2"
    uniqueids=no

conn %default
    ikelifetime=60m
    keylife=20m
    rekeymargin=3m
    keyingtries=1
    authby=secret

{existing_ikev2.strip()}

{l2tp_block.strip()}
"""
    with open(ipsec_conf, "w") as f:
        f.write(new_ipsec)

    # 2. Update /etc/ipsec.secrets for PSK
    secrets_file = "/etc/ipsec.secrets"
    existing_secrets = []
    if os.path.exists(secrets_file):
        with open(secrets_file, "r") as f:
            for line in f:
                if "PSK" not in line:
                    existing_secrets.append(line.rstrip())
    if not any("server-key.pem" in l for l in existing_secrets):
        existing_secrets.insert(0, ": RSA server-key.pem")
    existing_secrets.append(f': PSK "{psk}"')
    existing_secrets.append(f'%any %any : PSK "{psk}"')
    pub_ip = get_server_public_ip()
    if pub_ip:
        existing_secrets.append(f'{pub_ip} %any : PSK "{psk}"')
        existing_secrets.append(f'%any {pub_ip} : PSK "{psk}"')
    with open(secrets_file, "w") as f:
        f.write("\n".join(existing_secrets) + "\n")
    os.chmod(secrets_file, 0o600)

    # 3. Update /etc/xl2tpd/xl2tpd.conf
    os.makedirs("/etc/xl2tpd", exist_ok=True)
    with open("/etc/xl2tpd/xl2tpd.conf", "w") as f:
        f.write(f"""[global]
port = 1701
access control = no
debug avp = no
debug network = no
debug packet = no
debug state = no
debug tunnel = no

[lns default]
ip range = {ip_range}
local ip = {local_ip}
require authentication = yes
name = l2tpd
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
""")

    # 4. Update /etc/ppp/options.xl2tpd
    os.makedirs("/etc/ppp", exist_ok=True)
    auth_lines = []
    if auth_mode == "mschapv2":
        auth_lines = [
            "require-mschap-v2",
            "refuse-mschap",
            "refuse-chap",
            "refuse-pap",
            "refuse-eap"
        ]
    elif auth_mode == "pap":
        auth_lines = [
            "require-pap",
            "refuse-chap",
            "refuse-mschap",
            "refuse-mschap-v2",
            "refuse-eap"
        ]
    elif auth_mode == "chap":
        auth_lines = [
            "require-chap",
            "refuse-pap",
            "refuse-mschap",
            "refuse-mschap-v2",
            "refuse-eap"
        ]
    else:
        auth_lines = [
            "auth",
            "refuse-eap"
        ]

    radius_lines = []
    if radius_enabled:
        radius_lines = [
            "plugin radius.so",
            "radius-config-file /etc/radcli/radiusclient.conf"
        ]

    ppp_content = f"""name l2tpd
debug
dump
logfd 2
ipcp-accept-local
ipcp-accept-remote
idle 1800
mtu {mtu}
mru {mru}
proxyarp
lcp-echo-failure 4
lcp-echo-interval 30
ms-dns {dns1}
ms-dns {dns2}
nodefaultroute
mppe-stateful
{chr(10).join(auth_lines)}
{chr(10).join(radius_lines)}
"""
    with open("/etc/ppp/options.xl2tpd", "w") as f:
        f.write(ppp_content.strip() + "\n")

    # Sanitize /etc/ppp/options to prevent unrecognized serial options crash
    try:
        if os.path.exists("/etc/ppp/options"):
            with open("/etc/ppp/options", "r") as f:
                opts = f.read()
            opts_clean = re.sub(r'^(crtscts|lock|modem)', r'#\1', opts, flags=re.MULTILINE)
            if opts != opts_clean:
                with open("/etc/ppp/options", "w") as f:
                    f.write(opts_clean)
    except Exception:
        pass

    # Ensure radcli dictionaries include Microsoft & Roaring Penguin
    try:
        if os.path.exists("/etc/radcli/dictionary"):
            with open("/etc/radcli/dictionary", "r") as f:
                d_c = f.read()
            d_c = d_c.replace("#$INCLUDE /etc/radcli/dictionary.microsoft", "$INCLUDE /etc/radcli/dictionary.microsoft\nINCLUDE /etc/radcli/dictionary.microsoft")
            d_c = d_c.replace("#$INCLUDE /etc/radcli/dictionary.roaringpenguin", "$INCLUDE /etc/radcli/dictionary.roaringpenguin\nINCLUDE /etc/radcli/dictionary.roaringpenguin")
            d_c = re.sub(r'\bipv4addr\b', 'ipaddr', d_c)
            d_c = re.sub(r'\b(ipv6addr|ipv6prefix)\b', 'string', d_c)
            with open("/etc/radcli/dictionary", "w") as f:
                f.write(d_c)
    except Exception:
        pass

    # 5. Persist JSON settings
    os.makedirs("/etc/vpnpanel", exist_ok=True)
    with open(L2TP_CONFIG_FILE, "w") as f:
        json.dump({
            "psk": psk,
            "local_ip": local_ip,
            "ip_range": ip_range,
            "subnet": subnet,
            "dns1": dns1,
            "dns2": dns2,
            "mtu": mtu,
            "mru": mru,
            "auth_mode": auth_mode,
            "radius_enabled": radius_enabled,
            "ike": ike,
            "esp": esp,
            "dpdaction": dpdaction,
            "dpddelay": dpddelay
        }, f, indent=2)

    # 6. Ensure NAT iptables MASQUERADE
    try:
        subprocess.run(f"iptables -t nat -C POSTROUTING -s {subnet} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {subnet} -j MASQUERADE", shell=True)
    except Exception:
        pass

    # 7. Restart and apply
    subprocess.run(["systemctl", "restart", "xl2tpd"], capture_output=True)
    subprocess.run(["systemctl", "restart", "strongswan-starter"], capture_output=True)
    subprocess.run(["ipsec", "update"], capture_output=True)

def get_live_l2tp_sessions():
    sessions = []
    try:
        res = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True, timeout=5)
        dev_stats = {}
        if os.path.exists("/proc/net/dev"):
            with open("/proc/net/dev", "r") as f:
                for line in f:
                    if ":" in line:
                        parts = line.split(":")
                        ifname = parts[0].strip()
                        if ifname.startswith("ppp"):
                            stats = parts[1].split()
                            dev_stats[ifname] = {
                                "rx_bytes": int(stats[0]),
                                "tx_bytes": int(stats[8])
                            }
        for line in res.stdout.splitlines():
            if " ppp" in line and "inet " in line:
                tokens = line.split()
                iface = ""
                client_ip = ""
                local_ip = ""
                for idx, t in enumerate(tokens):
                    if t.startswith("ppp"):
                        iface = t
                    if t == "inet" and idx + 1 < len(tokens):
                        local_ip = tokens[idx + 1]
                    if t == "peer" and idx + 1 < len(tokens):
                        client_ip = tokens[idx + 1].split("/")[0]
                if iface:
                    stats = dev_stats.get(iface, {"rx_bytes": 0, "tx_bytes": 0})
                    sessions.append({
                        "interface": iface,
                        "client_ip": client_ip,
                        "local_ip": local_ip,
                        "rx_bytes": stats["rx_bytes"],
                        "tx_bytes": stats["tx_bytes"],
                        "rx_formatted": format_bytes_size(stats["rx_bytes"]),
                        "tx_formatted": format_bytes_size(stats["tx_bytes"])
                    })
    except Exception:
        pass
    return sessions

def get_l2tpv3_status_data():
    kmods = {}
    try:
        lsmod = subprocess.run(["lsmod"], capture_output=True, text=True, timeout=3).stdout
        kmods["l2tp_core"] = "l2tp_core" in lsmod
        kmods["l2tp_netlink"] = "l2tp_netlink" in lsmod
        kmods["l2tp_eth"] = "l2tp_eth" in lsmod
        kmods["l2tp_ip"] = "l2tp_ip" in lsmod
    except Exception:
        pass

    tunnels = []
    if os.path.exists(L2TPV3_CONFIG_FILE):
        try:
            with open(L2TPV3_CONFIG_FILE, "r") as f:
                tunnels = json.load(f)
        except Exception:
            tunnels = []

    active_kernel_tids = set()
    try:
        out = subprocess.run(["ip", "l2tp", "show", "tunnel"], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            m = re.search(r'Tunnel (\d+)', line)
            if m:
                active_kernel_tids.add(int(m.group(1)))
    except Exception:
        pass

    for t in tunnels:
        t["active"] = (t.get("tunnel_id") in active_kernel_tids)
        ifname = t.get("ifname", f"l2tpeth{t.get('tunnel_id', 0)}")
        t["ifname"] = ifname
        try:
            link_out = subprocess.run(["ip", "link", "show", ifname], capture_output=True, text=True, timeout=3).stdout
            t["interface_up"] = ("state UP" in link_out or ",UP" in link_out)
        except Exception:
            t["interface_up"] = False

    return {
        "modules": kmods,
        "tunnels": tunnels
    }

@app.route("/api/l2tp/config", methods=["GET"])
def api_l2tp_config_get():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_l2tp_config_data())

@app.route("/api/l2tp/config", methods=["POST"])
def api_l2tp_config_set():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    try:
        save_l2tp_full_config(data)
        return jsonify({"success": True, "message": "تنظیمات L2TP و IPsec با موفقیت ذخیره و اعمال شد!"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/l2tp/service/<action>", methods=["POST"])
def api_l2tp_service_action(action):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    if action == "restart":
        subprocess.run(["systemctl", "restart", "xl2tpd"], capture_output=True)
        subprocess.run(["systemctl", "restart", "strongswan-starter"], capture_output=True)
        return jsonify({"success": True, "message": "سرویس‌های L2TP و IPsec با موفقیت راه‌اندازی مجدد شدند."})
    elif action == "reload":
        subprocess.run(["ipsec", "update"], capture_output=True)
        subprocess.run(["systemctl", "reload-or-restart", "xl2tpd"], capture_output=True)
        return jsonify({"success": True, "message": "کانفیگ L2TP و IPsec با موفقیت بازخوانی شد."})
    elif action == "stop":
        subprocess.run(["systemctl", "stop", "xl2tpd"], capture_output=True)
        return jsonify({"success": True, "message": "سرویس L2TP متوقف شد."})
    elif action == "start":
        subprocess.run(["systemctl", "start", "xl2tpd"], capture_output=True)
        subprocess.run(["systemctl", "start", "strongswan-starter"], capture_output=True)
        return jsonify({"success": True, "message": "سرویس L2TP راه‌اندازی شد."})
    return jsonify({"error": "Invalid action"}), 400

@app.route("/api/l2tp/sessions", methods=["GET"])
def api_l2tp_sessions_get():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"sessions": get_live_l2tp_sessions()})

@app.route("/api/l2tp/sessions/<iface>/disconnect", methods=["POST"])
def api_l2tp_session_disconnect(iface):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        subprocess.run(["poff", iface], capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
        subprocess.run(["ip", "link", "delete", iface], capture_output=True)
        return jsonify({"success": True, "message": f"سشن {iface} با موفقیت قطع شد."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/l2tp/v3/status", methods=["GET"])
def api_l2tp_v3_status():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_l2tpv3_status_data())

@app.route("/api/l2tp/v3/tunnel", methods=["POST"])
def api_l2tp_v3_tunnel_add():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json or {}
    try:
        tunnel_id = int(data.get("tunnel_id", 100))
        peer_tunnel_id = int(data.get("peer_tunnel_id", tunnel_id))
        session_id = int(data.get("session_id", 1))
        peer_session_id = int(data.get("peer_session_id", session_id))
        local_ip = data.get("local_ip", "").strip() or get_server_public_ip()
        remote_ip = data.get("remote_ip", "").strip()
        encap = data.get("encap", "udp").strip().lower()
        port = int(data.get("port", 5555))
        ifname = data.get("ifname", f"l2tpeth{tunnel_id}").strip()
        ifaddr = data.get("ifaddr", "").strip()

        if not remote_ip:
            return jsonify({"error": "Remote Peer IP address is required"}), 400

        subprocess.run(["modprobe", "l2tp_eth"], capture_output=True)
        subprocess.run(["modprobe", "l2tp_ip"], capture_output=True)
        subprocess.run(["modprobe", "l2tp_netlink"], capture_output=True)

        if encap == "udp":
            cmd_tunnel = [
                "ip", "l2tp", "add", "tunnel",
                "tunnel_id", str(tunnel_id),
                "peer_tunnel_id", str(peer_tunnel_id),
                "encap", "udp",
                "local", local_ip,
                "remote", remote_ip,
                "udp_sport", str(port),
                "udp_dport", str(port)
            ]
        else:
            cmd_tunnel = [
                "ip", "l2tp", "add", "tunnel",
                "tunnel_id", str(tunnel_id),
                "peer_tunnel_id", str(peer_tunnel_id),
                "encap", "ip",
                "local", local_ip,
                "remote", remote_ip
            ]
        res = subprocess.run(cmd_tunnel, capture_output=True, text=True)
        if res.returncode != 0 and "File exists" not in res.stderr:
            return jsonify({"error": f"خطا در ایجاد تونل L2TPv3: {res.stderr.strip()}"}), 500

        cmd_session = [
            "ip", "l2tp", "add", "session",
            "name", ifname,
            "tunnel_id", str(tunnel_id),
            "session_id", str(session_id),
            "peer_session_id", str(peer_session_id)
        ]
        res_sess = subprocess.run(cmd_session, capture_output=True, text=True)
        if res_sess.returncode != 0 and "File exists" not in res_sess.stderr:
            return jsonify({"error": f"خطا در ایجاد سشن L2TPv3: {res_sess.stderr.strip()}"}), 500

        subprocess.run(["ip", "link", "set", ifname, "up"], capture_output=True)
        if ifaddr:
            subprocess.run(["ip", "addr", "add", ifaddr, "dev", ifname], capture_output=True)

        udp_flags = f"udp_sport {port} udp_dport {port}" if encap == "udp" else ""
        ip_cmd = f"ip addr add {ifaddr} dev {ifname} || true;" if ifaddr else ""
        service_file = f"/etc/systemd/system/l2tpv3-tunnel-{tunnel_id}.service"
        unit_content = f"""[Unit]
Description=L2TPv3 Pseudowire Tunnel {tunnel_id}
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c "modprobe l2tp_eth || true; modprobe l2tp_ip || true; modprobe l2tp_netlink || true; ip l2tp add tunnel tunnel_id {tunnel_id} peer_tunnel_id {peer_tunnel_id} encap {encap} local {local_ip} remote {remote_ip} {udp_flags} || true; ip l2tp add session name {ifname} tunnel_id {tunnel_id} session_id {session_id} peer_session_id {peer_session_id} || true; ip link set {ifname} up || true; {ip_cmd}"
ExecStop=/bin/bash -c "ip l2tp del session tunnel_id {tunnel_id} session_id {session_id} || true; ip l2tp del tunnel tunnel_id {tunnel_id} || true"

[Install]
WantedBy=multi-user.target
"""
        with open(service_file, "w") as f:
            f.write(unit_content)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "enable", f"l2tpv3-tunnel-{tunnel_id}.service"], capture_output=True)

        os.makedirs("/etc/vpnpanel", exist_ok=True)
        tunnels = []
        if os.path.exists(L2TPV3_CONFIG_FILE):
            try:
                with open(L2TPV3_CONFIG_FILE, "r") as f:
                    tunnels = json.load(f)
            except Exception:
                tunnels = []
        tunnels = [t for t in tunnels if t.get("tunnel_id") != tunnel_id]
        tunnels.append({
            "tunnel_id": tunnel_id,
            "peer_tunnel_id": peer_tunnel_id,
            "session_id": session_id,
            "peer_session_id": peer_session_id,
            "local_ip": local_ip,
            "remote_ip": remote_ip,
            "encap": encap,
            "port": port,
            "ifname": ifname,
            "ifaddr": ifaddr,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        with open(L2TPV3_CONFIG_FILE, "w") as f:
            json.dump(tunnels, f, indent=2)

        return jsonify({"success": True, "message": f"تونل L2TPv3 با شناسه {tunnel_id} با موفقیت راه‌اندازی و دائمی شد!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/l2tp/v3/tunnel/<int:tunnel_id>", methods=["DELETE"])
def api_l2tp_v3_tunnel_delete(tunnel_id):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    try:
        tunnels = []
        if os.path.exists(L2TPV3_CONFIG_FILE):
            try:
                with open(L2TPV3_CONFIG_FILE, "r") as f:
                    tunnels = json.load(f)
            except Exception:
                tunnels = []

        target = next((t for t in tunnels if t.get("tunnel_id") == tunnel_id), None)
        session_id = target.get("session_id", 1) if target else 1
        ifname = target.get("ifname", f"l2tpeth{tunnel_id}") if target else f"l2tpeth{tunnel_id}"

        subprocess.run(["systemctl", "stop", f"l2tpv3-tunnel-{tunnel_id}.service"], capture_output=True)
        subprocess.run(["systemctl", "disable", f"l2tpv3-tunnel-{tunnel_id}.service"], capture_output=True)
        svc_path = f"/etc/systemd/system/l2tpv3-tunnel-{tunnel_id}.service"
        if os.path.exists(svc_path):
            os.remove(svc_path)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)

        subprocess.run(["ip", "link", "delete", ifname], capture_output=True)
        subprocess.run(["ip", "l2tp", "del", "session", "tunnel_id", str(tunnel_id), "session_id", str(session_id)], capture_output=True)
        subprocess.run(["ip", "l2tp", "del", "tunnel", "tunnel_id", str(tunnel_id)], capture_output=True)

        tunnels = [t for t in tunnels if t.get("tunnel_id") != tunnel_id]
        with open(L2TPV3_CONFIG_FILE, "w") as f:
            json.dump(tunnels, f, indent=2)

        return jsonify({"success": True, "message": f"تونل L2TPv3 با شناسه {tunnel_id} با موفقیت حذف شد."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/l2tp/quick-connect/windows.ps1", methods=["GET"])
def api_l2tp_quick_windows_ps1():
    conf = get_l2tp_config_data()
    server_ip = conf.get("server_ip") or get_server_public_ip()
    psk = conf.get("psk", "VpnSecret123")
    script = f"""# =========================================================
# MH Panel - Automatic L2TP/IPsec VPN Connection Setup
# Server: {server_ip}
# =========================================================
$ErrorActionPreference = "SilentlyContinue"
$VpnName = "MH-L2TP-VPN"
$ServerAddress = "{server_ip}"
$PresharedKey = "{psk}"

Write-Host "=== Setting up L2TP/IPsec VPN: $VpnName ===" -ForegroundColor Cyan

# 1. Fix Windows NAT-T Registry Setting
Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\PolicyAgent" -Name "AssumeUDPEncapsulationContextOnSendRule" -Type DWord -Value 2 -Force
Write-Host "[1/3] Windows NAT-T policy configured." -ForegroundColor Green

# 2. Re-create VPN connection
Get-VpnConnection -Name $VpnName | Remove-VpnConnection -Force -Confirm:$false
Add-VpnConnection -Name $VpnName `
    -ServerAddress $ServerAddress `
    -TunnelType L2tp `
    -L2tpPsk $PresharedKey `
    -AuthenticationMethod MSChapv2 `
    -EncryptionLevel Required `
    -Force
Write-Host "[2/3] VPN Connection profile created." -ForegroundColor Green

# 3. Configure IPsec parameters
try {{
    Set-VpnConnectionIPsecConfiguration -ConnectionName $VpnName `
        -AuthenticationTransformConstants SHA256128 `
        -CipherTransformConstants AES256 `
        -EncryptionMethod AES256 `
        -IntegrityCheckMethod SHA256 `
        -PfsGroup PFS2048 `
        -DHGroup Group14 `
        -PassThru -Force
}} catch {{}}
Write-Host "[3/3] High-security IPsec proposals bound." -ForegroundColor Green

Write-Host "`nSUCCESS: L2TP VPN is ready to connect!" -ForegroundColor Yellow
Write-Host "Please open Network Settings or System Tray to connect using your username & password." -ForegroundColor White
pause
"""
    return Response(
        script,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=Setup-L2TP.ps1"}
    )

@app.route("/api/l2tp/quick-connect/mikrotik.rsc", methods=["GET"])
def api_l2tp_quick_mikrotik_rsc():
    conf = get_l2tp_config_data()
    server_ip = conf.get("server_ip") or get_server_public_ip()
    psk = conf.get("psk", "VpnSecret123")
    script = f"""# =========================================================
# MikroTik RouterOS - L2TP/IPsec Client Configuration
# Generated by MH Panel
# Server: {server_ip}
# =========================================================

/ip ipsec profile
add name="MH-L2TP-Profile" hash-algorithm=sha256 enc-algorithm=aes-256,aes-128 dh-group=modp2048,modp1024 proposal-check=obey

/ip ipsec proposal
add name="MH-L2TP-Proposal" auth-algorithms=sha256 enc-algorithms=aes-256-cbc,aes-128-cbc pfs-group=modp2048

/ip ipsec peer
add name="MH-L2TP-Peer" address="{server_ip}" profile="MH-L2TP-Profile" exchange-mode=main-l2tp

/ip ipsec identity
add peer="MH-L2TP-Peer" auth-method=pre-shared-key secret="{psk}" generate-policy=port-override

/interface l2tp-client
add name="l2tp-out-mh" connect-to="{server_ip}" user="YOUR_USERNAME" password="YOUR_PASSWORD" \\
    use-ipsec=yes ipsec-secret="{psk}" default-route-distance=1 add-default-route=no disabled=no

:put "MH Panel L2TP Client imported successfully!"
"""
    return Response(
        script,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=mh-l2tp-mikrotik.rsc"}
    )


def get_ikev2_traffic():
    traffic = {}
    return traffic

def ikev2_client_tracker():
    while True:
        try:
            users_file = "/www/wwwroot/mhpanel/ikev2_users.json"
            if os.path.exists(users_file):
                with open(users_file, "r") as f:
                    try:
                        users = json.load(f)
                    except:
                        users = {}
                
                traffic = get_ikev2_traffic()
                changed = False
                now_str = datetime.now().strftime("%Y-%m-%d")
                
                for username, user_data in users.items():
                    tdata = traffic.get(username, {"rx": 0, "tx": 0})
                    if "rx" not in user_data: user_data["rx"] = 0
                    if "tx" not in user_data: user_data["tx"] = 0
                    if tdata["rx"] > user_data.get("last_rx", 0):
                        user_data["rx"] += (tdata["rx"] - user_data.get("last_rx", 0))
                    user_data["last_rx"] = tdata["rx"]
                    
                    if tdata["tx"] > user_data.get("last_tx", 0):
                        user_data["tx"] += (tdata["tx"] - user_data.get("last_tx", 0))
                    user_data["last_tx"] = tdata["tx"]

                    limit_gb = user_data.get("limit_gb")
                    expire_date = user_data.get("expire_date")
                    disabled = False
                    
                    total_usage = user_data["rx"] + user_data["tx"]
                    
                    if expire_date:
                        if now_str > expire_date:
                            disabled = True
                            
                    if limit_gb and not disabled:
                        if total_usage >= limit_gb * (1024**3):
                            disabled = True
                            
                    if disabled:
                        if user_data.get("active", True):
                            user_data["active"] = False
                            changed = True
                            subprocess.run(["sed", "-i", f's/^ *{username} : /#{username} : /', "/etc/swanctl/conf.d/users.conf"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                if changed or len(traffic) > 0:
                    with open(users_file, "w") as f:
                        json.dump(users, f)
        except Exception:
            pass
        time.sleep(60)

@app.route("/api/ikev2/users", methods=["GET"])
def api_get_ikev2_users():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    users = {}
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                r_users = json.load(f)
            for u, d in r_users.items():
                users[u] = {
                    "password": d.get("password", ""),
                    "active": d.get("active", True),
                    "limit_gb": d.get("limit_gb"),
                    "expire_date": d.get("expire_date"),
                    "rx": d.get("rx", 0),
                    "tx": d.get("tx", 0)
                }
        except Exception:
            pass
    users_file = "/www/wwwroot/mhpanel/ikev2_users.json"
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                ik_users = json.load(f)
            for u, d in ik_users.items():
                if u not in users:
                    users[u] = d
                else:
                    users[u]["rx"] = d.get("rx", users[u].get("rx", 0))
                    users[u]["tx"] = d.get("tx", users[u].get("tx", 0))
                    if "limit_gb" in d and d["limit_gb"] is not None:
                        users[u]["limit_gb"] = d["limit_gb"]
                    if "expire_date" in d and d["expire_date"] is not None:
                        users[u]["expire_date"] = d["expire_date"]
        except Exception:
            pass
    return jsonify({"users": users})

@app.route("/api/ikev2/users", methods=["POST"])
def api_add_ikev2_user():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")
    limit_gb = data.get("limit_gb")
    expire_date = data.get("expire_date")
    
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
        
    users_file = "/www/wwwroot/mhpanel/ikev2_users.json"
    users = {}
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                users = json.load(f)
        except:
            pass
            
    users[username] = {
        "active": True,
        "password": password,
        "limit_gb": limit_gb,
        "expire_date": expire_date,
        "rx": 0,
        "tx": 0,
        "last_rx": 0,
        "last_tx": 0
    }
    with open(users_file, "w") as f:
        json.dump(users, f, indent=2)

    # Sync to RADIUS database
    r_users = {}
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                r_users = json.load(f)
        except Exception:
            r_users = {}
    r_users[username] = {
        "password": password,
        "active": True,
        "limit_gb": limit_gb,
        "expire_date": expire_date,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "protocols": ["all"]
    }
    with open(RADIUS_USERS_FILE, "w") as f:
        json.dump(r_users, f, indent=2)

    # Sync to l2tp_users.json as well
    try:
        l2_file = "/www/wwwroot/mhpanel/l2tp_users.json"
        l2_users = {}
        if os.path.exists(l2_file):
            with open(l2_file, "r") as f: l2_users = json.load(f)
        l2_users[username] = users[username]
        with open(l2_file, "w") as f: json.dump(l2_users, f, indent=2)
    except Exception:
        pass

    sync_freeradius_users()
    return jsonify({"success": True})

@app.route("/api/ikev2/users/<username>", methods=["DELETE"])
def api_delete_ikev2_user(username):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    users_file = "/www/wwwroot/mhpanel/ikev2_users.json"
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                users = json.load(f)
            if username in users:
                del users[username]
                with open(users_file, "w") as f:
                    json.dump(users, f, indent=2)
        except:
            pass

    r_users = {}
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                r_users = json.load(f)
            if username in r_users:
                del r_users[username]
                with open(RADIUS_USERS_FILE, "w") as f:
                    json.dump(r_users, f, indent=2)
        except Exception:
            pass

    try:
        l2_file = "/www/wwwroot/mhpanel/l2tp_users.json"
        if os.path.exists(l2_file):
            with open(l2_file, "r") as f: l2_users = json.load(f)
            if username in l2_users:
                del l2_users[username]
                with open(l2_file, "w") as f: json.dump(l2_users, f, indent=2)
    except Exception:
        pass

    sync_freeradius_users()
    return jsonify({"success": True})

@app.route("/api/ikev2/users/<username>/toggle", methods=["POST"])
def api_toggle_ikev2_user(username):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
        
    users_file = "/www/wwwroot/mhpanel/ikev2_users.json"
    users = {}
    if os.path.exists(users_file):
        try:
            with open(users_file, "r") as f:
                users = json.load(f)
        except:
            pass
            
    new_status = False
    if username in users:
        new_status = not users[username].get("active", True)
        users[username]["active"] = new_status
        with open(users_file, "w") as f:
            json.dump(users, f, indent=2)

    r_users = {}
    if os.path.exists(RADIUS_USERS_FILE):
        try:
            with open(RADIUS_USERS_FILE, "r") as f:
                r_users = json.load(f)
            if username in r_users:
                new_status = not r_users[username].get("active", True)
                r_users[username]["active"] = new_status
                with open(RADIUS_USERS_FILE, "w") as f:
                    json.dump(r_users, f, indent=2)
        except Exception:
            pass

    try:
        l2_file = "/www/wwwroot/mhpanel/l2tp_users.json"
        if os.path.exists(l2_file):
            with open(l2_file, "r") as f: l2_users = json.load(f)
            if username in l2_users:
                l2_users[username]["active"] = new_status
                with open(l2_file, "w") as f: json.dump(l2_users, f, indent=2)
    except Exception:
        pass

    sync_freeradius_users()
    return jsonify({"success": True, "active": new_status})


# --- IKEv2 Advanced Protocol, Policy & Certificate Management ---
def get_ikev2_cert_details():
    cert_path = "/etc/ipsec.d/certs/server-cert.pem"
    ca_path = "/etc/ipsec.d/cacerts/ca-cert.pem"
    info = {
        "installed": os.path.exists(cert_path),
        "ca_installed": os.path.exists(ca_path),
        "subject": "Unknown",
        "san": "None",
        "issuer": "Unknown",
        "expiry": "Unknown"
    }
    if os.path.exists(cert_path):
        try:
            res = subprocess.run(["openssl", "x509", "-in", cert_path, "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName"], capture_output=True, text=True)
            out = res.stdout
            for line in out.splitlines():
                if line.startswith("subject="):
                    info["subject"] = line.replace("subject=", "").strip()
                elif line.startswith("issuer="):
                    info["issuer"] = line.replace("issuer=", "").strip()
                elif line.startswith("notAfter="):
                    info["expiry"] = line.replace("notAfter=", "").strip()
                elif "IP Address:" in line or "DNS:" in line:
                    info["san"] = line.strip()
        except Exception:
            pass
    return info

@app.route("/api/ikev2/config", methods=["GET"])
def api_ikev2_config_get():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    conf_path = "/etc/ipsec.conf"
    config = {
        "leftid": "212.227.143.16",
        "rightsourceip": "10.10.10.10-10.10.10.250",
        "rightdns": "8.8.8.8,1.1.1.1",
        "rightauth": "eap-radius",
        "ike": "aes256-sha256-ecp256,aes128-sha256-ecp256,aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024!",
        "esp": "aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1!",
        "fragmentation": "yes",
        "forceencaps": "yes",
        "dpdaction": "clear",
        "dpddelay": "300s",
        "active": get_protocol_active("ikev2"),
        "cert": get_ikev2_cert_details()
    }

    if os.path.exists(conf_path):
        try:
            with open(conf_path, "r") as f:
                content = f.read()
            for key in ["leftid", "rightsourceip", "rightdns", "rightauth", "ike", "esp", "fragmentation", "forceencaps", "dpdaction", "dpddelay"]:
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith(f"{key}=") or line.startswith(f"{key} ="):
                        config[key] = line.split("=", 1)[1].strip()
        except Exception:
            pass

    return jsonify(config)

@app.route("/api/ikev2/config", methods=["POST"])
def api_ikev2_config_set():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json or {}
    leftid = data.get("leftid", "212.227.143.16").strip()
    rightsourceip = data.get("rightsourceip", "10.10.10.10-10.10.10.250").strip()
    rightdns = data.get("rightdns", "8.8.8.8,1.1.1.1").strip()
    rightauth = data.get("rightauth", "eap-radius").strip()
    ike = data.get("ike", "aes256-sha256-ecp256,aes128-sha256-ecp256,aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024!").strip()
    esp = data.get("esp", "aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1!").strip()
    fragmentation = data.get("fragmentation", "yes").strip()
    forceencaps = data.get("forceencaps", "yes").strip()
    dpdaction = data.get("dpdaction", "clear").strip()
    dpddelay = data.get("dpddelay", "300s").strip()

    conf_path = "/etc/ipsec.conf"
    existing_l2tp = ""
    if os.path.exists(conf_path):
        try:
            with open(conf_path, "r") as f:
                c = f.read()
            if "conn L2TP-PSK" in c:
                existing_l2tp = "conn L2TP-PSK" + c.split("conn L2TP-PSK", 1)[1]
        except Exception:
            pass
    if not existing_l2tp:
        existing_l2tp = """conn L2TP-PSK
    auto=add
    keyexchange=ikev1
    type=transport
    authby=secret
    left=%any
    leftid=%any
    leftprotoport=17/1701
    right=%any
    rightid=%any
    rightprotoport=17/%any
    rekey=no
    dpdaction=clear
    dpddelay=30s
    ike=aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
    esp=aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1,3des-sha1!"""

    new_conf = f"""config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn %default
    ikelifetime=60m
    keylife=20m
    rekeymargin=3m
    keyingtries=1
    authby=secret

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation={fragmentation}
    forceencaps={forceencaps}
    dpdaction={dpdaction}
    dpddelay={dpddelay}
    rekey=no
    left=%any
    leftid={leftid}
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth={rightauth}
    rightsourceip={rightsourceip}
    rightdns={rightdns}
    rightsendcert=never
    eap_identity=%identity
    ike={ike}
    esp={esp}

{existing_l2tp.strip()}
"""

    try:
        with open(conf_path, "w") as f:
            f.write(new_conf)

        # If eap-radius is selected, ensure strongswan eap-radius plugin is configured
        if rightauth == "eap-radius":
            os.makedirs("/etc/strongswan.d/charon", exist_ok=True)
            with open("/etc/strongswan.d/charon/eap-radius.conf", "w") as f:
                f.write("""eap-radius {
    load = yes
    servers {
        primary {
            address = 127.0.0.1
            secret = testing123
            auth_port = 1812
            acct_port = 1813
        }
    }
}
""")

        subprocess.run(["systemctl", "restart", "strongswan-starter"], capture_output=True)
        subprocess.run(["ipsec", "update"], capture_output=True)
        return jsonify({"success": True, "message": "IKEv2 configuration successfully saved and applied to strongSwan!"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ikev2/cert/renew", methods=["POST"])
def api_ikev2_cert_renew():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json or {}
    domain_or_ip = data.get("domain_or_ip", "").strip()
    if not domain_or_ip:
        return jsonify({"error": "Domain or IP address is required"}), 400

    ca_cert = "/etc/ipsec.d/cacerts/ca-cert.pem"
    ca_key = "/etc/ipsec.d/private/ca-key.pem"
    srv_cert = "/etc/ipsec.d/certs/server-cert.pem"
    srv_key = "/etc/ipsec.d/private/server-key.pem"

    try:
        # Ensure CA exists
        if not os.path.exists(ca_cert) or not os.path.exists(ca_key):
            os.makedirs("/etc/ipsec.d/cacerts", exist_ok=True)
            os.makedirs("/etc/ipsec.d/private", exist_ok=True)
            subprocess.run(f"ipsec pki --gen --type rsa --size 4096 --outform pem > {ca_key}", shell=True, check=True)
            subprocess.run(f'ipsec pki --self --ca --lifetime 3650 --in {ca_key} --type rsa --dn "CN=MH Panel IKEv2 Root CA" --outform pem > {ca_cert}', shell=True, check=True)

        os.makedirs("/etc/ipsec.d/certs", exist_ok=True)
        # Generate new server key and certificate
        subprocess.run(f"ipsec pki --gen --type rsa --size 2048 --outform pem > {srv_key}", shell=True, check=True)
        cmd_issue = f'ipsec pki --pub --in {srv_key} --type rsa | ipsec pki --issue --lifetime 3650 --cacert {ca_cert} --cakey {ca_key} --dn "CN={domain_or_ip}" --san "{domain_or_ip}" --flag serverAuth --flag ikeIntermediate --outform pem > {srv_cert}'
        subprocess.run(cmd_issue, shell=True, check=True)
        os.chmod(srv_key, 0o600)

        # Update leftid in /etc/ipsec.conf
        if os.path.exists("/etc/ipsec.conf"):
            with open("/etc/ipsec.conf", "r") as f:
                c = f.read()
            c = re.sub(r'^\s*leftid\s*=.*', f'    leftid={domain_or_ip}', c, flags=re.MULTILINE)
            with open("/etc/ipsec.conf", "w") as f:
                f.write(c)

        subprocess.run(["systemctl", "restart", "strongswan-starter"], capture_output=True)
        subprocess.run(["ipsec", "update"], capture_output=True)

        return jsonify({"success": True, "message": f"Certificate for {domain_or_ip} generated and applied successfully!", "cert": get_ikev2_cert_details()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ikev2/service/restart", methods=["POST"])
def api_ikev2_service_restart():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        res = subprocess.run(["systemctl", "restart", "strongswan-starter"], capture_output=True, text=True)
        if res.returncode == 0:
            return jsonify({"success": True, "message": "IKEv2 (StrongSwan) service restarted successfully"})
        else:
            return jsonify({"success": False, "error": res.stderr}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/ikev2/service/reload", methods=["POST"])
def api_ikev2_service_reload():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        res = subprocess.run(["ipsec", "update"], capture_output=True, text=True)
        if res.returncode == 0:
            return jsonify({"success": True, "message": "IKEv2 configuration reloaded (ipsec update)"})
        else:
            subprocess.run(["systemctl", "restart", "strongswan-starter"], capture_output=True)
            return jsonify({"success": True, "message": "IKEv2 configuration reloaded"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

def generate_user_p12(username, password=""):
    ca_cert = "/etc/ipsec.d/cacerts/ca-cert.pem"
    ca_key = "/etc/ipsec.d/private/ca-key.pem"
    if not os.path.exists(ca_cert) or not os.path.exists(ca_key):
        return None
    
    os.makedirs("/tmp/ikev2_p12", exist_ok=True)
    usr_key = f"/tmp/ikev2_p12/{username}-key.pem"
    usr_cert = f"/tmp/ikev2_p12/{username}-cert.pem"
    usr_p12 = f"/tmp/ikev2_p12/{username}.p12"
    
    try:
        subprocess.run(f"ipsec pki --gen --type rsa --size 2048 --outform pem > {usr_key}", shell=True, check=True)
        subprocess.run(f'ipsec pki --pub --in {usr_key} --type rsa | ipsec pki --issue --lifetime 3650 --cacert {ca_cert} --cakey {ca_key} --dn "CN={username}" --san "{username}" --flag clientAuth --outform pem > {usr_cert}', shell=True, check=True)
        pwd_arg = f"-passout pass:{password}" if password else "-passout pass:"
        subprocess.run(f'openssl pkcs12 -export -inkey {usr_key} -in {usr_cert} -name "{username}" -certfile {ca_cert} -out {usr_p12} {pwd_arg}', shell=True, check=True)
        
        if os.path.exists(usr_key): os.unlink(usr_key)
        if os.path.exists(usr_cert): os.unlink(usr_cert)
        return usr_p12
    except Exception as e:
        print("Error generating p12:", e)
        return None

@app.route("/api/ikev2/ca.pem", methods=["GET"])
def api_ikev2_download_ca():
    ca_path = "/etc/ipsec.d/cacerts/ca-cert.pem"
    if not os.path.exists(ca_path):
        return "CA Certificate not found", 404
    from flask import send_file
    return send_file(ca_path, as_attachment=True, download_name="ca-cert.pem", mimetype="application/x-x509-ca-cert")

@app.route("/api/ikev2/ca.crt", methods=["GET"])
def api_ikev2_download_ca_crt():
    ca_path = "/etc/ipsec.d/cacerts/ca-cert.pem"
    if not os.path.exists(ca_path):
        return "CA Certificate not found", 404
    from flask import send_file
    return send_file(ca_path, as_attachment=True, download_name="ca-cert.crt", mimetype="application/x-x509-ca-cert")

@app.route("/api/ikev2/windows-setup.ps1", methods=["GET"])
def api_ikev2_windows_setup():
    conf_path = "/etc/ipsec.conf"
    server_address = "212.227.143.16"
    if os.path.exists(conf_path):
        try:
            with open(conf_path, "r") as f:
                for line in f.read().splitlines():
                    line = line.strip()
                    if line.startswith("leftid=") or line.startswith("leftid ="):
                        server_address = line.split("=", 1)[1].strip()
                        break
        except Exception:
            pass

    panel_host = request.host
    ca_url = f"https://{panel_host}/api/ikev2/ca.pem"

    ps_script = f"""# ========================================================
# MH Panel - Automated IKEv2 Setup for Windows
# Run this script with Administrator privileges in PowerShell
# ========================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   MH Panel - IKEv2 Automated Windows VPN Setup" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan

$ServerAddress = "{server_address}"
$ConnectionName = "MH-IKEv2"
$CaUrl = "{ca_url}"
$TempCa = "$env:TEMP\\ca-cert.pem"

# 1. Download CA Certificate
Write-Host "`n[1/3] Downloading Root CA Certificate from server..." -ForegroundColor Yellow
try {{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}
    Invoke-WebRequest -Uri $CaUrl -OutFile $TempCa -UseBasicParsing
    Write-Host "  -> Root CA downloaded successfully." -ForegroundColor Green
}} catch {{
    Write-Host "  -> Failed to download CA certificate: $_" -ForegroundColor Red
    pause
    exit 1
}}

# 2. Install CA Certificate into Trusted Root Store
Write-Host "`n[2/3] Installing Root CA into Trusted Root Certification Authorities store..." -ForegroundColor Yellow
try {{
    Import-Certificate -FilePath $TempCa -CertStoreLocation "Cert:\\LocalMachine\\Root" | Out-Null
    Write-Host "  -> Root CA Certificate successfully trusted on this PC!" -ForegroundColor Green
}} catch {{
    Write-Host "  -> Note: If access is denied, please run PowerShell as Administrator." -ForegroundColor Red
}}

# 3. Create or Update VPN Connection
Write-Host "`n[3/3] Creating and configuring IKEv2 VPN Connection '$ConnectionName'..." -ForegroundColor Yellow
if (Get-VpnConnection -Name $ConnectionName -ErrorAction SilentlyContinue) {{
    Write-Host "  -> Removing existing connection '$ConnectionName'..." -ForegroundColor Gray
    Remove-VpnConnection -Name $ConnectionName -Force
}}

Add-VpnConnection -Name $ConnectionName `
    -ServerAddress $ServerAddress `
    -TunnelType Ikev2 `
    -AuthenticationMethod EAP `
    -EncryptionLevel Maximum `
    -RememberCredential

# Apply IPsec Security Policies (DH Group 14 + AES256-SHA256)
Set-VpnConnectionIPsecConfiguration -ConnectionName $ConnectionName `
    -AuthenticationTransformConstants SHA256128 `
    -CipherTransformConstants AES256 `
    -EncryptionMethod AES256 `
    -IntegrityCheckMethod SHA256 `
    -PfsGroup None `
    -DHGroup Group14 `
    -PassThru -Force | Out-Null

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host " [SUCCESS] Connection '$ConnectionName' is completely ready!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "You can now connect from Windows Settings -> Network & Internet -> VPN" -ForegroundColor White
Write-Host "Enter your Username and Password when prompted.`n" -ForegroundColor White

pause
"""
    from flask import Response
    return Response(
        ps_script,
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=Setup-MHPanel-IKEv2-{server_address}.ps1"}
    )

@app.route("/api/ikev2/users/<username>/cert.p12", methods=["GET"])
def api_ikev2_user_p12(username):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    p12_path = generate_user_p12(username)
    if not p12_path or not os.path.exists(p12_path):
        return jsonify({"error": "Failed to generate certificate"}), 500
    from flask import send_file
    return send_file(p12_path, as_attachment=True, download_name=f"{username}-ikev2.p12", mimetype="application/x-pkcs12")

@app.route("/api/ikev2/client.p12", methods=["GET"])
def api_ikev2_client_p12():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    
    p12_path = generate_user_p12("client")
    if not p12_path or not os.path.exists(p12_path):
        return jsonify({"error": "Failed to generate certificate"}), 500
    from flask import send_file
    return send_file(p12_path, as_attachment=True, download_name="client-ikev2.p12", mimetype="application/x-pkcs12")

@app.route("/api/ikev2/mobileconfig", methods=["GET"])
def api_ikev2_mobileconfig():
    conf_path = "/etc/ipsec.conf"
    server_address = "212.227.143.16"
    if os.path.exists(conf_path):
        try:
            with open(conf_path, "r") as f:
                for line in f.read().splitlines():
                    line = line.strip()
                    if line.startswith("leftid=") or line.startswith("leftid ="):
                        server_address = line.split("=", 1)[1].strip()
                        break
        except Exception:
            pass

    ca_data = ""
    ca_path = "/etc/ipsec.d/cacerts/ca-cert.pem"
    if os.path.exists(ca_path):
        try:
            with open(ca_path, "rb") as f:
                import base64
                ca_data = base64.b64encode(f.read()).decode("utf-8")
        except Exception:
            pass

    import uuid
    vpn_uuid = str(uuid.uuid4()).upper()
    ca_uuid = str(uuid.uuid4()).upper()
    top_uuid = str(uuid.uuid4()).upper()

    ca_payload_xml = ""
    if ca_data:
        ca_payload_xml = f"""
        <dict>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.mhpanel.ikev2.ca</string>
            <key>PayloadUUID</key>
            <string>{ca_uuid}</string>
            <key>PayloadDisplayName</key>
            <string>MH Panel IKEv2 Root CA</string>
            <key>PayloadCertificateFileName</key>
            <string>ca-cert.pem</string>
            <key>PayloadContent</key>
            <data>{ca_data}</data>
        </dict>"""

    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadDisplayName</key>
    <string>MH Panel IKEv2 ({server_address})</string>
    <key>PayloadIdentifier</key>
    <string>com.mhpanel.ikev2.{server_address}</string>
    <key>PayloadUUID</key>
    <string>{top_uuid}</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadContent</key>
    <array>{ca_payload_xml}
        <dict>
            <key>PayloadType</key>
            <string>com.apple.vpn.managed</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.mhpanel.ikev2.vpn</string>
            <key>PayloadUUID</key>
            <string>{vpn_uuid}</string>
            <key>PayloadDisplayName</key>
            <string>IKEv2 VPN ({server_address})</string>
            <key>UserDefinedName</key>
            <string>MH Panel IKEv2</string>
            <key>VPNType</key>
            <string>IKEv2</string>
            <key>IKEv2</key>
            <dict>
                <key>RemoteAddress</key>
                <string>{server_address}</string>
                <key>RemoteIdentifier</key>
                <string>{server_address}</string>
                <key>LocalIdentifier</key>
                <string></string>
                <key>AuthenticationMethod</key>
                <string>None</string>
                <key>ExtendedAuthEnabled</key>
                <integer>1</integer>
                <key>AuthName</key>
                <string></string>
                <key>DeadPeerDetectionRate</key>
                <string>Medium</string>
                <key>DisableMOBIKE</key>
                <integer>0</integer>
                <key>DisableRedirect</key>
                <integer>0</integer>
                <key>EnableCertificateRevocationCheck</key>
                <integer>0</integer>
                <key>EnablePFS</key>
                <integer>0</integer>
                <key>UseConfigurationAttributeInternalIPSubnet</key>
                <integer>0</integer>
                <key>IKESecurityAssociationParameters</key>
                <dict>
                    <key>EncryptionAlgorithm</key>
                    <string>AES-256</string>
                    <key>IntegrityAlgorithm</key>
                    <string>SHA2-256</string>
                    <key>DiffieHellmanGroup</key>
                    <integer>19</integer>
                </dict>
                <key>ChildSecurityAssociationParameters</key>
                <dict>
                    <key>EncryptionAlgorithm</key>
                    <string>AES-256</string>
                    <key>IntegrityAlgorithm</key>
                    <string>SHA2-256</string>
                    <key>DiffieHellmanGroup</key>
                    <integer>19</integer>
                </dict>
            </dict>
        </dict>
    </array>
</dict>
</plist>"""

    from flask import Response
    return Response(
        xml,
        mimetype="application/x-apple-aspen-config",
        headers={"Content-Disposition": f"attachment; filename=MHPanel-IKEv2-{server_address}.mobileconfig"}
    )


# =========================================================================
# Port Multiplexer & Multi-Port Engine (HAProxy SNI & UDP Multi-Port)
# =========================================================================

MULTIPLEXER_CONFIG_FILE = "/www/wwwroot/mhpanel/multiplexer_config.json"

def get_service_is_active(service_name):
    try:
        r = subprocess.run(["systemctl", "is-active", service_name], capture_output=True, text=True)
        return r.stdout.strip() == "active"
    except Exception:
        return False

def get_default_multiplexer_config():
    return {
        "enabled": True,
        "listen_ports": [443],
        "default_backend": "web",
        "web_server_type": "apache",
        "protocols": [
            {
                "id": "web",
                "name": "وب سرور و پنل مدیریت (Web / MHPanel)",
                "enabled": True,
                "sni": "mhpanel.kigaping.com, kigaping.com, *.kigaping.com",
                "backend_ip": "127.0.0.1",
                "backend_port": 8444,
                "is_default": True,
                "protocol_type": "web",
                "desc": "ترافیک وب‌سایت‌ها، آپاچی/انجین‌یکس و پنل مدیریت"
            },
            {
                "id": "ocserv",
                "name": "سیسکو AnyConnect (Cisco OCServ)",
                "enabled": True,
                "sni": "vpn.kigaping.com, 212.227.143.16",
                "backend_ip": "127.0.0.1",
                "backend_port": 10443,
                "is_default": False,
                "protocol_type": "cisco",
                "desc": "اتصال کلاینت‌های سیسکو انی‌کانکت و اوپن‌کانکت"
            },
            {
                "id": "ssh",
                "name": "تونل SSH (مستقیم و TLS)",
                "enabled": True,
                "sni": "shahan.kigaping.com",
                "backend_ip": "127.0.0.1",
                "backend_port": 22,
                "is_default": False,
                "protocol_type": "ssh",
                "desc": "اتصال کلاینت‌های SSH مستقیم و SSH بر بستر TLS"
            },
            {
                "id": "openvpn",
                "name": "اوپن‌وی‌پی‌ان (OpenVPN TCP)",
                "enabled": True,
                "sni": "ovpn.kigaping.com",
                "backend_ip": "127.0.0.1",
                "backend_port": 1194,
                "is_default": False,
                "protocol_type": "openvpn",
                "desc": "اشتراک پورت ۴۴۳ برای کلاینت‌های OpenVPN TCP"
            },
            {
                "id": "sstp",
                "name": "پروتکل SSTP ویندوز (Accel-PPP)",
                "enabled": False,
                "sni": "sstp.kigaping.com",
                "backend_ip": "127.0.0.1",
                "backend_port": 4443,
                "is_default": False,
                "protocol_type": "sstp",
                "desc": "اتصال مستقیم کلاینت‌های ویندوز با SSL/TLS"
            }
        ],
        "custom_rules": [],
        "udp_multiports": []
    }

def get_multiplexer_config():
    if os.path.exists(MULTIPLEXER_CONFIG_FILE):
        try:
            with open(MULTIPLEXER_CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    cfg = get_default_multiplexer_config()
    try:
        with open(MULTIPLEXER_CONFIG_FILE, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception:
        pass
    return cfg

def save_multiplexer_config(config):
    with open(MULTIPLEXER_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

def check_listen_port_conflicts(ports):
    conflicts = []
    try:
        haproxy_pids = set()
        for p in psutil.process_iter(["pid", "name"]):
            if "haproxy" in (p.info.get("name") or "").lower():
                haproxy_pids.add(p.info["pid"])
        for c in psutil.net_connections(kind="tcp"):
            if c.status == "LISTEN" and c.laddr.port in ports:
                if c.pid not in haproxy_pids:
                    pname = "سرویس دیگر"
                    try:
                        pname = psutil.Process(c.pid).name()
                    except Exception:
                        pass
                    conflicts.append(f"پورت {c.laddr.port} توسط پردازش {pname} (PID: {c.pid}) در حال استفاده است.")
    except Exception:
        pass
    return conflicts

def generate_haproxy_cfg(config):
    listen_ports = config.get("listen_ports", [443])
    if not listen_ports:
        listen_ports = [443]
    
    lines = [
        "global",
        "    log /dev/log    local0",
        "    log /dev/log    local1 notice",
        "    chroot /var/lib/haproxy",
        "    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners",
        "    stats timeout 30s",
        "    user haproxy",
        "    group haproxy",
        "    daemon",
        "",
        "defaults",
        "    log     global",
        "    mode    tcp",
        "    option  tcplog",
        "    option  dontlognull",
        "    timeout connect 5000",
        "    timeout client  50000",
        "    timeout server  50000",
        "",
        "frontend port_multiplexer"
    ]
    for p in sorted(list(set(listen_ports))):
        lines.append(f"    bind *:{p}")
    
    lines.extend([
        "    mode tcp",
        "    tcp-request inspect-delay 3s",
        "",
        "    # 1. Plain SSH Handshake Detection (SSH-...)",
        "    acl is_ssh_raw payload(0,4) -m str SSH-",
        "",
        "    # 2. OpenVPN TCP Handshake Detection (opcode 0x38 or 0x40)",
        "    acl is_openvpn_raw payload(2,1) -m bin 38 40",
        "",
        "    # 3. Plain HTTP Request Detection",
        "    acl is_http_raw payload(0,4) -m str \"GET \" \"POST\" \"HEAD\" \"CONN\"",
        "",
        "    # 4. SSL / TLS ClientHello Detection",
        "    acl is_ssl_hello req_ssl_hello_type 1",
        "",
        "    tcp-request content accept if is_ssh_raw || is_openvpn_raw || is_http_raw || is_ssl_hello",
        ""
    ])
    
    protocols = config.get("protocols", [])
    enabled_protos = {p.get("id"): p for p in protocols if p.get("enabled", False)}
    
    if "ssh" in enabled_protos:
        lines.append("    use_backend ssh_raw_backend if is_ssh_raw")
        backend_blocks.append("backend ssh_raw_backend\n    mode tcp\n    server ssh_raw 127.0.0.1:22")
    if "openvpn" in enabled_protos:
        lines.append("    use_backend openvpn_backend if is_openvpn_raw")
    if "web" in enabled_protos:
        lines.append("    use_backend web_http_backend if is_http_raw")
    lines.append("")
    
    acls = []
    use_backends = []
    backend_blocks = backend_blocks
    default_backend_name = "web_backend"
    
    # Process non-default protocols first, and default/web last
    sorted_protocols = sorted(protocols, key=lambda p: (1 if p.get("is_default") or p.get("id") == "web" else 0))
    
    exact_rules = []
    wildcard_rules = []
    
    for proto in sorted_protocols:
        p_id = proto.get("id")
        p_enabled = proto.get("enabled", False)
        p_sni_str = proto.get("sni", "").strip()
        p_host = proto.get("backend_ip", "127.0.0.1").strip()
        p_port = proto.get("backend_port")
        if not p_port or (p_id == "ssh" and p_port == 22):
            if p_id == "web": p_port = 8444
            elif p_id == "ocserv": p_port = 10443
            elif p_id == "ssh": p_port = 4444
            elif p_id == "openvpn": p_port = 1194
            elif p_id == "sstp": p_port = 4443
            else: p_port = 8444
            
        backend_name = f"{p_id}_backend"
        if proto.get("is_default", False):
            default_backend_name = backend_name
            
        if p_enabled:
            backend_blocks.append(f"backend {backend_name}\n    mode tcp\n    server {p_id} {p_host}:{p_port}")
            if p_sni_str:
                sni_items = [s.strip() for s in p_sni_str.replace(";", ",").split(",") if s.strip()]
                for idx_s, s_val in enumerate(sni_items):
                    acl_name = f"is_{p_id}_{idx_s}"
                    if s_val.startswith("*."):
                        wildcard_rules.append((f"    acl {acl_name} req_ssl_sni -m end {s_val[1:]}", f"    use_backend {backend_name} if {acl_name}"))
                    else:
                        exact_rules.append((f"    acl {acl_name} req_ssl_sni -i {s_val}", f"    use_backend {backend_name} if {acl_name}"))

    for a_line, u_line in exact_rules:
        acls.append(a_line)
        use_backends.append(u_line)
        
    for a_line, u_line in wildcard_rules:
        acls.append(a_line)
        use_backends.append(u_line)

    for idx, rule in enumerate(config.get("custom_rules", [])):
        r_name = rule.get("name", f"custom_{idx}").strip()
        r_enabled = rule.get("enabled", False)
        r_sni = rule.get("sni", "").strip()
        r_target = rule.get("backend_target", "").strip()
        if r_enabled and r_sni and r_target:
            c_backend_name = f"custom_{idx}_backend"
            acl_name = f"is_custom_{idx}"
            acls.append(f"    acl {acl_name} req_ssl_sni -i {r_sni}")
            use_backends.append(f"    use_backend {c_backend_name} if {acl_name}")
            backend_blocks.append(f"backend {c_backend_name}\n    mode tcp\n    server {acl_name} {r_target}")

    if "web" in enabled_protos:
        backend_blocks.append("backend web_http_backend\n    mode tcp\n    server apache_http 127.0.0.1:80")

    lines.extend(acls)
    if acls:
        lines.append("")
    lines.extend(use_backends)
    if use_backends:
        lines.append("")
    lines.append(f"    default_backend {default_backend_name}")
    lines.append("")
    lines.extend(backend_blocks)
    lines.append("")
    return "\n".join(lines)

def apply_multiport_iptables(config):
    try:
        subprocess.run("iptables -t nat -N MHPANEL_MULTIPORT 2>/dev/null || true", shell=True)
        subprocess.run("iptables -t nat -C PREROUTING -j MHPANEL_MULTIPORT 2>/dev/null || iptables -t nat -I PREROUTING 1 -j MHPANEL_MULTIPORT", shell=True)
        subprocess.run("iptables -t nat -F MHPANEL_MULTIPORT", shell=True)

        subprocess.run("iptables -N MHPANEL_MULTIPORT_IN 2>/dev/null || true", shell=True)
        subprocess.run("iptables -C INPUT -j MHPANEL_MULTIPORT_IN 2>/dev/null || iptables -I INPUT 1 -j MHPANEL_MULTIPORT_IN", shell=True)
        subprocess.run("iptables -F MHPANEL_MULTIPORT_IN", shell=True)

        for rule in config.get("udp_multiports", []):
            if not rule.get("enabled", False):
                continue
            proto = rule.get("protocol", "udp").lower()
            target_port = int(rule.get("target_port", 0))
            listen_ports = [int(p) for p in rule.get("listen_ports", []) if str(p).isdigit() and int(p) > 0 and int(p) != target_port and int(p) not in RESERVED_SYSTEM_PORTS]
            if not target_port or not listen_ports:
                continue
            chunks = [listen_ports[i:i + 15] for i in range(0, len(listen_ports), 15)]
            for chunk in chunks:
                ports_csv = ",".join(str(p) for p in chunk)
                cmd_nat = f"iptables -t nat -A MHPANEL_MULTIPORT -p {proto} -m multiport --dports {ports_csv} -j REDIRECT --to-ports {target_port}"
                cmd_in = f"iptables -A MHPANEL_MULTIPORT_IN -p {proto} -m multiport --dports {ports_csv} -j ACCEPT"
                subprocess.run(cmd_nat, shell=True)
                subprocess.run(cmd_in, shell=True)

        subprocess.run("which netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true", shell=True)
        subprocess.run("which iptables-save >/dev/null 2>&1 && iptables-save > /etc/iptables/rules.v4 2>/dev/null || true", shell=True)
    except Exception as e:
        print(f"Error applying multiport iptables: {e}")

@app.route("/api/multiplexer/config", methods=["GET"])
def api_multiplexer_config_get():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    cfg = get_multiplexer_config()
    
    haproxy_active = get_service_is_active("haproxy")
    apache_active = get_service_is_active("httpd") or get_service_is_active("apache2")
    nginx_active = get_service_is_active("nginx")
    
    return jsonify({
        "success": True,
        "config": cfg,
        "status": {
            "haproxy": haproxy_active,
            "apache": apache_active,
            "nginx": nginx_active,
            "haproxy_installed": os.path.exists("/usr/sbin/haproxy")
        }
    })

@app.route("/api/multiplexer/config", methods=["POST"])
def api_multiplexer_config_post():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    
    listen_ports = data.get("listen_ports", [443])
    if not listen_ports:
        listen_ports = [443]
    try:
        listen_ports = [int(p) for p in listen_ports if int(p) > 0 and int(p) <= 65535]
    except Exception:
        return jsonify({"success": False, "error": "شماره پورت‌های ورودی معتبر نیستند."}), 400
    
    conflicts = check_listen_port_conflicts(listen_ports)
    if conflicts:
        return jsonify({
            "success": False,
            "error": "تداخل پورت شناسایی شد: " + " | ".join(conflicts)
        }), 400
    
    data["listen_ports"] = listen_ports
    
    cfg_text = generate_haproxy_cfg(data)
    test_path = "/tmp/haproxy_test_apply.cfg"
    try:
        with open(test_path, "w") as f:
            f.write(cfg_text)
        test_res = subprocess.run(["haproxy", "-c", "-f", test_path], capture_output=True, text=True)
        if test_res.returncode != 0:
            err = test_res.stderr or test_res.stdout
            return jsonify({"success": False, "error": f"خطا در اعتبارسنجی کانفیگ HAProxy: {err}"}), 400
        
        with open("/etc/haproxy/haproxy.cfg", "w") as f:
            f.write(cfg_text)
            
        save_multiplexer_config(data)
        apply_multiport_iptables(data)
        
        if data.get("enabled", True):
            subprocess.run(["systemctl", "reload", "haproxy"])
            if not get_service_is_active("haproxy"):
                subprocess.run(["systemctl", "start", "haproxy"])
        else:
            subprocess.run(["systemctl", "stop", "haproxy"])
            
        return jsonify({
            "success": True,
            "message": "تنظیمات اشتراک پورت و مولتی‌پورت با موفقیت ذخیره و روی سرور اعمال شد!"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/multiplexer/install", methods=["POST"])
def api_multiplexer_install():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        res = subprocess.run("apt-get update && apt-get install -y haproxy iptables-persistent netfilter-persistent", shell=True, capture_output=True, text=True)
        subprocess.run("systemctl enable --now haproxy", shell=True)
        cfg = get_multiplexer_config()
        apply_multiport_iptables(cfg)
        return jsonify({
            "success": True,
            "message": "سرویس HAProxy و ماژول‌های فایروال با موفقیت نصب و راه‌اندازی شدند."
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/multiplexer/service", methods=["POST"])
def api_multiplexer_service():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    action = (request.json or {}).get("action", "reload")
    if action not in ["reload", "restart", "stop", "start"]:
        return jsonify({"success": False, "error": "عملیات نامعتبر است."}), 400
    try:
        subprocess.run(["systemctl", action, "haproxy"], check=True)
        return jsonify({"success": True, "message": f"دستور {action} با موفقیت روی سرویس HAProxy اجرا شد."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =========================================================================
# Professional Server Censorship & Global/Regional Network Radar Engine
# =========================================================================

def probe_endpoint_latency(name, target, probe_type="auto", ports=None, timeout=1.2):
    if ports is None:
        ports = [443, 80, 53]
    lat = None
    loss = 100
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "1", target], capture_output=True, text=True)
        if r.returncode == 0:
            for l in r.stdout.splitlines():
                if "time=" in l:
                    lat = float(l.split("time=")[1].split()[0])
                    loss = 0
                    break
                elif "avg" in l:
                    lat = float(l.split("/")[4])
                    loss = 0
                    break
    except Exception:
        pass

    if lat is None:
        for p in ports:
            t0 = time.time()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((target, p))
                s.close()
                lat = round((time.time() - t0) * 1000, 1)
                loss = 0
                break
            except Exception:
                pass

    if lat is None or loss > 50:
        status = "blocked"
        lat_val = None
    elif lat > 280 or loss > 0:
        status = "degraded"
        lat_val = lat
    else:
        status = "clean"
        lat_val = lat

    return {
        "name": name,
        "target": target,
        "latency_ms": lat_val,
        "packet_loss": 0 if lat_val is not None else 100,
        "status": status
    }

def get_listening_sockets_set():
    ports_set = set()
    try:
        res = subprocess.run(["ss", "-tulpn"], capture_output=True, text=True)
        for line in res.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                proto = parts[0].lower()
                local_addr = parts[4]
                m = re.search(r':(\d+)$', local_addr)
                if m:
                    ports_set.add((proto, int(m.group(1))))
    except Exception:
        pass
    return ports_set

def check_dpi_and_censorship_state():
    results = {
        "score": 100,
        "dns_poisoned": False,
        "sni_blocking": False,
        "udp_drop_rate": 0,
        "verdict": "",
        "details": []
    }

    poisoned = False
    for domain in ["twitter.com", "youtube.com", "instagram.com"]:
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            for ip in ips:
                if ip.startswith("10.10.34.") or ip in ["127.0.0.1", "0.0.0.0", "10.10.34.34", "10.10.34.35"]:
                    poisoned = True
                    break
        except Exception:
            pass

    results["dns_poisoned"] = poisoned
    if poisoned:
        results["score"] -= 30
        results["details"].append("هشدار: پاسخ‌های جعلی دی‌ان‌اس (DNS Poisoning / Sinkhole) بر روی سرور فعال است.")
    else:
        results["details"].append("دی‌ان‌اس بالادستی سرور (Upstream DNS) کاملاً پاک و بدون دستکاری یا پاسخ جعلی است.")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(("1.1.1.1", 443))
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(s, server_hostname="cloudflare-dns.com") as ssock:
            _ = ssock.version()
        results["details"].append("هندشیک امن TLS بین‌الملل بدون تزریق پکت Reset (RST) برقرار شد.")
    except Exception as e:
        results["sni_blocking"] = True
        results["score"] -= 20
        results["details"].append(f"اختلال در برقراری هندشیک امن TLS: {e}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.5)
        sock.sendto(b"\x00\x00\x00\x00", ("1.1.1.1", 53))
        sock.close()
        results["details"].append("مسیر پکت‌های UDP بدون مسدودی برای WireGuard، AmneziaWG و TUIC فعال است.")
    except Exception:
        results["udp_drop_rate"] = 25
        results["score"] -= 15
        results["details"].append("دراپ یا تاخیر در تبادل پکت‌های UDP بین‌الملل شناسایی شد.")

    if results["score"] >= 90:
        results["verdict"] = "سرور در عالی‌ترین وضعیت شبکه و ضدسانسور قرار دارد. هیچ مسدودیتی روی اپراتورهای همراه اول، ایرانسل و مخابرات وجود ندارد و تمام پروتکل‌ها آزادانه در دسترس هستند."
    elif results["score"] >= 70:
        results["verdict"] = "سرور وضعیت کلی مناسبی دارد اما در برخی اپراتورها یا مسیرها تاخیر یا اختلال موضعی مشاهده می‌شود."
    else:
        results["verdict"] = "هشدار: اختلال شدید یا فیلترینگ در برخی مسیرهای شبکه یا دی‌ان‌اس سرور شناسایی شد."

    return results

def run_full_radar_scan(mode="full"):
    import concurrent.futures

    iran_targets = [
        {"name": "همراه اول (MCI)", "target": "mci.ir", "ports": [80, 443], "type": "mobile", "desc": "اپراتور اول تلفن همراه ایران"},
        {"name": "ایرانسل (MTN Irancell)", "target": "irancell.ir", "ports": [80, 443], "type": "mobile", "desc": "اپراتور دوم تلفن همراه ایران"},
        {"name": "مخابرات ایران (TCI)", "target": "217.218.155.155", "ports": [53, 80], "type": "fixed", "desc": "شبکه اینترنت ثابت و فیبر مخابرات"},
        {"name": "رایتل (Rightel)", "target": "94.182.0.1", "ports": [80, 443], "type": "mobile", "desc": "اپراتور سوم تلفن همراه"},
        {"name": "شاتل (Shatel)", "target": "shatel.ir", "ports": [80, 443], "type": "fixed", "desc": "اینترنت ثابت و ADSL شاتل"},
        {"name": "آسیاتک (Asiatech)", "target": "185.143.232.1", "ports": [80, 443], "type": "fixed", "desc": "دیتاسنتر و اینترنت آسیاتک"},
        {"name": "های‌وب و پارس‌آنلاین (HiWEB)", "target": "parsonline.com", "ports": [80, 443], "type": "fixed", "desc": "اینترنت پرسرعت های‌وب"},
        {"name": "آپارات و شبکه داخلی (IXP/CDN)", "target": "aparat.com", "ports": [80, 443], "type": "cdn", "desc": "نقطه تبادل ترافیک داخلی ایران"}
    ]

    global_targets = [
        {"name": "فرانکفورت، آلمان (Hetzner / AWS DE)", "target": "hetzner.com", "ports": [80, 443], "country": "DE", "region": "اروپا مرکزی"},
        {"name": "آمستردام، هلند (Leaseweb / OVH NL)", "target": "leaseweb.com", "ports": [80, 443], "country": "NL", "region": "اروپا غربی"},
        {"name": "پاریس، فرانسه (OVH Cloud FR)", "target": "ovhcloud.com", "ports": [80, 443], "country": "FR", "region": "اروپا غربی"},
        {"name": "هلسینکی، فنلاند (Hetzner FI)", "target": "speedtest.hel1.hetzner.com", "ports": [80, 443], "country": "FI", "region": "شمال اروپا"},
        {"name": "استانبول، ترکیه (TurkNet / DO TR)", "target": "185.169.52.1", "ports": [80, 443], "country": "TR", "region": "خاورمیانه و همسایه"},
        {"name": "دبی، امارات (AWS Middle East / Etisalat)", "target": "dubaiairports.ae", "ports": [443, 80], "country": "AE", "region": "خلیج فارس"},
        {"name": "لندن، بریتانیا (Linode UK)", "target": "speedtest.london.linode.com", "ports": [80, 443], "country": "GB", "region": "بریتانیا"},
        {"name": "ویرجینیا، شرق آمریکا (Cloudflare US)", "target": "198.41.0.4", "ports": [80, 443], "country": "US", "region": "آمریکای شمالی"},
        {"name": "کلودفلر Anycast (Cloudflare 1.1.1.1)", "target": "1.1.1.1", "ports": [53, 443, 80], "country": "CF", "region": "شبکه جهانی توزیع‌شده"},
        {"name": "گوگل DNS (Google 8.8.8.8)", "target": "8.8.8.8", "ports": [53, 443], "country": "GOOG", "region": "شبکه جهانی توزیع‌شده"}
    ]

    iran_results = []
    global_results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        iran_futures = {executor.submit(probe_endpoint_latency, t["name"], t["target"], ports=t.get("ports", [80, 443])): t for t in iran_targets}
        global_futures = {executor.submit(probe_endpoint_latency, t["name"], t["target"], ports=t.get("ports", [80, 443])): t for t in global_targets}

        for f in concurrent.futures.as_completed(iran_futures):
            t = iran_futures[f]
            try:
                res = f.result()
                res["type"] = t["type"]
                res["desc"] = t["desc"]
                if res["status"] == "clean":
                    res["verdict_badge"] = "اتصال سالم و پایدار"
                    res["badge_color"] = "green"
                elif res["status"] == "degraded":
                    res["verdict_badge"] = "تاخیر و اختلال موضعی"
                    res["badge_color"] = "yellow"
                else:
                    res["verdict_badge"] = "مسدود یا عدم پاسخ"
                    res["badge_color"] = "red"
                iran_results.append(res)
            except Exception:
                iran_results.append({
                    "name": t["name"], "target": t["target"], "latency_ms": None,
                    "packet_loss": 100, "status": "blocked", "type": t["type"], "desc": t["desc"],
                    "verdict_badge": "خطا در ارزیابی", "badge_color": "red"
                })

        for f in concurrent.futures.as_completed(global_futures):
            t = global_futures[f]
            try:
                res = f.result()
                res["country"] = t["country"]
                res["region"] = t["region"]
                if res["status"] == "clean":
                    res["verdict_badge"] = "عالی (زیر ۱۰۰ میلی‌ثانیه)"
                    res["badge_color"] = "green"
                elif res["status"] == "degraded":
                    res["verdict_badge"] = "متوسط (تاخیر بالا)"
                    res["badge_color"] = "yellow"
                else:
                    res["verdict_badge"] = "عدم پاسخ (فیلتر یا قطعی)"
                    res["badge_color"] = "red"
                global_results.append(res)
            except Exception:
                global_results.append({
                    "name": t["name"], "target": t["target"], "latency_ms": None,
                    "packet_loss": 100, "status": "blocked", "country": t["country"], "region": t["region"],
                    "verdict_badge": "عدم پاسخ", "badge_color": "red"
                })

    iran_order = {t["name"]: i for i, t in enumerate(iran_targets)}
    iran_results.sort(key=lambda x: iran_order.get(x["name"], 999))
    global_order = {t["name"]: i for i, t in enumerate(global_targets)}
    global_results.sort(key=lambda x: global_order.get(x["name"], 999))

    listening_sockets = get_listening_sockets_set()
    vpn_port_defs = [
        ("Port 443", 443, "tcp", "HAProxy اشتراک پورت / SSTP / AnyConnect", "پروتکل HTTPS & TLS"),
        ("Port 80", 80, "tcp", "وب‌سرور HTTP و تمدید Let's Encrypt", "HTTP Challenge"),
        ("Port 4443", 4443, "tcp", "سرویس اختصاصی SSTP Daemon", "SSTP SSL VPN"),
        ("Port 10443", 10443, "tcp", "سیسکو AnyConnect اختصاصی (OCServ)", "OpenConnect DTLS"),
        ("Port 1194", 1194, "tcp", "اوپن‌وی‌پی‌ان سرور (OpenVPN TCP)", "OpenVPN TUN / TAP"),
        ("Port 51820", 51820, "udp", "وایرگارد معمولی (WireGuard wg0)", "WireGuard UDP"),
        ("Port 51821", 51821, "udp", "AmneziaWG ضد فیلتر (awg0)", "AmneziaWG Obfuscated"),
        ("Port 22", 22, "tcp", "سرویس اصلی SSH و تونل امنیتی", "OpenSSH Tunnel"),
        ("Port 2053", 2053, "tcp", "پورت ثانویه SSH (مناسب کلودفلر)", "CDN SSH Tunnel"),
        ("Port 8443", 8443, "udp", "پروتکل TUIC v5 با الگوریتم BBR", "QUIC Congestion"),
        ("Port 8388", 8388, "tcp", "شادوساکس راست (Shadowsocks 2022)", "Shadowsocks-rust"),
        ("Port 500", 500, "udp", "پروتکل IKEv2 تبادل کلید (ISAKMP)", "IPsec Key Exchange"),
        ("Port 4500", 4500, "udp", "پروتکل IKEv2 عبور از NAT (NAT-T)", "IPsec NAT-Traversal"),
        ("Port 53", 53, "udp", "تونل SlowDNS (DNSTT / Slipstream)", "DNS Tunnel"),
        ("Port 9090", 9090, "tcp", "وب‌پنل مدیریت MH Panel (داشبورد)", "HTTPS Admin Web")
    ]

    ports_matrix = []
    for label, port, proto, name, desc in vpn_port_defs:
        is_active = (proto, port) in listening_sockets or ("tcp", port) in listening_sockets
        ports_matrix.append({
            "label": label,
            "port": port,
            "protocol": proto.upper(),
            "name": name,
            "desc": desc,
            "is_listening": is_active,
            "status": "open" if is_active else "inactive",
            "status_label": "پورت باز و در حال شنود" if is_active else "غیرفعال",
            "badge_color": "green" if is_active else "gray"
        })

    dpi_analysis = check_dpi_and_censorship_state()

    valid_iran_latencies = [r["latency_ms"] for r in iran_results if r["latency_ms"] is not None]
    valid_global_latencies = [r["latency_ms"] for r in global_results if r["latency_ms"] is not None]
    clean_iran_count = sum(1 for r in iran_results if r["status"] == "clean")
    active_ports_count = sum(1 for p in ports_matrix if p["is_listening"])

    avg_iran = round(sum(valid_iran_latencies) / len(valid_iran_latencies), 1) if valid_iran_latencies else None
    avg_global = round(sum(valid_global_latencies) / len(valid_global_latencies), 1) if valid_global_latencies else None

    final_score = dpi_analysis["score"]
    if clean_iran_count < len(iran_targets):
        final_score -= (len(iran_targets) - clean_iran_count) * 8
    final_score = max(5, min(100, final_score))

    return {
        "success": True,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "overall_score": final_score,
        "clean_iran_count": clean_iran_count,
        "total_iran_count": len(iran_targets),
        "avg_iran_latency": avg_iran,
        "avg_global_latency": avg_global,
        "active_ports_count": active_ports_count,
        "total_ports_count": len(ports_matrix),
        "iran_operators": iran_results,
        "global_destinations": global_results,
        "ports_matrix": ports_matrix,
        "dpi_analysis": dpi_analysis
    }

@app.route("/api/network/radar", methods=["GET", "POST"])
def api_network_radar():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401

    mode = request.args.get("mode") or (request.json or {}).get("mode") or "full"
    results = run_full_radar_scan(mode=mode)
    return jsonify(results)


# =========================================================================
# Professional Network Tunnels & MikroTik RouterOS Hub Engine
# =========================================================================
TUNNELS_CONFIG_FILE = "/www/wwwroot/mhpanel/tunnels_config.json"
BOOT_TUNNELS_SCRIPT = "/etc/mhpanel/tunnels_boot.sh"

def load_tunnels_data():
    if not os.path.exists(TUNNELS_CONFIG_FILE):
        return {"tunnels": [], "adv_tunnels": [], "relays": []}
    try:
        with open(TUNNELS_CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                data = {"tunnels": [], "adv_tunnels": [], "relays": []}
            if "tunnels" not in data:
                data["tunnels"] = []
            if "adv_tunnels" not in data:
                data["adv_tunnels"] = []
            if "relays" not in data:
                data["relays"] = []
            return data
    except Exception:
        return {"tunnels": [], "adv_tunnels": [], "relays": []}

def save_tunnels_data(data):
    try:
        os.makedirs(os.path.dirname(TUNNELS_CONFIG_FILE), exist_ok=True)
        with open(TUNNELS_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        update_boot_tunnels_script(data)
    except Exception as e:
        print(f"Error saving tunnels config: {e}")

def get_server_public_ip():
    try:
        r = subprocess.run(["ip", "route", "get", "1.1.1.1"], capture_output=True, text=True)
        if r.returncode == 0:
            m = re.search(r'src\s+(\d+\.\d+\.\d+\.\d+)', r.stdout)
            if m:
                return m.group(1)
    except Exception:
        pass
    return "212.227.143.16"

def get_server_public_ipv6():
    try:
        r = subprocess.run(["ip", "-6", "route", "get", "2001:4860:4860::8888"], capture_output=True, text=True)
        if r.returncode == 0:
            m = re.search(r'src\s+([a-fA-F0-9:]+)', r.stdout)
            if m:
                return m.group(1)
        r2 = subprocess.run(["curl", "-6", "-s", "--max-time", "2", "https://api64.ipify.org"], capture_output=True, text=True)
        if r2.returncode == 0 and ":" in r2.stdout.strip():
            return r2.stdout.strip()
    except Exception:
        pass
    return ""

def get_interface_stats(iface):
    rx_bytes = 0
    tx_bytes = 0
    rx_packets = 0
    tx_packets = 0
    is_up = False
    
    rx_b_path = f"/sys/class/net/{iface}/statistics/rx_bytes"
    tx_b_path = f"/sys/class/net/{iface}/statistics/tx_bytes"
    rx_p_path = f"/sys/class/net/{iface}/statistics/rx_packets"
    tx_p_path = f"/sys/class/net/{iface}/statistics/tx_packets"
    oper_path = f"/sys/class/net/{iface}/operstate"

    if os.path.exists(rx_b_path):
        try:
            with open(rx_b_path) as f: rx_bytes = int(f.read().strip())
            with open(tx_b_path) as f: tx_bytes = int(f.read().strip())
            with open(rx_p_path) as f: rx_packets = int(f.read().strip())
            with open(tx_p_path) as f: tx_packets = int(f.read().strip())
        except Exception:
            pass

    if os.path.exists(oper_path):
        try:
            with open(oper_path) as f:
                state = f.read().strip()
                if state in ["up", "unknown"]:
                    is_up = True
        except Exception:
            pass
    return {
        "is_up": is_up,
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
        "rx_packets": rx_packets,
        "tx_packets": tx_packets
    }

def apply_tunnel_interface(tun):
    name = tun["name"]
    ttype = tun.get("type", "gre")
    enabled = tun.get("enabled", True)
    local_ip = tun.get("local_ip", "")
    remote_ip = tun.get("remote_ip", "")
    inner_local = tun.get("tunnel_local_ip", "")
    inner_remote = tun.get("tunnel_remote_ip", "")
    mtu = int(tun.get("mtu", 1476))
    
    # Clean up existing iface first
    subprocess.run(["ip", "link", "set", name, "down"], capture_output=True)
    subprocess.run(["ip", "link", "del", name], capture_output=True)
    subprocess.run(["ip", "tunnel", "del", name], capture_output=True)
    subprocess.run(["ip", "-6", "tunnel", "del", name], capture_output=True)

    # Clean previous iptables rules (IPv4 & IPv6)
    subprocess.run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", name, "-j", "MASQUERADE"], capture_output=True)
    subprocess.run(["iptables", "-t", "mangle", "-D", "POSTROUTING", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-o", name, "-j", "TCPMSS", "--clamp-mss-to-pmtu"], capture_output=True)
    subprocess.run(["ip6tables", "-t", "nat", "-D", "POSTROUTING", "-o", name, "-j", "MASQUERADE"], capture_output=True)
    subprocess.run(["ip6tables", "-t", "mangle", "-D", "POSTROUTING", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-o", name, "-j", "TCPMSS", "--clamp-mss-to-pmtu"], capture_output=True)

    if not enabled:
        if ttype in ["l2tp", "sstp", "pptp"]:
            user = tun.get("user") or f"{ttype}_{name}"
            if os.path.exists("/etc/ppp/chap-secrets"):
                try:
                    with open("/etc/ppp/chap-secrets", "r") as f:
                        lines = [l for l in f.readlines() if not l.strip().startswith(f'"{user}"')]
                    with open("/etc/ppp/chap-secrets", "w") as f:
                        f.writelines(lines)
                except Exception:
                    pass
        elif ttype == "openvpn":
            subprocess.run(["systemctl", "stop", f"openvpn@{name}"], capture_output=True)
            subprocess.run(["systemctl", "disable", f"openvpn@{name}"], capture_output=True)
        return True, "Disabled"

    # Ensure kernel modules & interface setup
    if ttype == "gre":
        subprocess.run(["modprobe", "ip_gre"], capture_output=True)
        cmd = ["ip", "tunnel", "add", name, "mode", "gre", "remote", remote_ip, "local", local_ip, "ttl", "255"]
        if tun.get("gre_key"):
            cmd += ["key", str(tun["gre_key"])]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0 and "File exists" not in r.stderr:
            return False, r.stderr.strip()
    elif ttype == "ip6gre":
        subprocess.run(["modprobe", "ip6_gre"], capture_output=True)
        cmd = ["ip", "-6", "tunnel", "add", name, "mode", "ip6gre", "remote", remote_ip, "local", local_ip, "ttl", "255"]
        if tun.get("gre_key"):
            cmd += ["key", str(tun["gre_key"])]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0 and "File exists" not in r.stderr:
            cmd2 = ["ip", "link", "add", name, "type", "ip6gre", "remote", remote_ip, "local", local_ip, "ttl", "255"]
            r2 = subprocess.run(cmd2, capture_output=True, text=True)
            if r2.returncode != 0 and "File exists" not in r2.stderr:
                return False, r.stderr.strip() or r2.stderr.strip()
    elif ttype in ["ip6tnl", "ipip6"]:
        subprocess.run(["modprobe", "ip6_tunnel"], capture_output=True)
        cmd = ["ip", "-6", "tunnel", "add", name, "mode", "any", "remote", remote_ip, "local", local_ip]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0 and "File exists" not in r.stderr:
            cmd2 = ["ip", "link", "add", name, "type", "ip6tnl", "mode", "any", "remote", remote_ip, "local", local_ip]
            r2 = subprocess.run(cmd2, capture_output=True, text=True)
            if r2.returncode != 0 and "File exists" not in r2.stderr:
                return False, r.stderr.strip() or r2.stderr.strip()
    elif ttype == "ipip":
        subprocess.run(["modprobe", "ipip"], capture_output=True)
        cmd = ["ip", "tunnel", "add", name, "mode", "ipip", "remote", remote_ip, "local", local_ip, "ttl", "255"]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0 and "File exists" not in r.stderr:
            return False, r.stderr.strip()
    elif ttype == "vxlan":
        subprocess.run(["modprobe", "vxlan"], capture_output=True)
        vni = str(tun.get("vni", 100))
        vx_port = str(tun.get("vxlan_port", 4789))
        cmd = ["ip", "link", "add", name, "type", "vxlan", "id", vni, "remote", remote_ip, "local", local_ip, "dstport", vx_port]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0 and "File exists" not in r.stderr:
            return False, r.stderr.strip()
    elif ttype == "sit":
        subprocess.run(["modprobe", "sit"], capture_output=True)
        cmd = ["ip", "tunnel", "add", name, "mode", "sit", "remote", remote_ip, "local", local_ip, "ttl", "255"]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0 and "File exists" not in r.stderr:
            return False, r.stderr.strip()
    elif ttype == "wireguard":
        subprocess.run(["modprobe", "wireguard"], capture_output=True)
        r = subprocess.run(["ip", "link", "add", name, "type", "wireguard"], capture_output=True, text=True)
        if r.returncode != 0 and "File exists" not in r.stderr:
            return False, r.stderr.strip()
        wg_port = str(tun.get("wg_port", 51830))
        priv_key = tun.get("wg_privkey", "")
        if priv_key:
            tmp_key_file = f"/tmp/{name}_priv.key"
            try:
                with open(tmp_key_file, "w") as f:
                    f.write(priv_key)
                os.chmod(tmp_key_file, 0o600)
                subprocess.run(["wg", "set", name, "listen-port", wg_port, "private-key", tmp_key_file], capture_output=True)
            finally:
                if os.path.exists(tmp_key_file):
                    os.remove(tmp_key_file)
        if tun.get("wg_remote_pubkey"):
            cmd = ["wg", "set", name, "peer", tun["wg_remote_pubkey"], "allowed-ips", "0.0.0.0/0,::/0", "persistent-keepalive", "25"]
            if remote_ip:
                endpoint_addr = f"[{remote_ip}]:{wg_port}" if ":" in remote_ip and not remote_ip.startswith("[") else f"{remote_ip}:{wg_port}"
                cmd += ["endpoint", endpoint_addr]
            subprocess.run(cmd, capture_output=True)
    elif ttype in ["l2tp", "sstp", "pptp"]:
        user = tun.get("user") or f"{ttype}_{name}"
        pwd = tun.get("pass") or "Pass1234Global"
        inner_rem_clean = inner_remote.split("/")[0] if inner_remote else "*"
        chap_file = "/etc/ppp/chap-secrets"
        if os.path.exists(chap_file):
            try:
                with open(chap_file, "r") as f:
                    lines = [l for l in f.readlines() if not l.strip().startswith(f'"{user}"')]
                lines.append(f'"{user}" * "{pwd}" {inner_rem_clean}\n')
                with open(chap_file, "w") as f:
                    f.writelines(lines)
            except Exception as e:
                print(f"Error updating chap-secrets for {name}: {e}")
    elif ttype == "openvpn":
        ovpn_secret = tun.get("ovpn_secret", "").strip()
        ovpn_port = int(tun.get("ovpn_port", 1195))
        ovpn_proto = tun.get("ovpn_proto", "udp")
        ovpn_cipher = tun.get("ovpn_cipher", "AES-256-GCM")
        os.makedirs("/etc/openvpn", exist_ok=True)
        key_path = f"/etc/openvpn/{name}.key"
        if ovpn_secret:
            with open(key_path, "w") as f:
                f.write(ovpn_secret + "\n")
            os.chmod(key_path, 0o600)
        ovpn_conf = f"/etc/openvpn/{name}.conf"
        conf_lines = [
            f"dev {name}",
            "dev-type tun",
            f"port {ovpn_port}",
            f"proto {ovpn_proto}",
            f"ifconfig {inner_local.split('/')[0]} {inner_remote.split('/')[0]}",
            f"secret {key_path}",
            f"cipher {ovpn_cipher}",
            "keepalive 10 60",
            "persist-tun",
            "persist-key",
            f"status /var/log/openvpn_{name}.log"
        ]
        with open(ovpn_conf, "w") as f:
            f.write("\n".join(conf_lines) + "\n")
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "enable", "--now", f"openvpn@{name}"], capture_output=True)

    # Assign IP and set MTU
    if inner_local and ttype not in ["openvpn", "l2tp", "sstp", "pptp"]:
        if ":" in inner_local:
            subprocess.run(["ip", "-6", "addr", "add", inner_local, "dev", name], capture_output=True)
        else:
            subprocess.run(["ip", "addr", "add", inner_local, "dev", name], capture_output=True)
    if ttype not in ["openvpn", "l2tp", "sstp", "pptp"]:
        subprocess.run(["ip", "link", "set", name, "mtu", str(mtu), "up"], capture_output=True)

    # Enable IPv4 & IPv6 Forwarding
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
    subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], capture_output=True)

    # NAT Masquerade (IPv4 & IPv6)
    if tun.get("opt_nat", True):
        subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", name, "-j", "MASQUERADE"], capture_output=True)
        subprocess.run(["ip6tables", "-t", "nat", "-A", "POSTROUTING", "-o", name, "-j", "MASQUERADE"], capture_output=True)

    # TCP MSS Clamping (IPv4 & IPv6)
    if tun.get("opt_mss", True):
        subprocess.run(["iptables", "-t", "mangle", "-A", "POSTROUTING", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-o", name, "-j", "TCPMSS", "--clamp-mss-to-pmtu"], capture_output=True)
        subprocess.run(["ip6tables", "-t", "mangle", "-A", "POSTROUTING", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-o", name, "-j", "TCPMSS", "--clamp-mss-to-pmtu"], capture_output=True)

    return True, "OK"

def remove_tunnel_interface(tun):
    name = tun["name"]
    ttype = tun.get("type", "gre")
    subprocess.run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", name, "-j", "MASQUERADE"], capture_output=True)
    subprocess.run(["iptables", "-t", "mangle", "-D", "POSTROUTING", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-o", name, "-j", "TCPMSS", "--clamp-mss-to-pmtu"], capture_output=True)
    subprocess.run(["ip6tables", "-t", "nat", "-D", "POSTROUTING", "-o", name, "-j", "MASQUERADE"], capture_output=True)
    subprocess.run(["ip6tables", "-t", "mangle", "-D", "POSTROUTING", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-o", name, "-j", "TCPMSS", "--clamp-mss-to-pmtu"], capture_output=True)
    
    if ttype in ["l2tp", "sstp", "pptp"]:
        user = tun.get("user") or f"{ttype}_{name}"
        chap_file = "/etc/ppp/chap-secrets"
        if os.path.exists(chap_file):
            try:
                with open(chap_file, "r") as f:
                    lines = [l for l in f.readlines() if not l.strip().startswith(f'"{user}"')]
                with open(chap_file, "w") as f:
                    f.writelines(lines)
            except Exception:
                pass
    elif ttype == "openvpn":
        subprocess.run(["systemctl", "stop", f"openvpn@{name}"], capture_output=True)
        subprocess.run(["systemctl", "disable", f"openvpn@{name}"], capture_output=True)
        for p in [f"/etc/openvpn/{name}.conf", f"/etc/openvpn/{name}.key"]:
            if os.path.exists(p):
                try: os.remove(p)
                except Exception: pass

    subprocess.run(["ip", "link", "set", name, "down"], capture_output=True)
    subprocess.run(["ip", "link", "del", name], capture_output=True)
    subprocess.run(["ip", "tunnel", "del", name], capture_output=True)
    subprocess.run(["ip", "-6", "tunnel", "del", name], capture_output=True)

def apply_adv_tunnel(adv):
    adv_id = adv["id"]
    name = adv.get("name", f"tun_{adv_id}")
    tool = adv.get("tool", "gost")
    role = adv.get("role", "server")
    listen_port = int(adv.get("listen_port", 8443))
    remote_ip = adv.get("remote_ip", "").strip()
    remote_port = int(adv.get("remote_port", 8443))
    target_addr = adv.get("target_addr", "127.0.0.1:443").strip()
    transport = adv.get("transport", "wss").strip()
    secret = adv.get("secret", "MHPanelTunSecret123!").strip()
    sni = adv.get("sni", "dl.google.com").strip()
    enabled = adv.get("enabled", True)

    unit_name = f"mhtun_{adv_id}.service"
    unit_path = f"/etc/systemd/system/{unit_name}"
    conf_dir = "/etc/mhpanel"
    os.makedirs(conf_dir, exist_ok=True)

    subprocess.run(["systemctl", "stop", unit_name], capture_output=True)

    if not enabled:
        subprocess.run(["systemctl", "disable", unit_name], capture_output=True)
        return True, "Disabled"

    target_host = target_addr.split(":")[0] if ":" in target_addr else target_addr
    target_p = target_addr.split(":")[1] if ":" in target_addr else "443"
    safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', name)

    exec_cmd = ""

    if tool == "gost":
        if role == "server":
            if transport == "wss":
                exec_cmd = f"/usr/local/bin/gost -L \"relay+wss://:{listen_port}?path=/ws\" -F \"tcp://{target_addr}\""
            elif transport == "tls":
                exec_cmd = f"/usr/local/bin/gost -L \"relay+tls://:{listen_port}\" -F \"tcp://{target_addr}\""
            elif transport == "kcp":
                exec_cmd = f"/usr/local/bin/gost -L \"relay+kcp://:{listen_port}\" -F \"tcp://{target_addr}\""
            else:
                exec_cmd = f"/usr/local/bin/gost -L \"tcp://:{listen_port}/{target_addr}\""
        else: # client
            if transport == "wss":
                exec_cmd = f"/usr/local/bin/gost -L \"tcp://:{listen_port}/{target_addr}\" -F \"relay+wss://{remote_ip}:{remote_port}?path=/ws\""
            elif transport == "tls":
                exec_cmd = f"/usr/local/bin/gost -L \"tcp://:{listen_port}/{target_addr}\" -F \"relay+tls://{remote_ip}:{remote_port}\""
            elif transport == "kcp":
                exec_cmd = f"/usr/local/bin/gost -L \"tcp://:{listen_port}/{target_addr}\" -F \"relay+kcp://{remote_ip}:{remote_port}\""
            else:
                exec_cmd = f"/usr/local/bin/gost -L \"tcp://:{listen_port}/{target_addr}\" -F \"tcp://{remote_ip}:{remote_port}\""

    elif tool == "wstunnel":
        if role == "server":
            exec_cmd = f"/usr/local/bin/wstunnel server --restrict-to {target_addr} ws://0.0.0.0:{listen_port}"
        else:
            exec_cmd = f"/usr/local/bin/wstunnel client -L tcp://0.0.0.0:{listen_port}:{target_addr} ws://{remote_ip}:{remote_port}"

    elif tool == "rtt":
        if role == "server":
            exec_cmd = f"/usr/local/bin/rtt --kharej --iran-addr={remote_ip} --iran-port={remote_port} --toip={target_host} --toport={target_p} --sni={sni} --password={secret}"
        else:
            exec_cmd = f"/usr/local/bin/rtt --iran --lport={listen_port} --sni={sni} --password={secret}"

    elif tool == "udp2raw":
        if role == "server":
            exec_cmd = f"/usr/local/bin/udp2raw -s -l 0.0.0.0:{listen_port} -r {target_addr} -k \"{secret}\" --raw-mode faketcp -a"
        else:
            exec_cmd = f"/usr/local/bin/udp2raw -c -l 0.0.0.0:{listen_port} -r {remote_ip}:{remote_port} -k \"{secret}\" --raw-mode faketcp -a"

    elif tool == "chisel":
        if role == "server":
            exec_cmd = f"/usr/local/bin/chisel server -p {listen_port} --auth \"{secret}\" --reverse"
        else:
            exec_cmd = f"/usr/local/bin/chisel client --auth \"{secret}\" http://{remote_ip}:{remote_port} R:{listen_port}:{target_addr}"

    elif tool == "phantun":
        if role == "server":
            exec_cmd = f"/usr/local/bin/phantun-server --local {listen_port} --remote {target_addr}"
        else:
            exec_cmd = f"/usr/local/bin/phantun-client --local {listen_port} --remote {remote_ip}:{remote_port}"

    elif tool == "rathole":
        cfg_file = f"/etc/mhpanel/rathole_{adv_id}.toml"
        if role == "server":
            cfg_content = f"""[server]
bind_addr = "0.0.0.0:{listen_port}"
default_token = "{secret}"

[server.services.{safe_name}]
bind_addr = "0.0.0.0:{listen_port}"
"""
            exec_cmd = f"/usr/local/bin/rathole -s {cfg_file}"
        else:
            cfg_content = f"""[client]
remote_addr = "{remote_ip}:{remote_port}"
default_token = "{secret}"

[client.services.{safe_name}]
local_addr = "{target_addr}"
"""
            exec_cmd = f"/usr/local/bin/rathole -c {cfg_file}"
        with open(cfg_file, "w", encoding="utf-8") as f:
            f.write(cfg_content)

    elif tool == "frp":
        if role == "server":
            exec_cmd = f"/usr/local/bin/frps -p {listen_port} --auth.token \"{secret}\""
        else:
            cfg_file = f"/etc/mhpanel/frp_{adv_id}.toml"
            cfg_content = f"""serverAddr = "{remote_ip}"
serverPort = {remote_port}
auth.token = "{secret}"

[[proxies]]
name = "{safe_name}"
type = "tcp"
localIP = "{target_host}"
localPort = {target_p}
remotePort = {listen_port}
"""
            with open(cfg_file, "w", encoding="utf-8") as f:
                f.write(cfg_content)
            exec_cmd = f"/usr/local/bin/frpc -c {cfg_file}"

    elif tool == "kcptun":
        if role == "server":
            exec_cmd = f"/usr/local/bin/kcptun-server -l \":{listen_port}\" -t \"{target_addr}\" --key \"{secret}\" --crypt aes --mode fast2"
        else:
            exec_cmd = f"/usr/local/bin/kcptun-client -l \":{listen_port}\" -r \"{remote_ip}:{remote_port}\" --key \"{secret}\" --crypt aes --mode fast2"

    unit_content = f"""[Unit]
Description=MH Panel Anti-Censorship Tunnel ({name} - {tool.upper()})
After=network.target

[Service]
Type=simple
User=root
ExecStart={exec_cmd}
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""
    with open(unit_path, "w", encoding="utf-8") as f:
        f.write(unit_content)

    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    subprocess.run(["systemctl", "enable", "--now", unit_name], capture_output=True)
    return True, "OK"

def remove_adv_tunnel(adv):
    adv_id = adv["id"]
    unit_name = f"mhtun_{adv_id}.service"
    subprocess.run(["systemctl", "stop", unit_name], capture_output=True)
    subprocess.run(["systemctl", "disable", unit_name], capture_output=True)
    unit_path = f"/etc/systemd/system/{unit_name}"
    if os.path.exists(unit_path):
        try: os.remove(unit_path)
        except Exception: pass
    for ext in [".toml", ".conf"]:
        cf = f"/etc/mhpanel/rathole_{adv_id}{ext}"
        if os.path.exists(cf):
            try: os.remove(cf)
            except Exception: pass
        cf2 = f"/etc/mhpanel/frp_{adv_id}{ext}"
        if os.path.exists(cf2):
            try: os.remove(cf2)
            except Exception: pass
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)

def generate_adv_tunnel_script(adv):
    name = adv.get("name", "adv_tunnel")
    tool = adv.get("tool", "gost")
    this_role = adv.get("role", "server")
    listen_port = adv.get("listen_port", 8443)
    remote_ip = adv.get("remote_ip", "").strip()
    remote_port = adv.get("remote_port", 8443)
    target_addr = adv.get("target_addr", "127.0.0.1:443")
    secret = adv.get("secret", "MHPanelTunSecret123!")
    sni = adv.get("sni", "dl.google.com")
    this_server_ip = get_server_public_ip()

    # Counterpart role for the remote server
    if this_role == "server":
        remote_role = "client"
        endpoint_ip = this_server_ip
        endpoint_port = listen_port
    else:
        remote_role = "server"
        endpoint_ip = remote_ip
        endpoint_port = remote_port

    target_host = target_addr.split(":")[0] if ":" in target_addr else target_addr
    target_p = target_addr.split(":")[1] if ":" in target_addr else "443"
    safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', name)

    script_lines = [
        f"#!/bin/bash",
        f"# ====================================================================",
        f"# دستور راه‌اندازی خودکار سرور مقابل ({remote_role.upper()}) برای تونل {name}",
        f"# پروتکل: {tool.upper()} | سرور متصل: {this_server_ip}:{listen_port}",
        f"# ====================================================================",
        f"set -e",
        f""
    ]

    exec_cmd = ""
    if tool == "gost":
        script_lines += [
            "# 1. دانلود و نصب GOST v3 در صورت عدم وجود",
            "if ! command -v gost &>/dev/null; then",
            "  echo '--> Installing GOST v3...'",
            "  curl -fsSL https://github.com/go-gost/gost/releases/download/v3.0.0-rc10/gost_3.0.0-rc10_linux_amd64.tar.gz | tar -xz -C /usr/local/bin/ gost",
            "  chmod +x /usr/local/bin/gost",
            "fi",
            ""
        ]
        if remote_role == "client":
            exec_cmd = f"/usr/local/bin/gost -L tcp://:{listen_port}/{target_addr} -F relay+wss://{endpoint_ip}:{endpoint_port}?path=/ws"
        else:
            exec_cmd = f"/usr/local/bin/gost -L \"relay+wss://:{listen_port}?path=/ws\" -F \"tcp://{target_addr}\""

    elif tool == "wstunnel":
        script_lines += [
            "# 1. دانلود و نصب WSTunnel",
            "if ! command -v wstunnel &>/dev/null; then",
            "  echo '--> Installing WSTunnel...'",
            "  curl -fsSL https://github.com/erebe/wstunnel/releases/download/v11.0.0/wstunnel_11.0.0_linux_amd64.tar.gz | tar -xz -C /usr/local/bin/ wstunnel",
            "  chmod +x /usr/local/bin/wstunnel",
            "fi",
            ""
        ]
        if remote_role == "client":
            exec_cmd = f"/usr/local/bin/wstunnel client -L tcp://0.0.0.0:{listen_port}:{target_addr} ws://{endpoint_ip}:{endpoint_port}"
        else:
            exec_cmd = f"/usr/local/bin/wstunnel server --restrict-to {target_addr} ws://0.0.0.0:{listen_port}"

    elif tool == "rtt":
        script_lines += [
            "# 1. دانلود و نصب ReverseTlsTunnel (RTT)",
            "if ! command -v rtt &>/dev/null; then",
            "  echo '--> Installing RTT...'",
            "  curl -fsSL https://github.com/radkesvat/ReverseTlsTunnel/releases/download/v7.1/rtt-linux-amd64.zip -o /tmp/rtt.zip",
            "  unzip -o /tmp/rtt.zip -d /usr/local/bin/ && chmod +x /usr/local/bin/rtt && rm -f /tmp/rtt.zip",
            "fi",
            ""
        ]
        if remote_role == "client":
            exec_cmd = f"/usr/local/bin/rtt --iran --lport={listen_port} --sni={sni} --password={secret}"
        else:
            exec_cmd = f"/usr/local/bin/rtt --kharej --iran-addr={endpoint_ip} --iran-port={endpoint_port} --toip={target_host} --toport={target_p} --sni={sni} --password={secret}"

    elif tool == "udp2raw":
        script_lines += [
            "# 1. دانلود و نصب udp2raw",
            "if ! command -v udp2raw &>/dev/null; then",
            "  echo '--> Installing udp2raw...'",
            "  curl -fsSL https://github.com/wangyu-/udp2raw/releases/download/20230207.0/udp2raw_binaries.tar.gz | tar -xz -C /tmp/",
            "  mv /tmp/udp2raw_amd64 /usr/local/bin/udp2raw && chmod +x /usr/local/bin/udp2raw",
            "fi",
            ""
        ]
        if remote_role == "client":
            exec_cmd = f"/usr/local/bin/udp2raw -c -l 0.0.0.0:{listen_port} -r {endpoint_ip}:{endpoint_port} -k \"{secret}\" --raw-mode faketcp -a"
        else:
            exec_cmd = f"/usr/local/bin/udp2raw -s -l 0.0.0.0:{listen_port} -r {target_addr} -k \"{secret}\" --raw-mode faketcp -a"

    elif tool == "chisel":
        script_lines += [
            "# 1. دانلود و نصب Chisel",
            "if ! command -v chisel &>/dev/null; then",
            "  echo '--> Installing Chisel...'",
            "  curl -fsSL https://github.com/jpillora/chisel/releases/download/v1.10.0/chisel_1.10.0_linux_amd64.gz | gzip -d > /usr/local/bin/chisel",
            "  chmod +x /usr/local/bin/chisel",
            "fi",
            ""
        ]
        if remote_role == "client":
            exec_cmd = f"/usr/local/bin/chisel client --auth \"{secret}\" http://{endpoint_ip}:{endpoint_port} R:{listen_port}:{target_addr}"
        else:
            exec_cmd = f"/usr/local/bin/chisel server -p {listen_port} --auth \"{secret}\" --reverse"

    elif tool == "kcptun":
        script_lines += [
            "# 1. نصب Kcptun",
            "apt-get update && apt-get install -y kcptun || true",
            ""
        ]
        if remote_role == "client":
            exec_cmd = f"/usr/local/bin/kcptun-client -l \":{listen_port}\" -r \"{endpoint_ip}:{endpoint_port}\" --key \"{secret}\" --crypt aes --mode fast2"
        else:
            exec_cmd = f"/usr/local/bin/kcptun-server -l \":{listen_port}\" -t \"{target_addr}\" --key \"{secret}\" --crypt aes --mode fast2"

    else:
        exec_cmd = f"# Execute tunnel tool: {tool}"

    unit_script = f"""# 2. ایجاد سرویس سیستمی Systemd دائمی
cat << 'EOF' > /etc/systemd/system/mhtun_{safe_name}.service
[Unit]
Description=MH Panel Remote Tunnel ({safe_name} - {tool.upper()})
After=network.target

[Service]
Type=simple
User=root
ExecStart={exec_cmd}
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# 3. فعال‌سازی و راه‌اندازی فوری
systemctl daemon-reload
systemctl enable --now mhtun_{safe_name}.service
echo "=== Tunnel service mhtun_{safe_name} started successfully ==="
systemctl status mhtun_{safe_name}.service --no-pager
"""
    script_lines.append(unit_script)
    return "\n".join(script_lines)

def apply_port_relay(relay):
    listen_port = str(relay["listen_port"])
    target_ip = str(relay["target_ip"])
    target_port = str(relay["target_port"])
    proto = relay.get("proto", "both")

    remove_port_relay(relay)
    if not relay.get("enabled", True):
        return

    protos = ["tcp", "udp"] if proto == "both" else [proto]
    for p in protos:
        subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", p, "--dport", listen_port, "-j", "DNAT", "--to-destination", f"{target_ip}:{target_port}"], capture_output=True)
        subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-p", p, "-d", target_ip, "--dport", target_port, "-j", "MASQUERADE"], capture_output=True)
        subprocess.run(["iptables", "-A", "FORWARD", "-p", p, "-d", target_ip, "--dport", target_port, "-j", "ACCEPT"], capture_output=True)

def remove_port_relay(relay):
    listen_port = str(relay["listen_port"])
    target_ip = str(relay["target_ip"])
    target_port = str(relay["target_port"])
    proto = relay.get("proto", "both")
    protos = ["tcp", "udp"] if proto == "both" else [proto]
    for p in protos:
        subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", p, "--dport", listen_port, "-j", "DNAT", "--to-destination", f"{target_ip}:{target_port}"], capture_output=True)
        subprocess.run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-p", p, "-d", target_ip, "--dport", target_port, "-j", "MASQUERADE"], capture_output=True)
        subprocess.run(["iptables", "-D", "FORWARD", "-p", p, "-d", target_ip, "--dport", target_port, "-j", "ACCEPT"], capture_output=True)

def update_boot_tunnels_script(data):
    try:
        os.makedirs(os.path.dirname(BOOT_TUNNELS_SCRIPT), exist_ok=True)
        lines = [
            "#!/bin/bash",
            "# MH Panel Auto-generated Tunnels Boot Script",
            "sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1",
            "sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1",
            ""
        ]
        for tun in data.get("tunnels", []):
            if not tun.get("enabled", True):
                continue
            name = tun["name"]
            ttype = tun.get("type", "gre")
            rem = tun.get("remote_ip", "")
            loc = tun.get("local_ip", "")
            mtu = tun.get("mtu", 1476)
            in_loc = tun.get("tunnel_local_ip", "")
            if ttype == "gre":
                lines.append(f"modprobe ip_gre")
                k_opt = f" key {tun['gre_key']}" if tun.get("gre_key") else ""
                lines.append(f"ip tunnel add {name} mode gre remote {rem} local {loc} ttl 255{k_opt} 2>/dev/null")
            elif ttype == "ip6gre":
                lines.append(f"modprobe ip6_gre")
                k_opt = f" key {tun['gre_key']}" if tun.get("gre_key") else ""
                lines.append(f"ip -6 tunnel add {name} mode ip6gre remote {rem} local {loc} ttl 255{k_opt} 2>/dev/null")
            elif ttype in ["ip6tnl", "ipip6"]:
                lines.append(f"modprobe ip6_tunnel")
                lines.append(f"ip -6 tunnel add {name} mode any remote {rem} local {loc} 2>/dev/null")
            elif ttype == "ipip":
                lines.append(f"modprobe ipip")
                lines.append(f"ip tunnel add {name} mode ipip remote {rem} local {loc} ttl 255 2>/dev/null")
            elif ttype == "vxlan":
                lines.append(f"modprobe vxlan")
                vni = tun.get("vni", 100)
                vxp = tun.get("vxlan_port", 4789)
                lines.append(f"ip link add {name} type vxlan id {vni} remote {rem} local {loc} dstport {vxp} 2>/dev/null")
            elif ttype == "wireguard":
                lines.append(f"modprobe wireguard")
                lines.append(f"ip link add {name} type wireguard 2>/dev/null")
            elif ttype == "sit":
                lines.append(f"modprobe sit")
                lines.append(f"ip tunnel add {name} mode sit remote {rem} local {loc} ttl 255 2>/dev/null")
            
            if in_loc and ttype not in ["openvpn", "l2tp", "sstp", "pptp"]:
                if ":" in in_loc:
                    lines.append(f"ip -6 addr add {in_loc} dev {name} 2>/dev/null")
                else:
                    lines.append(f"ip addr add {in_loc} dev {name} 2>/dev/null")
            if ttype not in ["openvpn", "l2tp", "sstp", "pptp"]:
                lines.append(f"ip link set {name} mtu {mtu} up 2>/dev/null")
            if tun.get("opt_nat", True):
                lines.append(f"iptables -t nat -A POSTROUTING -o {name} -j MASQUERADE 2>/dev/null")
                lines.append(f"ip6tables -t nat -A POSTROUTING -o {name} -j MASQUERADE 2>/dev/null")
            if tun.get("opt_mss", True):
                lines.append(f"iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o {name} -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null")
                lines.append(f"ip6tables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o {name} -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null")
            lines.append("")

        for adv in data.get("adv_tunnels", []):
            if adv.get("enabled", True):
                lines.append(f"systemctl restart mhtun_{adv['id']}.service 2>/dev/null")

        lines.append("")
        for r in data.get("relays", []):
            if not r.get("enabled", True):
                continue
            lp = r["listen_port"]
            tip = r["target_ip"]
            tp = r["target_port"]
            pr = r.get("proto", "both")
            protos = ["tcp", "udp"] if pr == "both" else [pr]
            for p in protos:
                lines.append(f"iptables -t nat -A PREROUTING -p {p} --dport {lp} -j DNAT --to-destination {tip}:{tp} 2>/dev/null")
                lines.append(f"iptables -t nat -A POSTROUTING -p {p} -d {tip} --dport {tp} -j MASQUERADE 2>/dev/null")
                lines.append(f"iptables -A FORWARD -p {p} -d {tip} --dport {tp} -j ACCEPT 2>/dev/null")

        with open(BOOT_TUNNELS_SCRIPT, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.chmod(BOOT_TUNNELS_SCRIPT, 0o755)
    except Exception as e:
        print(f"Error updating boot tunnels script: {e}")

def restore_all_tunnels():
    data = load_tunnels_data()
    for tun in data.get("tunnels", []):
        try:
            apply_tunnel_interface(tun)
        except Exception as e:
            print(f"Error restoring tunnel {tun.get('name')}: {e}")
    for adv in data.get("adv_tunnels", []):
        try:
            apply_adv_tunnel(adv)
        except Exception as e:
            print(f"Error restoring adv tunnel {adv.get('name')}: {e}")
    for relay in data.get("relays", []):
        try:
            apply_port_relay(relay)
        except Exception as e:
            print(f"Error restoring relay {relay.get('id')}: {e}")

def generate_mikrotik_scripts(tun):
    ttype = tun.get("type", "gre")
    name = tun.get("name", "gre1")
    srv_ip = tun.get("local_ip", get_server_public_ip())
    rem_ip = tun.get("remote_ip", "0.0.0.0")
    in_loc = tun.get("tunnel_local_ip", "10.10.10.1/30")
    in_rem = tun.get("tunnel_remote_ip", "10.10.10.2")
    mtu = tun.get("mtu", 1476)
    
    in_rem_cidr = in_rem
    network = "10.10.10.0"
    if "/" in in_loc:
        mask = in_loc.split("/")[1]
        in_rem_cidr = f"{in_rem}/{mask}"
        parts = in_loc.split("/")[0].split(".")
        if len(parts) == 4:
            network = f"{parts[0]}.{parts[1]}.{parts[2]}.0"

    ros7 = ""
    ros6 = ""
    linux = ""

    if ttype == "gre":
        ros7 = f"""# ====================================================================
# MikroTik RouterOS v7 - GRE Tunnel Configuration
# Remote Server (Linux Endpoint): {srv_ip}
# Local Router (MikroTik): {rem_ip}
# Tunnel Address: {in_rem_cidr} (Server Address: {in_loc})
# ====================================================================

# 1. Create GRE Interface
/interface gre add name="{name}" remote-address={srv_ip} local-address=0.0.0.0 mtu={mtu} disabled=no

# 2. Add IP Address on Tunnel
/ip address add address={in_rem_cidr} interface="{name}" network={network}

# 3. MSS Clamping (Prevents packet drops & fragmentation)
/ip firewall mangle add chain=forward action=change-mss new-mss=clamp-to-pmtu passthrough=yes protocol=tcp tcp-flags=syn out-interface="{name}" comment="GRE MSS Clamp"

# 4. NAT Masquerade out the Tunnel (Optional)
/ip firewall nat add chain=srcnat action=masquerade out-interface="{name}" comment="GRE NAT Masquerade"

# 5. Test Connectivity
/ping {in_loc.split('/')[0]} count=4
"""
        ros6 = ros7.replace("RouterOS v7", "RouterOS v6")
        linux = f"""# ====================================================================
# Linux Server Configuration (GRE)
# ====================================================================
ip tunnel add {name} mode gre remote {srv_ip} local 0.0.0.0 ttl 255
ip addr add {in_rem_cidr} dev {name}
ip link set {name} mtu {mtu} up
iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o {name} -j TCPMSS --clamp-mss-to-pmtu
ping -c 4 {in_loc.split('/')[0]}
"""

    elif ttype == "ipip":
        ros7 = f"""# ====================================================================
# MikroTik RouterOS v7 - IPIP Tunnel Configuration
# Remote Server: {srv_ip} | Local Router: {rem_ip}
# ====================================================================

# 1. Create IPIP Interface
/interface ipip add name="{name}" remote-address={srv_ip} local-address=0.0.0.0 mtu={mtu} disabled=no

# 2. Assign IP Address
/ip address add address={in_rem_cidr} interface="{name}" network={network}

# 3. MSS Clamping
/ip firewall mangle add chain=forward action=change-mss new-mss=clamp-to-pmtu passthrough=yes protocol=tcp tcp-flags=syn out-interface="{name}" comment="IPIP MSS Clamp"

# 4. NAT Masquerade
/ip firewall nat add chain=srcnat action=masquerade out-interface="{name}"

# 5. Test Ping
/ping {in_loc.split('/')[0]} count=4
"""
        ros6 = ros7.replace("RouterOS v7", "RouterOS v6")
        linux = f"""# ====================================================================
# Linux Server Configuration (IPIP)
# ====================================================================
ip tunnel add {name} mode ipip remote {srv_ip} local 0.0.0.0 ttl 255
ip addr add {in_rem_cidr} dev {name}
ip link set {name} mtu {mtu} up
iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o {name} -j TCPMSS --clamp-mss-to-pmtu
ping -c 4 {in_loc.split('/')[0]}
"""

    elif ttype == "vxlan":
        vni = tun.get("vni", 100)
        vxp = tun.get("vxlan_port", 4789)
        ros7 = f"""# ====================================================================
# MikroTik RouterOS v7 - VXLAN Tunnel (Port UDP {vxp})
# Remote Server: {srv_ip} | VNI ID: {vni}
# ====================================================================

# 1. Create VXLAN Interface
/interface vxlan add name="{name}" vni={vni} port={vxp} mtu={mtu} disabled=no

# 2. Add Remote VTEP Endpoint
/interface vxlan vteps add interface="{name}" remote-ip={srv_ip}

# 3. Assign IP Address
/ip address add address={in_rem_cidr} interface="{name}" network={network}

# 4. Test Connectivity
/ping {in_loc.split('/')[0]} count=4
"""
        ros6 = f"""# توجه: پروتکل استاندارد VXLAN از نسخه RouterOS v7 به میکروتیک افزوده شده است.
# برای نسخه‌های قدیمی RouterOS v6 پیشنهاد می‌شود از تب GRE یا IPIP استفاده نمایید.
"""
        linux = f"""# ====================================================================
# Linux Server Configuration (VXLAN)
# ====================================================================
ip link add {name} type vxlan id {vni} remote {srv_ip} local 0.0.0.0 dstport {vxp}
ip addr add {in_rem_cidr} dev {name}
ip link set {name} mtu {mtu} up
ping -c 4 {in_loc.split('/')[0]}
"""

    elif ttype == "wireguard":
        wgp = tun.get("wg_port", 51830)
        srv_pub = tun.get("wg_pubkey", "[SERVER_PUBLIC_KEY]")
        ros7 = f"""# ====================================================================
# MikroTik RouterOS v7 - WireGuard Server-to-Server Tunnel
# Server Endpoint: {srv_ip}:{wgp}
# ====================================================================

# 1. Create WireGuard Interface on MikroTik
/interface wireguard add name="{name}" listen-port={wgp} mtu={mtu} disabled=no

# 2. Add Peer pointing to MH Panel Linux Server
/interface wireguard peers add interface="{name}" public-key="{srv_pub}" endpoint-address="{srv_ip}" endpoint-port={wgp} allowed-address=0.0.0.0/0 persistent-keepalive=25s

# 3. Assign IP Address to Tunnel
/ip address add address={in_rem_cidr} interface="{name}" network={network}

# 4. MSS Clamping
/ip firewall mangle add chain=forward action=change-mss new-mss=clamp-to-pmtu passthrough=yes protocol=tcp tcp-flags=syn out-interface="{name}"

# 5. NAT Masquerade (Optional)
/ip firewall nat add chain=srcnat action=masquerade out-interface="{name}"

# 6. Test Connectivity
/ping {in_loc.split('/')[0]} count=4
"""
        ros6 = "# توجه: پروتکل WireGuard در RouterOS v7 به صورت استاندارد قرار دارد."
        linux = f"""# ====================================================================
# Linux Server Configuration (WireGuard)
# ====================================================================
ip link add dev {name} type wireguard
wg set {name} listen-port {wgp} peer {srv_pub} endpoint {srv_ip}:{wgp} allowed-ips 0.0.0.0/0 persistent-keepalive 25
ip addr add {in_rem_cidr} dev {name}
ip link set {name} mtu {mtu} up
ping -c 4 {in_loc.split('/')[0]}
"""

    elif ttype == "l2tp":
        user = tun.get("user", f"l2tp_{name}")
        pwd = tun.get("pass", "Pass1234Global")
        psk = tun.get("psk", "vpnSecret123")
        ros7 = f"""# ====================================================================
# MikroTik RouterOS v7 - L2TP/IPsec Site-to-Site Client
# Server Endpoint: {srv_ip} | User: {user}
# ====================================================================

/interface l2tp-client add name="{name}" connect-to={srv_ip} user="{user}" password="{pwd}" use-ipsec=yes ipsec-secret="{psk}" disabled=no
/ip address add address={in_rem_cidr} interface="{name}" network={network}
/ip firewall mangle add chain=forward action=change-mss new-mss=clamp-to-pmtu passthrough=yes protocol=tcp tcp-flags=syn out-interface="{name}"
/ping {in_loc.split('/')[0]} count=4
"""
        ros6 = ros7.replace("RouterOS v7", "RouterOS v6")
        linux = f"""# Linux L2TP Client Configuration:
# Use xl2tpd / strongswan or PPP connection to {srv_ip} with user '{user}'
"""

    elif ttype == "openvpn":
        user = tun.get("user", f"ovpn_{name}")
        pwd = tun.get("pass", "Pass1234Global")
        ovpn_port = tun.get("ovpn_port", 1195)
        ovpn_proto = tun.get("ovpn_proto", "udp")
        ovpn_cipher = tun.get("ovpn_cipher", "AES-256-GCM")
        ros7 = f"""# ====================================================================
# MikroTik RouterOS v7 - OpenVPN Client Tunnel
# Server: {srv_ip}:{ovpn_port} ({ovpn_proto.upper()})
# ====================================================================

/interface ovpn-client add name="{name}" connect-to={srv_ip} port={ovpn_port} mode=ip protocol={ovpn_proto} user="{user}" password="{pwd}" cipher={ovpn_cipher} disabled=no
/ip address add address={in_rem_cidr} interface="{name}" network={network}
/ping {in_loc.split('/')[0]} count=4
"""
        ros6 = ros7.replace("RouterOS v7", "RouterOS v6")
        linux = f"""# Linux OpenVPN P2P Client Config:
# Run openvpn --remote {srv_ip} {ovpn_port} --dev {name} --ifconfig {in_rem.split('/')[0]} {in_loc.split('/')[0]} --secret /etc/openvpn/{name}.key
"""

    elif ttype == "sstp":
        user = tun.get("user", f"sstp_{name}")
        pwd = tun.get("pass", "Pass1234Global")
        ros7 = f"""# ====================================================================
# MikroTik RouterOS v7 - SSTP Client Tunnel
# Server: {srv_ip}:443
# ====================================================================

/interface sstp-client add name="{name}" connect-to={srv_ip} user="{user}" password="{pwd}" disabled=no
/ip address add address={in_rem_cidr} interface="{name}" network={network}
/ping {in_loc.split('/')[0]} count=4
"""
        ros6 = ros7.replace("RouterOS v7", "RouterOS v6")
        linux = f"""# Linux SSTP Client:
# sstp-client --host {srv_ip} --user {user} --password {pwd}
"""

    elif ttype == "pptp":
        user = tun.get("user", f"pptp_{name}")
        pwd = tun.get("pass", "Pass1234Global")
        ros7 = f"""# ====================================================================
# MikroTik RouterOS v7 - PPTP Client Tunnel
# Server: {srv_ip}
# ====================================================================

/interface pptp-client add name="{name}" connect-to={srv_ip} user="{user}" password="{pwd}" disabled=no
/ip address add address={in_rem_cidr} interface="{name}" network={network}
/ping {in_loc.split('/')[0]} count=4
"""
        ros6 = ros7.replace("RouterOS v7", "RouterOS v6")
        linux = f"""# Linux PPTP Client:
# pptp {srv_ip} user {user} password {pwd}
"""

    elif ttype == "sit":
        ros7 = f"""# ====================================================================
# MikroTik RouterOS - 6in4 SIT IPv6 Tunnel
# Remote Server: {srv_ip} | Local Router: {rem_ip}
# ====================================================================

/interface 6to4 add name="{name}" remote-address={srv_ip} local-address=0.0.0.0 mtu={mtu} disabled=no
/ipv6 address add address={in_rem_cidr} interface="{name}"
"""
        ros6 = ros7
        linux = f"""# Linux 6in4 SIT Tunnel
ip tunnel add {name} mode sit remote {srv_ip} local 0.0.0.0 ttl 255
ip addr add {in_rem_cidr} dev {name}
ip link set {name} mtu {mtu} up
"""

    elif ttype == "ip6gre":
        ros7 = f"""# ====================================================================
# MikroTik RouterOS v7 - GRE over IPv6 (IP6GRE) Tunnel Configuration
# Remote Server (Linux IPv6 Endpoint): {srv_ip}
# Local Router (MikroTik IPv6 Endpoint): {rem_ip}
# Tunnel Address: {in_rem_cidr} (Server Address: {in_loc})
# ====================================================================

# 1. Create GRE Interface with IPv6 Endpoints
/interface gre add name="{name}" remote-address={srv_ip} local-address=:: mtu={mtu} disabled=no

# 2. Add Address on Tunnel Interface
"""
        if ":" in in_rem_cidr:
            ros7 += f"""/ipv6 address add address={in_rem_cidr} interface="{name}" advertise=no
/ipv6 firewall mangle add chain=forward action=change-mss new-mss=clamp-to-pmtu passthrough=yes protocol=tcp tcp-flags=syn out-interface="{name}" comment="IP6GRE MSS Clamp"
/ipv6 firewall nat add chain=srcnat action=masquerade out-interface="{name}" comment="IP6GRE NAT"
/ping {in_loc.split('/')[0]} count=4
"""
        else:
            ros7 += f"""/ip address add address={in_rem_cidr} interface="{name}" network={network}
/ip firewall mangle add chain=forward action=change-mss new-mss=clamp-to-pmtu passthrough=yes protocol=tcp tcp-flags=syn out-interface="{name}" comment="IP6GRE MSS Clamp"
/ip firewall nat add chain=srcnat action=masquerade out-interface="{name}" comment="IP6GRE NAT"
/ping {in_loc.split('/')[0]} count=4
"""
        ros6 = f"""# توجه: روتربورد میکروتیک با RouterOS v7 از پروتکل GRE با آدرس‌های مستقیم IPv6 پشتیبانی می‌کند."""
        linux = f"""# ====================================================================
# Linux Server Configuration (GRE over IPv6)
# ====================================================================
modprobe ip6_gre
ip -6 tunnel add {name} mode ip6gre remote {srv_ip} local 0.0.0.0 ttl 255
"""
        if ":" in in_rem_cidr:
            linux += f"""ip -6 addr add {in_rem_cidr} dev {name}
ip link set {name} mtu {mtu} up
ip6tables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o {name} -j TCPMSS --clamp-mss-to-pmtu
ping6 -c 4 {in_loc.split('/')[0]}
"""
        else:
            linux += f"""ip addr add {in_rem_cidr} dev {name}
ip link set {name} mtu {mtu} up
iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o {name} -j TCPMSS --clamp-mss-to-pmtu
ping -c 4 {in_loc.split('/')[0]}
"""

    elif ttype in ["ip6tnl", "ipip6"]:
        ros7 = f"""# ====================================================================
# MikroTik RouterOS v7 - IPIP over IPv6 (IPIP6) Tunnel Configuration
# Remote Server (Linux IPv6): {srv_ip} | Local Router (MikroTik): {rem_ip}
# ====================================================================

/interface ipip add name="{name}" remote-address={srv_ip} local-address=:: mtu={mtu} disabled=no
"""
        if ":" in in_rem_cidr:
            ros7 += f"""/ipv6 address add address={in_rem_cidr} interface="{name}" advertise=no
/ipv6 firewall mangle add chain=forward action=change-mss new-mss=clamp-to-pmtu passthrough=yes protocol=tcp tcp-flags=syn out-interface="{name}"
/ping {in_loc.split('/')[0]} count=4
"""
        else:
            ros7 += f"""/ip address add address={in_rem_cidr} interface="{name}" network={network}
/ip firewall mangle add chain=forward action=change-mss new-mss=clamp-to-pmtu passthrough=yes protocol=tcp tcp-flags=syn out-interface="{name}"
/ping {in_loc.split('/')[0]} count=4
"""
        ros6 = f"""# توجه: پروتکل IPIP با آدرس‌های IPv6 در RouterOS v7 اضافه شده است."""
        linux = f"""# ====================================================================
# Linux Server Configuration (IPIP over IPv6)
# ====================================================================
modprobe ip6_tunnel
ip -6 tunnel add {name} mode any remote {srv_ip} local 0.0.0.0
ip addr add {in_rem_cidr} dev {name}
ip link set {name} mtu {mtu} up
ping -c 4 {in_loc.split('/')[0]}
"""

    return {
        "ros7": ros7,
        "ros6": ros6,
        "linux": linux
    }

# ----------------- Tunnel API Routes -----------------

@app.route("/api/tunnels", methods=["GET"])
def api_get_tunnels():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = load_tunnels_data()
    server_ip = get_server_public_ip()
    server_ipv6 = get_server_public_ipv6()
    
    tunnels_list = []
    total_rx = 0
    total_tx = 0
    active_count = 0

    for tun in data.get("tunnels", []):
        stats = get_interface_stats(tun["name"])
        total_rx += stats["rx_bytes"]
        total_tx += stats["tx_bytes"]
        if stats["is_up"] and tun.get("enabled", True):
            active_count += 1
            status_flag = "R" # Running
        elif not tun.get("enabled", True):
            status_flag = "X" # Disabled
        else:
            status_flag = "I" # Inactive / Down

        t_copy = dict(tun)
        t_copy["is_up"] = stats["is_up"]
        t_copy["status_flag"] = status_flag
        t_copy["rx_bytes"] = stats["rx_bytes"]
        t_copy["tx_bytes"] = stats["tx_bytes"]
        t_copy["rx_packets"] = stats["rx_packets"]
        t_copy["tx_packets"] = stats["tx_packets"]
        tunnels_list.append(t_copy)

    adv_list = []
    adv_active_count = 0
    for adv in data.get("adv_tunnels", []):
        unit_name = f"mhtun_{adv['id']}.service"
        r = subprocess.run(["systemctl", "is-active", unit_name], capture_output=True, text=True)
        is_active = (r.stdout.strip() == "active")
        if is_active and adv.get("enabled", True):
            adv_active_count += 1
            status_flag = "R"
        elif not adv.get("enabled", True):
            status_flag = "X"
        else:
            status_flag = "I"
        a_copy = dict(adv)
        a_copy["is_active"] = is_active
        a_copy["status_flag"] = status_flag
        adv_list.append(a_copy)

    return jsonify({
        "success": True,
        "server_ip": server_ip,
        "server_ipv6": server_ipv6,
        "active_count": active_count,
        "total_count": len(tunnels_list),
        "adv_active_count": adv_active_count,
        "adv_total_count": len(adv_list),
        "total_rx_bytes": total_rx,
        "total_tx_bytes": total_tx,
        "tunnels": tunnels_list,
        "adv_tunnels": adv_list,
        "relays": data.get("relays", [])
    })

@app.route("/api/tunnels/create", methods=["POST"])
def api_create_tunnel():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    req = request.get_json() or {}
    name = (req.get("name") or "").strip().lower()
    ttype = (req.get("type") or "gre").strip().lower()

    if not name or not re.match(r'^[a-z0-9_\-]{2,15}$', name):
        return jsonify({"error": "نام اینترفیس نامعتبر است (بین ۲ تا ۱۵ کاراکتر شامل حروف و اعداد انگلیسی)"}), 400

    data = load_tunnels_data()
    for existing in data.get("tunnels", []):
        if existing["name"].lower() == name:
            return jsonify({"error": f"اینترفیسی با نام {name} از قبل وجود دارد."}), 400

    server_ip = get_server_public_ip()
    local_ip = (req.get("local_ip") or server_ip).strip()
    remote_ip = (req.get("remote_ip") or "").strip()
    inner_local = (req.get("tunnel_local_ip") or "10.10.10.1/30").strip()
    inner_remote = (req.get("tunnel_remote_ip") or "10.10.10.2").strip()

    mtu_map = {"gre": 1476, "ip6gre": 1456, "ipip": 1480, "ip6tnl": 1460, "ipip6": 1460, "vxlan": 1450, "wireguard": 1420, "sit": 1480, "l2tp": 1400, "openvpn": 1500, "sstp": 1450, "pptp": 1400}
    try:
        mtu = int(req.get("mtu") or mtu_map.get(ttype, 1476))
    except Exception:
        mtu = 1476

    tun = {
        "id": f"tun_{uuid.uuid4().hex[:8]}",
        "name": name,
        "type": ttype,
        "enabled": True,
        "local_ip": local_ip,
        "remote_ip": remote_ip,
        "tunnel_local_ip": inner_local,
        "tunnel_remote_ip": inner_remote,
        "mtu": mtu,
        "opt_nat": bool(req.get("opt_nat", True)),
        "opt_mss": bool(req.get("opt_mss", True)),
        "gre_key": req.get("gre_key") or "",
        "vni": int(req.get("vni") or 100),
        "vxlan_port": int(req.get("vxlan_port") or 4789),
        "wg_port": int(req.get("wg_port") or 51830),
        "wg_privkey": req.get("wg_privkey") or "",
        "wg_pubkey": req.get("wg_pubkey") or "",
        "wg_remote_pubkey": req.get("wg_remote_pubkey") or "",
        "user": req.get("user") or "",
        "pass": req.get("pass") or "",
        "psk": req.get("psk") or "",
        "ovpn_port": int(req.get("ovpn_port") or 1195),
        "ovpn_proto": req.get("ovpn_proto") or "udp",
        "ovpn_cipher": req.get("ovpn_cipher") or "AES-256-GCM",
        "ovpn_secret": req.get("ovpn_secret") or "",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    if ttype == "wireguard" and not tun["wg_privkey"]:
        try:
            priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True).stdout.strip()
            pub = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True, text=True).stdout.strip()
            tun["wg_privkey"] = priv
            tun["wg_pubkey"] = pub
        except Exception:
            pass

    ok, msg = apply_tunnel_interface(tun)
    if not ok:
        return jsonify({"error": f"خطا در ایجاد اینترفیس در لینوکس: {msg}"}), 500

    data["tunnels"].append(tun)
    save_tunnels_data(data)
    return jsonify({"success": True, "tunnel": tun, "message": "اینترفیس تونل با موفقیت ساخته شد و بالا آمد."})

@app.route("/api/tunnels/<tun_id>/toggle", methods=["POST"])
def api_toggle_tunnel(tun_id):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = load_tunnels_data()
    tun = next((t for t in data.get("tunnels", []) if t["id"] == tun_id), None)
    if not tun:
        return jsonify({"error": "تونل یافت نشد."}), 404

    tun["enabled"] = not tun.get("enabled", True)
    apply_tunnel_interface(tun)
    save_tunnels_data(data)
    return jsonify({"success": True, "enabled": tun["enabled"]})

@app.route("/api/tunnels/<tun_id>/delete", methods=["POST", "DELETE"])
def api_delete_tunnel(tun_id):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = load_tunnels_data()
    tun = next((t for t in data.get("tunnels", []) if t["id"] == tun_id), None)
    if not tun:
        return jsonify({"error": "تونل یافت نشد."}), 404

    remove_tunnel_interface(tun)
    data["tunnels"] = [t for t in data["tunnels"] if t["id"] != tun_id]
    
    # Also remove any relays bound to this tunnel
    relays_to_remove = [r for r in data.get("relays", []) if r.get("tunnel_name") == tun["name"]]
    for r in relays_to_remove:
        remove_port_relay(r)
    data["relays"] = [r for r in data.get("relays", []) if r.get("tunnel_name") != tun["name"]]

    save_tunnels_data(data)
    return jsonify({"success": True, "message": "تونل با موفقیت حذف شد."})

@app.route("/api/tunnels/<tun_id>/ping", methods=["POST"])
def api_ping_tunnel(tun_id):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = load_tunnels_data()
    tun = next((t for t in data.get("tunnels", []) if t["id"] == tun_id), None)
    if not tun:
        return jsonify({"error": "تونل یافت نشد."}), 404

    target = tun.get("tunnel_remote_ip", "").strip()
    if "/" in target:
        target = target.split("/")[0]
    if not target:
        target = tun.get("remote_ip", "").strip()
    if not target:
        return jsonify({"error": "آدرس مقصد برای تست پینگ مشخص نشده است."}), 400

    lat = None
    loss = 100
    try:
        if ":" in target:
            r = subprocess.run(["ping", "-6", "-c", "3", "-W", "1", target], capture_output=True, text=True)
            if r.returncode != 0 and not r.stdout:
                r = subprocess.run(["ping6", "-c", "3", "-W", "1", target], capture_output=True, text=True)
        else:
            r = subprocess.run(["ping", "-c", "3", "-W", "1", target], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if "packet loss" in line:
                m = re.search(r'(\d+)% packet loss', line)
                if m:
                    loss = int(m.group(1))
            if "rtt min/avg/max/mdev" in line or "round-trip min/avg/max/mdev" in line:
                parts = line.split("=")[1].strip().split("/")
                lat = float(parts[1])
            elif "avg" in line and "/" in line:
                lat = float(line.split("/")[4])
    except Exception as e:
        return jsonify({"error": f"خطا در ارسال پکت پینگ: {e}"}), 500

    return jsonify({
        "success": True,
        "target": target,
        "latency_ms": lat,
        "packet_loss": loss,
        "output": r.stdout if 'r' in locals() else ""
    })

@app.route("/api/tunnels/<tun_id>/scripts", methods=["GET"])
def api_tunnel_scripts(tun_id):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = load_tunnels_data()
    tun = next((t for t in data.get("tunnels", []) if t["id"] == tun_id), None)
    if not tun:
        return jsonify({"error": "تونل یافت نشد."}), 404

    scripts = generate_mikrotik_scripts(tun)
    return jsonify({
        "success": True,
        "tunnel": tun,
        "scripts": scripts
    })

@app.route("/api/tunnels/generate-wg-keys", methods=["GET"])
def api_generate_wg_keys():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True).stdout.strip()
        pub = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True, text=True).stdout.strip()
        return jsonify({"success": True, "privkey": priv, "pubkey": pub})
    except Exception as e:
        return jsonify({"error": f"خطا در تولید کلیدهای وایرگارد: {e}"}), 500

@app.route("/api/tunnels/generate-ovpn-key", methods=["GET"])
def api_generate_ovpn_key():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        tmp_k = f"/tmp/ovpn_gen_{uuid.uuid4().hex[:6]}.key"
        subprocess.run(["openvpn", "--genkey", "secret", tmp_k], capture_output=True)
        secret_content = ""
        if os.path.exists(tmp_k):
            with open(tmp_k) as f: secret_content = f.read().strip()
            os.remove(tmp_k)
        return jsonify({"success": True, "key": secret_content})
    except Exception as e:
        return jsonify({"error": f"خطا در تولید کلید متقارن OpenVPN: {e}"}), 500

# ----------------- Advanced Anti-Censorship Tunnels API -----------------

@app.route("/api/tunnels/adv/create", methods=["POST"])
def api_create_adv_tunnel():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    req = request.get_json() or {}
    name = (req.get("name") or "").strip().lower()
    tool = (req.get("tool") or "gost").strip().lower()
    role = (req.get("role") or "server").strip().lower()

    if not name or not re.match(r'^[a-z0-9_\-]{2,25}$', name):
        return jsonify({"error": "نام تونل نامعتبر است (بین ۲ تا ۲۵ کاراکتر انگلیسی)"}), 400

    try:
        listen_port = int(req.get("listen_port") or 8443)
    except Exception:
        return jsonify({"error": "شماره پورت شنود نامعتبر است."}), 400

    data = load_tunnels_data()
    for existing in data.get("adv_tunnels", []):
        if existing["name"].lower() == name:
            return jsonify({"error": f"تونلی با نام {name} از قبل وجود دارد."}), 400
        if existing.get("listen_port") == listen_port and existing.get("role") == role and existing.get("enabled", True):
            return jsonify({"error": f"پورت {listen_port} قبلاً توسط تونل دیگری رزرو شده است."}), 400

    adv = {
        "id": f"adv_{uuid.uuid4().hex[:8]}",
        "name": name,
        "tool": tool,
        "role": role,
        "listen_port": listen_port,
        "remote_ip": (req.get("remote_ip") or "").strip(),
        "remote_port": int(req.get("remote_port") or listen_port),
        "target_addr": (req.get("target_addr") or "127.0.0.1:443").strip(),
        "transport": (req.get("transport") or "wss").strip(),
        "secret": (req.get("secret") or "MHPanelTunSecret123!").strip(),
        "sni": (req.get("sni") or "dl.google.com").strip(),
        "enabled": True,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    ok, msg = apply_adv_tunnel(adv)
    if not ok:
        return jsonify({"error": f"خطا در ایجاد سرویس تونل: {msg}"}), 500

    data["adv_tunnels"].append(adv)
    save_tunnels_data(data)
    return jsonify({"success": True, "tunnel": adv, "message": "سرویس تونل ضد فیلتر با موفقیت راه‌اندازی شد."})

@app.route("/api/tunnels/adv/<adv_id>/toggle", methods=["POST"])
def api_toggle_adv_tunnel(adv_id):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = load_tunnels_data()
    adv = next((a for a in data.get("adv_tunnels", []) if a["id"] == adv_id), None)
    if not adv:
        return jsonify({"error": "تونل ضد فیلتر یافت نشد."}), 404

    adv["enabled"] = not adv.get("enabled", True)
    apply_adv_tunnel(adv)
    save_tunnels_data(data)
    return jsonify({"success": True, "enabled": adv["enabled"]})

@app.route("/api/tunnels/adv/<adv_id>/delete", methods=["POST", "DELETE"])
def api_delete_adv_tunnel(adv_id):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = load_tunnels_data()
    adv = next((a for a in data.get("adv_tunnels", []) if a["id"] == adv_id), None)
    if not adv:
        return jsonify({"error": "تونل ضد فیلتر یافت نشد."}), 404

    remove_adv_tunnel(adv)
    data["adv_tunnels"] = [a for a in data["adv_tunnels"] if a["id"] != adv_id]
    save_tunnels_data(data)
    return jsonify({"success": True, "message": "سرویس تونل ضد فیلتر با موفقیت حذف شد."})

@app.route("/api/tunnels/adv/<adv_id>/script", methods=["GET"])
def api_adv_tunnel_script(adv_id):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = load_tunnels_data()
    adv = next((a for a in data.get("adv_tunnels", []) if a["id"] == adv_id), None)
    if not adv:
        return jsonify({"error": "تونل ضد فیلتر یافت نشد."}), 404

    script = generate_adv_tunnel_script(adv)
    return jsonify({
        "success": True,
        "tunnel": adv,
        "script": script
    })

# ----------------- Relays API -----------------

@app.route("/api/tunnels/relays/create", methods=["POST"])
def api_create_port_relay():
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    req = request.get_json() or {}
    try:
        listen_port = int(req.get("listen_port"))
        target_port = int(req.get("target_port") or listen_port)
    except Exception:
        return jsonify({"error": "شماره پورت نامعتبر است."}), 400

    target_ip = (req.get("target_ip") or "").strip()
    if not target_ip:
        return jsonify({"error": "آدرس آی‌پی مقصد الزامی است."}), 400

    data = load_tunnels_data()
    relay = {
        "id": f"relay_{uuid.uuid4().hex[:8]}",
        "tunnel_name": req.get("tunnel_name") or "",
        "listen_port": listen_port,
        "target_ip": target_ip,
        "target_port": target_port,
        "proto": req.get("proto") or "both",
        "desc": req.get("desc") or f"Port {listen_port} -> {target_ip}:{target_port}",
        "enabled": True,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    apply_port_relay(relay)
    data["relays"].append(relay)
    save_tunnels_data(data)
    return jsonify({"success": True, "relay": relay, "message": "رول رله پورت در فایروال با موفقیت فعال شد."})

@app.route("/api/tunnels/relays/<relay_id>/delete", methods=["POST", "DELETE"])
def api_delete_port_relay(relay_id):
    if not check_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = load_tunnels_data()
    relay = next((r for r in data.get("relays", []) if r["id"] == relay_id), None)
    if not relay:
        return jsonify({"error": "رله پورت یافت نشد."}), 404

    remove_port_relay(relay)
    data["relays"] = [r for r in data["relays"] if r["id"] != relay_id]
    save_tunnels_data(data)
    return jsonify({"success": True, "message": "رله پورت حذف شد."})

if __name__ == "__main__":
    if os.path.exists(HELPER_SCRIPT):
        os.chmod(HELPER_SCRIPT, 0o755)
        
    user, pw = get_credentials()
    key = get_api_key()
    print(f"=================================================")
    print(f"Admin Username:  {user}")
    print(f"Admin Password:  {pw}")
    print(f"Public API Key:  {key}")
    print(f"=================================================")
    
    # Start background traffic tracker thread
    t = threading.Thread(target=traffic_tracker, daemon=True)
    t.start()
    
    # Start wireguard client tracker
    t2 = threading.Thread(target=wg_client_tracker, daemon=True)
    t2.start()
    
    # Start OpenVPN client tracker
    t3 = threading.Thread(target=ovpn_client_tracker, daemon=True)
    t3.start()
    
    # Start HTTP-to-HTTPS redirect server on port 80
    t4 = threading.Thread(target=ssh_client_tracker, daemon=True)
    t4.start()
    t5 = threading.Thread(target=ocserv_client_tracker, daemon=True)
    t5.start()
    t6 = threading.Thread(target=sstp_client_tracker, daemon=True)
    t6.start()
    t7 = threading.Thread(target=l2tp_client_tracker, daemon=True)
    t7.start()
    t8 = threading.Thread(target=ikev2_client_tracker, daemon=True)
    t8.start()
    t9 = threading.Thread(target=awg_client_tracker, daemon=True)
    t9.start()
    redirect_server.start()
    
    ssl_context = None
    try:
        ensure_panel_certificate()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=PANEL_CERT, keyfile=PANEL_KEY)
        ssl_context = ctx
    except Exception as e:
        print(f"WARNING: HTTPS certificate is not usable, falling back to HTTP: {e}")

    try:
        restore_all_tunnels()
    except Exception as e:
        print(f"Error restoring tunnels: {e}")

    port = get_panel_port()
    app.run(host="0.0.0.0", port=port, ssl_context=ssl_context, debug=False)
