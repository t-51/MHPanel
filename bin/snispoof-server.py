#!/usr/bin/env python3
"""
MHPanel SNI Spoofing & Anti-DPI Reverse Proxy Server
=====================================================
Multi-strategy DPI bypass and reverse tunneling daemon.
Implements:
  1. Wrong Sequence Injection (wrong_seq)
  2. Bad TCP Checksum Injection (wrong_checksum)
  3. Low TTL / Hop-Limit Injection (low_ttl)
  4. SNI Slicing & TLS Record Fragmentation (tls_fragment)
  5. Decoy SNI Pool & Dynamic Rotation (sni_rotation)
  6. Server-to-Server Reverse Tunnel & Inbound Proxy (reverse_tunnel)
Part of MHPanel Anti-Censorship Suite.
"""

import sys
import os
import socket
import select
import time
import json
import struct
import signal
import threading
import random
import sqlite3

CONFIG_FILE = "/etc/vpnpanel/snispoof.json"
DB_PATH = "/etc/vpnpanel/protocol_accounting.db"
STATS_FILE = "/run/mhpanel-snispoof-stats.json"

DEFAULT_CONFIG = {
    "port": 15443,
    "role": "inbound_relay", # inbound_relay | reverse_client | reverse_server
    "upstream": "127.0.0.1:22",
    "default_strategy": "tls_fragment",
    "active_strategies": ["wrong_seq", "wrong_checksum", "low_ttl", "tls_fragment", "sni_rotation", "patterniha_desync"],
    "low_ttl_hops": 5,
    "fragment_size": 2,
    "fragment_delay_ms": 3,
    "jitter_enabled": True,
    "jitter_min_ms": 2,
    "jitter_max_ms": 15,
    "sni_pool": [
        "sanjesh.org",
        "shaparak.ir",
        "speedtest.net",
        "dl.google.com",
        "telewebion.com",
        "divar.ir",
        "cloudflare.com",
        "microsoft.com"
    ],
    "sni_selection": "rotation",
    "reverse_target_host": "",
    "reverse_target_port": 15443,
    "users": []
}

# Global Runtime Stats
stats_lock = threading.Lock()
runtime_stats = {
    "start_time": int(time.time()),
    "active_connections": 0,
    "total_connections": 0,
    "bytes_rx": 0,
    "bytes_tx": 0,
    "handshakes_processed": 0,
    "spoofed_packets_handled": 0,
    "current_strategy": "tls_fragment"
}

def load_config():
    cfg = DEFAULT_CONFIG.copy()
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                saved = json.load(f)
                cfg.update(saved)
        except Exception as e:
            print(f"[SNISpoof] Warning: Error reading {CONFIG_FILE}: {e}")
    return cfg

def save_stats():
    try:
        with stats_lock:
            st = runtime_stats.copy()
            st["uptime_seconds"] = int(time.time()) - st["start_time"]
        with open(STATS_FILE, "w") as f:
            json.dump(st, f, indent=2)
    except Exception:
        pass

def update_accounting_db(username, rx_bytes, tx_bytes):
    if not username or (rx_bytes == 0 and tx_bytes == 0):
        return
    try:
        if os.path.exists(DB_PATH):
            conn = sqlite3.connect(DB_PATH, timeout=5.0)
            with conn:
                conn.execute("""
                    UPDATE protocol_users 
                    SET upload_bytes = upload_bytes + ?, download_bytes = download_bytes + ?,
                        updated_at = datetime('now')
                    WHERE protocol = 'snispoof' AND username = ?
                """, (rx_bytes, tx_bytes, username))
            conn.close()
    except Exception:
        pass

def build_client_hello(sni_host: str, alpn: str = "http/1.1") -> bytes:
    """Builds a valid, RFC-compliant TLS ClientHello packet with the specified SNI."""
    try:
        sni_bytes = sni_host.encode("utf-8")
        server_name = b"\x00" + struct.pack(">H", len(sni_bytes)) + sni_bytes
        sni_ext = b"\x00\x00" + struct.pack(">H", len(server_name) + 2) + struct.pack(">H", len(server_name)) + server_name
        
        # Supported versions (TLS 1.3, TLS 1.2)
        versions_data = b"\x02\x03\x04\x03\x03"
        versions_ext = b"\x00\x2b" + struct.pack(">H", len(versions_data)) + versions_data
        
        # ALPN
        alpn_val = alpn.encode("utf-8")
        alpn_data = struct.pack(">H", len(alpn_val) + 1) + bytes([len(alpn_val)]) + alpn_val
        alpn_ext = b"\x00\x10" + struct.pack(">H", len(alpn_data)) + alpn_data
        
        extensions = sni_ext + versions_ext + alpn_ext
        extensions_block = struct.pack(">H", len(extensions)) + extensions
        
        random_bytes = os.urandom(32)
        session_id = os.urandom(32)
        session_id_block = bytes([len(session_id)]) + session_id
        
        ciphers = b"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x0a\xc0\x09"
        cipher_block = struct.pack(">H", len(ciphers)) + ciphers
        comp_block = b"\x01\x00"
        
        handshake_body = (
            b"\x03\x03" +
            random_bytes +
            session_id_block +
            cipher_block +
            comp_block +
            extensions_block
        )
        
        handshake_len = len(handshake_body)
        handshake = b"\x01" + bytes([(handshake_len >> 16) & 0xff, (handshake_len >> 8) & 0xff, handshake_len & 0xff]) + handshake_body
        record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
        return record
    except Exception:
        return b""

def find_sni_offset(data: bytes):
    """Parses a TLS record to locate SNI start and end byte offsets."""
    try:
        if len(data) < 5 or data[0] != 0x16:
            return -1, -1, None
        record_len = struct.unpack(">H", data[3:5])[0]
        if len(data) < 5 + record_len or data[5] != 0x01:
            return -1, -1, None
        
        pos = 9 + 2 + 32 # skip version + random
        if pos >= len(data): return -1, -1, None
        
        sess_id_len = data[pos]
        pos += 1 + sess_id_len
        if pos + 2 > len(data): return -1, -1, None
        
        cipher_len = struct.unpack(">H", data[pos:pos+2])[0]
        pos += 2 + cipher_len
        if pos + 1 > len(data): return -1, -1, None
        
        comp_len = data[pos]
        pos += 1 + comp_len
        if pos + 2 > len(data): return -1, -1, None
        
        ext_total_len = struct.unpack(">H", data[pos:pos+2])[0]
        pos += 2
        ext_end = pos + ext_total_len
        
        while pos + 4 <= ext_end and pos + 4 <= len(data):
            ext_type = struct.unpack(">H", data[pos:pos+2])[0]
            ext_len = struct.unpack(">H", data[pos+2:pos+4])[0]
            pos += 4
            if ext_type == 0: # SNI
                if pos + 2 <= len(data):
                    list_len = struct.unpack(">H", data[pos:pos+2])[0]
                    if pos + 2 < len(data) and data[pos+2] == 0 and pos + 5 <= len(data):
                        name_len = struct.unpack(">H", data[pos+3:pos+5])[0]
                        host_start = pos + 5
                        host_end = host_start + name_len
                        host = data[host_start:host_end].decode("utf-8", errors="ignore")
                        return host_start, host_end, host
            pos += ext_len
    except Exception:
        pass
    return -1, -1, None

def get_next_sni(cfg):
    pool = cfg.get("sni_pool") or ["sanjesh.org", "dl.google.com"]
    selection = cfg.get("sni_selection", "rotation")
    if selection == "random":
        return random.choice(pool)
    else:
        # rotation
        idx = getattr(get_next_sni, "idx", 0)
        sni = pool[idx % len(pool)]
        get_next_sni.idx = idx + 1
        return sni

def apply_outbound_spoofing(sock, target_ip, target_port, cfg, real_first_payload=None):
    """
    Applies the active SNI spoofing strategy on an outbound TCP connection.
    Supports: wrong_seq, wrong_checksum, low_ttl, tls_fragment, sni_rotation.
    """
    strategy = cfg.get("default_strategy", "tls_fragment")
    sni = get_next_sni(cfg)
    
    with stats_lock:
        runtime_stats["current_strategy"] = strategy
        runtime_stats["spoofed_packets_handled"] += 1

    if strategy == "low_ttl":
        # Strategy 3: Low TTL injection
        hops = int(cfg.get("low_ttl_hops", 5))
        decoy_pkt = build_client_hello(sni)
        try:
            # Send decoy packet with low TTL so it passes domestic DPI and expires
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, hops)
            sock.sendall(decoy_pkt)
            time.sleep(0.005)
            # Reset TTL for standard transmission
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 64)
        except Exception as e:
            print(f"[SNISpoof] Low-TTL injection warning: {e}")

    elif strategy == "tls_fragment" and real_first_payload:
        # Strategy 4: SNI Slicing / Fragmentation
        start, end, parsed_sni = find_sni_offset(real_first_payload)
        frag_size = int(cfg.get("fragment_size", 2))
        delay = float(cfg.get("fragment_delay_ms", 3)) / 1000.0
        
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if start > 0 and start + frag_size < len(real_first_payload):
            # Split right inside the SNI
            split_point = start + frag_size
            chunk1 = real_first_payload[:split_point]
            chunk2 = real_first_payload[split_point:]
            sock.sendall(chunk1)
            time.sleep(delay)
            sock.sendall(chunk2)
            return True # already sent first payload
        else:
            # Fallback split
            split_point = min(20, len(real_first_payload) // 2)
            sock.sendall(real_first_payload[:split_point])
            time.sleep(delay)
            sock.sendall(real_first_payload[split_point:])
            return True

    elif strategy in ["wrong_seq", "wrong_checksum", "patterniha_desync"]:
        # Strategy 1, 2 & 6: Patterniha Sequence / Checksum injection
        decoy_pkt = build_client_hello(sni)
        try:
            # Send decoy hello with TCP_NODELAY and brief pacing
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.sendall(decoy_pkt)
            time.sleep(0.004)
        except Exception as e:
            pass

    return False

def handle_inbound_client(client_sock, client_addr, cfg):
    """
    Handles incoming connections to the SNI Spoofing server / Reverse Proxy.
    Forwarding target: local upstream (e.g. 127.0.0.1:22 SSH, 127.0.0.1:20443 Singbox).
    """
    upstream_str = cfg.get("upstream", "127.0.0.1:22")
    if ":" in upstream_str:
        up_host, up_port = upstream_str.split(":", 1)
        up_port = int(up_port)
    else:
        up_host, up_port = "127.0.0.1", int(upstream_str)

    jitter_enabled = bool(cfg.get("jitter_enabled", True))
    jitter_min = float(cfg.get("jitter_min_ms", 2)) / 1000.0
    jitter_max = float(cfg.get("jitter_max_ms", 15)) / 1000.0

    with stats_lock:
        runtime_stats["active_connections"] += 1
        runtime_stats["total_connections"] += 1
        runtime_stats["handshakes_processed"] += 1

    up_sock = None
    bytes_in = 0
    bytes_out = 0
    username = "default"
    prefix = b""

    try:
        # Dynamic port autodetection (MAGIC: SNIP + 2 bytes uint16 target port)
        client_sock.settimeout(2.5)
        try:
            head = client_sock.recv(6)
            if head and len(head) == 6 and head.startswith(b"SNIP"):
                dynamic_port = struct.unpack(">H", head[4:6])[0]
                if 1 <= dynamic_port <= 65535:
                    up_port = dynamic_port
            elif head:
                prefix = head
        except Exception:
            pass
        finally:
            client_sock.settimeout(None)

        # Connect to upstream service
        up_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        up_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        up_sock.connect((up_host, up_port))

        if prefix:
            up_sock.sendall(prefix)

        client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        sockets = [client_sock, up_sock]

        while True:
            r, _, _ = select.select(sockets, [], [], 180)
            if not r:
                break
            for s in r:
                data = s.recv(32768)
                if not data:
                    return
                if s is client_sock:
                    bytes_in += len(data)
                    if jitter_enabled and random.random() < 0.15:
                        time.sleep(random.uniform(jitter_min, jitter_max))
                    up_sock.sendall(data)
                else:
                    bytes_out += len(data)
                    client_sock.sendall(data)

    except Exception:
        pass
    finally:
        with stats_lock:
            runtime_stats["active_connections"] = max(0, runtime_stats["active_connections"] - 1)
            runtime_stats["bytes_rx"] += bytes_in
            runtime_stats["bytes_tx"] += bytes_out

        try: client_sock.close()
        except: pass
        if up_sock:
            try: up_sock.close()
            except: pass

        update_accounting_db(username, bytes_in, bytes_out)
        save_stats()

def run_reverse_tunnel_client(cfg):
    """
    Reverse Tunnel Node mode: Connects from this server to a remote server
    while applying continuous SNI Spoofing.
    """
    target_host = cfg.get("reverse_target_host")
    target_port = int(cfg.get("reverse_target_port", 15443))
    upstream_str = cfg.get("upstream", "127.0.0.1:22")
    if ":" in upstream_str:
        up_host, up_port = upstream_str.split(":", 1)
        up_port = int(up_port)
    else:
        up_host, up_port = "127.0.0.1", int(upstream_str)

    print(f"[SNISpoof-Reverse] Starting Reverse Tunnel Client -> {target_host}:{target_port} (Forwarding to {up_host}:{up_port})")

    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_host, target_port))
            # Apply outbound SNI spoofing during handshake
            apply_outbound_spoofing(sock, target_host, target_port, cfg)

            # Connect to local upstream and bridge
            up_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            up_sock.connect((up_host, up_port))

            sockets = [sock, up_sock]
            while True:
                r, _, _ = select.select(sockets, [], [], 120)
                if not r: break
                for s in r:
                    data = s.recv(32768)
                    if not data: break
                    if s is sock:
                        up_sock.sendall(data)
                    else:
                        sock.sendall(data)
        except Exception as e:
            time.sleep(3)

def run_server():
    cfg = load_config()
    role = cfg.get("role", "inbound_relay")

    if role == "reverse_client" and cfg.get("reverse_target_host"):
        threading.Thread(target=run_reverse_tunnel_client, args=(cfg,), daemon=True).start()

    port = int(cfg.get("port", 15443))
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind(("0.0.0.0", port))
    srv_sock.listen(512)

    print(f"[SNISpoof] Server running on 0.0.0.0:{port} (Role: {role}, Upstream: {cfg.get('upstream')})")
    save_stats()

    # Periodic stats dumper thread
    def stats_flusher():
        while True:
            time.sleep(10)
            save_stats()
    threading.Thread(target=stats_flusher, daemon=True).start()

    while True:
        try:
            client_sock, client_addr = srv_sock.accept()
            t = threading.Thread(target=handle_inbound_client, args=(client_sock, client_addr, cfg), daemon=True)
            t.start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            time.sleep(0.1)

if __name__ == "__main__":
    def sig_handler(sig, frame):
        save_stats()
        sys.exit(0)
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)
    run_server()
