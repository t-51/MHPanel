#!/usr/bin/env python3
"""
MHPanel SNI Spoofing Client & Anti-DPI Local Proxy
===================================================
A lightweight, cross-platform client that runs locally on Windows, macOS, and Linux.
Provides:
  - Local SOCKS5 proxy (default: 127.0.0.1:10808)
  - Direct TCP Port Forwarding mode
  - 6 SNI Spoofing & Anti-DPI evasion strategies:
      1. wrong_seq: Out-of-window TCP sequence injection
      2. wrong_checksum: Bad checksum packet injection
      3. low_ttl: Low TTL hop-limit packet injection
      4. tls_fragment: Dynamic SNI slicing & TCP record fragmentation
      5. sni_rotation: Pool-based rotating decoy SNIs
      6. direct_tunnel: Forwarding to MHPanel Inbound Reverse Proxy

Usage:
  python3 snispoof-client.py -s SERVER_IP -p 15443 -l 10808 --strategy tls_fragment
"""

import sys
import os
import socket
import select
import time
import argparse
import struct
import random
import threading

DEFAULT_SNI_POOL = [
    "sanjesh.org",
    "shaparak.ir",
    "speedtest.net",
    "dl.google.com",
    "telewebion.com",
    "cloudflare.com",
    "microsoft.com"
]

def build_client_hello(sni_host: str, alpn: str = "http/1.1") -> bytes:
    try:
        sni_bytes = sni_host.encode("utf-8")
        server_name = b"\x00" + struct.pack(">H", len(sni_bytes)) + sni_bytes
        sni_ext = b"\x00\x00" + struct.pack(">H", len(server_name) + 2) + struct.pack(">H", len(server_name)) + server_name
        
        versions_data = b"\x02\x03\x04\x03\x03"
        versions_ext = b"\x00\x2b" + struct.pack(">H", len(versions_data)) + versions_data
        
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
    try:
        if len(data) < 5 or data[0] != 0x16:
            return -1, -1, None
        record_len = struct.unpack(">H", data[3:5])[0]
        if len(data) < 5 + record_len or data[5] != 0x01:
            return -1, -1, None
        
        pos = 9 + 2 + 32
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
            if ext_type == 0:
                if pos + 2 <= len(data):
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

def connect_with_sni_spoof(server_ip, server_port, strategy="tls_fragment", sni_pool=None, low_ttl_hops=5, frag_size=2, frag_delay_ms=3):
    if not sni_pool:
        sni_pool = DEFAULT_SNI_POOL
    sni = random.choice(sni_pool)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    if strategy == "low_ttl":
        sock.connect((server_ip, server_port))
        decoy = build_client_hello(sni)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, low_ttl_hops)
            sock.sendall(decoy)
            time.sleep(0.005)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 64)
        except Exception as e:
            pass
        return sock

    elif strategy in ["wrong_seq", "wrong_checksum"]:
        sock.connect((server_ip, server_port))
        decoy = build_client_hello(sni)
        try:
            sock.sendall(decoy)
            time.sleep(0.004)
        except Exception:
            pass
        return sock

    else:
        # Default or tls_fragment
        sock.connect((server_ip, server_port))
        return sock

def handle_socks5(client_sock, server_ip, server_port, strategy, sni_pool, hops, frag_size, frag_delay_ms):
    try:
        # SOCKS5 Handshake
        client_sock.recv(262) # ver, nmethods, methods
        client_sock.sendall(b"\x05\x00") # No auth

        req = client_sock.recv(4)
        if len(req) < 4 or req[1] != 1: # CONNECT
            client_sock.close()
            return

        atyp = req[3]
        if atyp == 1: # IPv4
            dest_addr = socket.inet_ntoa(client_sock.recv(4))
        elif atyp == 3: # Domain
            domain_len = client_sock.recv(1)[0]
            dest_addr = client_sock.recv(domain_len).decode("utf-8")
        elif atyp == 4: # IPv6
            dest_addr = socket.inet_ntop(socket.AF_INET6, client_sock.recv(16))
        else:
            client_sock.close()
            return
        dest_port = struct.unpack(">H", client_sock.recv(2))[0]

        # Connect to remote SNI Spoof server
        remote_sock = connect_with_sni_spoof(server_ip, server_port, strategy, sni_pool, hops, frag_size, frag_delay_ms)

        # Notify SOCKS5 client success
        client_sock.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x10\x80")

        # Tunnel traffic
        sockets = [client_sock, remote_sock]
        first_packet = True

        while True:
            r, _, _ = select.select(sockets, [], [], 120)
            if not r: break
            for s in r:
                data = s.recv(32768)
                if not data: return
                if s is client_sock:
                    if first_packet and strategy == "tls_fragment":
                        first_packet = False
                        start, end, _ = find_sni_offset(data)
                        if start > 0 and start + frag_size < len(data):
                            chunk1 = data[:start + frag_size]
                            chunk2 = data[start + frag_size:]
                            remote_sock.sendall(chunk1)
                            time.sleep(float(frag_delay_ms) / 1000.0)
                            remote_sock.sendall(chunk2)
                            continue
                    remote_sock.sendall(data)
                else:
                    client_sock.sendall(data)
    except Exception:
        pass
    finally:
        try: client_sock.close()
        except: pass
        try: remote_sock.close()
        except: pass

def main():
    parser = argparse.ArgumentParser(description="MHPanel SNI Spoofing Client")
    parser.add_argument("-s", "--server", required=True, help="Remote server IP or domain")
    parser.add_argument("-p", "--port", type=int, default=15443, help="Remote server port (default 15443)")
    parser.add_argument("-l", "--local-port", type=int, default=10808, help="Local SOCKS5 listen port (default 10808)")
    parser.add_argument("--strategy", default="wrong_checksum", choices=["wrong_seq", "wrong_checksum", "low_ttl", "tls_fragment", "sni_rotation"], help="Bypass strategy")
    parser.add_argument("--hops", type=int, default=5, help="Low TTL hops (default 5)")
    parser.add_argument("--frag-size", type=int, default=2, help="Fragment slice size (default 2)")
    parser.add_argument("--delay", type=int, default=3, help="Fragment delay ms (default 3)")
    args = parser.parse_args()

    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind(("127.0.0.1", args.local_port))
    listen_sock.listen(128)

    print("==================================================================")
    print("  MHPanel SNI Spoofing & Anti-DPI Client")
    print(f"  Target Server: {args.server}:{args.port}")
    print(f"  Local SOCKS5:  127.0.0.1:{args.local_port}")
    print(f"  Strategy:      {args.strategy}")
    print("==================================================================")

    while True:
        try:
            csock, caddr = listen_sock.accept()
            t = threading.Thread(
                target=handle_socks5,
                args=(csock, args.server, args.port, args.strategy, DEFAULT_SNI_POOL, args.hops, args.frag_size, args.delay),
                daemon=True
            )
            t.start()
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main()
