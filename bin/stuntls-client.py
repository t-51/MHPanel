#!/usr/bin/env python3
"""
MHPanel StunTLS Client v2.0
RFC 5389 WebRTC STUN Obfuscated Tunnel Client
Disguises all outbound TCP traffic as standard WebRTC / VoIP STUN packets to bypass DPI firewalls.
Part of MHPanel Anti-Censorship Suite.

Usage:
  python stuntls-client.py -server 13.140.86.132:3478 -key stuntls-secret -l 1080
"""
import sys
import os
import socket
import select
import struct
import argparse
import threading
import time

STUN_MAGIC_COOKIE = 0x2112A442

def wrap_stun(data, msg_type=0x0001):
    """Encapsulates data in an RFC 5389 STUN Binding Request packet."""
    trans_id = os.urandom(12)
    hdr = struct.pack(">HHI", msg_type, len(data), STUN_MAGIC_COOKIE) + trans_id
    return hdr + data

def deframe_stun(buf):
    """Extracts payload packets from a STUN buffer."""
    packets = []
    while len(buf) >= 20:
        msg_type, msg_len, cookie = struct.unpack(">HHI", buf[:8])
        if cookie == STUN_MAGIC_COOKIE:
            total = 20 + msg_len
            if len(buf) >= total:
                packets.append(buf[20:total])
                buf = buf[total:]
            else:
                break
        else:
            packets.append(buf)
            buf = b""
            break
    return packets, buf

def forward_connection(local_conn, remote_host, remote_port, secret=None):
    remote_sock = None
    server_buf = b""
    try:
        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_sock.settimeout(12.0)
        remote_sock.connect((remote_host, remote_port))
        remote_sock.settimeout(None)

        sockets = [local_conn, remote_sock]

        while True:
            r, _, _ = select.select(sockets, [], [], 120)
            if not r:
                break
            for s in r:
                chunk = s.recv(16384)
                if not chunk:
                    return
                if s is local_conn:
                    # Application -> Server: Wrap in RFC 5389 STUN
                    stun_packet = wrap_stun(chunk)
                    remote_sock.sendall(stun_packet)
                else:
                    # Server -> Application: Unwrap STUN or pass raw
                    server_buf += chunk
                    pkts, server_buf = deframe_stun(server_buf)
                    for p in pkts:
                        local_conn.sendall(p)
    except Exception:
        pass
    finally:
        try: local_conn.close()
        except: pass
        if remote_sock:
            try: remote_sock.close()
            except: pass

def run_client(server_addr, local_port=1080, secret="stuntls-secret", bind_ip="127.0.0.1"):
    if ":" in server_addr:
        remote_host, remote_port = server_addr.split(":", 1)
        remote_port = int(remote_port)
    else:
        remote_host, remote_port = server_addr, 3478

    local_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local_server.bind((bind_ip, local_port))
    local_server.listen(128)

    print("=" * 65)
    print("      MHPanel StunTLS Tunnel Client v2.0 (RFC 5389)")
    print("=" * 65)
    print(f"  [+] Remote StunTLS Server : {remote_host}:{remote_port}")
    print(f"  [+] Tunnel Mode           : RFC 5389 WebRTC STUN Obfuscation")
    print(f"  [+] Local Listen Port     : {bind_ip}:{local_port}")
    print(f"  [+] Status                : Active & Ready! Listening for connections...")
    print("=" * 65)
    print(f"  >>> Configure your browser, Telegram or Proxifier to use SOCKS5/TCP at {bind_ip}:{local_port}")
    print("  >>> Press Ctrl+C to terminate.")
    print("=" * 65)

    while True:
        try:
            local_conn, addr = local_server.accept()
            t = threading.Thread(
                target=forward_connection,
                args=(local_conn, remote_host, remote_port, secret),
                daemon=True
            )
            t.start()
        except KeyboardInterrupt:
            print("\n[!] StunTLS Client stopped by user.")
            break
        except Exception:
            time.sleep(0.05)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="StunTLS WebRTC STUN Obfuscation Tunnel Client")
    parser.add_argument("-server", "--server", required=True, help="Remote StunTLS server host:port (e.g. 13.140.86.132:3478)")
    parser.add_argument("-key", "--key", default="stuntls-secret", help="Secret key (default: stuntls-secret)")
    parser.add_argument("-l", "--local", type=int, default=1080, help="Local listening port (default: 1080)")
    parser.add_argument("-b", "--bind", default="127.0.0.1", help="Local bind IP (default: 127.0.0.1)")
    args = parser.parse_args()

    run_client(server_addr=args.server, local_port=args.local, secret=args.key, bind_ip=args.bind)
