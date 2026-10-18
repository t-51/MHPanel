#!/usr/bin/env python3
"""
MHPanel High-Performance SSH-over-WebSocket & HTTP Payload Proxy
Supports:
  - RFC 6455 WebSocket Upgrade (Binary & Text frames)
  - HTTP Custom / NapsternetV / NetMod / OpenTunnel HTTP Payload Injection
  - Cloudflare CDN / ArvanCloud CDN Reverse Proxy
  - Direct TCP Bridging to local OpenSSH daemon (127.0.0.1:22)
"""

import asyncio
import base64
import hashlib
import struct
import sys
import os
import logging

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("ssh-ws-proxy")

SSH_HOST = "127.0.0.1"
SSH_PORT = 22
LISTEN_HOSTS = ["127.0.0.1", "0.0.0.0"]
LISTEN_PORTS = [8888, 8088]

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def compute_ws_accept(sec_key: str) -> str:
    combined = (sec_key.strip() + WS_GUID).encode("utf-8")
    return base64.b64encode(hashlib.sha1(combined).digest()).decode("utf-8")

def encode_ws_frame(data: bytes, opcode: int = 2) -> bytes:
    length = len(data)
    header = bytearray()
    header.append(0x80 | (opcode & 0x0F))
    if length < 126:
        header.append(length)
    elif length < 65536:
        header.append(126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(127)
        header.extend(struct.pack("!Q", length))
    return bytes(header) + data

class WebSocketParser:
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data: bytes):
        self.buffer.extend(data)

    def get_frames(self):
        frames = []
        while True:
            buf_len = len(self.buffer)
            if buf_len < 2:
                break
            b0 = self.buffer[0]
            b1 = self.buffer[1]
            opcode = b0 & 0x0F
            is_masked = (b1 & 0x80) != 0
            payload_len = b1 & 0x7F

            header_size = 2
            if payload_len == 126:
                if buf_len < 4:
                    break
                payload_len = struct.unpack("!H", self.buffer[2:4])[0]
                header_size = 4
            elif payload_len == 127:
                if buf_len < 10:
                    break
                payload_len = struct.unpack("!Q", self.buffer[2:10])[0]
                header_size = 10

            mask_key = None
            if is_masked:
                if buf_len < header_size + 4:
                    break
                mask_key = self.buffer[header_size:header_size + 4]
                header_size += 4

            total_frame_len = header_size + payload_len
            if buf_len < total_frame_len:
                break

            payload = self.buffer[header_size:total_frame_len]
            if is_masked and mask_key:
                unmasked = bytearray(payload_len)
                for i in range(payload_len):
                    unmasked[i] = payload[i] ^ mask_key[i % 4]
                payload = bytes(unmasked)
            else:
                payload = bytes(payload)

            frames.append((opcode, payload))
            del self.buffer[:total_frame_len]
        return frames

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    ssh_writer = None
    try:
        # 1. Read HTTP request header
        req_data = b""
        while b"\r\n\r\n" not in req_data and b"\n\n" not in req_data:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=10.0)
            if not chunk:
                writer.close()
                return
            req_data += chunk
            if len(req_data) > 65536:
                writer.close()
                return

        # Separate HTTP headers and any initial data
        if b"\r\n\r\n" in req_data:
            header_part, initial_data = req_data.split(b"\r\n\r\n", 1)
        else:
            header_part, initial_data = req_data.split(b"\n\n", 1)

        req_str = header_part.decode("utf-8", errors="ignore")
        headers = {}
        for line in req_str.splitlines()[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        is_ws = "upgrade" in headers.get("upgrade", "").lower() or "websocket" in headers.get("upgrade", "").lower()
        sec_key = headers.get("sec-websocket-key", "")

        # 2. Connect to local OpenSSH daemon
        ssh_reader, ssh_writer = await asyncio.open_connection(SSH_HOST, SSH_PORT)

        # 3. Send Handshake Response
        if is_ws and sec_key:
            accept_key = compute_ws_accept(sec_key)
            resp = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept_key}\r\n"
                "\r\n"
            ).encode("utf-8")
            writer.write(resp)
            await writer.drain()
            is_framed_ws = True
        else:
            # HTTP CONNECT or Custom Injection Payload (HTTP 101 or HTTP 200)
            resp = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                "\r\n"
            ).encode("utf-8")
            writer.write(resp)
            await writer.drain()
            is_framed_ws = False

        ws_parser = WebSocketParser()

        # If client sent initial payload after the headers, process it
        if initial_data:
            if is_framed_ws:
                # Check if client sent raw SSH handshake without framing (common in some injectors)
                if initial_data.startswith(b"SSH-"):
                    is_framed_ws = False
                    ssh_writer.write(initial_data)
                    await ssh_writer.drain()
                else:
                    ws_parser.feed(initial_data)
                    for opcode, payload in ws_parser.get_frames():
                        if opcode in (1, 2) and payload:
                            ssh_writer.write(payload)
                            await ssh_writer.drain()
                        elif opcode == 8: # Close
                            break
            else:
                ssh_writer.write(initial_data)
                await ssh_writer.drain()

        # 4. Bidirectional forwarders
        async def client_to_ssh():
            nonlocal is_framed_ws
            while True:
                data = await reader.read(16384)
                if not data:
                    break
                if not is_framed_ws:
                    # Direct raw stream
                    ssh_writer.write(data)
                    await ssh_writer.drain()
                else:
                    # Check if client suddenly switched to raw SSH data
                    if len(ws_parser.buffer) == 0 and data.startswith(b"SSH-"):
                        is_framed_ws = False
                        ssh_writer.write(data)
                        await ssh_writer.drain()
                        continue

                    ws_parser.feed(data)
                    for opcode, payload in ws_parser.get_frames():
                        if opcode in (1, 2) and payload:
                            ssh_writer.write(payload)
                            await ssh_writer.drain()
                        elif opcode == 8:  # Close frame
                            return
                        elif opcode == 9:  # Ping
                            pong = encode_ws_frame(payload, opcode=10)
                            writer.write(pong)
                            await writer.drain()

        async def ssh_to_client():
            while True:
                data = await ssh_reader.read(16384)
                if not data:
                    break
                if is_framed_ws:
                    frame = encode_ws_frame(data, opcode=2)
                    writer.write(frame)
                else:
                    writer.write(data)
                await writer.drain()

        done, pending = await asyncio.wait(
            [asyncio.create_task(client_to_ssh()), asyncio.create_task(ssh_to_client())],
            return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()

    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        logger.debug(f"Error handling peer {peer}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        if ssh_writer:
            try:
                ssh_writer.close()
                await ssh_writer.wait_closed()
            except Exception:
                pass

async def main():
    servers = []
    # Listen on 127.0.0.1:8888 (for reverse proxy)
    s1 = await asyncio.start_server(handle_client, "127.0.0.1", 8888)
    servers.append(s1)
    logger.info("SSH-WS listening on 127.0.0.1:8888 (Internal/Reverse Proxy)")

    # Listen on 0.0.0.0:8088 (Direct Public WS)
    try:
        s2 = await asyncio.start_server(handle_client, "0.0.0.0", 8088)
        servers.append(s2)
        logger.info("SSH-WS listening on 0.0.0.0:8088 (Direct Public WS)")
    except Exception as e:
        logger.warning(f"Could not bind 0.0.0.0:8088: {e}")

    async with asyncio.TaskGroup() as tg:
        for s in servers:
            tg.create_task(s.serve_forever())

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
