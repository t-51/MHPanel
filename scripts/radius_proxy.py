#!/usr/bin/env python3
import asyncio
import os
import sys
import json
import uuid
import time
import argparse
import hashlib
import socket
import logging
import traceback
from urllib.parse import urlparse
import base64

# Import pyrad
try:
    import pyrad.client
    import pyrad.packet
    from pyrad.dictionary import Dictionary
except ImportError:
    print("pyrad is required. Install it using pip install pyrad", file=sys.stderr)
    sys.exit(1)

# Import cryptography for Shadowsocks
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    import cryptography.hazmat.primitives.kdf.hkdf as hkdf
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("cryptography is required. Install it using pip install cryptography", file=sys.stderr)
    sys.exit(1)

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("radius_proxy")

# Global Active Sessions Tracking
active_sessions = {} # acct_session_id -> SessionObject

class SessionObject:
    def __init__(self, username, password, client_ip, nas_id):
        self.session_id = uuid.uuid4().hex
        self.username = username
        self.password = password
        self.client_ip = client_ip
        self.nas_id = nas_id
        self.start_time = time.time()
        self.bytes_in = 0  # Received from client (Input)
        self.bytes_out = 0 # Sent to client (Output)
        self.session_timeout = None
        self.total_limit = None # Total bytes limit
        self.recv_limit = None # Recv bytes limit (Mikrotik)
        self.xmit_limit = None # Xmit bytes limit (Mikrotik)
        self.interim_interval = 60
        self.stop_event = asyncio.Event()
        self.task = None
        self.connections = set() # Set of active asyncio transport writers or tasks

    def add_connection(self, task_or_writer):
        self.connections.add(task_or_writer)

    def remove_connection(self, task_or_writer):
        self.connections.discard(task_or_writer)
        if not self.connections:
            # All connections for this session are closed
            self.stop_event.set()

    def terminate(self):
        self.stop_event.set()
        for conn in list(self.connections):
            try:
                if hasattr(conn, 'close'):
                    conn.close()
                elif hasattr(conn, 'cancel'):
                    conn.cancel()
            except Exception:
                pass
        self.connections.clear()


# --- Config & Setup ---
CONFIG_FILE = "/etc/vpnpanel/radius_config.json"
DICTIONARY_FILE = "/opt/vpnpanel/dictionary"
USERS_CACHE_FILE = "/etc/vpnpanel/proxy_users.json"

def load_radius_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load RADIUS config: {e}")
    return {
        "server_ip": "127.0.0.1",
        "shared_secret": "testing123",
        "auth_port": 1812,
        "acct_port": 1813
    }

def cache_credentials(username, password):
    try:
        os.makedirs(os.path.dirname(USERS_CACHE_FILE), exist_ok=True)
        users = {}
        if os.path.exists(USERS_CACHE_FILE):
            with open(USERS_CACHE_FILE, "r") as f:
                users = json.load(f)
        users[username] = password
        with open(USERS_CACHE_FILE, "w") as f:
            json.dump(users, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to cache credentials: {e}")

def get_cached_users():
    if os.path.exists(USERS_CACHE_FILE):
        try:
            with open(USERS_CACHE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


# --- RADIUS Client Protocol ---
def get_radius_client(rad_config):
    dict_inst = Dictionary(DICTIONARY_FILE)
    client = pyrad.client.Client(
        server=rad_config["server_ip"],
        secret=rad_config["shared_secret"].encode(),
        dict=dict_inst,
        authport=int(rad_config.get("auth_port", 1812)),
        acctport=int(rad_config.get("acct_port", 1813))
    )
    client.timeout = 5
    return client

def authenticate_radius(username, password, rad_config, client_ip="127.0.0.1"):
    try:
        client = get_radius_client(rad_config)
        req = client.CreateAuthPacket(code=pyrad.packet.AccessRequest, User_Name=username)
        req["User-Password"] = req.PwCrypt(password)
        req["NAS-Identifier"] = "aethervpn-proxy"
        req["NAS-IP-Address"] = "127.0.0.1"
        req["Framed-IP-Address"] = client_ip
        
        reply = client.SendPacket(req)
        if reply.code == pyrad.packet.AccessAccept:
            # Parse limits
            limits = {}
            # Session-Timeout (27)
            if 27 in reply:
                limits["session_timeout"] = int(reply[27][0])
            # Mikrotik-Total-Limit (14988, 17)
            if (14988, 17) in reply:
                limits["total_limit"] = int(reply[(14988, 17)][0])
            # Mikrotik-Recv-Limit (14988, 1)
            if (14988, 1) in reply:
                limits["recv_limit"] = int(reply[(14988, 1)][0])
            # Mikrotik-Xmit-Limit (14988, 2)
            if (14988, 2) in reply:
                limits["xmit_limit"] = int(reply[(14988, 2)][0])
            # Acct-Interim-Interval (85)
            if 85 in reply:
                limits["interim_interval"] = int(reply[85][0])
            return True, limits
        return False, None
    except Exception as e:
        logger.error(f"RADIUS auth exception: {e}")
        return False, None

def check_proxy_auth(username, password, rad_config, client_ip="127.0.0.1", proxy_type="socks5"):
    """Check credentials against local proxy users file first, then fallback to RADIUS."""
    try:
        cached_users = get_cached_users()
        if username in cached_users:
            val = cached_users[username]
            if isinstance(val, dict):
                pw = val.get("password", "")
                enabled = val.get("enabled", True)
                protos = val.get("protocols", ["socks5", "http"])
                if enabled and pw == password and (proxy_type in protos or "all" in protos):
                    logger.info(f"Local auth success for user {username} on {proxy_type} from {client_ip}")
                    return True, {"is_local": True}
                elif not enabled:
                    logger.warning(f"User {username} is disabled locally")
                    return False, None
            elif str(val) == password:
                logger.info(f"Local auth success for user {username} on {proxy_type} from {client_ip}")
                return True, {"is_local": True}
    except Exception as e:
        logger.error(f"Local auth check error: {e}")

    # Fallback to RADIUS if enabled
    try:
        if rad_config and rad_config.get("server_ip"):
            res, limits = authenticate_radius(username, password, rad_config, client_ip)
            if res:
                return True, limits or {}
    except Exception as e:
        logger.error(f"RADIUS fallback failed: {e}")

    return False, None

def send_accounting_radius(session, status, rad_config):
    try:
        client = get_radius_client(rad_config)
        req = client.CreateAcctPacket(code=pyrad.packet.AccountingRequest, User_Name=session.username)
        req["Acct-Status-Type"] = status
        req["Acct-Session-Id"] = session.session_id
        req["NAS-Identifier"] = session.nas_id
        req["NAS-IP-Address"] = "127.0.0.1"
        req["Framed-IP-Address"] = session.client_ip
        
        # Traffic Counters
        if status in ["Stop", "Interim-Update"]:
            req["Acct-Session-Time"] = int(time.time() - session.start_time)
            
            # Divide into normal octets and Gigawords (overflow attributes)
            in_bytes = session.bytes_in
            out_bytes = session.bytes_out
            
            req["Acct-Input-Octets"] = in_bytes & 0xFFFFFFFF
            req["Acct-Output-Octets"] = out_bytes & 0xFFFFFFFF
            
            in_giga = in_bytes >> 32
            out_giga = out_bytes >> 32
            
            if in_giga > 0:
                req["Acct-Input-Gigawords"] = in_giga
            if out_giga > 0:
                req["Acct-Output-Gigawords"] = out_giga
                
        client.SendPacket(req)
        return True
    except Exception as e:
        logger.error(f"RADIUS accounting exception for {status}: {e}")
        return False


# --- Session Accounting Loop ---
async def session_accounting_loop(session, rad_config):
    if getattr(session, "is_local", False):
        logger.info(f"Local session active for {session.username} ({session.nas_id})")
        try:
            while not session.stop_event.is_set():
                try:
                    await asyncio.wait_for(session.stop_event.wait(), timeout=30)
                except asyncio.TimeoutError:
                    pass
        finally:
            active_sessions.pop(session.session_id, None)
            logger.info(f"Local session closed for {session.username}. Total: {session.bytes_in + session.bytes_out} bytes")
        return

    # Send Start
    send_accounting_radius(session, "Start", rad_config)
    logger.info(f"RADIUS Accounting started for session {session.session_id} ({session.username})")
    
    try:
        while not session.stop_event.is_set():
            # Wait for interval or stop event
            try:
                await asyncio.wait_for(session.stop_event.wait(), timeout=session.interim_interval)
            except asyncio.TimeoutError:
                pass
            
            if session.stop_event.is_set():
                break
                
            # Check Limits
            elapsed = time.time() - session.start_time
            if session.session_timeout and elapsed >= session.session_timeout:
                logger.warn(f"Session {session.session_id} exceeded session timeout ({session.session_timeout}s). Disconnecting.")
                session.terminate()
                break
                
            total_bytes = session.bytes_in + session.bytes_out
            if session.total_limit and total_bytes >= session.total_limit:
                logger.warn(f"Session {session.session_id} exceeded total volume limit ({session.total_limit} bytes). Disconnecting.")
                session.terminate()
                break
                
            if session.recv_limit and session.bytes_in >= session.recv_limit:
                logger.warn(f"Session {session.session_id} exceeded download limit ({session.recv_limit} bytes). Disconnecting.")
                session.terminate()
                break
                
            if session.xmit_limit and session.bytes_out >= session.xmit_limit:
                logger.warn(f"Session {session.session_id} exceeded upload limit ({session.xmit_limit} bytes). Disconnecting.")
                session.terminate()
                break
                
            # Send Interim Update
            send_accounting_radius(session, "Interim-Update", rad_config)
            
    finally:
        # Send Stop
        send_accounting_radius(session, "Stop", rad_config)
        logger.info(f"RADIUS Accounting stopped for session {session.session_id} ({session.username}). Total bytes: {session.bytes_in + session.bytes_out}")
        active_sessions.pop(session.session_id, None)


# --- Tunnel Piping ---
async def tunnel_stream(reader, writer, session, is_input):
    """Pipes bytes from reader to writer, recording data transfer size in session if active."""
    buffer_size = 8192
    try:
        while session is None or not session.stop_event.is_set():
            data = await reader.read(buffer_size)
            if not data:
                break
            writer.write(data)
            await writer.drain()
            
            if session:
                if is_input:
                    session.bytes_in += len(data)
                else:
                    session.bytes_out += len(data)
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# --- Packet of Disconnect / CoA Listener ---
async def coa_listener(rad_config):
    """Listens on UDP port 3799 for RADIUS POD (Packet of Disconnect) requests."""
    dict_inst = Dictionary(DICTIONARY_FILE)
    
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", 3799))
        sock.setblocking(False)
    except Exception as e:
        logger.error(f"Failed to bind UDP port 3799 for CoA: {e}")
        return
        
    logger.info("RADIUS Disconnect-Request (CoA) listener active on UDP 3799")
    loop = asyncio.get_running_loop()
    
    while True:
        try:
            data, addr = await loop.sock_recvfrom(sock, 4096)
            # Parse packet
            packet = pyrad.packet.Packet(packet=data, dict=dict_inst, secret=rad_config["shared_secret"].encode())
            
            if packet.code == pyrad.packet.DisconnectRequest:
                # Find matching session
                target_user = packet.get("User-Name", [None])[0]
                target_session_id = packet.get("Acct-Session-Id", [None])[0]
                
                logger.info(f"Received Disconnect-Request from {addr} for Username={target_user}, SessionID={target_session_id}")
                
                terminated = False
                for sid, session in list(active_sessions.items()):
                    if (target_session_id and session.session_id == target_session_id) or \
                       (target_user and session.username == target_user):
                        session.terminate()
                        logger.info(f"Session {session.session_id} successfully terminated via CoA")
                        terminated = True
                
                # Send Response
                reply = packet.CreateReply()
                if terminated:
                    reply.code = pyrad.packet.DisconnectACK
                else:
                    reply.code = pyrad.packet.DisconnectNAK
                    
                sock.sendto(reply.ReplyPacket(), addr)
                
        except Exception as e:
            logger.error(f"CoA listener exception: {e}")
            await asyncio.sleep(1)


# --- HTTP Proxy Server ---
async def handle_http_proxy(reader, writer, rad_config, use_radius):
    client_ip, _ = writer.get_extra_info('peername')
    
    try:
        # Read HTTP request header
        header_data = b""
        while b"\r\n\r\n" not in header_data:
            chunk = await reader.read(4096)
            if not chunk:
                break
            header_data += chunk
            if len(header_data) > 65536: # Protection
                break
                
        if not header_data:
            writer.close()
            return
            
        parts = header_data.split(b"\r\n\r\n", 1)
        header_lines = parts[0].split(b"\r\n")
        request_line = header_lines[0].decode('utf-8', errors='ignore')
        
        # Parse Request Line
        req_parts = request_line.split()
        if len(req_parts) < 2:
            writer.close()
            return
            
        method, url = req_parts[0], req_parts[1]
        
        username, password, limits = None, None, {}
        if use_radius:
            # Find Authorization Header
            for line in header_lines[1:]:
                line_str = line.decode('utf-8', errors='ignore')
                if line_str.lower().startswith("proxy-authorization: basic "):
                    encoded = line_str.split()[2]
                    decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
                    username, password = decoded.split(":", 1)
                    break
                    
            if not username or not password:
                # Request credentials
                writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                             b"Proxy-Authenticate: Basic realm=\"AetherVPN Proxy\"\r\n"
                             b"Connection: close\r\n\r\n")
                await writer.drain()
                writer.close()
                return
                
            # Authenticate via Local Users or RADIUS
            auth_success, limits = check_proxy_auth(username, password, rad_config, client_ip, proxy_type="http")
            if not auth_success:
                writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                await writer.drain()
                writer.close()
                return
                
            # Cache credentials for Shadowsocks fallback lookup
            cache_credentials(username, password)
        
        # Start Accounting Session if RADIUS is enabled
        session = None
        if use_radius:
            session = SessionObject(username, password, client_ip, "http-proxy")
            if limits and limits.get("is_local"):
                session.is_local = True
            if limits:
                session.session_timeout = limits.get("session_timeout")
                session.total_limit = limits.get("total_limit")
                session.recv_limit = limits.get("recv_limit")
                session.xmit_limit = limits.get("xmit_limit")
                session.interim_interval = limits.get("interim_interval", 60)
                
            active_sessions[session.session_id] = session
            session.task = asyncio.create_task(session_accounting_loop(session, rad_config))
            session.add_connection(asyncio.current_task())
        
        # Establish target connection
        if method.upper() == "CONNECT":
            # HTTPS tunnel
            target_host, target_port = url.decode('utf-8', errors='ignore').split(":") if isinstance(url, bytes) else url.split(":")
            target_port = int(target_port)
            
            try:
                remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port)
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
            except Exception as e:
                logger.error(f"Failed to connect to target {target_host}:{target_port}: {e}")
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
                if session:
                    session.remove_connection(asyncio.current_task())
                return
        else:
            # Plain HTTP forward
            parsed = urlparse(url.decode('utf-8', errors='ignore') if isinstance(url, bytes) else url)
            target_host = parsed.hostname
            target_port = parsed.port or 80
            
            try:
                remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port)
                # Re-send headers to remote, omitting Proxy-Authorization
                cleaned_headers = []
                for line in header_lines:
                    line_str = line.decode('utf-8', errors='ignore')
                    if not line_str.lower().startswith("proxy-authorization:"):
                        cleaned_headers.append(line)
                cleaned_headers.append(b"") # End of header
                
                remote_writer.write(b"\r\n".join(cleaned_headers) + b"\r\n")
                if len(parts) > 1:
                    remote_writer.write(parts[1])
                await remote_writer.drain()
            except Exception as e:
                logger.error(f"Failed to connect to target {target_host}:{target_port}: {e}")
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
                if session:
                    session.remove_connection(asyncio.current_task())
                return
                
        # Pipe traffic
        task_in = asyncio.create_task(tunnel_stream(reader, remote_writer, session, is_input=True))
        task_out = asyncio.create_task(tunnel_stream(remote_reader, writer, session, is_input=False))
        
        await asyncio.gather(task_in, task_out)
        
    except Exception as e:
        logger.error(f"HTTP handler exception: {e}")
    finally:
        if session:
            session.remove_connection(asyncio.current_task())
        writer.close()


# --- SOCKS5 Proxy Server ---
async def handle_socks_proxy(reader, writer, rad_config, use_radius):
    client_ip, _ = writer.get_extra_info('peername')
    session = None
    
    try:
        # SOCKS5 Handshake
        version, nmethods = await reader.readexactly(2)
        if version != 5:
            writer.close()
            return
            
        methods = await reader.readexactly(nmethods)
        if use_radius:
            if 2 not in methods: # Username/Password Auth Method
                # Reject: No acceptable methods
                writer.write(b"\x05\xFF")
                await writer.drain()
                writer.close()
                return
                
            # Select Username/Password Auth method
            writer.write(b"\x05\x02")
            await writer.drain()
            
            # Subnegotiation Auth
            auth_version = (await reader.readexactly(1))[0]
            if auth_version != 1:
                writer.close()
                return
                
            ulen = (await reader.readexactly(1))[0]
            username = (await reader.readexactly(ulen)).decode('utf-8')
            
            plen = (await reader.readexactly(1))[0]
            password = (await reader.readexactly(plen)).decode('utf-8')
            
            # Authenticate via Local Users or RADIUS
            auth_success, limits = check_proxy_auth(username, password, rad_config, client_ip, proxy_type="socks5")
            if not auth_success:
                writer.write(b"\x01\x01") # Auth failure status
                await writer.drain()
                writer.close()
                return
                
            writer.write(b"\x01\x00") # Auth success status
            await writer.drain()
            
            # Cache credentials for Shadowsocks fallback lookup
            cache_credentials(username, password)
            
            # Create session
            session = SessionObject(username, password, client_ip, "socks-proxy")
            if limits and limits.get("is_local"):
                session.is_local = True
            if limits:
                session.session_timeout = limits.get("session_timeout")
                session.total_limit = limits.get("total_limit")
                session.recv_limit = limits.get("recv_limit")
                session.xmit_limit = limits.get("xmit_limit")
                session.interim_interval = limits.get("interim_interval", 60)
                
            active_sessions[session.session_id] = session
            session.task = asyncio.create_task(session_accounting_loop(session, rad_config))
            session.add_connection(asyncio.current_task())
        else:
            # Select No Authentication method (0x00)
            if 0 not in methods:
                writer.write(b"\x05\xFF")
                await writer.drain()
                writer.close()
                return
            writer.write(b"\x05\x00")
            await writer.drain()
        
        # Parse SOCKS5 Request
        req_header = await reader.readexactly(4)
        cmd, atyp = req_header[1], req_header[3]
        
        if cmd != 1: # CONNECT = 1
            # Command not supported
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return
            
        # Parse Target Address
        if atyp == 1: # IPv4
            addr_bytes = await reader.readexactly(4)
            target_host = socket.inet_ntoa(addr_bytes)
        elif atyp == 3: # Domain
            domain_len = (await reader.readexactly(1))[0]
            target_host = (await reader.readexactly(domain_len)).decode('utf-8')
        elif atyp == 4: # IPv6
            addr_bytes = await reader.readexactly(16)
            target_host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        else:
            # Address type not supported
            writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return
            
        port_bytes = await reader.readexactly(2)
        target_port = int.from_bytes(port_bytes, 'big')
        
        # Connect to Target
        try:
            remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port)
            # Success reply
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
        except Exception as e:
            logger.error(f"SOCKS failed connect to {target_host}:{target_port}: {e}")
            writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00") # Host unreachable
            await writer.drain()
            return
            
        # Pipe traffic
        task_in = asyncio.create_task(tunnel_stream(reader, remote_writer, session, is_input=True))
        task_out = asyncio.create_task(tunnel_stream(remote_reader, writer, session, is_input=False))
        
        await asyncio.gather(task_in, task_out)
        
    except Exception as e:
        logger.error(f"SOCKS handler exception: {e}")
    finally:
        if session:
            session.remove_connection(asyncio.current_task())
        writer.close()


# --- Shadowsocks Protocol Implementation ---
class NonceCounter:
    def __init__(self):
        self.counter = 0
    def next_nonce(self):
        nonce = self.counter.to_bytes(12, byteorder='big')
        self.counter += 1
        return nonce

def derive_ss_master_key(password, key_len=32):
    m = []
    i = 0
    pwd_bytes = password.encode('utf-8')
    while len(b''.join(m)) < key_len:
        data = pwd_bytes
        if i > 0:
            data = m[i-1] + pwd_bytes
        m.append(hashlib.md5(data).digest())
        i += 1
    return b''.join(m)[:key_len]

def derive_ss_subkey(master_key, salt, key_len=32):
    hkdf_inst = hkdf.HKDF(
        algorithm=hashes.SHA1(),
        length=key_len,
        salt=salt,
        info=b"ss-subkey",
    )
    return hkdf_inst.derive(master_key)

async def decrypt_shadowsocks_header(reader, cached_users):
    """Attempts to read the salt and decrypt the first AEAD chunk length and payload
       using the passwords of cached users. Returns (username, password, subkey_in, decrypted_payload, remaining_header_data)."""
    
    salt = await reader.readexactly(32)
    chunk_length_enc = await reader.readexactly(18) # 2 bytes length + 16 bytes tag
    
    # Try each user to decrypt chunk length
    for username, password in cached_users.items():
        master_key = derive_ss_master_key(password, 32)
        try:
            subkey_in = derive_ss_subkey(master_key, salt, 32)
            aes = AESGCM(subkey_in)
            # Decrypt length using nonce 0
            len_nonce = b'\x00' * 12
            len_bytes = aes.decrypt(len_nonce, chunk_length_enc, None)
            
            # If length decrypted, read payload chunk
            payload_len = int.from_bytes(len_bytes, 'big')
            payload_enc = await reader.readexactly(payload_len + 16)
            
            # Decrypt payload using nonce 1
            payload_nonce = (1).to_bytes(12, 'big')
            payload = aes.decrypt(payload_nonce, payload_enc, None)
            
            return username, password, subkey_in, payload, salt
        except Exception:
            # Continue trying next user
            continue
            
    raise Exception("Authentication Failed: Unable to decrypt Shadowsocks stream with any user password")

async def encrypt_tunnel_ss(reader, writer, session, subkey_out):
    """Downstream piping: Reads from target, encrypts to Shadowsocks client."""
    aes = AESGCM(subkey_out)
    nonce_counter = NonceCounter()
    buffer_size = 4096
    
    try:
        while not session.stop_event.is_set():
            data = await reader.read(buffer_size)
            if not data:
                break
            
            # Encrypt Length
            chunk_len = len(data)
            len_bytes = chunk_len.to_bytes(2, 'big')
            len_nonce = nonce_counter.next_nonce()
            len_enc = aes.encrypt(len_nonce, len_bytes, None)
            
            # Encrypt Payload
            payload_nonce = nonce_counter.next_nonce()
            payload_enc = aes.encrypt(payload_nonce, data, None)
            
            writer.write(len_enc + payload_enc)
            await writer.drain()
            session.bytes_out += chunk_len
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass

async def decrypt_tunnel_ss(reader, writer, session, subkey_in, initial_nonce_val):
    """Upstream piping: Reads from Shadowsocks client, decrypts, and writes to target."""
    aes = AESGCM(subkey_in)
    nonce_counter = NonceCounter()
    nonce_counter.counter = initial_nonce_val # Resume after header read (which used 0 and 1)
    
    try:
        while not session.stop_event.is_set():
            # Read length chunk (18 bytes)
            len_enc = await reader.readexactly(18)
            len_nonce = nonce_counter.next_nonce()
            len_bytes = aes.decrypt(len_nonce, len_enc, None)
            
            payload_len = int.from_bytes(len_bytes, 'big')
            
            # Read payload chunk
            payload_enc = await reader.readexactly(payload_len + 16)
            payload_nonce = nonce_counter.next_nonce()
            payload = aes.decrypt(payload_nonce, payload_enc, None)
            
            writer.write(payload)
            await writer.drain()
            session.bytes_in += payload_len
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass

async def handle_ss_proxy(reader, writer, rad_config, use_radius):
    client_ip, _ = writer.get_extra_info('peername')
    session = None
    
    try:
        # Load user passwords from cache or static file
        if use_radius:
            cached_users = get_cached_users()
        else:
            static_password = ""
            if os.path.exists("/etc/vpnpanel/shadowsocks_password"):
                try:
                    with open("/etc/vpnpanel/shadowsocks_password", "r") as f:
                        static_password = f.read().strip()
                except Exception:
                    pass
            cached_users = {"shadowsocks": static_password}
            
        if not cached_users:
            logger.error("No active users in proxy cache. Rejecting Shadowsocks connection.")
            writer.close()
            return
            
        # Identify user by decrypting the header
        try:
            username, password, subkey_in, payload, salt = await decrypt_shadowsocks_header(reader, cached_users)
        except Exception as e:
            logger.warn(f"Shadowsocks handshake decryption failed from {client_ip}: {e}")
            writer.close()
            return
            
        limits = {}
        if use_radius:
            # Verify user still valid in RADIUS
            auth_success, limits = authenticate_radius(username, password, rad_config, client_ip)
            if not auth_success:
                logger.warn(f"RADIUS reject for user {username} during Shadowsocks authentication")
                writer.close()
                return
            
        # Create session if RADIUS is active
        if use_radius:
            session = SessionObject(username, password, client_ip, "shadowsocks-proxy")
            if limits:
                session.session_timeout = limits.get("session_timeout")
                session.total_limit = limits.get("total_limit")
                session.recv_limit = limits.get("recv_limit")
                session.xmit_limit = limits.get("xmit_limit")
                session.interim_interval = limits.get("interim_interval", 60)
                
            active_sessions[session.session_id] = session
            session.task = asyncio.create_task(session_accounting_loop(session, rad_config))
            session.add_connection(asyncio.current_task())
        
        # Parse payload containing SOCKS5 style target address
        atyp = payload[0]
        if atyp == 1: # IPv4
            target_host = socket.inet_ntoa(payload[1:5])
            target_port = int.from_bytes(payload[5:7], 'big')
            data_start_idx = 7
        elif atyp == 3: # Domain
            domain_len = payload[1]
            target_host = payload[2:2+domain_len].decode('utf-8')
            target_port = int.from_bytes(payload[2+domain_len:4+domain_len], 'big')
            data_start_idx = 4 + domain_len
        elif atyp == 4: # IPv6
            target_host = socket.inet_ntop(socket.AF_INET6, payload[1:17])
            target_port = int.from_bytes(payload[17:19], 'big')
            data_start_idx = 19
        else:
            logger.error("Unknown address type in Shadowsocks request")
            return
            
        # Connect to Target
        try:
            remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port)
        except Exception as e:
            logger.error(f"Shadowsocks failed to connect to target {target_host}:{target_port}: {e}")
            if session:
                session.remove_connection(asyncio.current_task())
            return
            
        # Send initial data block to remote if present in payload chunk
        if len(payload) > data_start_idx:
            remote_writer.write(payload[data_start_idx:])
            await remote_writer.drain()
            
        # Initialize output subkey (encrypt path from server to client)
        server_salt = os.urandom(32)
        writer.write(server_salt) # First 32 bytes to client is salt
        await writer.drain()
        
        master_key = derive_ss_master_key(password, 32)
        subkey_out = derive_ss_subkey(master_key, server_salt, 32)
        
        # Pipe traffic
        task_in = asyncio.create_task(decrypt_tunnel_ss(reader, remote_writer, session, subkey_in, initial_nonce_val=2))
        task_out = asyncio.create_task(encrypt_tunnel_ss(remote_reader, writer, session, subkey_out))
        
        await asyncio.gather(task_in, task_out)
        
    except Exception as e:
        logger.error(f"Shadowsocks handler exception: {e}")
    finally:
        if session:
            session.remove_connection(asyncio.current_task())
        writer.close()


# --- Main Service Runner ---
async def main():
    parser = argparse.ArgumentParser(description="Antigravity VPN Dynamic RADIUS Proxy Server")
    parser.add_argument("--listen", required=True, help="Listen URI, e.g. http://0.0.0.0:8080")
    args = parser.parse_args()
    
    # Parse listen URI
    parsed = urlparse(args.listen)
    if parsed.scheme == "http":
        proxy_type = "http"
    elif parsed.scheme in ["socks5", "socks"]:
        proxy_type = "socks"
    elif parsed.scheme == "ss":
        proxy_type = "ss"
    else:
        logger.fatal(f"Unknown scheme: {parsed.scheme}")
        sys.exit(1)
        
    port = parsed.port
    if not port:
        logger.fatal("Port must be specified in the listen URI")
        sys.exit(1)
        
    rad_config = load_radius_config()
    enabled_protocols = rad_config.get("enabled_protocols", [])
    rad_proto_map = {
        "http": "http",
        "socks": "socks",
        "ss": "shadowsocks"
    }
    use_radius = rad_proto_map.get(proxy_type) in enabled_protocols
    
    logger.info(f"Loaded RADIUS Config: IP={rad_config['server_ip']}, UseRADIUS={use_radius}")
    
    # Callback dispatcher
    if proxy_type == "http":
        handler = lambda r, w: handle_http_proxy(r, w, rad_config, use_radius)
        logger.info(f"Starting HTTP Proxy Server on port {port} (RADIUS: {use_radius})...")
    elif proxy_type == "socks":
        handler = lambda r, w: handle_socks_proxy(r, w, rad_config, use_radius)
        logger.info(f"Starting SOCKS5 Proxy Server on port {port} (RADIUS: {use_radius})...")
    elif proxy_type == "ss":
        handler = lambda r, w: handle_ss_proxy(r, w, rad_config, use_radius)
        logger.info(f"Starting Shadowsocks Proxy Server on port {port} (RADIUS: {use_radius})...")
        
    # Start Proxy Listener
    server = await asyncio.start_server(handler, "0.0.0.0", port)
    
    # Start CoA Disconnect Listener (Only run if RADIUS is enabled)
    if use_radius:
        coa_task = asyncio.create_task(coa_listener(rad_config))
    
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Proxy server stopped.")
    except Exception as e:
        logger.fatal(f"Fatal error: {e}")
        traceback.print_exc()
        sys.exit(1)
