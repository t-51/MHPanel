#!/usr/bin/env python3
import subprocess
import time
import os
import sys
import json
import uuid
import re
import logging
import socket

# Import pyrad
try:
    import pyrad.client
    import pyrad.packet
    from pyrad.dictionary import Dictionary
except ImportError:
    print("pyrad is required. Install it using pip install pyrad", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] WG-RADIUS: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("wg_radius")

CONFIG_FILE = "/etc/vpnpanel/radius_config.json"
DICTIONARY_FILE = "/opt/vpnpanel/dictionary"
WG_CONF = "/etc/wireguard/wg0.conf"
STATE_FILE = "/var/run/wg_radius_sessions.json"

# Global state tracking: peer_pubkey -> session_info
# session_info contains: session_id, username, start_time, rx_baseline, tx_baseline, last_active
sessions_state = {}

def load_radius_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load RADIUS config: {e}")
    return None

def get_radius_client(rad_config):
    dict_inst = Dictionary(DICTIONARY_FILE)
    client = pyrad.client.Client(
        server=rad_config["server_ip"],
        secret=rad_config["shared_secret"].encode(),
        dict=dict_inst,
        authport=int(rad_config.get("auth_port", 1812)),
        acctport=int(rad_config.get("acct_port", 1813))
    )
    client.timeout = 4
    return client

def authenticate_radius(username, rad_config, client_ip="127.0.0.1"):
    try:
        client = get_radius_client(rad_config)
        # Use username as password for WireGuard peers
        req = client.CreateAuthPacket(code=pyrad.packet.AccessRequest, User_Name=username)
        req["User-Password"] = req.PwCrypt(username)
        req["NAS-Identifier"] = "aethervpn-wg"
        req["NAS-IP-Address"] = "127.0.0.1"
        req["Framed-IP-Address"] = client_ip
        
        reply = client.SendPacket(req)
        if reply.code == pyrad.packet.AccessAccept:
            limits = {}
            if 27 in reply:
                limits["session_timeout"] = int(reply[27][0])
            if (14988, 17) in reply:
                limits["total_limit"] = int(reply[(14988, 17)][0])
            if (14988, 1) in reply:
                limits["recv_limit"] = int(reply[(14988, 1)][0])
            if (14988, 2) in reply:
                limits["xmit_limit"] = int(reply[(14988, 2)][0])
            return True, limits
        return False, None
    except Exception as e:
        logger.error(f"RADIUS auth exception for {username}: {e}")
        return False, None

def send_accounting_radius(username, session_id, status, rx_bytes, tx_bytes, elapsed, rad_config, client_ip="127.0.0.1"):
    try:
        client = get_radius_client(rad_config)
        req = client.CreateAcctPacket(code=pyrad.packet.AccountingRequest, User_Name=username)
        req["Acct-Status-Type"] = status
        req["Acct-Session-Id"] = session_id
        req["NAS-Identifier"] = "aethervpn-wg"
        req["NAS-IP-Address"] = "127.0.0.1"
        req["Framed-IP-Address"] = client_ip
        
        if status in ["Stop", "Interim-Update"]:
            req["Acct-Session-Time"] = int(elapsed)
            req["Acct-Input-Octets"] = rx_bytes & 0xFFFFFFFF
            req["Acct-Output-Octets"] = tx_bytes & 0xFFFFFFFF
            
            in_giga = rx_bytes >> 32
            out_giga = tx_bytes >> 32
            if in_giga > 0:
                req["Acct-Input-Gigawords"] = in_giga
            if out_giga > 0:
                req["Acct-Output-Gigawords"] = out_giga
                
        client.SendPacket(req)
        return True
    except Exception as e:
        logger.error(f"RADIUS accounting exception for {username} ({status}): {e}")
        return False

def parse_wg_peers():
    """Parses current WireGuard running peers using `wg show wg0 dump`."""
    peers = {}
    try:
        res = subprocess.run(["wg", "show", "wg0", "dump"], capture_output=True, text=True, check=True)
        for line in res.stdout.strip().split('\n'):
            parts = line.split('\t')
            if len(parts) >= 8:
                pubkey = parts[0]
                allowed_ips = parts[3]
                latest_handshake = int(parts[4])
                tx_bytes = int(parts[5])
                rx_bytes = int(parts[6])
                peers[pubkey] = {
                    "allowed_ips": allowed_ips,
                    "latest_handshake": latest_handshake,
                    "tx": tx_bytes,
                    "rx": rx_bytes
                }
    except Exception as e:
        logger.error(f"Failed to parse WireGuard status: {e}")
    return peers

def parse_wg_conf():
    """Parses peer name and public keys from wg0.conf configuration."""
    mappings = {}
    if not os.path.exists(WG_CONF):
        return mappings
    
    current_name = None
    with open(WG_CONF, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("# Name:"):
                current_name = line.replace("# Name:", "").strip()
            elif line.lower() == "[peer]":
                pass
            elif "=" in line:
                key_part, val_part = line.split("=", 1)
                key_part = key_part.strip().lower()
                val_part = val_part.strip()
                if key_part == "publickey" and current_name:
                    mappings[val_part] = current_name
                    current_name = None
    return mappings

def save_state():
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(sessions_state, f)
    except Exception:
        pass

def load_state():
    global sessions_state
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                sessions_state = json.load(f)
        except Exception:
            pass

def remove_peer_from_interface(pubkey):
    try:
        subprocess.run(["wg", "set", "wg0", "peer", pubkey, "remove"], check=True)
        logger.info(f"Temporarily disabled WireGuard peer: {pubkey}")
    except Exception as e:
        logger.error(f"Failed to remove peer {pubkey} from interface: {e}")

def restore_peer_to_interface(pubkey, allowed_ips):
    try:
        # Re-add peer dynamically to the running kernel module
        subprocess.run(["wg", "set", "wg0", "peer", pubkey, "allowed-ips", allowed_ips], check=True)
        logger.info(f"Re-enabled WireGuard peer: {pubkey} (AllowedIPs={allowed_ips})")
    except Exception as e:
        logger.error(f"Failed to restore peer {pubkey}: {e}")

def main():
    logger.info("WireGuard RADIUS Sync Daemon starting...")
    load_state()
    
    while True:
        rad_config = load_radius_config()
        if not rad_config:
            logger.warn("RADIUS configuration not found. Sleeping for 30s...")
            time.sleep(30)
            continue
            
        # Parse current config and stats
        wg_peers_stats = parse_wg_peers()
        conf_mappings = parse_wg_conf()
        
        current_time = time.time()
        
        # 1. Update/check active sessions
        for pubkey, username in conf_mappings.items():
            stats = wg_peers_stats.get(pubkey)
            
            # If peer not in interface, it was removed. Check if we should restore it.
            if not stats:
                # Run Auth check to see if the user is valid now
                is_valid, limits = authenticate_radius(username, rad_config)
                if is_valid:
                    # Retrieve AllowedIPs from wg0.conf
                    # Let's find its allowed ips from config
                    allowed_ips = None
                    # Simple parse of allowed ips in wg0.conf for this pubkey
                    with open(WG_CONF, "r") as f:
                        lines = f.readlines()
                    for idx, line in enumerate(lines):
                        if pubkey in line:
                            # search down for AllowedIPs
                            j = idx
                            while j < len(lines) and not lines[j].strip().startswith("[Peer]"):
                                if "allowedips" in lines[j].lower():
                                    allowed_ips = lines[j].split("=", 1)[1].strip()
                                    break
                                j += 1
                            break
                    if allowed_ips:
                        restore_peer_to_interface(pubkey, allowed_ips)
                continue
                
            client_ip = stats["allowed_ips"].split("/")[0]
            
            # Detect handshake in the last 5 minutes to declare session active
            handshake_age = current_time - stats["latest_handshake"] if stats["latest_handshake"] > 0 else 999999
            
            session_active = handshake_age < 300
            
            if session_active:
                # Session is active!
                state = sessions_state.get(pubkey)
                if not state:
                    # New Session!
                    # Authenticate first
                    is_valid, limits = authenticate_radius(username, rad_config, client_ip)
                    if not is_valid:
                        logger.warn(f"User {username} failed RADIUS Auth. Disabling peer.")
                        remove_peer_from_interface(pubkey)
                        continue
                        
                    session_id = uuid.uuid4().hex
                    state = {
                        "session_id": session_id,
                        "username": username,
                        "start_time": current_time,
                        "rx_baseline": stats["rx"],
                        "tx_baseline": stats["tx"],
                        "client_ip": client_ip,
                        "total_limit": limits.get("total_limit"),
                        "recv_limit": limits.get("recv_limit"),
                        "xmit_limit": limits.get("xmit_limit"),
                        "session_timeout": limits.get("session_timeout"),
                        "last_accounting": current_time
                    }
                    sessions_state[pubkey] = state
                    save_state()
                    
                    # Send Start
                    send_accounting_radius(username, session_id, "Start", 0, 0, 0, rad_config, client_ip)
                    logger.info(f"WireGuard Accounting START for user {username} ({pubkey})")
                else:
                    # Existing Session. Compute delta bytes
                    session_rx = max(0, stats["rx"] - state["rx_baseline"])
                    session_tx = max(0, stats["tx"] - state["tx_baseline"])
                    elapsed = current_time - state["start_time"]
                    
                    # Check limits
                    limit_exceeded = False
                    if state.get("session_timeout") and elapsed >= state["session_timeout"]:
                        logger.warn(f"User {username} session timeout. Disabling peer.")
                        limit_exceeded = True
                    elif state.get("total_limit") and (session_rx + session_tx) >= state["total_limit"]:
                        logger.warn(f"User {username} total limit exceeded. Disabling peer.")
                        limit_exceeded = True
                    elif state.get("recv_limit") and session_rx >= state["recv_limit"]:
                        logger.warn(f"User {username} recv limit exceeded. Disabling peer.")
                        limit_exceeded = True
                    elif state.get("xmit_limit") and session_tx >= state["xmit_limit"]:
                        logger.warn(f"User {username} xmit limit exceeded. Disabling peer.")
                        limit_exceeded = True
                        
                    if limit_exceeded:
                        send_accounting_radius(username, state["session_id"], "Stop", session_rx, session_tx, elapsed, rad_config, client_ip)
                        remove_peer_from_interface(pubkey)
                        sessions_state.pop(pubkey, None)
                        save_state()
                        continue
                        
                    # Periodically send interim update (every 60s)
                    if current_time - state["last_accounting"] >= 60:
                        # Re-authenticate to ensure account wasn't disabled in panel/user-manager
                        is_valid, _ = authenticate_radius(username, rad_config, client_ip)
                        if not is_valid:
                            logger.warn(f"User {username} became invalid in RADIUS. Disabling peer.")
                            send_accounting_radius(username, state["session_id"], "Stop", session_rx, session_tx, elapsed, rad_config, client_ip)
                            remove_peer_from_interface(pubkey)
                            sessions_state.pop(pubkey, None)
                            save_state()
                            continue
                            
                        send_accounting_radius(username, state["session_id"], "Interim-Update", session_rx, session_tx, elapsed, rad_config, client_ip)
                        state["last_accounting"] = current_time
                        save_state()
            else:
                # Session is inactive. Check if we should stop accounting
                state = sessions_state.get(pubkey)
                if state:
                    # Peer has gone silent. Send STOP
                    session_rx = max(0, stats["rx"] - state["rx_baseline"])
                    session_tx = max(0, stats["tx"] - state["tx_baseline"])
                    elapsed = current_time - state["start_time"]
                    
                    send_accounting_radius(username, state["session_id"], "Stop", session_rx, session_tx, elapsed, rad_config, client_ip)
                    logger.info(f"WireGuard Accounting STOP (Inactive) for user {username} ({pubkey})")
                    sessions_state.pop(pubkey, None)
                    save_state()
                    
        # Clean up stale states for peers that were deleted from wg0.conf
        for pubkey in list(sessions_state.keys()):
            if pubkey not in conf_mappings:
                state = sessions_state.pop(pubkey)
                send_accounting_radius(state["username"], state["session_id"], "Stop", 0, 0, 0, rad_config)
                save_state()
                
        time.sleep(10) # Poll every 10 seconds

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Daemon stopped.")
