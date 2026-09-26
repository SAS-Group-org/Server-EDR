import hashlib
import hmac
import json
import os
import socket
import ssl
import struct
import threading
from datetime import datetime

try:
    import pwd
except ImportError:
    pwd = None

# ═══════════════════════════════════════════════════════════════
#  CONFIGURATION — edit these values for deployment (or use env vars)
# ═══════════════════════════════════════════════════════════════

SERVER_HOST             = os.environ.get("EDR_SERVER_HOST", os.environ.get("RAT_SERVER_HOST", "127.0.0.1"))
SERVER_PORT             = int(os.environ.get("EDR_SERVER_PORT", os.environ.get("RAT_SERVER_PORT", "4444")))
PSK                     = os.environ.get("EDR_PSK", os.environ.get("RAT_PSK", "PASTE_PSK_HERE"))
CERT_FINGERPRINT        = os.environ.get("EDR_CERT_FINGERPRINT", os.environ.get("RAT_CERT_FINGERPRINT", ""))
USE_TLS                 = os.environ.get("EDR_USE_TLS", os.environ.get("RAT_USE_TLS", "1")).lower() not in ("0", "false", "no")
RECONNECT_SECS          = int(os.environ.get("EDR_RECONNECT_SECS", os.environ.get("RAT_RECONNECT_SECS", "10")))
MAX_MSG_BYTES           = 50 * 1024 * 1024

# Defense Configurations
FIM_ENABLED             = True
FIM_CHECK_INTERVAL_SECS = 30
DLP_ENABLED             = True
DLP_BLOCK_TRANSFERS     = False
OPENEDR_LOG_PATH        = "/var/log/edrsvc/output_events"
AUTO_INSTALL_OPENEDR    = os.environ.get("EDR_AUTO_INSTALL_OPENEDR", os.environ.get("RAT_AUTO_INSTALL_OPENEDR", "0")).lower() in ("1", "true", "yes")


# ═══════════════════════════════════════════════════════════════
#  Protocol & Stream Synchronization
# ═══════════════════════════════════════════════════════════════

_send_lock = threading.Lock()

def send_msg(stream, data: dict):
    """Thread-safe send of length-prefixed JSON message."""
    payload = json.dumps(data).encode("utf-8")
    header  = struct.pack("<I", len(payload))
    with _send_lock:
        stream.sendall(header + payload)

def recv_msg(stream) -> dict:
    """Receive length-prefixed JSON message."""
    def recv_exact(n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = stream.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed")
            buf += chunk
        return buf
    
    hdr = recv_exact(4)
    length = struct.unpack("<I", hdr)[0]
    if length == 0 or length > MAX_MSG_BYTES:
        raise ValueError(f"Invalid message length: {length}")
    raw = recv_exact(length)
    return json.loads(raw.decode("utf-8", errors="replace"))

def send_event(stream, subsystem: str, severity: str, title: str, details: str, **kwargs):
    """Emit an asynchronous security alert event to the server."""
    msg = {
        "type": "event",
        "subsystem": subsystem,
        "severity": severity,
        "title": title,
        "details": details,
        "timestamp": datetime.now().isoformat(),
        "host": socket.gethostname(),
    }
    msg.update(kwargs)
    try:
        send_msg(stream, msg)
    except Exception:
        pass

def send_telemetry(stream, category: str, events: list):
    """Emit a batched telemetry frame to the server."""
    msg = {
        "type": "telemetry",
        "category": category,
        "events": events,
        "timestamp": datetime.now().isoformat(),
        "host": socket.gethostname(),
    }
    try:
        send_msg(stream, msg)
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════
#  HMAC Authentication & TLS Pinning
# ═══════════════════════════════════════════════════════════════

def authenticate(stream, psk: str):
    """Perform HMAC challenge/response authentication."""
    challenge = recv_msg(stream)
    if challenge.get("type") != "challenge":
        raise ValueError(f"Expected challenge, got {challenge.get('type')}")
    
    nonce_bytes = bytes.fromhex(challenge["nonce"])
    hmac_digest = hmac.new(psk.encode(), nonce_bytes, hashlib.sha256).digest()
    send_msg(stream, {"type": "auth", "hmac": hmac_digest.hex()})
    
    auth_resp = recv_msg(stream)
    if auth_resp.get("type") != "auth_ok":
        raise ValueError("Authentication failed — check PSK")

def get_secure_stream(sock):
    """Upgrade socket to TLS with optional certificate pinning."""
    if not USE_TLS:
        return sock
    
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    tls_stream = context.wrap_socket(sock, server_hostname=SERVER_HOST)
    
    if CERT_FINGERPRINT:
        der = tls_stream.getpeercert(binary_form=True)
        actual_fp = hashlib.sha256(der).hexdigest().upper()
        if actual_fp != CERT_FINGERPRINT.upper():
            tls_stream.close()
            raise ValueError(f"Cert fingerprint mismatch: {actual_fp} != {CERT_FINGERPRINT}")
    
    return tls_stream


# ═══════════════════════════════════════════════════════════════
#  System Info Helpers
# ═══════════════════════════════════════════════════════════════

def get_username() -> str:
    if pwd and hasattr(os, "getuid"):
        try:
            return pwd.getpwuid(os.getuid()).pw_name
        except Exception:
            pass
    return os.environ.get("USER", os.environ.get("USERNAME", "unknown"))

def get_hostname() -> str:
    return socket.gethostname()

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Unknown"

def is_root() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return False

def get_uptime() -> str:
    try:
        with open("/proc/uptime") as f:
            uptime_secs = float(f.read().split()[0])
        days = int(uptime_secs // 86400)
        hours = int((uptime_secs % 86400) // 3600)
        mins = int((uptime_secs % 3600) // 60)
        return f"{days}d {hours}h {mins}m"
    except Exception:
        return "N/A"

def get_ram_gb():
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    return round(kb / (1024 ** 2), 2)
    except Exception:
        pass
    return "N/A"
