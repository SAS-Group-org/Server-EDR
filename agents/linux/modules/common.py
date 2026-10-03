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
#  CONFIGURATION & DYNAMIC LOADER — agent_config.json / env vars
# ═══════════════════════════════════════════════════════════════

DEFAULT_AGENT_CONFIG = {
    "server_host": "127.0.0.1",
    "server_port": 443,
    "psk": "PASTE_PSK_HERE",
    "cert_fingerprint": "",
    "use_tls": True,
    "reconnect_secs": 10,
    "max_reconnect_delay": 60,
    "log_level": "INFO",
    "watchdog_enabled": True,
    "watchdog_interval": 3,
    "heartbeat_interval": 10,
    "fim_enabled": True,
    "fim_check_interval_secs": 30,
    "dlp_enabled": True,
    "dlp_block_transfers": False,
    "openedr_log_path": "/var/log/edrsvc/output_events",
    "auto_install_openedr": False,
    "server": {
        "host": "127.0.0.1",
        "port": 443,
        "use_tls": True,
        "cert_fingerprint": "",
        "reconnect_interval": 10,
        "max_reconnect_delay": 60,
    },
    "auth": {
        "psk": "PASTE_PSK_HERE",
    },
    "agent": {
        "log_level": "INFO",
        "watchdog_enabled": True,
        "watchdog_interval": 3,
        "heartbeat_interval": 10,
    }
}

DEFAULT_CONFIG_LOCATIONS = [
    "agent_config.json",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent_config.json"),
    "/etc/sas-edr/agent_config.json",
    "/etc/sas-edr/agent.config.json",
    "/etc/server-edr/agent_config.json",
    "/etc/server-edr/agent.config.json",
]


class ValidationResultList(list):
    """List of validation errors with formatted string representation."""
    def __str__(self):
        if not self:
            return "Configuration is valid"
        return "; ".join(self)


class ConnectionProbeResult(tuple):
    """Probe result tuple (reachable, message) with direct boolean evaluation."""
    def __new__(cls, reachable: bool, message: str):
        return super().__new__(cls, (reachable, message))

    def __bool__(self):
        return bool(self[0])


def _coerce_bool(val) -> bool:
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    return s in ("1", "true", "yes", "on", "enabled")


def load_agent_config(config_path: str = None) -> dict:
    """
    Load agent configuration from injected file or environment variables.
    Priority: base defaults < injected config file < environment variables.
    Supports both nested ('server', 'auth', 'agent') and flat key layouts.
    """
    import copy
    config = copy.deepcopy(DEFAULT_AGENT_CONFIG)

    # Determine target config file path
    target_path = config_path or os.environ.get("EDR_CONFIG_FILE")
    if not target_path:
        for candidate in DEFAULT_CONFIG_LOCATIONS:
            if os.path.isfile(candidate):
                target_path = candidate
                break

    # Load from injected config file if provided or found
    if target_path:
        if os.path.exists(target_path):
            try:
                with open(target_path, "r", encoding="utf-8") as f:
                    injected = json.load(f)
                if isinstance(injected, dict):
                    # Handle nested schema
                    if isinstance(injected.get("server"), dict):
                        srv = injected["server"]
                        if "host" in srv: config["server_host"] = srv["host"]
                        if "port" in srv: config["server_port"] = srv["port"]
                        if "use_tls" in srv: config["use_tls"] = srv["use_tls"]
                        if "cert_fingerprint" in srv: config["cert_fingerprint"] = srv["cert_fingerprint"]
                        if "reconnect_interval" in srv: config["reconnect_secs"] = srv["reconnect_interval"]
                        if "max_reconnect_delay" in srv: config["max_reconnect_delay"] = srv["max_reconnect_delay"]

                    if isinstance(injected.get("auth"), dict):
                        auth = injected["auth"]
                        if "psk" in auth: config["psk"] = auth["psk"]

                    if isinstance(injected.get("agent"), dict):
                        ag = injected["agent"]
                        if "log_level" in ag: config["log_level"] = ag["log_level"]
                        if "watchdog_enabled" in ag: config["watchdog_enabled"] = ag["watchdog_enabled"]
                        if "watchdog_interval" in ag: config["watchdog_interval"] = ag["watchdog_interval"]
                        if "heartbeat_interval" in ag: config["heartbeat_interval"] = ag["heartbeat_interval"]
                        if "fim_enabled" in ag: config["fim_enabled"] = ag["fim_enabled"]
                        if "fim_check_interval_secs" in ag: config["fim_check_interval_secs"] = ag["fim_check_interval_secs"]
                        if "dlp_enabled" in ag: config["dlp_enabled"] = ag["dlp_enabled"]
                        if "dlp_block_transfers" in ag: config["dlp_block_transfers"] = ag["dlp_block_transfers"]
                        if "openedr_log_path" in ag: config["openedr_log_path"] = ag["openedr_log_path"]
                        if "auto_install_openedr" in ag: config["auto_install_openedr"] = ag["auto_install_openedr"]

                    # Also update any top-level keys
                    for k, v in injected.items():
                        if k not in ("server", "auth", "agent"):
                            config[k] = v

                    config["_config_source"] = os.path.abspath(target_path)
            except Exception as e:
                print(f"[!] Failed to load config file {target_path}: {e}")
        elif config_path:
            print(f"[!] Injected config file not found: {config_path}")

    # Environment variables override file config
    env_mappings = {
        "EDR_SERVER_HOST": "server_host",
        "EDR_SERVER_PORT": "server_port",
        "EDR_PSK": "psk",
        "EDR_CERT_FINGERPRINT": "cert_fingerprint",
        "EDR_USE_TLS": "use_tls",
        "EDR_RECONNECT_SECS": "reconnect_secs",
        "EDR_LOG_LEVEL": "log_level",
        "EDR_FIM_ENABLED": "fim_enabled",
        "EDR_FIM_CHECK_INTERVAL_SECS": "fim_check_interval_secs",
        "EDR_DLP_ENABLED": "dlp_enabled",
        "EDR_DLP_BLOCK_TRANSFERS": "dlp_block_transfers",
        "EDR_OPENEDR_LOG_PATH": "openedr_log_path",
        "EDR_AUTO_INSTALL_OPENEDR": "auto_install_openedr",
    }

    # Backward compatibility with legacy RAT_* environment variables
    rat_mappings = {
        "RAT_SERVER": "server_host",
        "RAT_SERVER_HOST": "server_host",
        "RAT_PORT": "server_port",
        "RAT_SERVER_PORT": "server_port",
        "RAT_PSK": "psk",
        "RAT_CERT_FINGERPRINT": "cert_fingerprint",
        "RAT_USE_TLS": "use_tls",
        "RAT_RECONNECT_SECS": "reconnect_secs",
        "RAT_AUTO_INSTALL_OPENEDR": "auto_install_openedr",
    }

    for env_var, config_key in rat_mappings.items():
        val = os.environ.get(env_var)
        if val is not None:
            config[config_key] = val

    for env_var, config_key in env_mappings.items():
        val = os.environ.get(env_var)
        if val is not None:
            config[config_key] = val

    # Type normalization
    try:
        config["server_port"] = int(config.get("server_port", 443))
    except (ValueError, TypeError):
        config["server_port"] = 443

    try:
        config["reconnect_secs"] = int(config.get("reconnect_secs", 10))
    except (ValueError, TypeError):
        config["reconnect_secs"] = 10

    try:
        config["fim_check_interval_secs"] = int(config.get("fim_check_interval_secs", 30))
    except (ValueError, TypeError):
        config["fim_check_interval_secs"] = 30

    config["use_tls"] = _coerce_bool(config.get("use_tls", True))
    config["fim_enabled"] = _coerce_bool(config.get("fim_enabled", True))
    config["dlp_enabled"] = _coerce_bool(config.get("dlp_enabled", True))
    config["dlp_block_transfers"] = _coerce_bool(config.get("dlp_block_transfers", False))
    config["auto_install_openedr"] = _coerce_bool(config.get("auto_install_openedr", False))
    config["server_host"] = str(config.get("server_host", "127.0.0.1"))
    config["psk"] = str(config.get("psk", ""))
    config["cert_fingerprint"] = str(config.get("cert_fingerprint", ""))
    config["log_level"] = str(config.get("log_level", "INFO")).upper()
    config["openedr_log_path"] = str(config.get("openedr_log_path", "/var/log/edrsvc/output_events"))

    # Synchronize nested dictionary structures
    config["server"] = {
        "host": config["server_host"],
        "port": config["server_port"],
        "use_tls": config["use_tls"],
        "cert_fingerprint": config["cert_fingerprint"],
        "reconnect_interval": config["reconnect_secs"],
        "max_reconnect_delay": config.get("max_reconnect_delay", 60),
    }
    config["auth"] = {
        "psk": config["psk"],
    }
    config["agent"] = {
        "log_level": config["log_level"],
        "watchdog_enabled": _coerce_bool(config.get("watchdog_enabled", True)),
        "watchdog_interval": int(config.get("watchdog_interval", 3)),
        "heartbeat_interval": int(config.get("heartbeat_interval", 10)),
    }

    return config


def validate_agent_config(config: dict) -> tuple:
    """
    Validates critical settings (SERVER_HOST, SERVER_PORT, PSK, etc.).
    Returns (is_valid: bool, errors: ValidationResultList).
    """
    errors = ValidationResultList()

    # Extract values supporting both nested and flat structures
    host = ""
    if isinstance(config.get("server"), dict) and "host" in config["server"]:
        host = str(config["server"]["host"]).strip()
    elif "server_host" in config:
        host = str(config["server_host"]).strip()

    if not host:
        errors.append("SERVER_HOST must be a non-empty address or hostname")

    port = None
    if isinstance(config.get("server"), dict) and "port" in config["server"]:
        port = config["server"]["port"]
    elif "server_port" in config:
        port = config["server_port"]

    try:
        port_int = int(port)
        if not (1 <= port_int <= 65535):
            errors.append(f"SERVER_PORT must be an integer between 1 and 65535 (got: {port})")
    except (ValueError, TypeError):
        errors.append(f"SERVER_PORT must be a valid integer (got: {port})")

    # Check TLS fingerprint format if present
    fp = ""
    if isinstance(config.get("server"), dict) and "cert_fingerprint" in config["server"]:
        fp = str(config["server"]["cert_fingerprint"]).strip()
    elif "cert_fingerprint" in config:
        fp = str(config["cert_fingerprint"]).strip()

    if fp:
        clean_fp = fp.replace(":", "").replace(" ", "")
        if len(clean_fp) != 64 or not all(c in "0123456789abcdefABCDEF" for c in clean_fp):
            errors.append(f"Invalid TLS certificate fingerprint format: '{fp}' (expected 64 hex characters)")

    # Check intervals
    reconnect_interval = None
    if isinstance(config.get("server"), dict) and "reconnect_interval" in config["server"]:
        reconnect_interval = config["server"]["reconnect_interval"]
    elif "reconnect_secs" in config:
        reconnect_interval = config["reconnect_secs"]

    if reconnect_interval is not None:
        try:
            ri = int(reconnect_interval)
            if ri <= 0:
                errors.append(f"reconnect_interval must be greater than 0 (got: {ri})")
        except (ValueError, TypeError):
            errors.append(f"reconnect_interval must be an integer (got: {reconnect_interval})")

    max_reconnect = None
    if isinstance(config.get("server"), dict) and "max_reconnect_delay" in config["server"]:
        max_reconnect = config["server"]["max_reconnect_delay"]
    elif "max_reconnect_delay" in config:
        max_reconnect = config["max_reconnect_delay"]

    if max_reconnect is not None and reconnect_interval is not None:
        try:
            if int(max_reconnect) < int(reconnect_interval):
                errors.append(f"max_reconnect_delay ({max_reconnect}) cannot be less than reconnect_interval ({reconnect_interval})")
        except (ValueError, TypeError):
            pass

    # Check agent intervals
    if isinstance(config.get("agent"), dict):
        ag = config["agent"]
        if "watchdog_interval" in ag:
            try:
                if int(ag["watchdog_interval"]) <= 0:
                    errors.append(f"watchdog_interval must be greater than 0")
            except (ValueError, TypeError):
                errors.append("watchdog_interval must be an integer")
        if "heartbeat_interval" in ag:
            try:
                if int(ag["heartbeat_interval"]) <= 0:
                    errors.append(f"heartbeat_interval must be greater than 0")
            except (ValueError, TypeError):
                errors.append("heartbeat_interval must be an integer")

    return (len(errors) == 0, errors)


def save_agent_config(config: dict, config_path: str) -> bool:
    """Saves agent configuration JSON with restrictive file permissions (0600)."""
    try:
        parent = os.path.dirname(os.path.abspath(config_path))
        if parent and not os.path.exists(parent):
            os.makedirs(parent, mode=0o700, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(config_path, flags, 0o600)
        with open(fd, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        try:
            if os.name == "posix":
                os.chmod(config_path, 0o600)
        except Exception:
            pass
        return True
    except Exception as e:
        print(f"[!] Failed to save configuration to {config_path}: {e}")
        return False


def check_server_connectivity(host: str, port: int, timeout: float = 3.0) -> ConnectionProbeResult:
    """Probes server endpoint connectivity. Returns ConnectionProbeResult(reachable, message)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, int(port)))
        return ConnectionProbeResult(True, f"Successfully reached server endpoint at {host}:{port}")
    except Exception as e:
        return ConnectionProbeResult(False, f"Connection to {host}:{port} failed: {e}")
    finally:
        try:
            s.close()
        except Exception:
            pass


def apply_agent_config(config: dict) -> None:
    """Updates module-level globals in common.py with values from config dictionary."""
    global SERVER_HOST, SERVER_PORT, PSK, CERT_FINGERPRINT, USE_TLS, RECONNECT_SECS
    global MODULE_SERVER_HOST, MODULE_SERVER_PORT, MODULE_PSK, MODULE_USE_TLS, MODULE_CERT_FINGERPRINT
    global FIM_ENABLED, FIM_CHECK_INTERVAL_SECS, DLP_ENABLED, DLP_BLOCK_TRANSFERS
    global OPENEDR_LOG_PATH, AUTO_INSTALL_OPENEDR

    # Read from nested or flat
    if isinstance(config.get("server"), dict):
        srv = config["server"]
        SERVER_HOST      = srv.get("host", SERVER_HOST)
        SERVER_PORT      = srv.get("port", SERVER_PORT)
        USE_TLS          = srv.get("use_tls", USE_TLS)
        CERT_FINGERPRINT = srv.get("cert_fingerprint", CERT_FINGERPRINT)
        RECONNECT_SECS   = srv.get("reconnect_interval", RECONNECT_SECS)

    if isinstance(config.get("auth"), dict):
        PSK = config["auth"].get("psk", PSK)

    # Flat fallback
    SERVER_HOST             = config.get("server_host", SERVER_HOST)
    SERVER_PORT             = config.get("server_port", SERVER_PORT)
    PSK                     = config.get("psk", PSK)
    CERT_FINGERPRINT        = config.get("cert_fingerprint", CERT_FINGERPRINT)
    USE_TLS                 = config.get("use_tls", USE_TLS)
    RECONNECT_SECS          = config.get("reconnect_secs", RECONNECT_SECS)
    FIM_ENABLED             = config.get("fim_enabled", FIM_ENABLED)
    FIM_CHECK_INTERVAL_SECS = config.get("fim_check_interval_secs", FIM_CHECK_INTERVAL_SECS)
    DLP_ENABLED             = config.get("dlp_enabled", DLP_ENABLED)
    DLP_BLOCK_TRANSFERS     = config.get("dlp_block_transfers", DLP_BLOCK_TRANSFERS)
    OPENEDR_LOG_PATH        = config.get("openedr_log_path", OPENEDR_LOG_PATH)
    AUTO_INSTALL_OPENEDR    = config.get("auto_install_openedr", AUTO_INSTALL_OPENEDR)

    # Module alias globals
    MODULE_SERVER_HOST      = SERVER_HOST
    MODULE_SERVER_PORT      = SERVER_PORT
    MODULE_PSK              = PSK
    MODULE_USE_TLS          = USE_TLS
    MODULE_CERT_FINGERPRINT = CERT_FINGERPRINT


# Initial bootstrap of module-level config globals
_initial_config = load_agent_config()
SERVER_HOST             = os.environ.get("EDR_SERVER_HOST", os.environ.get("RAT_SERVER_HOST", _initial_config["server_host"]))
SERVER_PORT             = int(os.environ.get("EDR_SERVER_PORT", os.environ.get("RAT_SERVER_PORT", str(_initial_config["server_port"]))))
PSK                     = _initial_config["psk"]
CERT_FINGERPRINT        = _initial_config["cert_fingerprint"]
USE_TLS                 = _initial_config["use_tls"]
RECONNECT_SECS          = _initial_config["reconnect_secs"]
MAX_MSG_BYTES           = 50 * 1024 * 1024
FIM_ENABLED             = _initial_config["fim_enabled"]
FIM_CHECK_INTERVAL_SECS = _initial_config["fim_check_interval_secs"]
DLP_ENABLED             = _initial_config["dlp_enabled"]
DLP_BLOCK_TRANSFERS     = _initial_config["dlp_block_transfers"]
OPENEDR_LOG_PATH        = _initial_config["openedr_log_path"]
AUTO_INSTALL_OPENEDR    = _initial_config["auto_install_openedr"]

MODULE_SERVER_HOST      = SERVER_HOST
MODULE_SERVER_PORT      = SERVER_PORT
MODULE_PSK              = PSK
MODULE_USE_TLS          = USE_TLS
MODULE_CERT_FINGERPRINT = CERT_FINGERPRINT


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

def get_secure_stream(sock, host: str = None, fingerprint: str = None, use_tls: bool = None):
    """Upgrade socket to TLS with optional certificate pinning."""
    active_tls = USE_TLS if use_tls is None else use_tls
    if not active_tls:
        return sock
    
    target_host = SERVER_HOST if host is None else host
    target_fp = CERT_FINGERPRINT if fingerprint is None else fingerprint

    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    tls_stream = context.wrap_socket(sock, server_hostname=target_host)
    
    if target_fp:
        der = tls_stream.getpeercert(binary_form=True)
        actual_fp = hashlib.sha256(der).hexdigest().upper()
        if actual_fp != target_fp.upper():
            tls_stream.close()
            raise ValueError(f"Cert fingerprint mismatch: {actual_fp} != {target_fp}")
    
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
