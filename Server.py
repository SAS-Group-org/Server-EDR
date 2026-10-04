#!/usr/bin/env python3
"""
Secure Endpoint Detection, Response & Defense Platform — Web Portal & Headless C2 Server
Requires: Python 3.8+
Optional: pip install cryptography   (for automatic TLS cert generation)

Features:
  - Dual-listener architecture: C2 Agent Engine (Port 443) and Web Portal (Port 8443)
  - TLS 1.2+ encryption with certificate pinning & rotating audit log
  - HMAC-SHA256 challenge-response pre-shared key (PSK) authentication
  - Duplex asynchronous messaging (synchronous commands + real-time alerts + telemetry)
  - Web Portal (HTTPS / REST API / WebSocket Live Stream on Port 8443)
  - Endpoint Defense Dashboard (SPA):
      * Security Alerts Tab (Unified real-time feed for FIM, DLP, Malware, and OpenEDR)
      * Malware Prevention & Quarantine Tab (Remote scans, quarantine vault manager)
      * File Integrity Monitoring (FIM) Tab (Baselines, real-time change detection)
      * Data Loss Prevention (DLP) Tab (PII, credit card Luhn check, transfer protection)
      * OpenEDR Tab (Service status, kernel telemetry streaming, emergency host containment)
"""
from __future__ import annotations

import argparse, asyncio, base64, collections, hashlib, hmac as _hmac, json, logging, os, queue, re
import secrets, socket, ssl, stat, struct, sys, threading, time, uuid
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network, IPv4Network
from logging.handlers import RotatingFileHandler
from typing import Callable, Dict, List, Optional, Tuple, Any, Set
from aiohttp import web, WSMsgType

try:
    from agents.linux.package_linux_agent import build_linux_package
except ImportError:
    build_linux_package = None

try:
    from agents.windows.package_windows_agent import build_windows_package
except ImportError:
    build_windows_package = None

# ─────────────────────────────────────────────────────────────
DEFAULT_HOST            = "127.0.0.1"
DEFAULT_C2_PORT         = 443       # Migrated from 4444
DEFAULT_PORT            = DEFAULT_C2_PORT
DEFAULT_WEB_PORT        = 8443      # Web Portal binding port
MAX_MSG_BYTES           = 50 * 1024 * 1024   # 50 MB hard cap — prevents memory DoS
AUTH_TIMEOUT_SECS       = 15                  # seconds to complete TLS + HMAC handshake
CERT_FILE               = "edr_server.crt" if os.path.exists("edr_server.crt") or not os.path.exists("rat_server.crt") else "rat_server.crt"
KEY_FILE                = "edr_server.key" if os.path.exists("edr_server.key") or not os.path.exists("rat_server.key") else "rat_server.key"
PSK_FILE                = "edr_psk.txt" if os.path.exists("edr_psk.txt") or not os.path.exists("rat_psk.txt") else "rat_psk.txt"
FPRINT_FILE             = "edr_fingerprint.txt" if os.path.exists("edr_fingerprint.txt") or not os.path.exists("rat_fingerprint.txt") else "rat_fingerprint.txt"
LOG_FILE                = "edr_audit.log"
DEFAULT_CONFIG_FILE     = "server_config.json"
DEFAULT_ENROLLMENT_FILE = "enrollment_credentials.json"

C = {
    "base":    "#1e1e2e", "mantle":  "#181825", "crust":   "#11111b",
    "surface0":"#313244", "surface1":"#45475a", "surface2":"#585b70",
    "overlay0":"#6c7086", "overlay1":"#7f849c", "text":    "#cdd6f4",
    "subtext": "#a6adc8", "blue":    "#89b4fa", "lavender":"#b4befe",
    "mauve":   "#cba6f7", "red":     "#f38ba8", "peach":   "#fab387",
    "yellow":  "#f9e2af", "green":   "#a6e3a1", "teal":    "#94e2d5",
    "sky":     "#89dceb",
}

MONO = "Courier New"


# ════════════════════════════════════════════════════════════════
#  DLP Engine (Server-side & Shared Rule Verification)
# ════════════════════════════════════════════════════════════════

def luhn_checksum_valid(card_number: str) -> bool:
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


class DLPEngine:
    PATTERNS = {
        "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        "US_SSN": re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b"),
        "AWS_KEY": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "GITHUB_PAT": re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"),
        "PRIVATE_KEY": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "JWT_TOKEN": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    }

    @classmethod
    def scan_text(cls, text: str) -> List[dict]:
        findings = []
        for match in cls.PATTERNS["CREDIT_CARD"].finditer(text):
            raw = re.sub(r"[ -]", "", match.group(0))
            if luhn_checksum_valid(raw):
                redacted = raw[:4] + "*" * (len(raw) - 8) + raw[-4:]
                findings.append({"rule": "CREDIT_CARD", "severity": "CRITICAL", "preview": redacted})
        for match in cls.PATTERNS["US_SSN"].finditer(text):
            val = match.group(0)
            redacted = "***-**-" + val.replace("-", "").replace(" ", "")[-4:]
            findings.append({"rule": "US_SSN", "severity": "HIGH", "preview": redacted})
        for match in cls.PATTERNS["AWS_KEY"].finditer(text):
            val = match.group(1)
            findings.append({"rule": "AWS_KEY", "severity": "CRITICAL", "preview": val[:4] + "..." + val[-4:]})
        for match in cls.PATTERNS["GITHUB_PAT"].finditer(text):
            val = match.group(1)
            findings.append({"rule": "GITHUB_PAT", "severity": "CRITICAL", "preview": val[:8] + "..."})
        if cls.PATTERNS["PRIVATE_KEY"].search(text):
            findings.append({"rule": "PRIVATE_KEY", "severity": "CRITICAL", "preview": "-----BEGIN PRIVATE KEY----- [REDACTED]"})
        for match in cls.PATTERNS["JWT_TOKEN"].finditer(text):
            val = match.group(0)
            findings.append({"rule": "JWT_TOKEN", "severity": "MEDIUM", "preview": val[:12] + "..."})
        return findings

    @classmethod
    def scan_file(cls, path: str, max_bytes: int = 5 * 1024 * 1024) -> List[dict]:
        if not os.path.isfile(path):
            return []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return cls.scan_text(f.read(max_bytes))
        except Exception:
            return []


# ════════════════════════════════════════════════════════════════
#  TLS Certificate & Key Management
# ════════════════════════════════════════════════════════════════

def _pem_fingerprint(pem_path: str) -> str:
    with open(pem_path, "rb") as f:
        pem = f.read()
    b64_lines = []
    inside = False
    for line in pem.splitlines():
        if b"BEGIN CERTIFICATE" in line:
            inside = True
            continue
        if b"END CERTIFICATE" in line:
            break
        if inside:
            b64_lines.append(line.strip())
    der = base64.b64decode(b"".join(b64_lines))
    return hashlib.sha256(der).hexdigest().upper()


# ════════════════════════════════════════════════════════════════
#  Security & Restrictive Permissions Management
# ════════════════════════════════════════════════════════════════

def set_restrictive_permissions(path: str) -> bool:
    """Sets restrictive file permissions (0600 on POSIX, restricted ACLs on Windows)."""
    if not os.path.exists(path):
        return False
    try:
        if os.name == "posix":
            os.chmod(path, 0o600)
            return True
        elif os.name == "nt":
            username = os.environ.get("USERNAME")
            if username:
                import subprocess
                cmd = [
                    "icacls.exe", path, "/inheritance:r",
                    "/grant:r", f"{username}:F",
                    "/grant:r", "*S-1-5-32-544:F",  # BUILTIN\Administrators
                    "/grant:r", "*S-1-5-18:F"       # NT AUTHORITY\SYSTEM
                ]
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            os.chmod(path, 0o600)
            return True
    except Exception as e:
        print(f"[!] Warning: Failed setting restrictive permissions on {path}: {e}")
        return False
    return True


def check_restrictive_permissions(path: str) -> bool:
    """Checks if file has restrictive permissions (no group/world access on POSIX)."""
    if not os.path.exists(path):
        return False
    if os.name == "posix":
        mode = os.stat(path).st_mode
        return (mode & 0o077) == 0
    return True


def secure_write_file(path: str, content: str | bytes) -> None:
    """Safely writes content to a file ensuring restrictive permissions (0600) from creation."""
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.exists(parent):
        os.makedirs(parent, mode=0o700, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = 0o600
    fd = os.open(path, flags, mode)
    with open(fd, "wb" if isinstance(content, bytes) else "w", encoding=None if isinstance(content, bytes) else "utf-8") as f:
        f.write(content)
    set_restrictive_permissions(path)


def mask_credential(val: str, show_prefix: int = 4, show_suffix: int = 4) -> str:
    """Masks a secret credential for secure display or logging."""
    if not val:
        return ""
    if len(val) <= show_prefix + show_suffix:
        return "*" * len(val)
    return val[:show_prefix] + "..." + val[-show_suffix:]


# ════════════════════════════════════════════════════════════════
#  TLS Certificate & Key Management
# ════════════════════════════════════════════════════════════════

def _gen_cert_cryptography(cert_path: str, key_path: str) -> str:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime as dt, ipaddress as ipa

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EDRServer")])

    san_ips = {ipa.IPv4Address("127.0.0.1")}
    try:
        san_ips.add(ipa.IPv4Address(socket.gethostbyname(socket.gethostname())))
    except Exception:
        pass

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName("localhost")] + [x509.IPAddress(ip) for ip in san_ips]
        ), critical=False)
        .sign(key, hashes.SHA256())
    )

    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    secure_write_file(key_path, key_bytes)
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    set_restrictive_permissions(cert_path)
    return _pem_fingerprint(cert_path)


def _gen_cert_openssl(cert_path: str, key_path: str) -> str:
    import subprocess
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:4096",
        "-keyout", key_path, "-out", cert_path,
        "-days", "3650", "-nodes", "-subj", "/CN=EDRServer"
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    set_restrictive_permissions(key_path)
    set_restrictive_permissions(cert_path)
    return _pem_fingerprint(cert_path)


def generate_tls_identity(
    cert_path: str = CERT_FILE,
    key_path: str = KEY_FILE,
    force: bool = False
) -> Tuple[str, str, str]:
    """Generates TLS identity (certificate + private key) with restrictive permissions on key."""
    if not force and os.path.exists(cert_path) and os.path.exists(key_path):
        fp = _pem_fingerprint(cert_path)
        set_restrictive_permissions(key_path)
        return cert_path, key_path, fp

    print("[*] Generating TLS identity files (4096-bit RSA certificate and private key)...")
    fp = None
    for gen in (_gen_cert_cryptography, _gen_cert_openssl):
        try:
            fp = gen(cert_path, key_path)
            set_restrictive_permissions(key_path)
            set_restrictive_permissions(cert_path)
            print(f"[+] TLS certificate generated: {cert_path}")
            print(f"[+] TLS private key generated: {key_path}")
            break
        except ImportError:
            pass
        except Exception as e:
            print(f"[!] TLS generation failed with generator {gen.__name__}: {e}")

    if not fp and os.path.exists(cert_path):
        fp = _pem_fingerprint(cert_path)
    if not fp:
        raise RuntimeError("Failed to generate TLS identity files using both cryptography and openssl.")
    return cert_path, key_path, fp


def ensure_cert(cert_path: str, key_path: str) -> Optional[str]:
    if os.path.exists(cert_path) and os.path.exists(key_path):
        set_restrictive_permissions(key_path)
        return _pem_fingerprint(cert_path)
    try:
        _, _, fp = generate_tls_identity(cert_path, key_path)
        return fp
    except Exception as e:
        print(f"[!] cert gen failed: {e}")
        return None


def ensure_psk(psk_file: str, explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    if os.path.exists(psk_file):
        set_restrictive_permissions(psk_file)
        with open(psk_file, "r", encoding="utf-8") as f:
            return f.read().strip()
    psk = secrets.token_hex(32)
    secure_write_file(psk_file, psk)
    print(f"[+] Auto-generated PSK saved to {psk_file} with restrictive permissions")
    return psk


# ════════════════════════════════════════════════════════════════
#  Enrollment Credentials Management
# ════════════════════════════════════════════════════════════════

def generate_enrollment_credentials(
    server_host: str,
    server_port: int,
    psk: str,
    cert_fingerprint: str = "",
    use_tls: bool = True,
    reconnect_secs: int = 5,
    web_port: int = DEFAULT_WEB_PORT,
) -> Dict[str, Any]:
    """Generates enrollment credentials for secure server-client communication."""
    return {
        "server_host": server_host,
        "server_port": int(server_port),
        "web_port": int(web_port),
        "psk": psk,
        "cert_fingerprint": cert_fingerprint,
        "use_tls": bool(use_tls),
        "reconnect_secs": int(reconnect_secs),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def export_enrollment_credentials(
    credentials: Dict[str, Any],
    output_path: str = DEFAULT_ENROLLMENT_FILE
) -> str:
    """Exports enrollment credentials to a file with restrictive permissions (0600)."""
    secure_write_file(output_path, json.dumps(credentials, indent=2))
    return output_path


def generate_agent_config(
    credentials: Dict[str, Any],
    output_path: Optional[str] = None,
    **overrides
) -> Dict[str, Any]:
    """Generates an agent_config.json configuration structure compatible with Windows and Linux agents."""
    host = credentials.get("server_host", "127.0.0.1")
    if host in ("0.0.0.0", "::"):
        try:
            host = socket.gethostbyname(socket.gethostname())
        except Exception:
            host = "127.0.0.1"

    config = {
        "server_host": overrides.get("server_host", host),
        "server_port": overrides.get("server_port", credentials.get("server_port", DEFAULT_PORT)),
        "psk": overrides.get("psk", credentials.get("psk", "")),
        "cert_fingerprint": overrides.get("cert_fingerprint", credentials.get("cert_fingerprint", "")),
        "use_tls": overrides.get("use_tls", credentials.get("use_tls", True)),
        "reconnect_secs": overrides.get("reconnect_secs", credentials.get("reconnect_secs", 5)),
        "fim_enabled": overrides.get("fim_enabled", True),
        "fim_check_interval_secs": overrides.get("fim_check_interval_secs", 10),
        "dlp_enabled": overrides.get("dlp_enabled", True),
        "dlp_block_transfers": overrides.get("dlp_block_transfers", False),
        "openedr_log_path": overrides.get("openedr_log_path", "/var/log/server-edr/telemetry.log"),
        "auto_install_openedr": overrides.get("auto_install_openedr", True)
    }
    if output_path:
        secure_write_file(output_path, json.dumps(config, indent=2))
    return config


# ════════════════════════════════════════════════════════════════
#  Configuration Persistence & Model
# ════════════════════════════════════════════════════════════════

class ServerConfig:
    """Persistent configuration for Server-EDR."""
    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        web_port: int = DEFAULT_WEB_PORT,
        psk: str = "",
        use_tls: bool = True,
        cert_file: str = CERT_FILE,
        key_file: str = KEY_FILE,
        cert_fingerprint: str = "",
        psk_file: str = PSK_FILE,
        fingerprint_file: str = FPRINT_FILE,
        allow_cidrs: Optional[List[str]] = None,
        enrollment_credentials: Optional[Dict[str, Any]] = None,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
        config_path: str = DEFAULT_CONFIG_FILE,
    ):
        self.host = host
        self.port = int(port)
        self.web_port = int(web_port)
        self.psk = psk
        self.use_tls = bool(use_tls)
        self.cert_file = cert_file
        self.key_file = key_file
        self.cert_fingerprint = cert_fingerprint
        self.psk_file = psk_file
        self.fingerprint_file = fingerprint_file
        self.allow_cidrs = list(allow_cidrs or [])
        self.config_path = config_path
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.updated_at = updated_at or datetime.now(timezone.utc).isoformat()
        self.enrollment_credentials = enrollment_credentials or generate_enrollment_credentials(
            self.host, self.port, self.psk, self.cert_fingerprint, self.use_tls, web_port=self.web_port
        )

    def validate(self) -> None:
        if not self.host or not isinstance(self.host, str):
            raise ValueError(f"Invalid server host: {self.host}")
        if not (1 <= self.port <= 65535):
            raise ValueError(f"Invalid server port (must be 1-65535): {self.port}")
        if not (1 <= self.web_port <= 65535):
            raise ValueError(f"Invalid server web_port (must be 1-65535): {self.web_port}")
        if not self.psk:
            raise ValueError("Pre-shared key (PSK) cannot be empty")
        if self.allow_cidrs:
            for cidr in self.allow_cidrs:
                try:
                    ip_network(cidr, strict=False)
                except ValueError as e:
                    raise ValueError(f"Invalid CIDR in allowlist '{cidr}': {e}")
        if self.use_tls:
            if not self.cert_file or not self.key_file:
                raise ValueError("TLS is enabled but cert_file or key_file is not specified")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server_host": self.host,
            "server_port": self.port,
            "web_port": self.web_port,
            "psk": self.psk,
            "use_tls": self.use_tls,
            "cert_file": self.cert_file,
            "key_file": self.key_file,
            "cert_fingerprint": self.cert_fingerprint,
            "psk_file": self.psk_file,
            "fingerprint_file": self.fingerprint_file,
            "allow_cidrs": self.allow_cidrs,
            "enrollment_credentials": self.enrollment_credentials,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], config_path: str = DEFAULT_CONFIG_FILE) -> ServerConfig:
        cfg = cls(
            host=data.get("server_host", data.get("host", DEFAULT_HOST)),
            port=data.get("server_port", data.get("port", DEFAULT_PORT)),
            web_port=data.get("web_port", DEFAULT_WEB_PORT),
            psk=data.get("psk", ""),
            use_tls=data.get("use_tls", True),
            cert_file=data.get("cert_file", CERT_FILE),
            key_file=data.get("key_file", KEY_FILE),
            cert_fingerprint=data.get("cert_fingerprint", ""),
            psk_file=data.get("psk_file", PSK_FILE),
            fingerprint_file=data.get("fingerprint_file", FPRINT_FILE),
            allow_cidrs=data.get("allow_cidrs", []),
            enrollment_credentials=data.get("enrollment_credentials"),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            config_path=config_path,
        )
        cfg.validate()
        return cfg

    def to_agent_config(self, **overrides) -> Dict[str, Any]:
        return generate_agent_config(self.enrollment_credentials, **overrides)

    def to_enrollment_credentials(self) -> Dict[str, Any]:
        return generate_enrollment_credentials(
            self.host, self.port, self.psk, self.cert_fingerprint, self.use_tls, web_port=self.web_port
        )


def save_server_config(config: ServerConfig, config_path: Optional[str] = None) -> str:
    """Persists ServerConfig to JSON file with restrictive permissions (0600)."""
    path = config_path or config.config_path or DEFAULT_CONFIG_FILE
    config.validate()
    config.updated_at = datetime.now(timezone.utc).isoformat()
    config.enrollment_credentials = config.to_enrollment_credentials()
    data = config.to_dict()
    secure_write_file(path, json.dumps(data, indent=2))
    AUDIT.info("CONFIG_SAVED  path=%s  host=%s  port=%d  web_port=%d", path, config.host, config.port, config.web_port)
    return path


def load_server_config(config_path: str = DEFAULT_CONFIG_FILE) -> ServerConfig:
    """Loads and validates configuration from persistent storage with permission enforcement."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Server configuration file not found: {config_path}")

    if not check_restrictive_permissions(config_path):
        print(f"[!] Warning: Permissive file permissions detected on {config_path}. Restricting...")
        set_restrictive_permissions(config_path)

    with open(config_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse server configuration JSON: {e}")

    config = ServerConfig.from_dict(data, config_path=config_path)
    if os.path.exists(config.key_file):
        set_restrictive_permissions(config.key_file)
    if os.path.exists(config.psk_file):
        set_restrictive_permissions(config.psk_file)
    return config


def reload_server_config(
    current_config: Optional[ServerConfig] = None,
    config_path: str = DEFAULT_CONFIG_FILE
) -> ServerConfig:
    """Reloads configuration from persistent storage and updates running state."""
    new_cfg = load_server_config(config_path)
    if current_config is not None:
        current_config.host = new_cfg.host
        current_config.port = new_cfg.port
        current_config.web_port = new_cfg.web_port
        current_config.psk = new_cfg.psk
        current_config.use_tls = new_cfg.use_tls
        current_config.cert_file = new_cfg.cert_file
        current_config.key_file = new_cfg.key_file
        current_config.cert_fingerprint = new_cfg.cert_fingerprint
        current_config.allow_cidrs = new_cfg.allow_cidrs
        current_config.enrollment_credentials = new_cfg.enrollment_credentials
        current_config.updated_at = new_cfg.updated_at
    AUDIT.info("CONFIG_RELOAD  path=%s  host=%s  port=%d  web_port=%d  tls=%s",
               config_path, new_cfg.host, new_cfg.port, new_cfg.web_port, new_cfg.use_tls)
    return new_cfg


# ════════════════════════════════════════════════════════════════
#  First-Run Configuration Wizard & GUI Dialogs
# ════════════════════════════════════════════════════════════════

# ════════════════════════════════════════════════════════════════
#  Agent Package Builder (Programmatic Backend)
# ════════════════════════════════════════════════════════════════

def build_agent_package(
    os_type: str,
    output_path: Optional[str] = None,
    server_host: Optional[str] = None,
    server_port: Optional[int] = None,
    psk: Optional[str] = None,
    cert_fingerprint: Optional[str] = None,
    use_tls: bool = True,
    polling_interval: int = 10,
    group_tag: Optional[str] = None,
    overrides: Optional[Dict[str, Any]] = None,
    config: Optional[ServerConfig] = None,
    version: str = "1.0.0"
) -> str:
    """
    Builds a deployable agent package for Linux (.tar.gz) or Windows (.zip).
    Supports server endpoint, polling interval, and group-tag overrides.
    """
    os_type_clean = os_type.strip().lower()
    if os_type_clean not in ("linux", "windows"):
        raise ValueError(f"Unsupported OS type '{os_type}'. Supported: 'linux', 'windows'")

    # Load default server config if not provided
    if config is None:
        try:
            config = load_server_config(DEFAULT_CONFIG_FILE)
        except Exception:
            config = None

    host = server_host or (config.host if config else "127.0.0.1")
    port = int(server_port or (config.port if config else DEFAULT_PORT))
    psk_val = psk or (config.psk if config else "")
    fp = cert_fingerprint or (config.cert_fingerprint if config else "")
    tls = use_tls if use_tls is not None else (config.use_tls if config else True)
    interval = int(polling_interval or 10)
    tag = str(group_tag or "")

    agent_config_data = {
        "server": {
            "host": host,
            "port": port,
            "use_tls": tls,
            "cert_fingerprint": fp,
            "reconnect_interval": interval,
            "max_reconnect_delay": max(interval * 6, 60)
        },
        "auth": {
            "psk": psk_val
        },
        "agent": {
            "log_level": "INFO",
            "group_tag": tag,
            "polling_interval": interval,
            "heartbeat_interval": interval,
            "watchdog_enabled": True,
            "watchdog_interval": 3,
            "fim_enabled": True,
            "dlp_enabled": True,
            "dlp_block_transfers": False
        },
        "server_host": host,
        "server_port": port,
        "psk": psk_val,
        "cert_fingerprint": fp,
        "cert_thumbprint": fp,
        "use_tls": tls,
        "reconnect_secs": interval,
        "group_tag": tag,
    }
    if overrides:
        agent_config_data.update(overrides)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    dist_dir = os.path.join(base_dir, "dist")
    os.makedirs(dist_dir, exist_ok=True)

    if os_type_clean == "linux":
        if build_linux_package is None:
            raise ImportError("build_linux_package is not available in agents.linux.package_linux_agent")
        out = output_path or os.path.join(dist_dir, "server-edr-agent-linux.tar.gz")
        res_path = build_linux_package(
            output_path=out,
            config_data=agent_config_data,
            source_dir=os.path.join(base_dir, "agents", "linux")
        )
    else:  # windows
        if build_windows_package is None:
            raise ImportError("build_windows_package is not available in agents.windows.package_windows_agent")
        out = output_path or os.path.join(dist_dir, f"Server-EDR-Agent-Windows-v{version}.zip")
        res_path = build_windows_package(
            output_path=out,
            config_data=agent_config_data,
            source_dir=os.path.join(base_dir, "agents", "windows"),
            version=version
        )

    AUDIT.info("AGENT_PACKAGE_BUILT  os=%s  path=%s  host=%s  port=%d  group=%s  interval=%d",
               os_type_clean, res_path, host, port, tag, interval)
    return res_path


def run_config_wizard(
    config_path: str = DEFAULT_CONFIG_FILE,
    interactive: bool = False,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    psk: Optional[str] = None,
    use_tls: bool = True,
    cert_file: str = CERT_FILE,
    key_file: str = KEY_FILE,
    allow_cidrs: Optional[List[str]] = None,
    web_port: int = DEFAULT_WEB_PORT,
    **kwargs
) -> ServerConfig:
    """
    Executes first-run configuration wizard flow.
    Generates automated first-run configuration with secure defaults for headless server operation.
    """
    psk_val = psk or secrets.token_hex(32)
    fingerprint = ""
    if use_tls:
        try:
            _, _, fingerprint = generate_tls_identity(cert_file, key_file)
        except Exception as e:
            print(f"[!] Failed generating TLS identity: {e}. Falling back to unencrypted mode.")
            use_tls = False

    secure_write_file(PSK_FILE, psk_val)
    if fingerprint:
        secure_write_file(FPRINT_FILE, fingerprint)

    enrollment = generate_enrollment_credentials(
        host, port, psk_val, fingerprint, use_tls, web_port=web_port
    )
    export_enrollment_credentials(enrollment, DEFAULT_ENROLLMENT_FILE)

    config = ServerConfig(
        host=host,
        port=port,
        web_port=web_port,
        psk=psk_val,
        use_tls=use_tls,
        cert_file=cert_file,
        key_file=key_file,
        cert_fingerprint=fingerprint,
        allow_cidrs=allow_cidrs or [],
        enrollment_credentials=enrollment,
        config_path=config_path,
    )
    save_server_config(config, config_path)
    return config


def load_authoritative_checksums() -> Dict[str, str]:
    """Loads authoritative SHA-256 hashes from Checksums file."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(os.getcwd(), "Checksums"),
        os.path.join(script_dir, "Checksums"),
    ]
    hashes: Dict[str, str] = {}
    for c in candidates:
        if os.path.isfile(c):
            try:
                with open(c, "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            h = parts[0].lower()
                            p = parts[1].strip()
                            hashes[p] = h
                            hashes[p.replace("\\", "/")] = h
                            hashes[os.path.basename(p)] = h
                break
            except Exception:
                pass
    return hashes


# ════════════════════════════════════════════════════════════════
#  Audit & Server Logging
# ════════════════════════════════════════════════════════════════

def configure_server_logging(debug: bool = False, log_file: str = LOG_FILE, console: bool = True) -> logging.Logger:
    """Configures server logging with rotating file handler and optional console stream handler."""
    global AUDIT
    log = logging.getLogger("edr_audit")
    level = logging.DEBUG if debug else logging.INFO
    log.setLevel(level)

    for h in list(log.handlers):
        log.removeHandler(h)

    formatter = logging.Formatter(
        "%(asctime)s  %(levelname)-7s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    try:
        fh = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(formatter)
        log.addHandler(fh)
    except Exception as e:
        print(f"[!] Warning: Failed initializing audit log at {log_file}: {e}")

    if console:
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(level)
        ch.setFormatter(logging.Formatter(
            "[%(asctime)s] [%(levelname)-7s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        log.addHandler(ch)

    AUDIT = log
    return log


def _setup_audit_log() -> logging.Logger:
    env_debug = os.environ.get("EDR_DEBUG", "").lower() in ("1", "true", "yes") or os.environ.get("EDR_LOG_LEVEL", "").upper() == "DEBUG"
    return configure_server_logging(debug=env_debug, log_file=LOG_FILE, console=True)


AUDIT = _setup_audit_log()


# ════════════════════════════════════════════════════════════════
#  Network Layer & Agent Abstraction
# ════════════════════════════════════════════════════════════════

class Agent:
    """Represents an authenticated endpoint sensor."""

    def __init__(self, conn: socket.socket, addr: Tuple[str, int]):
        self.conn         = conn
        self.addr         = addr
        self.id           = uuid.uuid4().hex[:8]
        self.hostname     = "Unknown"
        self.username     = "Unknown"
        self.os           = "Unknown"
        self.arch         = "Unknown"
        self.ip           = addr[0]
        self.is_admin     = False
        self.ps_ver       = "?"
        self.os_type      = "windows"
        self.defense_caps = []
        self.connected_at = datetime.now()
        self.last_seen: datetime = datetime.now()
        self.attestation_status: str = "Unverified"
        self.attestation_details: dict = {}
        self._liveness_alerted: bool = False
        self._send_lock   = threading.Lock()
        self._pend_lock   = threading.Lock()
        self._pending: Dict[str, dict] = {}

    def _recv_exact(self, n: int) -> Optional[bytes]:
        buf = b""
        while len(buf) < n:
            try:
                chunk = self.conn.recv(n - len(buf))
            except (OSError, ssl.SSLError):
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    def recv_msg(self) -> Optional[dict]:
        hdr = self._recv_exact(4)
        if not hdr:
            return None
        length = struct.unpack("<I", hdr)[0]
        if length == 0 or length > MAX_MSG_BYTES:
            AUDIT.warning("BAD_LENGTH  len=%d  ip=%s", length, self.addr[0])
            return None
        raw = self._recv_exact(length)
        if not raw:
            return None
        try:
            msg = json.loads(raw.decode("utf-8", errors="replace"))
            AUDIT.debug("RECV_MSG  ip=%s  type=%s  id=%s  size=%d",
                        self.addr[0], msg.get("type"), msg.get("id", ""), length)
            return msg
        except json.JSONDecodeError as e:
            AUDIT.warning("BAD_JSON  ip=%s  err=%s", self.addr[0], e)
            return None

    def send_msg(self, data: dict) -> bool:
        try:
            payload = json.dumps(data).encode("utf-8")
            header  = struct.pack("<I", len(payload))
            with self._send_lock:
                self.conn.sendall(header + payload)
            AUDIT.debug("SEND_MSG  ip=%s  type=%s  id=%s  size=%d",
                        self.addr[0], data.get("type"), data.get("id", ""), len(payload))
            return True
        except (OSError, ssl.SSLError) as e:
            AUDIT.debug("SEND_MSG_FAIL  ip=%s  type=%s  err=%s",
                        self.addr[0], data.get("type"), e)
            return False

    def send_command(self, command: str, args=None, **kwargs) -> Tuple[str, threading.Event]:
        mid = uuid.uuid4().hex[:8]
        msg = {"id": mid, "command": command}
        if args is not None:
            msg["args"] = args
        msg.update(kwargs)
        ev = threading.Event()
        with self._pend_lock:
            self._pending[mid] = {"event": ev, "response": None}
        sent = self.send_msg(msg)
        if not sent:
            with self._pend_lock:
                entry = self._pending.get(mid)
                if entry:
                    entry["response"] = {"status": "error", "output": "Connection lost: failed to send command"}
                    entry["event"].set()
        return mid, ev

    def abort_pending(self, reason: str = "Agent disconnected"):
        """Wake all waiting caller threads if the agent disconnects unexpectedly."""
        with self._pend_lock:
            for mid, entry in list(self._pending.items()):
                if entry.get("response") is None:
                    entry["response"] = {"status": "error", "output": reason}
                    entry["event"].set()

    def deliver_response(self, mid: str, response: dict):
        with self._pend_lock:
            entry = self._pending.get(mid)
        if entry:
            entry["response"] = response
            entry["event"].set()

    def wait_response(self, mid: str, timeout: float = 30) -> Optional[dict]:
        with self._pend_lock:
            entry = self._pending.get(mid)
        if not entry:
            return None
        hit = entry["event"].wait(timeout)
        with self._pend_lock:
            self._pending.pop(mid, None)
        return entry["response"] if hit else None


class EDRServer:
    """
    Multi-agent TCP server with TLS 1.2+, HMAC challenge auth,
    and multiplexed command/alert/telemetry dispatching.
    """

    def __init__(
        self,
        host: str,
        port: int,
        psk: str,
        tls_context: Optional[ssl.SSLContext] = None,
        allow_nets: Optional[List[IPv4Network]] = None,
    ):
        self.host        = host
        self.port        = port
        self._psk        = psk.encode()
        self.tls_context = tls_context
        self.allow_nets  = allow_nets or []
        self._agents: Dict[str, Agent] = {}
        self._lock       = threading.Lock()
        self._cbs: List[Callable] = []
        self._security_events = collections.deque(maxlen=1000)
        self._telemetry_events = collections.deque(maxlen=500)
        self._sock: Optional[socket.socket] = None

    def update_credentials(self, psk: Optional[str] = None, allow_nets: Optional[List[IPv4Network]] = None):
        """Updates pre-shared key and allowed networks at runtime."""
        with self._lock:
            if psk:
                self._psk = psk.encode()
            if allow_nets is not None:
                self.allow_nets = allow_nets

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(50)
        threading.Thread(target=self._accept_loop, daemon=True, name="accept").start()
        threading.Thread(target=self._liveness_loop, daemon=True, name="liveness").start()

    def _ip_allowed(self, ip: str) -> bool:
        if not self.allow_nets:
            return True
        try:
            addr = ip_address(ip)
            return any(addr in net for net in self.allow_nets)
        except ValueError:
            return False

    def _accept_loop(self):
        while True:
            try:
                raw_conn, addr = self._sock.accept()
            except OSError:
                break
            AUDIT.debug("TCP_ACCEPT  ip=%s  port=%d", addr[0], addr[1])
            if not self._ip_allowed(addr[0]):
                AUDIT.warning("REJECT_IP  ip=%s  port=%d (not in allowlist)", addr[0], addr[1])
                raw_conn.close()
                continue
            raw_conn.settimeout(AUTH_TIMEOUT_SECS)
            threading.Thread(
                target=self._handle,
                args=(raw_conn, addr),
                daemon=True,
                name=f"agent-{addr[0]}:{addr[1]}",
            ).start()

    def _handle(self, raw_conn: socket.socket, addr: Tuple[str, int]):
        conn = raw_conn
        if self.tls_context:
            AUDIT.debug("TLS_START  ip=%s  port=%d", addr[0], addr[1])
            try:
                conn = self.tls_context.wrap_socket(raw_conn, server_side=True)
                cipher = conn.cipher()
                ssl_ver = conn.version()
                AUDIT.debug("TLS_OK  ip=%s  ver=%s  cipher=%s", addr[0], ssl_ver, cipher[0] if cipher else "Unknown")
            except (ssl.SSLError, OSError) as e:
                AUDIT.warning("TLS_FAIL  ip=%s  err=%s", addr[0], e)
                try:
                    raw_conn.close()
                except Exception:
                    pass
                return

        agent = Agent(conn, addr)
        try:
            AUDIT.debug("AUTH_START  ip=%s", addr[0])
            auth_ok, auth_err = self._authenticate_with_reason(agent)
            if not auth_ok:
                AUDIT.warning("AUTH_FAIL  ip=%s  reason=%s", addr[0], auth_err)
                conn.close()
                return

            AUDIT.debug("WAIT_REGISTER  ip=%s", addr[0])
            msg = agent.recv_msg()
            if not msg:
                AUDIT.warning("BAD_REGISTER  ip=%s  reason=Connection closed or timeout waiting for register payload", addr[0])
                conn.close()
                return
            if msg.get("type") != "register":
                AUDIT.warning("BAD_REGISTER  ip=%s  reason=Expected type 'register', received '%s'", addr[0], msg.get("type"))
                conn.close()
                return

            conn.settimeout(None)

            agent.hostname     = str(msg.get("hostname", "Unknown"))[:64]
            agent.username     = str(msg.get("username", "Unknown"))[:64]
            agent.os           = str(msg.get("os",       "Unknown"))[:128]
            agent.arch         = str(msg.get("arch",     "Unknown"))[:32]
            agent.ip           = str(msg.get("ip",       addr[0]))[:45]
            agent.defense_caps = msg.get("defense_capabilities", [])

            os_lower = agent.os.lower()
            if "linux" in os_lower or "unix" in os_lower or "darwin" in os_lower:
                agent.os_type  = "linux"
                agent.is_admin = bool(msg.get("is_root", False))
                agent.ps_ver   = str(msg.get("python_ver", "?"))[:32]
            else:
                agent.os_type  = "windows"
                agent.is_admin = bool(msg.get("is_admin", False))
                agent.ps_ver   = str(msg.get("ps_ver", "?"))[:32]

            with self._lock:
                self._agents[agent.id] = agent
                total_active = len(self._agents)

            AUDIT.info("CONNECT  agent_id=%s  user=%s  host=%s  ip=%s  os=%s  admin=%s  active_agents=%d",
                       agent.id, agent.username, agent.hostname, agent.ip,
                       agent.os, agent.is_admin, total_active)
            self._fire("connect", agent)

            # Auto-verify code attestation asynchronously
            threading.Thread(
                target=self.verify_agent_attestation,
                args=(agent,),
                daemon=True,
                name=f"attest-{agent.id}"
            ).start()

            # Multiplexed Dispatch Loop
            while True:
                msg = agent.recv_msg()
                if msg is None:
                    AUDIT.debug("RECV_EOF  agent_id=%s  host=%s", agent.id, agent.hostname)
                    break
                agent.last_seen = datetime.now()
                agent._liveness_alerted = False
                mtype = msg.get("type")
                if mtype == "response" and "id" in msg:
                    agent.deliver_response(msg["id"], msg)
                elif mtype in ("event", "alert"):
                    self._dispatch_security_event(agent, msg)
                elif mtype == "telemetry":
                    self._dispatch_telemetry(agent, msg)

        except Exception as e:
            AUDIT.error("AGENT_HANDLER_EXCEPTION  ip=%s  err=%s", addr[0], e, exc_info=True)
        finally:
            with self._lock:
                self._agents.pop(agent.id, None)
                remaining = len(self._agents)
            agent.abort_pending("Agent disconnected")
            AUDIT.info("DISCONNECT  agent_id=%s  user=%s  host=%s  ip=%s  remaining_agents=%d",
                       agent.id, agent.username, agent.hostname, agent.ip, remaining)
            self._fire("disconnect", agent)
            try:
                conn.close()
            except Exception:
                pass

    def _authenticate(self, agent: Agent) -> bool:
        ok, _ = self._authenticate_with_reason(agent)
        return ok

    def _authenticate_with_reason(self, agent: Agent) -> Tuple[bool, str]:
        nonce = secrets.token_bytes(32)
        AUDIT.debug("AUTH_SEND_CHALLENGE  ip=%s  nonce=%s...", agent.addr[0], nonce.hex()[:16])
        if not agent.send_msg({"type": "challenge", "nonce": nonce.hex()}):
            return False, "Failed to send challenge nonce to agent"
        msg = agent.recv_msg()
        if not msg:
            return False, "Connection closed or timeout waiting for auth response"
        if msg.get("type") != "auth":
            return False, f"Expected message type 'auth', received '{msg.get('type')}'"
        raw_hmac = msg.get("hmac")
        if not raw_hmac:
            return False, "Missing 'hmac' token in auth response"
        try:
            claimed = bytes.fromhex(raw_hmac)
        except (KeyError, ValueError, TypeError) as e:
            return False, f"Invalid hex encoding in hmac token: {e}"
        expected = _hmac.new(self._psk, nonce, hashlib.sha256).digest()
        if not _hmac.compare_digest(expected, claimed):
            return False, "HMAC signature mismatch (incorrect PSK configured on agent or server)"
        if not agent.send_msg({"type": "auth_ok"}):
            return False, "Failed to send auth_ok confirmation to agent"
        AUDIT.debug("AUTH_SUCCESS  ip=%s", agent.addr[0])
        return True, "Success"

    def _dispatch_security_event(self, agent: Agent, msg: dict):
        AUDIT.warning("SECURITY_EVENT  host=%s  subsystem=%s  sev=%s  title=%s",
                      agent.hostname, msg.get("subsystem"), msg.get("severity"), msg.get("title"))
        msg["agent_id"] = agent.id
        msg["host"]     = agent.hostname
        msg["ip"]       = agent.ip
        with self._lock:
            self._security_events.append(msg)
        self._fire("security_event", (agent, msg))

    def _dispatch_telemetry(self, agent: Agent, msg: dict):
        msg["agent_id"] = agent.id
        msg["host"]     = agent.hostname
        with self._lock:
            self._telemetry_events.append(msg)
        self._fire("telemetry", (agent, msg))

    def _fire(self, ev: str, data: Any):
        for cb in self._cbs:
            try:
                cb(ev, data)
            except Exception:
                pass

    def on_event(self, cb: Callable):
        self._cbs.append(cb)

    def agents(self) -> List[Agent]:
        with self._lock:
            return list(self._agents.values())

    def get(self, aid: str) -> Optional[Agent]:
        with self._lock:
            return self._agents.get(aid)

    def audit_cmd(self, agent: Agent, command: str, args: str = ""):
        AUDIT.info("CMD  user=%s  host=%s  cmd=%s  args=%.200s",
                   agent.username, agent.hostname, command, args)

    def verify_agent_attestation(self, agent: Agent) -> Tuple[bool, str]:
        """Requests cryptographic attestation proof and compares against authoritative checksums."""
        nonce = secrets.token_hex(16)
        mid, _ = agent.send_command("attest", nonce)
        resp = agent.wait_response(mid, timeout=12)
        if not resp or resp.get("status") != "ok":
            agent.attestation_status = "Attestation Failed"
            err = resp.get("output") if resp else "Timeout waiting for attestation"
            AUDIT.warning("ATTEST_FAILED  host=%s  ip=%s  err=%s", agent.hostname, agent.ip, err)
            self._fire("attestation_update", agent)
            return False, f"Failed to get attestation: {err}"

        try:
            data = json.loads(resp["output"])
            raw_sha256 = data.get("raw_sha256", "").lower()
            agent.attestation_details = data

            checksums = load_authoritative_checksums()
            leaf_name = os.path.basename(str(data.get("path", "")))
            expected_hash = checksums.get(leaf_name)
            if not expected_hash:
                if agent.os_type == "linux":
                    expected_hash = checksums.get("agent_core.py")
                else:
                    expected_hash = checksums.get("Agent-Core.ps1")

            if expected_hash:
                if raw_sha256 == expected_hash:
                    agent.attestation_status = "Verified ✓"
                    AUDIT.info("ATTEST_OK  host=%s  ip=%s  hash=%s", agent.hostname, agent.ip, raw_sha256[:16])
                    self._fire("attestation_update", agent)
                    return True, "Code integrity verified against Checksums"
                else:
                    agent.attestation_status = "⚠️ TAMPERED / CODE MISMATCH"
                    AUDIT.warning("ATTEST_MISMATCH  host=%s  ip=%s  got=%s  expected=%s",
                                  agent.hostname, agent.ip, raw_sha256, expected_hash)
                    self._fire("attestation_update", agent)
                    self._dispatch_security_event(agent, {
                        "type": "event",
                        "subsystem": "tamper",
                        "severity": "CRITICAL",
                        "title": "🚨 ANTI-TAMPER: Agent Code Mismatch",
                        "details": (
                            f"Agent '{agent.hostname}' failed attestation! "
                            f"Calculated SHA-256 ({raw_sha256[:16]}...) does not match "
                            f"authoritative baseline ({expected_hash[:16]}...)."
                        ),
                        "timestamp": datetime.now().isoformat(),
                        "expected_hash": expected_hash,
                        "actual_hash": raw_sha256,
                    })
                    return False, f"Hash mismatch: {raw_sha256} != {expected_hash}"
            else:
                agent.attestation_status = f"Attested (SHA: {raw_sha256[:12]}...)"
                AUDIT.info("ATTEST_UNTRACKED  host=%s  ip=%s  hash=%s", agent.hostname, agent.ip, raw_sha256[:16])
                self._fire("attestation_update", agent)
                return True, "Attestation received, but no baseline in Checksums"
        except Exception as e:
            agent.attestation_status = "Attestation Error"
            AUDIT.error("ATTEST_ERROR  host=%s  ip=%s  err=%s", agent.hostname, agent.ip, e)
            self._fire("attestation_update", agent)
            return False, f"Error processing attestation: {e}"

    def _liveness_loop(self):
        """Dead-man liveness monitor: periodically verifies agents are active and responsive."""
        while True:
            time.sleep(15)
            now = datetime.now()
            with self._lock:
                active_agents = list(self._agents.values())

            for agent in active_agents:
                elapsed = (now - agent.last_seen).total_seconds()
                if elapsed > 30 and elapsed <= 45:
                    def _do_ping(a=agent):
                        mid, _ = a.send_command("ping")
                        res = a.wait_response(mid, timeout=8)
                        if res and res.get("status") == "ok":
                            a.last_seen = datetime.now()
                            a._liveness_alerted = False
                    threading.Thread(target=_do_ping, daemon=True).start()
                elif elapsed > 45:
                    if not getattr(agent, "_liveness_alerted", False):
                        agent._liveness_alerted = True
                        AUDIT.warning("LIVENESS_TIMEOUT  host=%s  ip=%s  elapsed=%ds",
                                      agent.hostname, agent.ip, int(elapsed))
                        self._dispatch_security_event(agent, {
                            "type": "event",
                            "subsystem": "tamper",
                            "severity": "CRITICAL",
                            "title": "🚨 SUSPECTED TAMPERING: Agent Unresponsive",
                            "details": (
                                f"Agent '{agent.hostname}' ({agent.ip}) has been silent and unresponsive "
                                f"for {int(elapsed)} seconds. Possible adversary suppression, network severance, "
                                f"or process kill."
                            ),
                            "timestamp": datetime.now().isoformat(),
                            "elapsed_seconds": int(elapsed),
                        })


RATServer = EDRServer  # Backward-compatible alias


# ════════════════════════════════════════════════════════════════
#  GUI & Defense Management Console
# ════════════════════════════════════════════════════════════════

# ════════════════════════════════════════════════════════════════
#  Authentication & JWT Token Management
# ════════════════════════════════════════════════════════════════

def create_jwt_token(payload: dict, secret: str, expires_in: int = 86400) -> str:
    """Creates a standard HMAC-SHA256 (HS256) JWT token."""
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    full_payload = dict(payload)
    full_payload["iat"] = now
    full_payload["exp"] = now + expires_in

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = _b64url(json.dumps(full_payload, separators=(",", ":")).encode("utf-8"))
    sig_input = f"{h_b64}.{p_b64}".encode("utf-8")
    sig = _hmac.new(secret.encode("utf-8"), sig_input, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{_b64url(sig)}"


def verify_jwt_token(token: str, secret: str) -> Optional[dict]:
    """Validates an HS256 JWT token signature and expiration."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        h_b64, p_b64, s_b64 = parts
        sig_input = f"{h_b64}.{p_b64}".encode("utf-8")
        expected_sig = _hmac.new(secret.encode("utf-8"), sig_input, hashlib.sha256).digest()

        rem = len(s_b64) % 4
        s_pad = s_b64 + ("=" * (4 - rem) if rem else "")
        claimed_sig = base64.urlsafe_b64decode(s_pad.encode("utf-8"))
        if not _hmac.compare_digest(expected_sig, claimed_sig):
            return None

        rem_p = len(p_b64) % 4
        p_pad = p_b64 + ("=" * (4 - rem_p) if rem_p else "")
        payload = json.loads(base64.urlsafe_b64decode(p_pad.encode("utf-8")).decode("utf-8"))
        if not isinstance(payload, dict):
            return None
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None


# ════════════════════════════════════════════════════════════════
#  Single Page Application (SPA) HTML5 Dashboard
# ════════════════════════════════════════════════════════════════

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Server-EDR // Defense Console</title>
  <style>
    :root {
      --bg: #1e1e2e;
      --mantle: #181825;
      --crust: #11111b;
      --surface0: #313244;
      --surface1: #45475a;
      --surface2: #585b70;
      --overlay0: #6c7086;
      --text: #cdd6f4;
      --subtext: #a6adc8;
      --blue: #89b4fa;
      --lavender: #b4befe;
      --mauve: #cba6f7;
      --red: #f38ba8;
      --peach: #fab387;
      --yellow: #f9e2af;
      --green: #a6e3a1;
      --teal: #94e2d5;
      --mono: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 14px;
      height: 100vh;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    header {
      background: var(--crust);
      padding: 10px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid var(--surface0);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: 700;
      font-size: 16px;
      letter-spacing: 0.5px;
      color: var(--blue);
      font-family: var(--mono);
    }
    .header-badges {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .badge {
      background: var(--surface0);
      color: var(--subtext);
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-family: var(--mono);
    }
    .badge-live {
      background: rgba(166, 227, 161, 0.15);
      color: var(--green);
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .live-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--green);
      animation: pulse 1.8s infinite;
    }
    @keyframes pulse {
      0% { opacity: 0.4; }
      50% { opacity: 1; transform: scale(1.2); }
      100% { opacity: 0.4; }
    }
    .agent-bar {
      background: var(--mantle);
      padding: 8px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid var(--surface0);
      gap: 16px;
    }
    .agent-select-wrap {
      display: flex;
      align-items: center;
      gap: 10px;
      flex: 1;
    }
    select, input, textarea {
      background: var(--surface0);
      border: 1px solid var(--surface1);
      color: var(--text);
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 13px;
      outline: none;
      font-family: inherit;
    }
    select:focus, input:focus, textarea:focus {
      border-color: var(--blue);
    }
    .nav-tabs {
      background: var(--crust);
      display: flex;
      border-bottom: 1px solid var(--surface0);
      padding: 0 20px;
    }
    .tab-btn {
      background: none;
      border: none;
      color: var(--subtext);
      padding: 12px 18px;
      cursor: pointer;
      font-size: 13px;
      font-weight: 600;
      border-bottom: 2px solid transparent;
      transition: all 0.2s;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .tab-btn:hover { color: var(--text); }
    .tab-btn.active {
      color: var(--blue);
      border-bottom: 2px solid var(--blue);
      background: rgba(137, 180, 250, 0.05);
    }
    .content-area {
      flex: 1;
      overflow-y: auto;
      padding: 20px;
      background: var(--bg);
    }
    .tab-pane { display: none; }
    .tab-pane.active { display: block; }
    .card {
      background: var(--mantle);
      border: 1px solid var(--surface0);
      border-radius: 8px;
      padding: 18px;
      margin-bottom: 18px;
    }
    .card-title {
      font-size: 15px;
      font-weight: 700;
      color: var(--lavender);
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .btn {
      background: var(--surface1);
      border: 1px solid var(--surface2);
      color: var(--text);
      padding: 7px 14px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 13px;
      font-weight: 600;
      transition: all 0.2s;
    }
    .btn:hover { background: var(--surface2); }
    .btn-primary { background: #3b5998; border-color: var(--blue); color: white; }
    .btn-primary:hover { background: var(--blue); color: var(--crust); }
    .btn-danger { background: rgba(243, 139, 168, 0.2); border-color: var(--red); color: var(--red); }
    .btn-danger:hover { background: var(--red); color: var(--crust); }
    .btn-success { background: rgba(166, 227, 161, 0.2); border-color: var(--green); color: var(--green); }
    .btn-success:hover { background: var(--green); color: var(--crust); }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
      font-size: 13px;
    }
    th, td {
      padding: 10px 12px;
      text-align: left;
      border-bottom: 1px solid var(--surface0);
    }
    th {
      background: var(--crust);
      color: var(--subtext);
      font-family: var(--mono);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }
    .log-box {
      background: var(--crust);
      border: 1px solid var(--surface0);
      border-radius: 6px;
      padding: 12px;
      font-family: var(--mono);
      font-size: 12px;
      height: 300px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-all;
      color: var(--text);
      line-height: 1.6;
    }
    .badge-critical { background: rgba(243, 139, 168, 0.25); color: var(--red); font-weight: bold; padding: 2px 8px; border-radius: 4px; }
    .badge-high { background: rgba(250, 179, 135, 0.25); color: var(--peach); font-weight: bold; padding: 2px 8px; border-radius: 4px; }
    .badge-medium { background: rgba(249, 226, 175, 0.25); color: var(--yellow); font-weight: bold; padding: 2px 8px; border-radius: 4px; }
    .badge-low { background: rgba(137, 180, 250, 0.25); color: var(--blue); padding: 2px 8px; border-radius: 4px; }
    .pill { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-family: var(--mono); background: var(--surface0); }
    .containment-banner {
      background: rgba(243, 139, 168, 0.1);
      border: 1px solid var(--red);
      padding: 14px;
      border-radius: 8px;
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .filter-bar {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 14px;
      flex-wrap: wrap;
    }
    .modal {
      display: none;
      position: fixed;
      top: 0; left: 0; width: 100%; height: 100%;
      background: rgba(0, 0, 0, 0.7);
      backdrop-filter: blur(4px);
      align-items: center;
      justify-content: center;
      z-index: 1000;
    }
    .modal.active { display: flex; }
    .modal-box {
      background: var(--mantle);
      border: 1px solid var(--surface0);
      border-radius: 10px;
      padding: 24px;
      width: 420px;
      max-width: 90%;
      box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <span>🛡️</span> SERVER-EDR // DEFENSE CONSOLE
    </div>
    <div class="header-badges">
      <span class="badge">C2 Port: <strong id="c2-port-val">443</strong></span>
      <span class="badge">Web Port: <strong id="web-port-val">8443</strong></span>
      <span class="badge">Active Sensors: <strong id="active-sensor-count">0</strong></span>
      <span class="badge badge-live" id="ws-indicator"><span class="live-dot"></span> <span id="ws-status-text">CONNECTING</span></span>
      <button class="btn" id="btn-auth" onclick="showAuthModal()">Auth</button>
    </div>
  </header>

  <div class="agent-bar">
    <div class="agent-select-wrap">
      <label style="font-weight: 600; color: var(--subtext);">Target Sensor:</label>
      <select id="agent-select" onchange="onAgentSelectChange()" style="min-width: 320px;">
        <option value="">-- No Agents Connected --</option>
      </select>
      <span id="agent-attest-badge" class="badge" style="display: none;">Verified ✓</span>
    </div>
    <div style="display: flex; gap: 8px;">
      <button class="btn" onclick="refreshAgents()">🔄 Refresh</button>
      <button class="btn" onclick="dispatchQuick('ping')">Ping</button>
      <button class="btn" onclick="dispatchQuick('sysinfo')">Sysinfo</button>
      <button class="btn" onclick="dispatchQuick('attest')">Verify Attestation</button>
    </div>
  </div>

  <div class="nav-tabs">
    <button class="tab-btn active" onclick="switchTab('alerts')">🚨 Security Alerts</button>
    <button class="tab-btn" onclick="switchTab('malware')">🦠 Malware & Quarantine</button>
    <button class="tab-btn" onclick="switchTab('fim')">📂 File Integrity (FIM)</button>
    <button class="tab-btn" onclick="switchTab('dlp')">🔒 Data Loss Prevention (DLP)</button>
    <button class="tab-btn" onclick="switchTab('openedr')">⚡ OpenEDR & Host Containment</button>
  </div>

  <div class="content-area">
    <!-- Tab 1: Security Alerts -->
    <div id="tab-alerts" class="tab-pane active">
      <div class="card">
        <div class="card-title">
          <span>Unified Real-Time Security Alert Stream</span>
          <div style="display: flex; gap: 8px;">
            <button class="btn" onclick="clearAlerts()">Clear Feed</button>
            <button class="btn" onclick="exportAlerts()">Export JSON</button>
          </div>
        </div>
        <div class="filter-bar">
          <label style="color: var(--subtext);">Subsystem:</label>
          <select id="filter-subsystem" onchange="applyAlertFilters()">
            <option value="">ALL Subsystems</option>
            <option value="fim">FIM</option>
            <option value="dlp">DLP</option>
            <option value="malware">Malware</option>
            <option value="openedr">OpenEDR</option>
            <option value="tamper">Anti-Tamper</option>
          </select>
          <label style="color: var(--subtext); margin-left: 12px;">Severity:</label>
          <select id="filter-severity" onchange="applyAlertFilters()">
            <option value="">ALL Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
          <input type="text" id="filter-search" placeholder="Search title or details..." oninput="applyAlertFilters()" style="flex: 1; min-width: 200px;">
        </div>
        <table>
          <thead>
            <tr>
              <th style="width: 160px;">Timestamp</th>
              <th style="width: 140px;">Host / Agent</th>
              <th style="width: 100px;">Subsystem</th>
              <th style="width: 100px;">Severity</th>
              <th>Alert Details</th>
            </tr>
          </thead>
          <tbody id="alerts-tbody">
            <tr><td colspan="5" style="text-align: center; color: var(--overlay0);">No security events recorded.</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Tab 2: Malware & Quarantine -->
    <div id="tab-malware" class="tab-pane">
      <div class="card">
        <div class="card-title">Remote File System Scanner (On-Demand)</div>
        <div style="display: flex; gap: 10px; margin-bottom: 12px;">
          <input type="text" id="malware-scan-path" value="." placeholder="Target directory or file path to scan..." style="flex: 1;">
          <button class="btn btn-primary" onclick="runMalwareScan()">🔍 Run Malware Scan</button>
        </div>
        <div id="malware-scan-results" class="log-box" style="height: 140px;">Ready to scan endpoint file system.</div>
      </div>

      <div class="card">
        <div class="card-title">Quarantine Vault Manager (Isolated Threats)</div>
        <div style="display: flex; gap: 10px; margin-bottom: 16px;">
          <input type="text" id="quarantine-target-path" placeholder="Path to suspicious executable to isolate..." style="flex: 1;">
          <button class="btn btn-danger" onclick="quarantineTargetFile()">⚠️ Quarantine File</button>
          <button class="btn" onclick="refreshQuarantineVault()">🔄 Refresh Vault</button>
        </div>
        <table>
          <thead>
            <tr>
              <th>Quarantine Item</th>
              <th>Original Path</th>
              <th>Quarantine Time</th>
              <th>SHA-256 Hash</th>
              <th style="width: 110px;">Actions</th>
            </tr>
          </thead>
          <tbody id="quarantine-tbody">
            <tr><td colspan="5" style="text-align: center; color: var(--overlay0);">No files currently quarantined.</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Tab 3: File Integrity Monitoring (FIM) -->
    <div id="tab-fim" class="tab-pane">
      <div class="card">
        <div class="card-title">
          <span>File Integrity Baselines & Monitoring Controls</span>
          <div style="display: flex; gap: 8px;">
            <button class="btn btn-primary" onclick="dispatchQuick('fim_init')">⚡ Init / Rebuild Baseline</button>
            <button class="btn" onclick="dispatchQuick('fim_check')">🔎 Run Integrity Audit</button>
          </div>
        </div>
        <div style="display: flex; gap: 10px; margin-top: 10px;">
          <input type="text" id="fim-add-path-input" placeholder="Enter path to add to monitoring scope..." style="flex: 1;">
          <button class="btn" onclick="addFimPath()">+ Add Monitored Path</button>
        </div>
      </div>
      <div class="card">
        <div class="card-title">FIM Change Event Audit Feed</div>
        <div id="fim-log-box" class="log-box">FIM monitoring initialized. Real-time integrity changes appear here.</div>
      </div>
    </div>

    <!-- Tab 4: Data Loss Prevention (DLP) -->
    <div id="tab-dlp" class="tab-pane">
      <div class="card">
        <div class="card-title">Inspect Sensitive Data & PII (Credit Cards / API Keys / SSN)</div>
        <textarea id="dlp-input-text" rows="4" style="width: 100%; margin-bottom: 10px;" placeholder="Paste text buffer or enter target file path to inspect for PII or API tokens..."></textarea>
        <div style="display: flex; gap: 8px; align-items: center;">
          <button class="btn btn-primary" onclick="runDlpScan()">🔍 Inspect Sensitive Data</button>
          <span style="color: var(--subtext); font-size: 12px; margin-left: 10px;">Test Presets:</span>
          <button class="btn" onclick="setDlpPreset('visa')">Test Visa (Luhn)</button>
          <button class="btn" onclick="setDlpPreset('aws')">Test AWS Key</button>
        </div>
      </div>
      <div class="card">
        <div class="card-title">DLP Rule Violations & Redacted Findings</div>
        <table>
          <thead>
            <tr>
              <th style="width: 140px;">Rule Name</th>
              <th style="width: 110px;">Severity</th>
              <th>Redacted Preview</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody id="dlp-tbody">
            <tr><td colspan="4" style="text-align: center; color: var(--overlay0);">No sensitive data violations detected.</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Tab 5: OpenEDR & Host Containment -->
    <div id="tab-openedr" class="tab-pane">
      <div class="containment-banner">
        <div>
          <strong style="color: var(--red); font-size: 15px;">🚨 Emergency Host Containment & Network Isolation</strong>
          <p style="color: var(--subtext); font-size: 12px; margin-top: 4px;">Sever all inbound and outbound host network connections instantly while preserving the secure Server-EDR C2 channel on port 443.</p>
        </div>
        <div style="display: flex; gap: 10px;">
          <button class="btn btn-danger" onclick="isolateHost(true)">EMERGENCY ISOLATE HOST</button>
          <button class="btn btn-success" onclick="isolateHost(false)">RESTORE NETWORK</button>
        </div>
      </div>

      <div class="card">
        <div class="card-title">
          <span>OpenEDR Sensor Health & Control</span>
          <div style="display: flex; gap: 8px;">
            <button class="btn" onclick="checkOpenEdrStatus()">Check Status</button>
            <button class="btn" onclick="fetchOpenEdrTelemetry()">Fetch Telemetry Events</button>
            <button class="btn" onclick="installOpenEdr()">Install OpenEDR</button>
          </div>
        </div>
        <div style="display: flex; gap: 20px; font-family: var(--mono); font-size: 13px; margin-top: 8px;">
          <div>Service: <span id="edr-svc-badge" class="badge">Unknown</span></div>
          <div>Kernel Minifilter: <span id="edr-filter-badge" class="badge">N/A</span></div>
          <div>Log Size: <span id="edr-log-size">N/A</span></div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Live Kernel & OpenEDR Telemetry Stream</div>
        <div id="telemetry-log-box" class="log-box">Telemetry events from OpenEDR kernel sensors stream here live...</div>
      </div>
    </div>
  </div>

  <!-- Modal for Admin Auth -->
  <div id="modal-auth" class="modal">
    <div class="modal-box">
      <h3 style="color: var(--blue); margin-bottom: 12px;">Administrator Authentication</h3>
      <p style="color: var(--subtext); font-size: 13px; margin-bottom: 16px;">Enter the Pre-Shared Key (PSK) or administrator password configured for Server-EDR:</p>
      <input type="password" id="auth-psk-input" placeholder="Pre-Shared Key (PSK)..." style="width: 100%; margin-bottom: 16px;">
      <div style="display: flex; justify-content: flex-end; gap: 8px;">
        <button class="btn" onclick="showAuthModal(false)">Cancel</button>
        <button class="btn btn-primary" onclick="doAuthLogin()">Authenticate</button>
      </div>
    </div>
  </div>

  <script>
    const state = {
      token: localStorage.getItem('edr_jwt') || '',
      agents: [],
      selectedAgentId: '',
      alerts: [],
      quarantine: [],
      activeTab: 'alerts',
      ws: null
    };

    async function api(url, method = 'GET', body = null) {
      const headers = { 'Content-Type': 'application/json' };
      if (state.token) headers['Authorization'] = 'Bearer ' + state.token;
      const opts = { method, headers };
      if (body) opts.body = JSON.stringify(body);
      try {
        const res = await fetch(url, opts);
        if (res.status === 401) {
          showAuthModal(true);
          return { status: 'error', error: 'Unauthorized' };
        }
        return await res.json();
      } catch (e) {
        return { status: 'error', error: e.toString() };
      }
    }

    function showAuthModal(show = true) {
      document.getElementById('modal-auth').classList.toggle('active', show);
      if (show) document.getElementById('auth-psk-input').focus();
    }

    async function doAuthLogin() {
      const psk = document.getElementById('auth-psk-input').value.trim();
      const res = await api('/api/v1/auth/login', 'POST', { password: psk });
      if (res.status === 'ok') {
        state.token = res.token;
        localStorage.setItem('edr_jwt', res.token);
        showAuthModal(false);
        document.getElementById('btn-auth').textContent = 'Logged In ✓';
        initWS();
        refreshAgents();
        refreshAlerts();
      } else {
        alert('Authentication failed: ' + (res.error || 'Invalid credentials'));
      }
    }

    function switchTab(name) {
      state.activeTab = name;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      event.target.classList.add('active');
      document.getElementById('tab-' + name).classList.add('active');
      if (name === 'quarantine') refreshQuarantineVault();
    }

    async function refreshAgents() {
      const res = await api('/api/v1/agents');
      if (res.status === 'ok') {
        state.agents = res.agents || [];
        const select = document.getElementById('agent-select');
        select.innerHTML = '';
        if (state.agents.length === 0) {
          select.innerHTML = '<option value="">-- No Agents Connected --</option>';
          document.getElementById('active-sensor-count').textContent = '0';
          document.getElementById('agent-attest-badge').style.display = 'none';
          state.selectedAgentId = '';
        } else {
          document.getElementById('active-sensor-count').textContent = state.agents.length;
          state.agents.forEach(a => {
            const opt = document.createElement('option');
            opt.value = a.id;
            opt.textContent = `${a.hostname} (${a.ip} - ${a.os}) [${a.attestation_status}]`;
            select.appendChild(opt);
          });
          if (!state.selectedAgentId || !state.agents.some(a => a.id === state.selectedAgentId)) {
            state.selectedAgentId = state.agents[0].id;
          }
          select.value = state.selectedAgentId;
          onAgentSelectChange();
        }
      }
    }

    function onAgentSelectChange() {
      state.selectedAgentId = document.getElementById('agent-select').value;
      const agent = state.agents.find(a => a.id === state.selectedAgentId);
      const badge = document.getElementById('agent-attest-badge');
      if (agent) {
        badge.style.display = 'inline-block';
        badge.textContent = agent.attestation_status;
        badge.style.color = agent.attestation_status.includes('Verified') ? 'var(--green)' :
                           (agent.attestation_status.includes('TAMPER') ? 'var(--red)' : 'var(--yellow)');
      } else {
        badge.style.display = 'none';
      }
    }

    async function dispatchQuick(cmd, args = null) {
      if (!state.selectedAgentId) {
        alert('Please select an active target sensor first.');
        return;
      }
      const res = await api('/api/v1/commands/dispatch', 'POST', {
        agent_id: state.selectedAgentId,
        command: cmd,
        args: args
      });
      if (res.status === 'ok') {
        const out = res.response ? (res.response.output || JSON.stringify(res.response)) : 'Command sent';
        alert(`[${cmd}] Response from ${res.hostname}:

` + out);
        refreshAgents();
      } else {
        alert(`[!] Command error: ` + (res.error || 'Failed'));
      }
    }

    async function refreshAlerts() {
      const res = await api('/api/v1/alerts');
      if (res.status === 'ok') {
        state.alerts = res.alerts || [];
        renderAlertsTable();
      }
    }

    function renderAlertsTable() {
      const tbody = document.getElementById('alerts-tbody');
      const sub = document.getElementById('filter-subsystem').value.toLowerCase();
      const sev = document.getElementById('filter-severity').value.toUpperCase();
      const query = document.getElementById('filter-search').value.toLowerCase();

      const filtered = state.alerts.filter(a => {
        if (sub && (a.subsystem || '').toLowerCase() !== sub) return false;
        if (sev && (a.severity || '').toUpperCase() !== sev) return false;
        if (query) {
          const hay = ((a.title || '') + ' ' + (a.details || '') + ' ' + (a.host || '')).toLowerCase();
          if (!hay.includes(query)) return false;
        }
        return true;
      });

      if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--overlay0);">No matching security events.</td></tr>';
        return;
      }

      tbody.innerHTML = filtered.map(a => {
        const sClass = (a.severity === 'CRITICAL') ? 'badge-critical' :
                       (a.severity === 'HIGH') ? 'badge-high' :
                       (a.severity === 'MEDIUM') ? 'badge-medium' : 'badge-low';
        return `<tr>
          <td style="font-family: var(--mono); font-size: 11px; color: var(--subtext);">${(a.timestamp || '').slice(0, 19)}</td>
          <td><strong>${a.host || a.agent_id || 'Unknown'}</strong></td>
          <td><span class="pill">${a.subsystem || 'general'}</span></td>
          <td><span class="${sClass}">${a.severity || 'INFO'}</span></td>
          <td>
            <div style="font-weight: 600; color: var(--text);">${a.title || 'Security Event'}</div>
            <div style="font-size: 12px; color: var(--subtext); margin-top: 2px;">${a.details || ''}</div>
          </td>
        </tr>`;
      }).join('');
    }

    function applyAlertFilters() { renderAlertsTable(); }
    function clearAlerts() { state.alerts = []; renderAlertsTable(); }
    function exportAlerts() {
      const blob = new Blob([JSON.stringify(state.alerts, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `edr-alerts-${Date.now()}.json`;
      a.click();
    }

    async function runMalwareScan() {
      if (!state.selectedAgentId) return alert('Select a sensor first.');
      const path = document.getElementById('malware-scan-path').value.trim() || '.';
      const box = document.getElementById('malware-scan-results');
      box.textContent = `[*] Scanning path '${path}' on selected endpoint...`;
      const res = await api('/api/v1/commands/dispatch', 'POST', {
        agent_id: state.selectedAgentId,
        command: 'malware_scan',
        args: path,
        timeout: 60
      });
      if (res.status === 'ok') {
        try {
          const findings = JSON.parse(res.response.output);
          if (!findings || findings.length === 0) {
            box.textContent = `✓ Scan complete: No malicious threats detected in '${path}'.`;
          } else {
            box.textContent = `🚨 DETECTED ${findings.length} THREATS in '${path}':
` + JSON.stringify(findings, null, 2);
          }
        } catch {
          box.textContent = res.response.output;
        }
      } else {
        box.textContent = `[-] Scan failed: ${res.error || 'Timeout'}`;
      }
    }

    async function quarantineTargetFile() {
      if (!state.selectedAgentId) return alert('Select a sensor first.');
      const path = document.getElementById('quarantine-target-path').value.trim();
      if (!path) return alert('Please enter path to file.');
      if (!confirm(`Quarantine file '${path}' on selected endpoint?`)) return;
      const res = await api('/api/v1/commands/dispatch', 'POST', {
        agent_id: state.selectedAgentId,
        command: 'quarantine',
        args: path
      });
      alert(res.status === 'ok' ? '✓ ' + res.response.output : '[-] ' + res.error);
      refreshQuarantineVault();
    }

    async function refreshQuarantineVault() {
      const res = await api('/api/v1/quarantine' + (state.selectedAgentId ? '?agent_id=' + state.selectedAgentId : ''));
      const tbody = document.getElementById('quarantine-tbody');
      if (res.status === 'ok' && res.quarantine && res.quarantine.length > 0) {
        tbody.innerHTML = res.quarantine.map(item => {
          return `<tr>
            <td style="font-family: var(--mono);">${item.quarantine_file}</td>
            <td>${item.original_path}</td>
            <td>${new Date((item.quarantine_time || 0) * 1000).toLocaleString()}</td>
            <td style="font-family: var(--mono); font-size: 11px;">${(item.hash || '').slice(0, 16)}...</td>
            <td><button class="btn btn-success" style="padding: 3px 8px; font-size: 11px;" onclick="restoreQuarantineFile('${item.quarantine_file}')">Restore</button></td>
          </tr>`;
        }).join('');
      } else {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--overlay0);">No files currently quarantined.</td></tr>';
      }
    }

    async function restoreQuarantineFile(file) {
      if (!confirm(`Restore quarantined file '${file}' to its original location?`)) return;
      const res = await api('/api/v1/commands/dispatch', 'POST', {
        agent_id: state.selectedAgentId,
        command: 'quarantine_restore',
        args: file
      });
      alert(res.status === 'ok' ? '✓ ' + res.response.output : '[-] ' + res.error);
      refreshQuarantineVault();
    }

    async function addFimPath() {
      const path = document.getElementById('fim-add-path-input').value.trim();
      if (!path) return;
      dispatchQuick('fim_add_path', path);
      document.getElementById('fim-add-path-input').value = '';
    }

    async function runDlpScan() {
      if (!state.selectedAgentId) return alert('Select a sensor first.');
      const txt = document.getElementById('dlp-input-text').value.trim();
      if (!txt) return alert('Enter buffer text or file path to scan.');
      const res = await api('/api/v1/commands/dispatch', 'POST', {
        agent_id: state.selectedAgentId,
        command: 'dlp_scan',
        args: txt
      });
      const tbody = document.getElementById('dlp-tbody');
      if (res.status === 'ok') {
        try {
          const findings = JSON.parse(res.response.output);
          if (!findings || findings.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--green);">✓ Scan passed: 0 sensitive items detected.</td></tr>';
          } else {
            tbody.innerHTML = findings.map(f => `<tr>
              <td><strong>${f.rule}</strong></td>
              <td><span class="badge-high">${f.severity || 'HIGH'}</span></td>
              <td style="font-family: var(--mono);">${f.preview || ''}</td>
              <td>Rule violation matched in buffer/file</td>
            </tr>`).join('');
          }
        } catch {
          tbody.innerHTML = `<tr><td colspan="4">${res.response.output}</td></tr>`;
        }
      } else {
        tbody.innerHTML = `<tr><td colspan="4" style="color: var(--red);">Error: ${res.error}</td></tr>`;
      }
    }

    function setDlpPreset(type) {
      const inp = document.getElementById('dlp-input-text');
      if (type === 'visa') inp.value = "Customer Visa payment card record: 4532 0150 1234 5671 for account verification.";
      if (type === 'aws') inp.value = "AWS Cloud Secrets: AKIAIOSFODNN7EXAMPLE and secret key payload.";
    }

    async function checkOpenEdrStatus() {
      if (!state.selectedAgentId) return alert('Select a sensor first.');
      const res = await api('/api/v1/commands/dispatch', 'POST', {
        agent_id: state.selectedAgentId,
        command: 'openedr_status'
      });
      if (res.status === 'ok') {
        try {
          const st = JSON.parse(res.response.output);
          document.getElementById('edr-svc-badge').textContent = st.running ? 'Running ✓' : 'Stopped';
          document.getElementById('edr-svc-badge').style.color = st.running ? 'var(--green)' : 'var(--peach)';
          document.getElementById('edr-filter-badge').textContent = st.minifilter ? 'Loaded ✓' : 'Standard';
          document.getElementById('edr-log-size').textContent = (st.log_size_bytes / (1024*1024)).toFixed(2) + ' MB';
        } catch {
          alert(res.response.output);
        }
      }
    }

    async function fetchOpenEdrTelemetry() {
      if (!state.selectedAgentId) return alert('Select a sensor first.');
      const res = await api('/api/v1/commands/dispatch', 'POST', {
        agent_id: state.selectedAgentId,
        command: 'openedr_fetch_telemetry'
      });
      const box = document.getElementById('telemetry-log-box');
      if (res.status === 'ok') {
        box.textContent = `=== OpenEDR Telemetry Frame ===
` + res.response.output;
      }
    }

    async function installOpenEdr() {
      if (!confirm('Deploy and configure OpenEDR service on selected endpoint sensor?')) return;
      dispatchQuick('install_openedr');
    }

    async function isolateHost(enable) {
      const verb = enable ? 'ISOLATE' : 'RESTORE NETWORK FOR';
      if (!confirm(`Are you sure you want to ${verb} the selected endpoint host?

This will drop all external network connections while preserving the Server-EDR C2 channel.`)) return;
      const res = await api('/api/v1/commands/dispatch', 'POST', {
        agent_id: state.selectedAgentId,
        command: 'isolate_host',
        args: enable ? 'true' : 'false'
      });
      alert(res.status === 'ok' ? res.response.output : '[-] ' + res.error);
    }

    function initWS() {
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const url = `${proto}//${location.host}/ws/live-stream${state.token ? '?token=' + encodeURIComponent(state.token) : ''}`;
      try {
        state.ws = new WebSocket(url);
      } catch (e) {
        document.getElementById('ws-status-text').textContent = 'ERROR';
        return;
      }
      state.ws.onopen = () => {
        document.getElementById('ws-status-text').textContent = 'LIVE STREAM';
        document.getElementById('ws-indicator').style.color = 'var(--green)';
      };
      state.ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.type === 'security_event' && msg.alert) {
            state.alerts.unshift(msg.alert);
            renderAlertsTable();
          } else if (msg.type === 'telemetry') {
            const box = document.getElementById('telemetry-log-box');
            box.textContent = `[${new Date().toLocaleTimeString()}] ${JSON.stringify(msg.telemetry, null, 2)}\n` + box.textContent.slice(0, 10000);
          } else if (msg.type === 'agent_connected' || msg.type === 'agent_disconnected' || msg.type === 'attestation_update') {
            refreshAgents();
          }
        } catch (e) { console.error('WS parse error:', e); }
      };
      state.ws.onclose = () => {
        document.getElementById('ws-status-text').textContent = 'DISCONNECTED';
        document.getElementById('ws-indicator').style.color = 'var(--red)';
        setTimeout(initWS, 4000);
      };
    }

    // Initialize on load
    window.addEventListener('load', () => {
      refreshAgents();
      refreshAlerts();
      initWS();
      setInterval(refreshAgents, 15000);
    });
  </script>
</body>
</html>
"""


# ════════════════════════════════════════════════════════════════
#  Web Portal Engine (HTTPS / REST API / WebSocket Streaming)
# ════════════════════════════════════════════════════════════════

class WebPortal:
    """
    Headless Web Portal listening on port 8443 (or custom web_port)
    providing REST endpoints and WebSocket live-stream.
    Shares the server TLS context with the C2 engine.
    """
    def __init__(
        self,
        server: EDRServer,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_WEB_PORT,
        config: Optional[ServerConfig] = None,
        tls_context: Optional[ssl.SSLContext] = None,
    ):
        self.server = server
        self.host = host
        self.port = port
        self.config = config
        self.tls_context = tls_context
        self.psk = (config.psk if config else "").strip()
        self._app = web.Application()
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._ws_clients: Set[web.WebSocketResponse] = set()

        self._setup_routes()
        self.server.on_event(self._on_server_event)

    @property
    def app(self) -> web.Application:
        return self._app

    def _setup_routes(self):
        # REST API Routes
        self._app.router.add_post("/api/v1/auth/login", self.handle_login)
        self._app.router.add_get("/api/v1/agents", self.handle_get_agents)
        self._app.router.add_get("/api/v1/alerts", self.handle_get_alerts)
        self._app.router.add_post("/api/v1/commands/dispatch", self.handle_command_dispatch)
        self._app.router.add_get("/api/v1/quarantine", self.handle_get_quarantine)
        self._app.router.add_get("/api/v1/status", self.handle_status)

        # WebSocket Live Stream Route
        self._app.router.add_get("/ws/live-stream", self.handle_ws)

        # HTML5 Single Page Application Dashboard
        self._app.router.add_get("/", self.handle_dashboard)
        self._app.router.add_get("/index.html", self.handle_dashboard)

        # CORS Options handler
        self._app.router.add_route("OPTIONS", "/{tail:.*}", self.handle_options)

    def _check_auth(self, request: web.Request) -> bool:
        expected_psk = self.psk or (self.server._psk.decode() if self.server and self.server._psk else "")
        if not expected_psk:
            return True

        # 1. Bearer Token Header
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            token = auth_hdr[7:].strip()
            payload = verify_jwt_token(token, expected_psk)
            if payload:
                return True

        # 2. Query param ?token=
        q_token = request.query.get("token", "").strip()
        if q_token:
            payload = verify_jwt_token(q_token, expected_psk)
            if payload:
                return True

        # 3. PSK Header or Param
        req_psk = request.headers.get("X-EDR-PSK") or request.query.get("psk")
        if req_psk and req_psk == expected_psk:
            return True

        return False

    async def handle_options(self, request: web.Request) -> web.Response:
        return web.Response(
            status=204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, X-EDR-PSK"
            }
        )

    async def handle_dashboard(self, request: web.Request) -> web.Response:
        # Prepopulate C2 and Web port values in SPA
        rendered = DASHBOARD_HTML.replace('id="c2-port-val">443<', f'id="c2-port-val">{self.server.port}<')
        rendered = rendered.replace('id="web-port-val">8443<', f'id="web-port-val">{self.port}<')
        return web.Response(text=rendered, content_type="text/html")

    async def handle_login(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"status": "error", "error": "Invalid JSON"}, status=400)

        username = body.get("username", "admin")
        password = body.get("password") or body.get("psk") or body.get("token") or body.get("secret") or ""
        expected_psk = self.psk or (self.server._psk.decode() if self.server and self.server._psk else "")

        if not expected_psk or password == expected_psk:
            token = create_jwt_token({"sub": username, "role": "admin"}, secret=expected_psk or "edr_secret")
            AUDIT.info("WEB_AUTH_LOGIN_SUCCESS  user=%s  ip=%s", username, request.remote)
            return web.json_response({
                "status": "ok",
                "token": token,
                "expires_in": 86400,
                "user": username
            })

        AUDIT.warning("WEB_AUTH_LOGIN_FAILED  user=%s  ip=%s", username, request.remote)
        return web.json_response({"status": "error", "error": "Invalid administrator credentials"}, status=401)

    async def handle_get_agents(self, request: web.Request) -> web.Response:
        if not self._check_auth(request):
            return web.json_response({"status": "error", "error": "Unauthorized"}, status=401)

        agents = self.server.agents()
        agent_list = []
        for a in agents:
            agent_list.append({
                "id": a.id,
                "hostname": a.hostname,
                "username": a.username,
                "os": a.os,
                "os_type": a.os_type,
                "arch": a.arch,
                "ip": a.ip,
                "is_admin": a.is_admin,
                "ps_ver": a.ps_ver,
                "defense_capabilities": a.defense_caps,
                "attestation_status": a.attestation_status,
                "attestation_details": getattr(a, "attestation_details", {}),
                "connected_at": a.connected_at.isoformat() if hasattr(a.connected_at, "isoformat") else str(a.connected_at),
                "last_seen": a.last_seen.isoformat() if hasattr(a.last_seen, "isoformat") else str(a.last_seen)
            })
        return web.json_response({"status": "ok", "count": len(agent_list), "agents": agent_list})

    async def handle_get_alerts(self, request: web.Request) -> web.Response:
        if not self._check_auth(request):
            return web.json_response({"status": "error", "error": "Unauthorized"}, status=401)

        sev = request.query.get("severity", "").strip().upper()
        sub = request.query.get("subsystem", "").strip().lower()
        aid = request.query.get("agent_id", "").strip()
        try:
            limit = min(int(request.query.get("limit", 100)), 1000)
        except ValueError:
            limit = 100

        with self.server._lock:
            raw = list(self.server._security_events)

        alerts = []
        for item in reversed(raw):
            if sev and str(item.get("severity", "")).upper() != sev:
                continue
            if sub and str(item.get("subsystem", "")).lower() != sub:
                continue
            if aid and str(item.get("agent_id", "")) != aid:
                continue
            alerts.append(item)
            if len(alerts) >= limit:
                break
        return web.json_response({"status": "ok", "total": len(alerts), "alerts": alerts})

    async def handle_command_dispatch(self, request: web.Request) -> web.Response:
        if not self._check_auth(request):
            return web.json_response({"status": "error", "error": "Unauthorized"}, status=401)

        try:
            body = await request.json()
        except Exception:
            return web.json_response({"status": "error", "error": "Invalid JSON body"}, status=400)

        agent_id = body.get("agent_id")
        command = body.get("command")
        args = body.get("args")
        timeout = float(body.get("timeout", 30))

        if not command:
            return web.json_response({"status": "error", "error": "Missing 'command' parameter"}, status=400)

        agent = None
        if agent_id:
            agent = self.server.get(agent_id)
            if not agent:
                return web.json_response({"status": "error", "error": f"Agent '{agent_id}' not found"}, status=404)
        else:
            active = self.server.agents()
            if len(active) == 1:
                agent = active[0]
            elif not active:
                return web.json_response({"status": "error", "error": "No active agents connected"}, status=404)
            else:
                return web.json_response({"status": "error", "error": "Multiple agents active; please specify 'agent_id'"}, status=400)

        self.server.audit_cmd(agent, command, str(args) if args is not None else "")
        mid, _ = agent.send_command(command, args)
        loop = asyncio.get_event_loop()
        resp = await loop.run_in_executor(None, agent.wait_response, mid, timeout)

        if resp is None:
            return web.json_response({
                "status": "error",
                "agent_id": agent.id,
                "command": command,
                "error": f"Command timed out after {timeout} seconds"
            }, status=504)

        return web.json_response({
            "status": "ok",
            "agent_id": agent.id,
            "hostname": agent.hostname,
            "command": command,
            "response": resp
        })

    async def handle_get_quarantine(self, request: web.Request) -> web.Response:
        if not self._check_auth(request):
            return web.json_response({"status": "error", "error": "Unauthorized"}, status=401)

        agent_id = request.query.get("agent_id")
        targets = []
        if agent_id:
            a = self.server.get(agent_id)
            if not a:
                return web.json_response({"status": "error", "error": f"Agent '{agent_id}' not found"}, status=404)
            targets = [a]
        else:
            targets = self.server.agents()

        loop = asyncio.get_event_loop()
        items = []
        for a in targets:
            mid, _ = a.send_command("quarantine_list")
            resp = await loop.run_in_executor(None, a.wait_response, mid, 15)
            if resp and resp.get("status") == "ok":
                try:
                    q_items = json.loads(resp["output"])
                    for q in q_items:
                        items.append({
                            "agent_id": a.id,
                            "hostname": a.hostname,
                            "ip": a.ip,
                            "quarantine_file": q.get("quarantine_file", q.get("original_name", "")),
                            "original_path": q.get("original_path", ""),
                            "quarantine_time": q.get("quarantine_time", 0),
                            "hash": q.get("hash", "")
                        })
                except Exception:
                    pass
        return web.json_response({"status": "ok", "count": len(items), "quarantine": items})

    async def handle_status(self, request: web.Request) -> web.Response:
        return web.json_response({
            "status": "ok",
            "server": "Server-EDR",
            "c2_host": self.server.host,
            "c2_port": self.server.port,
            "web_port": self.port,
            "tls_enabled": self.tls_context is not None,
            "active_agents": len(self.server.agents()),
            "time": datetime.now().isoformat()
        })

    async def handle_ws(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        if not self._check_auth(request):
            await ws.send_json({"type": "error", "error": "Unauthorized - supply ?token= or ?psk="})
            await ws.close(code=4001, message=b"Unauthorized")
            return ws

        self._ws_clients.add(ws)
        await ws.send_json({
            "type": "init",
            "c2_port": self.server.port,
            "web_port": self.port,
            "agent_count": len(self.server.agents()),
            "timestamp": datetime.now().isoformat()
        })

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        action = data.get("action") or data.get("type")
                        if action == "ping":
                            await ws.send_json({"type": "pong", "timestamp": datetime.now().isoformat()})
                        elif action == "dispatch":
                            aid = data.get("agent_id")
                            cmd = data.get("command")
                            args = data.get("args")
                            timeout = float(data.get("timeout", 30))
                            agent = self.server.get(aid) if aid else None
                            if not agent:
                                active = self.server.agents()
                                if len(active) == 1: agent = active[0]
                            if agent and cmd:
                                self.server.audit_cmd(agent, cmd, str(args) if args is not None else "")
                                mid, _ = agent.send_command(cmd, args)
                                loop = asyncio.get_event_loop()
                                resp = await loop.run_in_executor(None, agent.wait_response, mid, timeout)
                                await ws.send_json({
                                    "type": "command_result",
                                    "agent_id": agent.id,
                                    "command": cmd,
                                    "response": resp
                                })
                            else:
                                await ws.send_json({"type": "command_error", "error": "Target agent not found or missing command"})
                    except Exception as e:
                        await ws.send_json({"type": "error", "error": str(e)})
                elif msg.type == WSMsgType.ERROR:
                    break
        finally:
            self._ws_clients.discard(ws)
        return ws

    def _on_server_event(self, ev: str, data: Any):
        if not self._loop or not self._loop.is_running():
            return

        payload = None
        if ev == "connect":
            payload = {
                "type": "agent_connected",
                "agent": {
                    "id": data.id,
                    "hostname": data.hostname,
                    "username": data.username,
                    "ip": data.ip,
                    "os": data.os,
                    "defense_capabilities": data.defense_caps,
                    "attestation_status": data.attestation_status
                },
                "timestamp": datetime.now().isoformat()
            }
        elif ev == "disconnect":
            payload = {
                "type": "agent_disconnected",
                "agent_id": data.id,
                "hostname": data.hostname,
                "timestamp": datetime.now().isoformat()
            }
        elif ev == "security_event":
            agent, alert = data
            payload = {
                "type": "security_event",
                "agent_id": agent.id,
                "hostname": agent.hostname,
                "alert": alert,
                "timestamp": datetime.now().isoformat()
            }
        elif ev == "telemetry":
            agent, frame = data
            payload = {
                "type": "telemetry",
                "agent_id": agent.id,
                "hostname": agent.hostname,
                "telemetry": frame,
                "timestamp": datetime.now().isoformat()
            }
        elif ev == "attestation_update":
            payload = {
                "type": "attestation_update",
                "agent_id": data.id,
                "hostname": data.hostname,
                "status": data.attestation_status,
                "details": getattr(data, "attestation_details", {}),
                "timestamp": datetime.now().isoformat()
            }

        if payload:
            asyncio.run_coroutine_threadsafe(self._broadcast(payload), self._loop)

    async def _broadcast(self, msg: dict):
        dead = []
        for ws in list(self._ws_clients):
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._ws_clients.discard(ws)

    def broadcast_event(self, msg: dict):
        """Broadcasts an event message dictionary to all connected WebSocket clients."""
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self._broadcast(msg), self._loop)
        else:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._broadcast(msg))
            except RuntimeError:
                pass

    def start(self):
        """Starts embedded web portal listening on self.port in a dedicated background daemon thread."""
        def _run():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._runner = web.AppRunner(self._app)
            self._loop.run_until_complete(self._runner.setup())
            self._site = web.TCPSite(
                self._runner,
                self.host,
                self.port,
                ssl_context=self.tls_context
            )
            self._loop.run_until_complete(self._site.start())
            scheme = "https" if self.tls_context else "http"
            AUDIT.info("WEB_PORTAL_START  url=%s://%s:%d", scheme, self.host, self.port)
            self._loop.run_forever()

        self._thread = threading.Thread(target=_run, daemon=True, name="web-portal")
        self._thread.start()

    def stop(self):
        """Stops the embedded web portal runner and closes client connections."""
        if self._loop and self._loop.is_running():
            async def _cleanup():
                for ws in list(self._ws_clients):
                    try: await ws.close()
                    except Exception: pass
                if self._site:
                    await self._site.stop()
                if self._runner:
                    await self._runner.cleanup()
            asyncio.run_coroutine_threadsafe(_cleanup(), self._loop)
            self._loop.call_soon_threadsafe(self._loop.stop)


App = WebPortal  # Headless WebPortal replaces the legacy desktop Tkinter App


def ensure_server_dependencies():
    """Installs required/optional server dependencies like cryptography if missing."""
    try:
        import cryptography
        print("[+] cryptography is already installed.")
    except ImportError:
        print("[*] Installing cryptography for automated TLS certificate management...")
        import subprocess
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "cryptography"], check=True)
            print("[+] Successfully installed cryptography.")
        except Exception as e:
            print(f"[!] Warning: Failed to install cryptography automatically: {e}")


def main():
    p = argparse.ArgumentParser(description="Secure Endpoint Detection, Response & Defense Server")
    p.add_argument("--host",   default=DEFAULT_HOST, help=f"Bind address (default: {DEFAULT_HOST})")
    p.add_argument("--port",   type=int, default=DEFAULT_C2_PORT, help=f"C2 TCP port (default: {DEFAULT_C2_PORT})")
    p.add_argument("--web-port", type=int, default=DEFAULT_WEB_PORT, help=f"Web Portal port (default: {DEFAULT_WEB_PORT})")
    p.add_argument("--psk",    default=None, help="Pre-shared key for agent auth (auto-generated if omitted)")
    p.add_argument("--cert",   default=None, help=f"TLS certificate PEM (default: {CERT_FILE} or from config)")
    p.add_argument("--key",    default=None, help=f"TLS private key PEM (default: {KEY_FILE} or from config)")
    p.add_argument("--no-tls", action="store_true", help="Disable TLS — NOT recommended for production")
    p.add_argument("--allow",  action="append", metavar="CIDR", help="Restrict incoming connections to CIDR (repeatable)")
    p.add_argument("--install-deps", action="store_true", help="Install missing server dependencies (e.g. cryptography)")
    p.add_argument("--config", default=DEFAULT_CONFIG_FILE, help=f"Configuration file path (default: {DEFAULT_CONFIG_FILE})")
    p.add_argument("--wizard", "--first-run", action="store_true", dest="wizard", help="Force launch first-run configuration wizard")
    p.add_argument("--headless", "--non-interactive", action="store_true", dest="headless", help="Run without interactive prompts")
    p.add_argument("--reload", action="store_true", help="Validate and reload existing configuration from disk, then exit")
    p.add_argument("--build-package", choices=["linux", "windows", "all"], default=None, help="Build deployable agent package archive and exit")
    p.add_argument("--package-output", default=None, help="Target output file or directory for built package")
    p.add_argument("--package-host", default=None, help="Server host override for built package")
    p.add_argument("--package-port", type=int, default=None, help="Server port override for built package")
    p.add_argument("--package-psk", default=None, help="PSK override for built package")
    p.add_argument("--package-fingerprint", default=None, help="Certificate fingerprint override for built package")
    p.add_argument("--package-group", default=None, help="Group tag override for built package (e.g. servers)")
    p.add_argument("--package-interval", type=int, default=10, help="Polling/heartbeat interval override in seconds")
    p.add_argument("--debug", action="store_true", help="Enable verbose DEBUG logging to console and log file for troubleshooting connectivity")
    args = p.parse_args()

    # Reconfigure logging early if --debug is passed
    if args.debug:
        configure_server_logging(debug=True, log_file=LOG_FILE, console=True)
        AUDIT.debug("DEBUG_MODE  Debug logging enabled via --debug flag")

    if args.install_deps:
        ensure_server_dependencies()

    config_path = args.config

    if args.reload:
        cfg = load_server_config(config_path)
        print(f"[+] Successfully loaded and validated configuration from {config_path}")
        print(f"    C2 Server:  {cfg.host}:{cfg.port}")
        print(f"    Web Portal: {cfg.host}:{cfg.web_port}")
        print(f"    TLS:        {cfg.use_tls}")
        print(f"    Fingerprint:{cfg.cert_fingerprint}")
        print(f"    PSK:        {mask_credential(cfg.psk)}")
        return

    is_first_run = not os.path.exists(config_path) or args.wizard

    if is_first_run:
        config = run_config_wizard(
            config_path=config_path,
            interactive=False,
            host=args.host or DEFAULT_HOST,
            port=args.port or DEFAULT_C2_PORT,
            web_port=args.web_port or DEFAULT_WEB_PORT,
            psk=args.psk,
            use_tls=not args.no_tls,
            cert_file=args.cert or CERT_FILE,
            key_file=args.key or KEY_FILE,
            allow_cidrs=args.allow or [],
        )
    else:
        config = load_server_config(config_path)
        if args.host is not None:
            config.host = args.host
        if args.port is not None:
            config.port = args.port
        if args.web_port is not None:
            config.web_port = args.web_port
        if args.psk is not None:
            config.psk = args.psk
        if args.cert is not None:
            config.cert_file = args.cert
        if args.key is not None:
            config.key_file = args.key
        if args.no_tls:
            config.use_tls = False
        if args.allow is not None:
            config.allow_cidrs = args.allow

    set_restrictive_permissions(config_path)
    if os.path.exists(config.key_file):
        set_restrictive_permissions(config.key_file)
    if os.path.exists(config.psk_file):
        set_restrictive_permissions(config.psk_file)

    psk = config.psk
    print(f"\n{'='*60}")
    print(f"  PSK  ->  {psk}")
    print("  Configure PSK in agents/windows/Agent-Core.ps1 or agents/linux/agent_core.py")

    tls_context: Optional[ssl.SSLContext] = None
    fingerprint: Optional[str] = config.cert_fingerprint

    if config.use_tls:
        fp = ensure_cert(config.cert_file, config.key_file)
        if fp:
            fingerprint = fp
            config.cert_fingerprint = fp
            secure_write_file(config.fingerprint_file, fingerprint)
            print(f"\n  Cert fingerprint  ->  {fingerprint}")
            print("  Configure $CertThumbprint or CERT_FINGERPRINT in agents")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(config.cert_file, config.key_file)
            tls_context = ctx
        else:
            print("\n  WARNING: TLS unavailable -- traffic will be unencrypted")
    else:
        print("\n  WARNING: TLS disabled -- traffic will be unencrypted")
    print(f"{'='*60}\n")

    if args.build_package:
        target_os_list = ["linux", "windows"] if args.build_package == "all" else [args.build_package]
        for target_os in target_os_list:
            print(f"[*] Building {target_os} agent package via CLI...")
            try:
                res_path = build_agent_package(
                    os_type=target_os,
                    output_path=args.package_output if args.build_package != "all" else None,
                    server_host=args.package_host or config.host,
                    server_port=args.package_port or config.port,
                    psk=args.package_psk or config.psk,
                    cert_fingerprint=args.package_fingerprint or fingerprint or config.cert_fingerprint,
                    use_tls=config.use_tls and not args.no_tls,
                    polling_interval=args.package_interval if args.package_interval is not None else 10,
                    group_tag=args.package_group or "default",
                    config=config
                )
                with open(res_path, "rb") as f:
                    sha256 = hashlib.sha256(f.read()).hexdigest()
                size_bytes = os.path.getsize(res_path)
                print(f"[+] Agent package created successfully:")
                print(f"    Target:  {target_os}")
                print(f"    Path:    {res_path}")
                print(f"    SHA256:  {sha256}")
                print(f"    Size:    {size_bytes:,} bytes")
            except Exception as e:
                print(f"[!] Package build failed for {target_os}: {e}")
                sys.exit(1)
        return

    allow_nets: List[IPv4Network] = []
    if config.allow_cidrs:
        for cidr in config.allow_cidrs:
            try:
                allow_nets.append(ip_network(cidr, strict=False))
                print(f"[*] IP restriction: {cidr}")
            except ValueError as e:
                print(f"[!] Invalid CIDR '{cidr}': {e}")

    AUDIT.info("SERVER_START  host=%s  c2_port=%d  web_port=%d  tls=%s  allow=%s  debug=%s",
               config.host, config.port, config.web_port, tls_context is not None,
               [str(n) for n in allow_nets] or "any", args.debug)
    AUDIT.debug("SERVER_CONFIG  psk_len=%d  cert=%s  key=%s  fingerprint=%s",
                len(psk), config.cert_file, config.key_file,
                fingerprint[:16] + "..." if fingerprint else "None")

    # Start C2 Agent TCP Listener (Default port 443)
    server = EDRServer(config.host, config.port, psk, tls_context, allow_nets)
    server.start()
    AUDIT.debug("C2_LISTENER_STARTED  host=%s  port=%d", config.host, config.port)

    # Start Web Portal (Default port 8443) sharing the TLS context
    web_port = getattr(config, "web_port", DEFAULT_WEB_PORT)
    portal = WebPortal(server, config.host, web_port, config, tls_context)
    portal.start()
    AUDIT.debug("WEB_PORTAL_STARTED  host=%s  port=%d", config.host, web_port)

    scheme = "https" if tls_context else "http"
    print(f"[+] Server-EDR C2 Socket listening on {config.host}:{config.port}")
    print(f"[+] Server-EDR Web Portal listening on {scheme}://{config.host}:{web_port}")
    if args.debug:
        print(f"[*] DEBUG MODE ACTIVE — verbose connection diagnostics enabled in console and {LOG_FILE}")
    print(f"[*] Dual-listener infrastructure active. (Press Ctrl+C to terminate)")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[*] Server shutting down...")
        portal.stop()


if __name__ == "__main__":
    main()
