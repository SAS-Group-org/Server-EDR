#!/usr/bin/env python3
"""
Secure Endpoint Detection, Response & Defense Platform — GUI Server
Requires: Python 3.8+
Optional: pip install cryptography   (for automatic TLS cert generation)

Features:
  - TLS 1.2+ encryption with certificate pinning & rotating audit log
  - HMAC-SHA256 challenge-response pre-shared key (PSK) authentication
  - Duplex asynchronous messaging (synchronous commands + real-time alerts + telemetry)
  - Endpoint Defense Console:
      * Security Alerts Tab (Unified real-time feed for FIM, DLP, Malware, and OpenEDR)
      * Malware Prevention & Quarantine Tab (Remote scans, quarantine vault manager)
      * File Integrity Monitoring (FIM) Tab (Baselines, real-time change detection)
      * Data Loss Prevention (DLP) Tab (PII, credit card Luhn check, transfer protection)
      * OpenEDR Tab (Service status, kernel telemetry streaming, emergency host containment)
"""
from __future__ import annotations

import argparse, base64, collections, hashlib, hmac as _hmac, json, logging, os, queue, re
import secrets, socket, ssl, stat, struct, sys, threading, time, uuid
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network, IPv4Network
from logging.handlers import RotatingFileHandler
from typing import Callable, Dict, List, Optional, Tuple, Any

try:
    from agents.linux.package_linux_agent import build_linux_package
except ImportError:
    build_linux_package = None

try:
    from agents.windows.package_windows_agent import build_windows_package
except ImportError:
    build_windows_package = None

# ─────────────────────────────────────────────────────────────
DEFAULT_HOST            = "0.0.0.0"
DEFAULT_PORT            = 4444
DEFAULT_CONFIG_FILE     = "server_config.json"
DEFAULT_ENROLLMENT_FILE = "edr_enrollment.json"
MAX_MSG_BYTES           = 50 * 1024 * 1024   # 50 MB hard cap — prevents memory DoS
AUTH_TIMEOUT_SECS       = 15                  # seconds to complete TLS + HMAC handshake
CERT_FILE               = "edr_server.crt" if os.path.exists("edr_server.crt") or not os.path.exists("rat_server.crt") else "rat_server.crt"
KEY_FILE                = "edr_server.key" if os.path.exists("edr_server.key") or not os.path.exists("rat_server.key") else "rat_server.key"
PSK_FILE                = "edr_psk.txt" if os.path.exists("edr_psk.txt") or not os.path.exists("rat_psk.txt") else "rat_psk.txt"
FPRINT_FILE             = "edr_fingerprint.txt" if os.path.exists("edr_fingerprint.txt") or not os.path.exists("rat_fingerprint.txt") else "rat_fingerprint.txt"
LOG_FILE                = "edr_audit.log"

C = {
    "base":    "#1e1e2e", "mantle":  "#181825", "crust":   "#11111b",
    "surface0":"#313244", "surface1":"#45475a", "surface2":"#585b70",
    "overlay0":"#6c7086", "overlay1":"#7f849c", "text":    "#cdd6f4",
    "subtext": "#a6adc8", "blue":    "#89b4fa", "lavender":"#b4befe",
    "mauve":   "#cba6f7", "red":     "#f38ba8", "peach":   "#fab387",
    "yellow":  "#f9e2af", "green":   "#a6e3a1", "teal":    "#94e2d5",
    "sky":     "#89dceb",
}


# ════════════════════════════════════════════════════════════════
#  Font detection
# ════════════════════════════════════════════════════════════════

def _pick_mono() -> str:
    try:
        import tkinter.font as tkfont
        import tkinter as _tk
        _r = _tk.Tk(); _r.withdraw()
        available = set(tkfont.families())
        _r.destroy()
    except Exception:
        available = set()
    for candidate in (
        "Courier New", "DejaVu Sans Mono", "Liberation Mono",
        "Hack", "Fira Mono", "Cascadia Mono", "JetBrains Mono",
        "Source Code Pro", "Roboto Mono", "Courier 10 Pitch",
        "Courier", "Monospace", "fixed",
    ):
        if candidate in available:
            return candidate
    return "TkFixedFont"


MONO = _pick_mono()


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
    reconnect_secs: int = 5
) -> Dict[str, Any]:
    """Generates enrollment credentials for secure server-client communication."""
    return {
        "server_host": server_host,
        "server_port": int(server_port),
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
            self.host, self.port, self.psk, self.cert_fingerprint, self.use_tls
        )

    def validate(self) -> None:
        if not self.host or not isinstance(self.host, str):
            raise ValueError(f"Invalid server host: {self.host}")
        if not (1 <= self.port <= 65535):
            raise ValueError(f"Invalid server port (must be 1-65535): {self.port}")
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
            self.host, self.port, self.psk, self.cert_fingerprint, self.use_tls
        )


def save_server_config(config: ServerConfig, config_path: Optional[str] = None) -> str:
    """Persists ServerConfig to JSON file with restrictive permissions (0600)."""
    path = config_path or config.config_path or DEFAULT_CONFIG_FILE
    config.validate()
    config.updated_at = datetime.now(timezone.utc).isoformat()
    config.enrollment_credentials = config.to_enrollment_credentials()
    data = config.to_dict()
    secure_write_file(path, json.dumps(data, indent=2))
    AUDIT.info("CONFIG_SAVED  path=%s  host=%s  port=%d", path, config.host, config.port)
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
        current_config.psk = new_cfg.psk
        current_config.use_tls = new_cfg.use_tls
        current_config.cert_file = new_cfg.cert_file
        current_config.key_file = new_cfg.key_file
        current_config.cert_fingerprint = new_cfg.cert_fingerprint
        current_config.allow_cidrs = new_cfg.allow_cidrs
        current_config.enrollment_credentials = new_cfg.enrollment_credentials
        current_config.updated_at = new_cfg.updated_at
    AUDIT.info("CONFIG_RELOAD  path=%s  host=%s  port=%d  tls=%s",
               config_path, new_cfg.host, new_cfg.port, new_cfg.use_tls)
    return new_cfg


# ════════════════════════════════════════════════════════════════
#  First-Run Configuration Wizard & GUI Dialogs
# ════════════════════════════════════════════════════════════════

class ConfigWizardDialog(tk.Toplevel):
    """First-Run Server Configuration Wizard Dialog."""
    def __init__(
        self,
        parent: tk.Tk | tk.Toplevel,
        config_path: str = DEFAULT_CONFIG_FILE,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        psk: Optional[str] = None,
        use_tls: bool = True,
        cert_file: str = CERT_FILE,
        key_file: str = KEY_FILE,
        allow_cidrs: Optional[List[str]] = None,
    ):
        super().__init__(parent)
        self.title("Server-EDR // First-Run Configuration Wizard")
        self.geometry("620x600")
        self.minsize(580, 540)
        self.configure(bg=C["base"])
        self.transient(parent)
        self.grab_set()

        self.config_path = config_path
        self.result_config: Optional[ServerConfig] = None

        self._host_var = tk.StringVar(value=host)
        self._port_var = tk.StringVar(value=str(port))
        self._tls_var = tk.BooleanVar(value=use_tls)
        self._cert_var = tk.StringVar(value=cert_file)
        self._key_var = tk.StringVar(value=key_file)
        self._psk_var = tk.StringVar(value=psk or secrets.token_hex(32))
        self._cidrs_var = tk.StringVar(value=", ".join(allow_cidrs or []))
        self._restrict_perms_var = tk.BooleanVar(value=True)

        self._build_ui()

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=C["crust"], height=64)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="🛡️  SERVER-EDR INITIAL CONFIGURATION WIZARD",
                 bg=C["crust"], fg=C["blue"], font=(MONO, 12, "bold")).pack(anchor="w", padx=16, pady=(10, 2))
        tk.Label(hdr, text="First-run setup: configure listening endpoint, TLS identity, and client enrollment credentials.",
                 bg=C["crust"], fg=C["subtext"], font=(MONO, 8)).pack(anchor="w", padx=16)

        # Body
        body = tk.Frame(self, bg=C["base"], padx=18, pady=12)
        body.pack(fill="both", expand=True)

        def make_section(title: str):
            f = tk.Frame(body, bg=C["base"])
            f.pack(fill="x", pady=(8, 4))
            tk.Label(f, text=title, bg=C["base"], fg=C["mauve"], font=(MONO, 9, "bold")).pack(anchor="w")
            tk.Frame(f, bg=C["surface0"], height=1).pack(fill="x", pady=2)
            return f

        # Network section
        make_section("1. Network & Listening Endpoint")
        grid1 = tk.Frame(body, bg=C["base"])
        grid1.pack(fill="x", pady=2)
        tk.Label(grid1, text="Bind Address:", bg=C["base"], fg=C["text"], font=(MONO, 9)).grid(row=0, column=0, sticky="w", pady=3)
        ttk.Entry(grid1, textvariable=self._host_var, width=20).grid(row=0, column=1, sticky="w", padx=8, pady=3)
        tk.Label(grid1, text="TCP Port:", bg=C["base"], fg=C["text"], font=(MONO, 9)).grid(row=0, column=2, sticky="w", padx=(12, 0), pady=3)
        ttk.Entry(grid1, textvariable=self._port_var, width=10).grid(row=0, column=3, sticky="w", padx=8, pady=3)

        tk.Label(grid1, text="Allowed CIDRs:", bg=C["base"], fg=C["text"], font=(MONO, 9)).grid(row=1, column=0, sticky="w", pady=3)
        ttk.Entry(grid1, textvariable=self._cidrs_var, width=38).grid(row=1, column=1, columnspan=3, sticky="we", padx=8, pady=3)

        # TLS Identity section
        make_section("2. TLS Transport Identity")
        grid2 = tk.Frame(body, bg=C["base"])
        grid2.pack(fill="x", pady=2)
        tk.Checkbutton(grid2, text="Enable TLS 1.2+ Transport Encryption", variable=self._tls_var,
                       bg=C["base"], fg=C["green"], selectcolor=C["surface0"], activebackground=C["base"],
                       activeforeground=C["green"], font=(MONO, 9, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=2)

        tk.Label(grid2, text="Certificate File:", bg=C["base"], fg=C["text"], font=(MONO, 9)).grid(row=1, column=0, sticky="w", pady=2)
        ttk.Entry(grid2, textvariable=self._cert_var, width=32).grid(row=1, column=1, sticky="w", padx=8, pady=2)

        tk.Label(grid2, text="Private Key File:", bg=C["base"], fg=C["text"], font=(MONO, 9)).grid(row=2, column=0, sticky="w", pady=2)
        ttk.Entry(grid2, textvariable=self._key_var, width=32).grid(row=2, column=1, sticky="w", padx=8, pady=2)

        # Authentication & Enrollment
        make_section("3. Sensor Authentication & Enrollment")
        grid3 = tk.Frame(body, bg=C["base"])
        grid3.pack(fill="x", pady=2)
        tk.Label(grid3, text="Pre-Shared Key (PSK):", bg=C["base"], fg=C["text"], font=(MONO, 9)).grid(row=0, column=0, sticky="w", pady=2)
        ttk.Entry(grid3, textvariable=self._psk_var, width=36).grid(row=0, column=1, sticky="w", padx=8, pady=2)
        ttk.Button(grid3, text="🔄 Generate", command=lambda: self._psk_var.set(secrets.token_hex(32))).grid(row=0, column=2, sticky="w", pady=2)

        # Hardening Notice
        make_section("4. Security Persistence & Permissions")
        sec_f = tk.Frame(body, bg=C["surface0"], padx=10, pady=8)
        sec_f.pack(fill="x", pady=4)
        tk.Checkbutton(sec_f, text="🔒 Enforce Restrictive Permissions (0600 / restricted ACLs)", variable=self._restrict_perms_var,
                       bg=C["surface0"], fg=C["text"], selectcolor=C["base"], activebackground=C["surface0"],
                       activeforeground=C["text"], font=(MONO, 9)).pack(anchor="w")
        tk.Label(sec_f, text="Configuration, private key, and PSK will be saved with owner-only access to prevent unauthorized credential access.",
                 bg=C["surface0"], fg=C["subtext"], font=(MONO, 8), wraplength=520, justify="left").pack(anchor="w", pady=(2, 0))

        # Bottom buttons
        btn_bar = tk.Frame(self, bg=C["crust"], height=48, padx=16)
        btn_bar.pack(fill="x", side="bottom")
        btn_bar.pack_propagate(False)

        ttk.Button(btn_bar, text="Save & Start Server", style="Success.TButton", command=self._on_save).pack(side="right", padx=6, pady=8)
        ttk.Button(btn_bar, text="Cancel", style="Danger.TButton", command=self.destroy).pack(side="right", padx=6, pady=8)

    def _on_save(self):
        host = self._host_var.get().strip() or DEFAULT_HOST
        port_str = self._port_var.get().strip()
        psk = self._psk_var.get().strip()
        use_tls = self._tls_var.get()
        cert_file = self._cert_var.get().strip() or CERT_FILE
        key_file = self._key_var.get().strip() or KEY_FILE
        cidrs_raw = self._cidrs_var.get().strip()

        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError()
        except Exception:
            messagebox.showerror("Invalid Port", "Port must be an integer between 1 and 65535.")
            return

        if not psk:
            messagebox.showerror("Invalid PSK", "Pre-shared key (PSK) cannot be empty.")
            return

        allow_cidrs = []
        if cidrs_raw:
            for c in [x.strip() for x in cidrs_raw.split(",") if x.strip()]:
                try:
                    ip_network(c, strict=False)
                    allow_cidrs.append(c)
                except ValueError as e:
                    messagebox.showerror("Invalid CIDR", f"Invalid CIDR '{c}': {e}")
                    return

        fingerprint = ""
        if use_tls:
            try:
                _, _, fingerprint = generate_tls_identity(cert_file, key_file)
            except Exception as e:
                messagebox.showerror("TLS Error", f"Failed generating TLS certificate and key: {e}")
                return

        # Save PSK and fingerprint files
        secure_write_file(PSK_FILE, psk)
        if fingerprint:
            secure_write_file(FPRINT_FILE, fingerprint)

        enrollment = generate_enrollment_credentials(
            host, port, psk, fingerprint, use_tls
        )
        export_enrollment_credentials(enrollment, DEFAULT_ENROLLMENT_FILE)

        config = ServerConfig(
            host=host,
            port=port,
            psk=psk,
            use_tls=use_tls,
            cert_file=cert_file,
            key_file=key_file,
            cert_fingerprint=fingerprint,
            allow_cidrs=allow_cidrs,
            enrollment_credentials=enrollment,
            config_path=self.config_path,
        )
        save_server_config(config, self.config_path)
        self.result_config = config
        self.destroy()


class ServerConfigDialog(tk.Toplevel):
    """Runtime Configuration Viewer & Reload Dialog."""
    def __init__(
        self,
        parent: tk.Tk | tk.Toplevel,
        config: Optional[ServerConfig],
        on_reload: Optional[Callable] = None,
    ):
        super().__init__(parent)
        self.title("Server-EDR // Active Server Configuration")
        self.geometry("600x520")
        self.minsize(540, 460)
        self.configure(bg=C["base"])
        self.transient(parent)
        self.grab_set()

        self.config = config
        self.on_reload = on_reload
        self._psk_revealed = False

        self._build_ui()

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=C["crust"], height=50)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="⚙️  ACTIVE SERVER CONFIGURATION",
                 bg=C["crust"], fg=C["blue"], font=(MONO, 11, "bold")).pack(side="left", padx=16, pady=12)

        body = tk.Frame(self, bg=C["base"], padx=18, pady=12)
        body.pack(fill="both", expand=True)

        if not self.config:
            tk.Label(body, text="No active configuration file loaded.", bg=C["base"], fg=C["peach"], font=(MONO, 10)).pack(pady=20)
            return

        cfg = self.config
        rows = [
            ("Config File:", cfg.config_path),
            ("Listen Host:", cfg.host),
            ("Listen Port:", str(cfg.port)),
            ("TLS Transport:", "Enabled (TLS 1.2+)" if cfg.use_tls else "Disabled (Plaintext)"),
            ("Cert File:", cfg.cert_file),
            ("Key File:", cfg.key_file),
            ("Cert Fingerprint:", cfg.cert_fingerprint or "N/A"),
            ("Allow CIDRs:", ", ".join(cfg.allow_cidrs) if cfg.allow_cidrs else "Any (0.0.0.0/0)"),
            ("Last Updated:", cfg.updated_at),
        ]

        for i, (k, v) in enumerate(rows):
            tk.Label(body, text=k, bg=C["base"], fg=C["subtext"], font=(MONO, 9, "bold")).grid(row=i, column=0, sticky="w", pady=3)
            tk.Label(body, text=v, bg=C["base"], fg=C["text"], font=(MONO, 9)).grid(row=i, column=1, sticky="w", padx=10, pady=3)

        # PSK row with reveal toggle
        r_psk = len(rows)
        tk.Label(body, text="Pre-Shared Key:", bg=C["base"], fg=C["subtext"], font=(MONO, 9, "bold")).grid(row=r_psk, column=0, sticky="w", pady=3)
        self._lbl_psk = tk.Label(body, text=mask_credential(cfg.psk), bg=C["base"], fg=C["yellow"], font=(MONO, 9))
        self._lbl_psk.grid(row=r_psk, column=1, sticky="w", padx=10, pady=3)
        ttk.Button(body, text="👁 Toggle", command=self._toggle_psk).grid(row=r_psk, column=2, sticky="w", pady=3)

        # Buttons
        btn_bar = tk.Frame(self, bg=C["crust"], height=48, padx=16)
        btn_bar.pack(fill="x", side="bottom")
        btn_bar.pack_propagate(False)

        ttk.Button(btn_bar, text="Close", command=self.destroy).pack(side="right", padx=6, pady=8)
        if self.on_reload:
            ttk.Button(btn_bar, text="🔄 Reload from Disk", command=self._do_reload).pack(side="left", padx=6, pady=8)
        ttk.Button(btn_bar, text="📦 Build Package", command=self._open_package_builder).pack(side="left", padx=6, pady=8)

    def _open_package_builder(self):
        creds = self.config.to_enrollment_credentials() if self.config else {}
        AgentPackageBuilderDialog(self.master, credentials=creds, config=self.config)

    def _toggle_psk(self):
        if not self.config: return
        self._psk_revealed = not self._psk_revealed
        self._lbl_psk.config(text=self.config.psk if self._psk_revealed else mask_credential(self.config.psk))

    def _do_reload(self):
        if self.on_reload:
            self.on_reload()
            self.destroy()


class EnrollmentCredentialsDialog(tk.Toplevel):
    """Enrollment Credentials Display and Export Modal."""
    def __init__(
        self,
        parent: tk.Tk | tk.Toplevel,
        credentials: Dict[str, Any]
    ):
        super().__init__(parent)
        self.title("Server-EDR // Client Enrollment Credentials")
        self.geometry("640x480")
        self.minsize(580, 420)
        self.configure(bg=C["base"])
        self.transient(parent)
        self.grab_set()

        self.credentials = credentials
        self._build_ui()

    def _build_ui(self):
        hdr = tk.Frame(self, bg=C["crust"], height=50)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="🔑  CLIENT ENROLLMENT CREDENTIALS",
                 bg=C["crust"], fg=C["blue"], font=(MONO, 11, "bold")).pack(side="left", padx=16, pady=12)

        body = tk.Frame(self, bg=C["base"], padx=18, pady=12)
        body.pack(fill="both", expand=True)

        tk.Label(body, text="Configure these credentials into endpoint defense agents or export agent packages:",
                 bg=C["base"], fg=C["subtext"], font=(MONO, 8)).pack(anchor="w", pady=(0, 10))

        c = self.credentials
        rows = [
            ("Server Endpoint:", f"{c.get('server_host')}:{c.get('server_port')}"),
            ("TLS Fingerprint:", c.get("cert_fingerprint", "N/A")),
            ("PSK (Hex Token):", c.get("psk", "")),
            ("TLS Required:", "Yes" if c.get("use_tls") else "No"),
            ("Reconnect Interval:", f"{c.get('reconnect_secs', 5)}s"),
        ]

        for k, v in rows:
            f = tk.Frame(body, bg=C["base"])
            f.pack(fill="x", pady=4)
            tk.Label(f, text=f"{k:<20}", bg=C["base"], fg=C["blue"], font=(MONO, 9, "bold")).pack(side="left")
            val_ent = ttk.Entry(f, width=42)
            val_ent.insert(0, str(v))
            val_ent.configure(state="readonly")
            val_ent.pack(side="left", padx=8)

        # Export Buttons
        btn_bar = tk.Frame(self, bg=C["crust"], height=48, padx=16)
        btn_bar.pack(fill="x", side="bottom")
        btn_bar.pack_propagate(False)

        ttk.Button(btn_bar, text="Close", command=self.destroy).pack(side="right", padx=6, pady=8)
        ttk.Button(btn_bar, text="Export edr_enrollment.json", command=self._export_enrollment).pack(side="left", padx=6, pady=8)
        ttk.Button(btn_bar, text="Export agent_config.json", command=self._export_agent_config).pack(side="left", padx=6, pady=8)
        ttk.Button(btn_bar, text="📦 Build Package", command=self._open_package_builder).pack(side="left", padx=6, pady=8)

    def _open_package_builder(self):
        AgentPackageBuilderDialog(self.master, credentials=self.credentials)

    def _export_enrollment(self):
        fpath = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile="edr_enrollment.json",
            filetypes=[("JSON files", "*.json"), ("All Files", "*.*")]
        )
        if fpath:
            export_enrollment_credentials(self.credentials, fpath)
            messagebox.showinfo("Export Successful", f"Saved enrollment credentials to:\n{fpath}")

    def _export_agent_config(self):
        fpath = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile="agent_config.json",
            filetypes=[("JSON files", "*.json"), ("All Files", "*.*")]
        )
        if fpath:
            generate_agent_config(self.credentials, output_path=fpath)
            messagebox.showinfo("Export Successful", f"Saved agent config to:\n{fpath}")


# ════════════════════════════════════════════════════════════════
#  Agent Package Builder (GUI & Programmatic Backend)
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


class AgentPackageBuilderDialog(tk.Toplevel):
    """GUI Agent Package Builder Dialog for Linux (.tar.gz) and Windows (.zip)."""
    def __init__(
        self,
        parent: tk.Tk | tk.Toplevel,
        credentials: Optional[Dict[str, Any]] = None,
        config: Optional[ServerConfig] = None,
    ):
        super().__init__(parent)
        self.title("Server-EDR // GUI Agent Package Builder")
        self.geometry("640x660")
        self.minsize(600, 600)
        self.configure(bg=C["base"])
        self.transient(parent)
        self.grab_set()

        self.credentials = credentials or {}
        self.config = config
        self._target_os_var = tk.StringVar(value="linux")
        self._use_tls_var = tk.BooleanVar(value=self.credentials.get("use_tls", True))

        self._build_ui()

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=C["crust"], height=52)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="📦  GUI AGENT PACKAGE BUILDER",
                 bg=C["crust"], fg=C["blue"], font=(MONO, 12, "bold")).pack(side="left", padx=16, pady=12)

        # Body container
        body = tk.Frame(self, bg=C["base"], padx=20, pady=12)
        body.pack(fill="both", expand=True)

        # 1. Target OS selector
        os_frame = tk.LabelFrame(body, text=" 1. Target Operating System & Format ",
                                 bg=C["base"], fg=C["blue"], font=(MONO, 9, "bold"), padx=12, pady=8)
        os_frame.pack(fill="x", pady=(0, 10))

        rb_linux = tk.Radiobutton(os_frame, text="Linux Sensor (.tar.gz)", value="linux",
                                  variable=self._target_os_var, command=self._on_os_change,
                                  bg=C["base"], fg=C["text"], selectcolor=C["surface0"],
                                  activebackground=C["base"], activeforeground=C["lavender"], font=(MONO, 9))
        rb_linux.pack(side="left", padx=(10, 20))

        rb_win = tk.Radiobutton(os_frame, text="Windows Sensor (.zip)", value="windows",
                                variable=self._target_os_var, command=self._on_os_change,
                                bg=C["base"], fg=C["text"], selectcolor=C["surface0"],
                                activebackground=C["base"], activeforeground=C["lavender"], font=(MONO, 9))
        rb_win.pack(side="left", padx=10)

        # 2. Server Endpoint & Authentication
        net_frame = tk.LabelFrame(body, text=" 2. Endpoint & Authentication Settings ",
                                  bg=C["base"], fg=C["blue"], font=(MONO, 9, "bold"), padx=12, pady=8)
        net_frame.pack(fill="x", pady=(0, 10))

        # Host & Port
        f_ep = tk.Frame(net_frame, bg=C["base"])
        f_ep.pack(fill="x", pady=2)
        tk.Label(f_ep, text="Server Host:", width=14, anchor="w", bg=C["base"], fg=C["subtext"], font=(MONO, 9)).pack(side="left")
        self._ent_host = ttk.Entry(f_ep, width=24)
        self._ent_host.insert(0, str(self.credentials.get("server_host", "127.0.0.1")))
        self._ent_host.pack(side="left", padx=(0, 12))

        tk.Label(f_ep, text="Port:", width=6, anchor="w", bg=C["base"], fg=C["subtext"], font=(MONO, 9)).pack(side="left")
        self._ent_port = ttk.Entry(f_ep, width=10)
        self._ent_port.insert(0, str(self.credentials.get("server_port", 4444)))
        self._ent_port.pack(side="left")

        # PSK
        f_psk = tk.Frame(net_frame, bg=C["base"])
        f_psk.pack(fill="x", pady=4)
        tk.Label(f_psk, text="Pre-Shared Key:", width=14, anchor="w", bg=C["base"], fg=C["subtext"], font=(MONO, 9)).pack(side="left")
        self._ent_psk = ttk.Entry(f_psk, width=36)
        self._ent_psk.insert(0, str(self.credentials.get("psk", "")))
        self._ent_psk.pack(side="left", padx=(0, 8))
        ttk.Button(f_psk, text="🎲 New PSK", command=self._gen_psk).pack(side="left")

        # TLS & Fingerprint
        f_tls = tk.Frame(net_frame, bg=C["base"])
        f_tls.pack(fill="x", pady=2)
        tk.Checkbutton(f_tls, text="Require TLS Encryption", variable=self._use_tls_var,
                       bg=C["base"], fg=C["text"], selectcolor=C["surface0"],
                       activebackground=C["base"], font=(MONO, 9)).pack(side="left")

        f_fp = tk.Frame(net_frame, bg=C["base"])
        f_fp.pack(fill="x", pady=2)
        tk.Label(f_fp, text="TLS Fingerprint:", width=14, anchor="w", bg=C["base"], fg=C["subtext"], font=(MONO, 9)).pack(side="left")
        self._ent_fp = ttk.Entry(f_fp, width=46)
        self._ent_fp.insert(0, str(self.credentials.get("cert_fingerprint", "")))
        self._ent_fp.pack(side="left")

        # 3. Overrides (Sub-Issue #19)
        ovr_frame = tk.LabelFrame(body, text=" 3. Deployment Overrides (Group Tag & Polling) ",
                                  bg=C["base"], fg=C["blue"], font=(MONO, 9, "bold"), padx=12, pady=8)
        ovr_frame.pack(fill="x", pady=(0, 10))

        f_ovr = tk.Frame(ovr_frame, bg=C["base"])
        f_ovr.pack(fill="x", pady=2)
        tk.Label(f_ovr, text="Group Tag:", width=14, anchor="w", bg=C["base"], fg=C["subtext"], font=(MONO, 9)).pack(side="left")
        self._ent_group = ttk.Entry(f_ovr, width=20)
        self._ent_group.insert(0, "default-fleet")
        self._ent_group.pack(side="left", padx=(0, 12))

        tk.Label(f_ovr, text="Polling Interval (s):", anchor="w", bg=C["base"], fg=C["subtext"], font=(MONO, 9)).pack(side="left")
        self._ent_poll = ttk.Entry(f_ovr, width=8)
        self._ent_poll.insert(0, "10")
        self._ent_poll.pack(side="left", padx=4)

        # 4. Destination File
        out_frame = tk.LabelFrame(body, text=" 4. Output Package File ",
                                  bg=C["base"], fg=C["blue"], font=(MONO, 9, "bold"), padx=12, pady=8)
        out_frame.pack(fill="x", pady=(0, 10))

        f_out = tk.Frame(out_frame, bg=C["base"])
        f_out.pack(fill="x", pady=2)
        self._ent_out = ttk.Entry(f_out, width=48)
        self._ent_out.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(f_out, text="Browse...", command=self._browse_output).pack(side="right")

        self._update_default_output()

        # Build Status / Log Area
        self._lbl_status = tk.Label(body, text="Select configuration and click 'Build Package' to generate deployable archive.",
                                    bg=C["base"], fg=C["overlay0"], font=(MONO, 8), wraplength=580, justify="left")
        self._lbl_status.pack(fill="x", pady=(4, 0))

        # Buttons
        btn_bar = tk.Frame(self, bg=C["crust"], height=50, padx=16)
        btn_bar.pack(fill="x", side="bottom")
        btn_bar.pack_propagate(False)

        ttk.Button(btn_bar, text="Cancel", command=self.destroy).pack(side="right", padx=6, pady=10)
        ttk.Button(btn_bar, text="🔨 Build Package", style="Accent.TButton",
                   command=self._do_build).pack(side="right", padx=6, pady=10)

    def _on_os_change(self):
        self._update_default_output()

    def _update_default_output(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        dist_dir = os.path.join(base_dir, "dist")
        os.makedirs(dist_dir, exist_ok=True)
        os_choice = self._target_os_var.get()
        if os_choice == "linux":
            default_path = os.path.join(dist_dir, "server-edr-agent-linux.tar.gz")
        else:
            default_path = os.path.join(dist_dir, "Server-EDR-Agent-Windows-v1.0.0.zip")
        self._ent_out.delete(0, "end")
        self._ent_out.insert(0, default_path)

    def _gen_psk(self):
        new_token = secrets.token_hex(24)
        self._ent_psk.delete(0, "end")
        self._ent_psk.insert(0, new_token)

    def _browse_output(self):
        os_choice = self._target_os_var.get()
        if os_choice == "linux":
            filetypes = [("Tar GZip archives", "*.tar.gz"), ("All Files", "*.*")]
            defext = ".tar.gz"
            initialfile = "server-edr-agent-linux.tar.gz"
        else:
            filetypes = [("Zip archives", "*.zip"), ("All Files", "*.*")]
            defext = ".zip"
            initialfile = "Server-EDR-Agent-Windows-v1.0.0.zip"

        fpath = filedialog.asksaveasfilename(
            defaultextension=defext,
            initialfile=initialfile,
            filetypes=filetypes
        )
        if fpath:
            self._ent_out.delete(0, "end")
            self._ent_out.insert(0, fpath)

    def _do_build(self):
        os_type = self._target_os_var.get()
        host = self._ent_host.get().strip()
        port_str = self._ent_port.get().strip()
        psk = self._ent_psk.get().strip()
        fp = self._ent_fp.get().strip()
        use_tls = self._use_tls_var.get()
        group_tag = self._ent_group.get().strip()
        poll_str = self._ent_poll.get().strip()
        out_path = self._ent_out.get().strip()

        if not host:
            messagebox.showerror("Validation Error", "Server Host cannot be empty.")
            return

        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError()
        except ValueError:
            messagebox.showerror("Validation Error", "Port must be an integer between 1 and 65535.")
            return

        try:
            polling_interval = int(poll_str)
            if polling_interval <= 0:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Validation Error", "Polling interval must be a positive integer.")
            return

        if not out_path:
            messagebox.showerror("Validation Error", "Output path cannot be empty.")
            return

        self._lbl_status.config(text=f"Building {os_type.capitalize()} package... Please wait.", fg=C["yellow"])
        self.update_idletasks()

        try:
            res_path = build_agent_package(
                os_type=os_type,
                output_path=out_path,
                server_host=host,
                server_port=port,
                psk=psk,
                cert_fingerprint=fp,
                use_tls=use_tls,
                polling_interval=polling_interval,
                group_tag=group_tag,
                config=self.config
            )
            size_kb = os.path.getsize(res_path) / 1024
            with open(res_path, "rb") as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()

            msg = (
                f"✓ Package Created Successfully!\n\n"
                f"Platform: {os_type.capitalize()}\n"
                f"File: {res_path}\n"
                f"Size: {size_kb:.1f} KB\n"
                f"Group Tag: {group_tag}\n"
                f"Endpoint: {host}:{port}\n"
                f"SHA256: {sha256}"
            )
            self._lbl_status.config(text=f"✓ Package built: {os.path.basename(res_path)} ({size_kb:.1f} KB) | SHA256: {sha256[:16]}...", fg=C["green"])
            messagebox.showinfo("Package Build Complete", msg)
        except Exception as e:
            self._lbl_status.config(text=f"[-] Error: {e}", fg=C["red"])
            messagebox.showerror("Build Error", f"Failed to build package:\n{e}")



def run_config_wizard(
    config_path: str = DEFAULT_CONFIG_FILE,
    interactive: bool = True,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    psk: Optional[str] = None,
    use_tls: bool = True,
    cert_file: str = CERT_FILE,
    key_file: str = KEY_FILE,
    allow_cidrs: Optional[List[str]] = None,
    parent_window: Optional[tk.Tk | tk.Toplevel] = None
) -> ServerConfig:
    """
    Executes first-run configuration wizard flow.
    Supports interactive GUI dialog or non-interactive/headless automated generation.
    """
    if interactive:
        try:
            temp_root = None
            if parent_window is None:
                temp_root = tk.Tk()
                temp_root.withdraw()
                parent = temp_root
            else:
                parent = parent_window

            dlg = ConfigWizardDialog(
                parent,
                config_path=config_path,
                host=host,
                port=port,
                psk=psk,
                use_tls=use_tls,
                cert_file=cert_file,
                key_file=key_file,
                allow_cidrs=allow_cidrs,
            )
            dlg.wait_window()
            result = dlg.result_config
            if temp_root:
                temp_root.destroy()
            if result:
                return result
            print("[*] Wizard cancelled by user. Using default automated configuration...")
        except Exception as e:
            print(f"[*] Interactive wizard unavailable ({e}); falling back to automated setup...")

    # Non-interactive / headless setup
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
        host, port, psk_val, fingerprint, use_tls
    )
    export_enrollment_credentials(enrollment, DEFAULT_ENROLLMENT_FILE)

    config = ServerConfig(
        host=host,
        port=port,
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
                            hashes[parts[1]] = parts[0].lower()
                break
            except Exception:
                pass
    return hashes


# ════════════════════════════════════════════════════════════════
#  Audit Logging
# ════════════════════════════════════════════════════════════════

def _setup_audit_log() -> logging.Logger:
    log = logging.getLogger("edr_audit")
    log.setLevel(logging.INFO)
    if not log.handlers:
        fh = RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s  %(levelname)-7s  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        log.addHandler(fh)
    return log


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
            return json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return None

    def send_msg(self, data: dict) -> bool:
        try:
            payload = json.dumps(data).encode("utf-8")
            header  = struct.pack("<I", len(payload))
            with self._send_lock:
                self.conn.sendall(header + payload)
            return True
        except (OSError, ssl.SSLError):
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
            if not self._ip_allowed(addr[0]):
                AUDIT.warning("REJECT_IP  ip=%s", addr[0])
                raw_conn.close()
                continue
            raw_conn.settimeout(AUTH_TIMEOUT_SECS)
            threading.Thread(
                target=self._handle,
                args=(raw_conn, addr),
                daemon=True,
                name=f"agent-{addr[0]}",
            ).start()

    def _handle(self, raw_conn: socket.socket, addr: Tuple[str, int]):
        conn = raw_conn
        if self.tls_context:
            try:
                conn = self.tls_context.wrap_socket(raw_conn, server_side=True)
            except (ssl.SSLError, OSError) as e:
                AUDIT.warning("TLS_FAIL  ip=%s  err=%s", addr[0], e)
                raw_conn.close()
                return

        agent = Agent(conn, addr)
        try:
            if not self._authenticate(agent):
                conn.close()
                return

            msg = agent.recv_msg()
            if not msg or msg.get("type") != "register":
                AUDIT.warning("BAD_REGISTER  ip=%s", addr[0])
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

            AUDIT.info("CONNECT  user=%s  host=%s  ip=%s  os=%s  admin=%s",
                       agent.username, agent.hostname, agent.ip,
                       agent.os, agent.is_admin)
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

        except Exception:
            pass
        finally:
            with self._lock:
                self._agents.pop(agent.id, None)
            agent.abort_pending("Agent disconnected")
            AUDIT.info("DISCONNECT  user=%s  host=%s  ip=%s",
                       agent.username, agent.hostname, agent.ip)
            self._fire("disconnect", agent)
            try:
                conn.close()
            except Exception:
                pass

    def _authenticate(self, agent: Agent) -> bool:
        nonce = secrets.token_bytes(32)
        if not agent.send_msg({"type": "challenge", "nonce": nonce.hex()}):
            return False
        msg = agent.recv_msg()
        if not msg or msg.get("type") != "auth":
            return False
        try:
            claimed = bytes.fromhex(msg["hmac"])
        except (KeyError, ValueError):
            return False
        expected = _hmac.new(self._psk, nonce, hashlib.sha256).digest()
        if not _hmac.compare_digest(expected, claimed):
            return False
        agent.send_msg({"type": "auth_ok"})
        return True

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

class App:
    def __init__(
        self,
        root: tk.Tk,
        host: str,
        port: int,
        psk: str,
        tls_context: Optional[ssl.SSLContext],
        fingerprint: Optional[str],
        allow_nets: Optional[List[IPv4Network]],
        config: Optional[ServerConfig] = None,
    ):
        self.root = root
        self.config = config
        self.root.title("EDR Server // Endpoint Detection, Response & Defense Platform")
        self.root.geometry("1340x860")
        self.root.minsize(1050, 680)
        self.root.configure(bg=C["base"])

        self._host        = host
        self._port        = port
        self._tls         = tls_context is not None
        self._fingerprint = fingerprint

        self.server = EDRServer(host, port, psk, tls_context, allow_nets)
        self.server.on_event(self._on_server_event)

        self._sel_id: Optional[str]    = None
        self._tree_map: Dict[str, str] = {}
        self._cmd_history: List[str]   = []
        self._hist_idx: int            = -1
        self._proc_cache: List         = []
        self._sysinfo_tab_frame: Optional[tk.Frame] = None
        self._gui_event_queue: queue.Queue = queue.Queue()

        self._apply_styles()
        self._build_ui()
        self._start_clock()
        self.root.after(100, self._flush_gui_events)

        self.server.start()
        tls_badge = "TLS ✓" if self._tls else "⚠ NO TLS"
        self._log(f"[+] Endpoint Defense Server Listening on {host}:{port}  [{tls_badge}]",
                  "success" if self._tls else "warn")
        if fingerprint:
            self._log(f"[*] SHA-256 Fingerprint: {fingerprint}", "dim")
        self._log("[*] Defense Sensors active: Malware Prevention, FIM, DLP, OpenEDR", "info")

    def _apply_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure(".", background=C["base"], foreground=C["text"],
                     font=(MONO, 10), borderwidth=0, relief="flat")
        s.configure("Treeview", background=C["mantle"], foreground=C["text"],
                     fieldbackground=C["mantle"], rowheight=26,
                     borderwidth=0, relief="flat")
        s.configure("Treeview.Heading", background=C["surface0"], foreground=C["blue"],
                     font=(MONO, 10, "bold"), relief="flat")
        s.map("Treeview",
              background=[("selected", C["surface0"])],
              foreground=[("selected", C["lavender"])])
        s.configure("TButton", background=C["surface0"], foreground=C["text"],
                     font=(MONO, 10), padding=(8, 4), relief="flat")
        s.map("TButton",
              background=[("active", C["surface1"]), ("pressed", C["surface2"])])
        s.configure("Accent.TButton", background=C["blue"], foreground=C["crust"],
                     font=(MONO, 10, "bold"), padding=(10, 4))
        s.map("Accent.TButton", background=[("active", C["lavender"])])
        s.configure("Danger.TButton", background=C["red"], foreground=C["crust"],
                     font=(MONO, 10, "bold"), padding=(8, 4))
        s.map("Danger.TButton", background=[("active", "#ff9999")])
        s.configure("Success.TButton", background=C["green"], foreground=C["crust"],
                     font=(MONO, 10, "bold"), padding=(8, 4))
        s.map("Success.TButton", background=[("active", "#b8f0b4")])
        s.configure("TFrame", background=C["base"])
        s.configure("TLabel", background=C["base"], foreground=C["text"])
        s.configure("TEntry", fieldbackground=C["surface0"], foreground=C["text"],
                     insertcolor=C["text"], borderwidth=1, relief="solid")
        s.configure("TNotebook", background=C["base"], tabmargins=(2, 4, 0, 0),
                     borderwidth=0)
        s.configure("TNotebook.Tab", background=C["surface0"], foreground=C["subtext"],
                     padding=(12, 5), font=(MONO, 10))
        s.map("TNotebook.Tab",
              background=[("selected", C["base"])],
              foreground=[("selected", C["blue"])])
        s.configure("TScrollbar", background=C["surface0"], troughcolor=C["mantle"],
                     arrowcolor=C["overlay0"], borderwidth=0, relief="flat")
        s.map("TScrollbar", background=[("active", C["surface1"])])

    def _build_ui(self):
        # Top bar
        topbar = tk.Frame(self.root, bg=C["crust"], height=44)
        topbar.pack(fill="x", side="top")
        topbar.pack_propagate(False)
        tk.Label(topbar, text="🛡️  ENDPOINT DEFENSE & EDR CONSOLE", bg=C["crust"], fg=C["blue"],
                 font=(MONO, 13, "bold")).pack(side="left", padx=16, pady=8)
        self._lbl_count = tk.Label(topbar, text="Sensors: 0", bg=C["crust"],
                                    fg=C["green"], font=(MONO, 10))
        self._lbl_count.pack(side="left", padx=12)
        tls_color = C["green"] if self._tls else C["peach"]
        tls_label = "TLS 1.2+ ✓" if self._tls else "⚠ NO TLS"
        tk.Label(topbar, text=tls_label, bg=C["crust"], fg=tls_color,
                 font=(MONO, 10, "bold")).pack(side="left", padx=8)
        self._lbl_alert_badge = tk.Label(topbar, text="Alerts: 0", bg=C["crust"],
                                         fg=C["peach"], font=(MONO, 10, "bold"))
        self._lbl_alert_badge.pack(side="left", padx=12)

        ttk.Button(topbar, text="⚙️ Config", command=self._show_config_dialog).pack(side="right", padx=4)
        ttk.Button(topbar, text="🔑 Enrollment", command=self._show_enrollment_dialog).pack(side="right", padx=4)
        ttk.Button(topbar, text="📦 Build Package", command=self._show_package_builder_dialog).pack(side="right", padx=4)
        self._lbl_clock = tk.Label(topbar, text="", bg=C["crust"], fg=C["overlay0"],
                                    font=(MONO, 10))
        self._lbl_clock.pack(side="right", padx=8)

        # Main split
        pane = ttk.PanedWindow(self.root, orient="horizontal")
        pane.pack(fill="both", expand=True)
        lf = tk.Frame(pane, bg=C["base"], width=310)
        pane.add(lf, weight=1)
        self._build_agent_panel(lf)
        rf = tk.Frame(pane, bg=C["base"])
        pane.add(rf, weight=5)
        self._build_workspace(rf)

        # Status bar
        sb = tk.Frame(self.root, bg=C["crust"], height=24)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)
        self._lbl_status = tk.Label(sb, text="Ready", bg=C["crust"], fg=C["overlay0"],
                                     font=(MONO, 9))
        self._lbl_status.pack(side="left", padx=12)
        tk.Label(sb, text=f"Listening  •  {self._host}:{self._port}",
                 bg=C["crust"], fg=C["teal"], font=(MONO, 9)).pack(side="right", padx=12)

    def _build_agent_panel(self, parent):
        tk.Label(parent, text="CONNECTED ENDPOINTS", bg=C["base"], fg=C["blue"],
                 font=(MONO, 10, "bold")).pack(anchor="w", padx=10, pady=(10, 4))
        tk.Frame(parent, bg=C["surface0"], height=1).pack(fill="x", padx=10)

        cols = ("host", "user", "ip")
        self._atree = ttk.Treeview(parent, columns=cols, show="headings",
                                    selectmode="browse", height=20)
        self._atree.heading("host", text="Hostname")
        self._atree.heading("user", text="User")
        self._atree.heading("ip",   text="IP")
        self._atree.column("host", width=110, minwidth=80)
        self._atree.column("user", width=90,  minwidth=60)
        self._atree.column("ip",   width=100, minwidth=80)
        vsb = ttk.Scrollbar(parent, orient="vertical", command=self._atree.yview)
        self._atree.configure(yscrollcommand=vsb.set)
        self._atree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=8)
        vsb.pack(side="left", fill="y", pady=8, padx=(2, 8))
        self._atree.bind("<<TreeviewSelect>>", self._on_select)

        bf = tk.Frame(parent, bg=C["base"])
        bf.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(bf, text="Sysinfo", command=self._cmd_sysinfo).pack(side="left", padx=(0, 4))
        ttk.Button(bf, text="Disconnect", style="Danger.TButton",
                   command=self._disconnect).pack(side="right")

    def _build_workspace(self, parent):
        self._info_strip = tk.Frame(parent, bg=C["mantle"], height=32)
        self._info_strip.pack(fill="x")
        self._info_strip.pack_propagate(False)
        self._lbl_info = tk.Label(self._info_strip, text="  No agent selected",
                                   bg=C["mantle"], fg=C["overlay0"], font=(MONO, 9))
        self._lbl_info.pack(side="left", padx=10, pady=5)
        self._lbl_admin = tk.Label(self._info_strip, text="", bg=C["mantle"],
                                    fg=C["yellow"], font=(MONO, 9, "bold"))
        self._lbl_admin.pack(side="right", padx=10)

        self._nb = ttk.Notebook(parent)
        self._nb.pack(fill="both", expand=True)

        # Core Admin Tabs
        self._build_terminal_tab()
        self._build_processes_tab()
        self._build_files_tab()
        self._build_sysinfo_tab()

        # Endpoint Defense Tabs
        self._build_alerts_tab()
        self._build_malware_tab()
        self._build_fim_tab()
        self._build_dlp_tab()
        self._build_openedr_tab()

    # ── Admin Tabs ───────────────────────────────────────────

    def _build_terminal_tab(self):
        f = tk.Frame(self._nb, bg=C["base"])
        self._nb.add(f, text="  Terminal  ")
        self._term = scrolledtext.ScrolledText(
            f, bg=C["mantle"], fg=C["text"], insertbackground=C["text"],
            font=(MONO, 10), state="disabled", wrap="word",
            relief="flat", bd=0, padx=10, pady=8,
            selectbackground=C["surface1"])
        self._term.pack(fill="both", expand=True)
        for tag, fg in [
            ("info", C["blue"]), ("success", C["green"]), ("error", C["red"]),
            ("warn", C["peach"]), ("prompt", C["mauve"]), ("output", C["text"]),
            ("dim", C["overlay0"]),
        ]:
            self._term.tag_config(tag, foreground=fg)
        self._term.tag_config("ts", foreground=C["overlay0"], font=(MONO, 9))

        ir = tk.Frame(f, bg=C["crust"])
        ir.pack(fill="x")
        self._lbl_ps = tk.Label(ir, text="PS >", bg=C["crust"], fg=C["mauve"],
                                 font=(MONO, 11, "bold"), padx=10, pady=6)
        self._lbl_ps.pack(side="left")
        self._entry = ttk.Entry(ir, font=(MONO, 11))
        self._entry.pack(side="left", fill="x", expand=True, ipady=3)
        self._entry.bind("<Return>", self._run_shell)
        self._entry.bind("<Up>",     self._hist_up)
        self._entry.bind("<Down>",   self._hist_down)
        ttk.Button(ir, text="Run ▶", style="Accent.TButton",
                   command=self._run_shell).pack(side="left", padx=(6, 10))

    def _build_processes_tab(self):
        f = tk.Frame(self._nb, bg=C["base"])
        self._nb.add(f, text="  Processes  ")
        bar = tk.Frame(f, bg=C["base"])
        bar.pack(fill="x", padx=8, pady=6)
        ttk.Button(bar, text="⟳  Refresh", command=self._refresh_procs).pack(side="left", padx=(0, 4))
        ttk.Button(bar, text="⛔  Kill", style="Danger.TButton", command=self._kill_proc).pack(side="left", padx=4)
        tk.Label(bar, text="Filter:", bg=C["base"], fg=C["subtext"]).pack(side="right", padx=(4, 0))
        self._pf = ttk.Entry(bar, font=(MONO, 10), width=20)
        self._pf.pack(side="right", padx=4)
        self._pf.bind("<KeyRelease>", self._filter_procs)

        cols = ("pid", "name", "cpu", "ram")
        self._ptree = ttk.Treeview(f, columns=cols, show="headings")
        self._ptree.heading("pid",  text="PID")
        self._ptree.heading("name", text="Process Name")
        self._ptree.heading("cpu",  text="CPU (s)")
        self._ptree.heading("ram",  text="RAM (MB)")
        self._ptree.column("pid",  width=70,  anchor="center")
        self._ptree.column("name", width=220)
        self._ptree.column("cpu",  width=90,  anchor="e")
        self._ptree.column("ram",  width=90,  anchor="e")
        psb = ttk.Scrollbar(f, orient="vertical", command=self._ptree.yview)
        self._ptree.configure(yscrollcommand=psb.set)
        self._ptree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=4)
        psb.pack(side="left", fill="y", pady=4, padx=(2, 8))

    def _build_files_tab(self):
        f = tk.Frame(self._nb, bg=C["base"])
        self._nb.add(f, text="  Files  ")
        pb = tk.Frame(f, bg=C["base"])
        pb.pack(fill="x", padx=8, pady=6)
        tk.Label(pb, text="Path:", bg=C["base"], fg=C["subtext"]).pack(side="left", padx=(0, 4))
        self._path_e = ttk.Entry(pb, font=(MONO, 10))
        self._path_e.pack(side="left", fill="x", expand=True)
        self._path_e.bind("<Return>", self._browse)
        ttk.Button(pb, text="Go",   command=self._browse).pack(side="left", padx=4)
        ttk.Button(pb, text="↑ Up", command=self._go_up).pack(side="left", padx=4)

        ab = tk.Frame(f, bg=C["base"])
        ab.pack(fill="x", padx=8, pady=(0, 4))
        ttk.Button(ab, text="⬇ Download", command=self._download).pack(side="left", padx=(0, 4))
        ttk.Button(ab, text="⬆ Upload", command=self._upload).pack(side="left")

        cols = ("name", "type", "size", "modified")
        self._ftree = ttk.Treeview(f, columns=cols, show="headings")
        self._ftree.heading("name",     text="Name")
        self._ftree.heading("type",     text="Type")
        self._ftree.heading("size",     text="Size")
        self._ftree.heading("modified", text="Modified")
        self._ftree.column("name",     width=280)
        self._ftree.column("type",     width=55,  anchor="center")
        self._ftree.column("size",     width=90,  anchor="e")
        self._ftree.column("modified", width=160, anchor="center")
        fsb = ttk.Scrollbar(f, orient="vertical", command=self._ftree.yview)
        self._ftree.configure(yscrollcommand=fsb.set)
        self._ftree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=4)
        fsb.pack(side="left", fill="y", pady=4, padx=(2, 8))
        self._ftree.bind("<Double-1>", self._file_dbl)
        self._ftree.tag_configure("dir",  foreground=C["yellow"])
        self._ftree.tag_configure("file", foreground=C["text"])

    def _build_sysinfo_tab(self):
        f = tk.Frame(self._nb, bg=C["base"])
        self._nb.add(f, text="  Sysinfo  ")
        self._sysinfo_tab_frame = f
        bar = tk.Frame(f, bg=C["base"])
        bar.pack(anchor="w", padx=8, pady=8)
        ttk.Button(bar, text="⟳  Refresh", command=self._refresh_sysinfo).pack(side="left", padx=(0, 6))
        ttk.Button(bar, text="🛡️  Verify Integrity", command=self._cmd_verify_integrity).pack(side="left")
        self._si_text = scrolledtext.ScrolledText(
            f, bg=C["mantle"], fg=C["text"], font=(MONO, 10), state="disabled", wrap="word",
            relief="flat", bd=0, padx=16, pady=10)
        self._si_text.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self._si_text.tag_config("key", foreground=C["blue"], font=(MONO, 10, "bold"))
        self._si_text.tag_config("val", foreground=C["text"])
        self._si_text.tag_config("head", foreground=C["mauve"], font=(MONO, 11, "bold"))
        self._si_text.tag_config("admin_y", foreground=C["yellow"], font=(MONO, 10, "bold"))
        self._si_text.tag_config("admin_n", foreground=C["subtext"])
        self._si_text.tag_config("tamper", foreground=C["red"], font=(MONO, 10, "bold"))
        self._si_text.tag_config("verified", foreground=C["green"], font=(MONO, 10, "bold"))

    # ── Endpoint Defense Tabs ────────────────────────────────

    def _build_alerts_tab(self):
        f = tk.Frame(self._nb, bg=C["base"])
        self._nb.add(f, text="  🚨 Security Alerts  ")

        bar = tk.Frame(f, bg=C["base"])
        bar.pack(fill="x", padx=8, pady=6)
        tk.Label(bar, text="Filter:", bg=C["base"], fg=C["subtext"]).pack(side="left", padx=(0, 4))
        self._alert_filter = ttk.Combobox(bar, values=["ALL", "tamper", "malware", "fim", "dlp", "openedr"],
                                          state="readonly", width=12)
        self._alert_filter.set("ALL")
        self._alert_filter.pack(side="left", padx=4)
        self._alert_filter.bind("<<ComboboxSelected>>", self._render_alerts)

        ttk.Button(bar, text="Clear Alerts", command=self._clear_alerts).pack(side="right", padx=4)
        ttk.Button(bar, text="Export JSON", command=self._export_alerts).pack(side="right", padx=4)

        cols = ("time", "host", "subsystem", "severity", "title", "details")
        self._alert_tree = ttk.Treeview(f, columns=cols, show="headings", height=15)
        self._alert_tree.heading("time",      text="Timestamp")
        self._alert_tree.heading("host",      text="Endpoint")
        self._alert_tree.heading("subsystem", text="Subsystem")
        self._alert_tree.heading("severity",  text="Severity")
        self._alert_tree.heading("title",     text="Alert Title")
        self._alert_tree.heading("details",   text="Details")

        self._alert_tree.column("time",      width=140, anchor="center")
        self._alert_tree.column("host",      width=110, anchor="center")
        self._alert_tree.column("subsystem", width=90,  anchor="center")
        self._alert_tree.column("severity",  width=85,  anchor="center")
        self._alert_tree.column("title",     width=250)
        self._alert_tree.column("details",   width=350)

        asb = ttk.Scrollbar(f, orient="vertical", command=self._alert_tree.yview)
        self._alert_tree.configure(yscrollcommand=asb.set)
        self._alert_tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=4)
        asb.pack(side="left", fill="y", pady=4, padx=(2, 8))

        self._alert_tree.tag_configure("CRITICAL", foreground=C["red"])
        self._alert_tree.tag_configure("HIGH",     foreground=C["peach"])
        self._alert_tree.tag_configure("MEDIUM",   foreground=C["yellow"])
        self._alert_tree.tag_configure("INFO",     foreground=C["blue"])

    def _build_malware_tab(self):
        f = tk.Frame(self._nb, bg=C["base"])
        self._nb.add(f, text="  ☣ Malware & Quarantine  ")

        # Top scan launcher
        sb = tk.Frame(f, bg=C["base"])
        sb.pack(fill="x", padx=8, pady=6)
        tk.Label(sb, text="Target Scan Path:", bg=C["base"], fg=C["subtext"]).pack(side="left", padx=(0, 4))
        self._mal_path = ttk.Entry(sb, font=(MONO, 10), width=35)
        self._mal_path.pack(side="left", fill="x", expand=True, padx=4)
        ttk.Button(sb, text="🔍 Scan Path", style="Accent.TButton",
                   command=self._cmd_scan_malware).pack(side="left", padx=4)

        # Quarantine vault table
        tk.Label(f, text="QUARANTINE VAULT (Isolated Threats)", bg=C["base"], fg=C["mauve"],
                 font=(MONO, 10, "bold")).pack(anchor="w", padx=10, pady=(8, 2))

        qb = tk.Frame(f, bg=C["base"])
        qb.pack(fill="x", padx=8, pady=(0, 4))
        ttk.Button(qb, text="⟳ Refresh Vault", command=self._refresh_quarantine).pack(side="left", padx=(0, 4))
        ttk.Button(qb, text="↩ Restore Selected", style="Success.TButton",
                   command=self._restore_quarantine).pack(side="left", padx=4)
        ttk.Button(qb, text="☣ Quarantine File", style="Danger.TButton",
                   command=self._quarantine_file_dialog).pack(side="left", padx=4)

        cols = ("file", "orig_path", "date", "hash")
        self._qtree = ttk.Treeview(f, columns=cols, show="headings", height=8)
        self._qtree.heading("file",      text="Quarantine ID")
        self._qtree.heading("orig_path", text="Original Path")
        self._qtree.heading("date",      text="Date Quarantined")
        self._qtree.heading("hash",      text="SHA-256")

        self._qtree.column("file",      width=160)
        self._qtree.column("orig_path", width=300)
        self._qtree.column("date",      width=140, anchor="center")
        self._qtree.column("hash",      width=260)

        qsb = ttk.Scrollbar(f, orient="vertical", command=self._qtree.yview)
        self._qtree.configure(yscrollcommand=qsb.set)
        self._qtree.pack(side="top", fill="both", expand=True, padx=8, pady=4)
        qsb.pack(side="right", fill="y", pady=4)

    def _build_fim_tab(self):
        f = tk.Frame(self._nb, bg=C["base"])
        self._nb.add(f, text="  📁 FIM Integrity  ")

        bar = tk.Frame(f, bg=C["base"])
        bar.pack(fill="x", padx=8, pady=6)
        ttk.Button(bar, text="✦ Init / Rebuild Baseline", style="Accent.TButton",
                   command=self._cmd_fim_init).pack(side="left", padx=(0, 4))
        ttk.Button(bar, text="⟳ Run Integrity Check",
                   command=self._cmd_fim_check).pack(side="left", padx=4)

        tk.Label(bar, text="Add Path:", bg=C["base"], fg=C["subtext"]).pack(side="left", padx=(16, 4))
        self._fim_path_entry = ttk.Entry(bar, font=(MONO, 10), width=28)
        self._fim_path_entry.pack(side="left", padx=4)
        ttk.Button(bar, text="+ Add", command=self._cmd_fim_add_path).pack(side="left", padx=4)

        self._fim_log = scrolledtext.ScrolledText(
            f, bg=C["mantle"], fg=C["text"], font=(MONO, 10), state="disabled", wrap="word",
            relief="flat", bd=0, padx=12, pady=8)
        self._fim_log.pack(fill="both", expand=True, padx=8, pady=4)
        self._fim_log.tag_config("MODIFIED", foreground=C["red"], font=(MONO, 10, "bold"))
        self._fim_log.tag_config("DELETED",  foreground=C["peach"], font=(MONO, 10, "bold"))
        self._fim_log.tag_config("ADDED",    foreground=C["green"])
        self._fim_log.tag_config("INFO",     foreground=C["blue"])

    def _build_dlp_tab(self):
        f = tk.Frame(self._nb, bg=C["base"])
        self._nb.add(f, text="  🛡️ DLP (Data Loss Prevention)  ")

        bar = tk.Frame(f, bg=C["base"])
        bar.pack(fill="x", padx=8, pady=6)
        tk.Label(bar, text="Scan Endpoint Path / Buffer:", bg=C["base"], fg=C["subtext"]).pack(side="left", padx=(0, 4))
        self._dlp_input = ttk.Entry(bar, font=(MONO, 10), width=35)
        self._dlp_input.pack(side="left", fill="x", expand=True, padx=4)
        ttk.Button(bar, text="🛡️ Inspect Sensitive Data", style="Accent.TButton",
                   command=self._cmd_dlp_scan).pack(side="left", padx=4)

        self._dlp_text = scrolledtext.ScrolledText(
            f, bg=C["mantle"], fg=C["text"], font=(MONO, 10), state="disabled", wrap="word",
            relief="flat", bd=0, padx=12, pady=8)
        self._dlp_text.pack(fill="both", expand=True, padx=8, pady=4)
        self._dlp_text.tag_config("CRITICAL", foreground=C["red"], font=(MONO, 10, "bold"))
        self._dlp_text.tag_config("HIGH",     foreground=C["peach"], font=(MONO, 10, "bold"))
        self._dlp_text.tag_config("preview",  foreground=C["yellow"])

    def _build_openedr_tab(self):
        f = tk.Frame(self._nb, bg=C["base"])
        self._nb.add(f, text="  ⚡ OpenEDR & Telemetry  ")

        # Status row
        bar = tk.Frame(f, bg=C["base"])
        bar.pack(fill="x", padx=8, pady=6)
        ttk.Button(bar, text="⟳ Refresh Service Status", command=self._cmd_openedr_status).pack(side="left", padx=(0, 4))
        ttk.Button(bar, text="📥 Stream Telemetry", command=self._cmd_openedr_fetch_telemetry).pack(side="left", padx=4)
        ttk.Button(bar, text="⚙️ Install OpenEDR", command=self._cmd_openedr_install).pack(side="left", padx=4)

        # Emergency containment button
        ttk.Button(bar, text="⚠️ ISOLATE HOST", style="Danger.TButton",
                   command=lambda: self._cmd_host_isolation(True)).pack(side="right", padx=4)
        ttk.Button(bar, text="🌐 Restore Network", style="Success.TButton",
                   command=lambda: self._cmd_host_isolation(False)).pack(side="right", padx=4)

        self._edr_status_lbl = tk.Label(
            f, text="Service Status: Unknown  |  Kernel Filter: Unknown  |  Telemetry Log: None",
            bg=C["surface0"], fg=C["teal"], font=(MONO, 10, "bold"), padx=10, pady=6)
        self._edr_status_lbl.pack(fill="x", padx=8, pady=(2, 4))

        self._edr_log = scrolledtext.ScrolledText(
            f, bg=C["mantle"], fg=C["text"], font=(MONO, 10), state="disabled", wrap="none",
            relief="flat", bd=0, padx=12, pady=8)
        self._edr_log.pack(fill="both", expand=True, padx=8, pady=4)
        self._edr_log.tag_config("event", foreground=C["lavender"])
        self._edr_log.tag_config("info",  foreground=C["blue"])

    # ════════════════════════════════════════════════════════════
    #  Event Dispatcher from EDRServer
    # ════════════════════════════════════════════════════════════

    def _on_server_event(self, ev: str, data: Any):
        if ev in ("security_event", "telemetry"):
            self._gui_event_queue.put((ev, data))
        else:
            self.root.after(0, self._dispatch_server_event, ev, data)

    def _flush_gui_events(self):
        try:
            alerts_batch = []
            edr_chunks = []
            fim_chunks = []
            dlp_chunks = []
            count = 0
            while not self._gui_event_queue.empty() and count < 100:
                ev, data = self._gui_event_queue.get_nowait()
                count += 1
                if ev == "security_event":
                    agent, msg = data
                    alerts_batch.append((agent, msg))
                elif ev == "telemetry":
                    agent, msg = data
                    events = msg.get("events", [])
                    edr_chunks.append(f"--- Telemetry Batch ({len(events)} events) from {msg.get('host')} ---\n")
                    for tev in events:
                        edr_chunks.append(json.dumps(tev) + "\n")

            if alerts_batch:
                for agent, msg in alerts_batch:
                    ts = msg.get("timestamp", datetime.now().strftime("%H:%M:%S"))[:19].replace("T", " ")
                    host = msg.get("host", "Unknown")
                    sub = msg.get("subsystem", "general").upper()
                    sev = msg.get("severity", "INFO").upper()
                    title = msg.get("title", "")
                    details = str(msg.get("details", ""))

                    self._alert_tree.insert("", 0, values=(ts, host, sub, sev, title, details), tags=(sev,))
                    self._log(f"[{sub} ALERT - {sev}] {host}: {title}", "error" if sev == "CRITICAL" else "warn")

                    if sub == "FIM":
                        fim_chunks.append(f"[{ts}] [{sev}] {title}\n  Details: {details}\n")
                    elif sub == "DLP":
                        dlp_chunks.append(f"[{ts}] [{sev}] {title}\n  Details: {details}\n")

                self._lbl_alert_badge.config(text=f"Alerts: {len(self.server._security_events)}")

            if edr_chunks:
                self._append_edr_log("".join(edr_chunks))
            if fim_chunks:
                self._append_fim_log("".join(fim_chunks))
            if dlp_chunks:
                self._append_dlp_log("".join(dlp_chunks))
        except Exception:
            pass
        finally:
            try:
                self.root.after(100, self._flush_gui_events)
            except Exception:
                pass

    def _dispatch_server_event(self, ev: str, data: Any):
        if ev == "connect":
            agent: Agent = data
            admin_tag = " ★" if (agent.is_admin and agent.os_type == "windows") else ""
            root_tag  = " ⚡" if (agent.is_admin and agent.os_type == "linux") else ""
            priv_tag  = admin_tag or root_tag

            iid = self._atree.insert("", "end", values=(
                agent.hostname,
                agent.username.split("\\")[-1].split("/")[-1] + priv_tag,
                agent.ip,
            ))
            self._tree_map[agent.id] = iid
            self._log(f"[+] Sensor Connected: {agent.username}@{agent.hostname} ({agent.ip}) [{agent.os}]", "success")

        elif ev == "disconnect":
            agent: Agent = data
            iid = self._tree_map.pop(agent.id, None)
            if iid:
                try: self._atree.delete(iid)
                except tk.TclError: pass
            if self._sel_id == agent.id:
                self._sel_id = None
                self._lbl_info.config(text="  Agent disconnected", fg=C["red"])
                self._lbl_admin.config(text="")
            self._log(f"[-] Disconnected: {agent.username}@{agent.hostname}", "warn")

        self._lbl_count.config(text=f"Sensors: {len(self.server.agents())}")

    def _render_alerts(self, _=None):
        flt = self._alert_filter.get().lower()
        for iid in self._alert_tree.get_children():
            self._alert_tree.delete(iid)
        for ev in reversed(self.server._security_events):
            sub = ev.get("subsystem", "general").lower()
            if flt != "all" and sub != flt:
                continue
            ts = ev.get("timestamp", "")[:19].replace("T", " ")
            sev = ev.get("severity", "INFO").upper()
            self._alert_tree.insert("", "end", values=(
                ts, ev.get("host", ""), sub.upper(), sev, ev.get("title", ""), str(ev.get("details", ""))
            ), tags=(sev,))

    def _clear_alerts(self):
        with self.server._lock:
            self.server._security_events.clear()
        self._render_alerts()
        self._lbl_alert_badge.config(text="Alerts: 0")

    def _export_alerts(self):
        f = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if not f:
            return
        with open(f, "w") as fh:
            json.dump(list(self.server._security_events), fh, indent=2)
        messagebox.showinfo("Exported", f"Saved {len(self.server._security_events)} alerts to {f}")

    # ── Agent Selection & Prompt Helpers ─────────────────────

    def _on_select(self, _=None):
        sel = self._atree.selection()
        if not sel:
            return
        iid = sel[0]
        for aid, tiid in list(self._tree_map.items()):
            if tiid == iid:
                self._sel_id = aid
                a = self.server.get(aid)
                if a:
                    ts = a.connected_at.strftime("%H:%M:%S")
                    caps = ", ".join(a.defense_caps) if a.defense_caps else "standard"
                    self._lbl_info.config(
                        fg=C["subtext"],
                        text=f"  {a.username}@{a.hostname} · {a.ip} · {a.os} · Defense: [{caps}] · since {ts}")
                    if a.os_type == "linux":
                        self._lbl_ps.config(text=f"$ {a.hostname} >")
                        self._lbl_admin.config(text="  ⚡ ROOT  " if a.is_admin else "")
                        if not self._path_e.get(): self._path_e.insert(0, "/")
                    else:
                        self._lbl_ps.config(text=f"PS {a.hostname} >")
                        self._lbl_admin.config(text="  ★ ADMIN  " if a.is_admin else "")
                        if not self._path_e.get(): self._path_e.insert(0, "C:\\")
                break

    def _get_agent(self, warn: bool = True) -> Optional[Agent]:
        if not self._sel_id:
            if warn: messagebox.showwarning("No Sensor", "Select an endpoint sensor first.")
            return None
        a = self.server.get(self._sel_id)
        if not a:
            if warn: messagebox.showerror("Disconnected", "Selected endpoint is no longer connected.")
            return None
        return a

    def _log(self, text: str, tag: str = "output"):
        self._term.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self._term.insert("end", f"[{ts}] ", "ts")
        self._term.insert("end", text + "\n", tag)
        self._term.see("end")
        self._term.config(state="disabled")
        self._lbl_status.config(text=text[:80])

    # ── Terminal Command Dispatch ────────────────────────────

    def _run_shell(self, _=None):
        a = self._get_agent()
        if not a: return
        cmd = self._entry.get().strip()
        if not cmd: return
        self._cmd_history.append(cmd)
        self._hist_idx = len(self._cmd_history)
        self._entry.delete(0, "end")
        prompt_sym = "$" if a.os_type == "linux" else "PS"
        self._log(f"{prompt_sym} > {cmd}", "prompt")

        # Intercept cd command to update agent working directory and browser persistently
        if cmd.strip().lower() == "cd" or cmd.strip().lower().startswith("cd "):
            target_dir = cmd.strip()[2:].strip() or ("/" if a.os_type == "linux" else "C:\\")
            self.server.audit_cmd(a, "cd", target_dir)
            def run_cd():
                mid, _ = a.send_command("cd", target_dir)
                resp = a.wait_response(mid, timeout=15)
                if resp:
                    out = (resp.get("output") or "").rstrip()
                    tag = "output" if resp.get("status") == "ok" else "error"
                    self.root.after(0, self._log, out or target_dir, tag)
                    if resp.get("status") == "ok":
                        self.root.after(0, self._path_e.delete, 0, "end")
                        self.root.after(0, self._path_e.insert, 0, out or target_dir)
                        self.root.after(0, self._browse)
                else:
                    self.root.after(0, self._log, "Timeout waiting for response", "error")
            threading.Thread(target=run_cd, daemon=True).start()
            return

        self.server.audit_cmd(a, "shell", cmd)

        def run():
            mid, _ = a.send_command("shell", cmd)
            resp = a.wait_response(mid, timeout=30)
            if resp:
                out = (resp.get("output") or "").rstrip()
                tag = "output" if resp.get("status") == "ok" else "error"
                self.root.after(0, self._log, out or "(no output)", tag)
            else:
                self.root.after(0, self._log, "Timeout waiting for response", "error")

        threading.Thread(target=run, daemon=True).start()

    def _hist_up(self, _):
        if self._cmd_history and self._hist_idx > 0:
            self._hist_idx -= 1
            self._entry.delete(0, "end")
            self._entry.insert(0, self._cmd_history[self._hist_idx])

    def _hist_down(self, _):
        if self._hist_idx < len(self._cmd_history) - 1:
            self._hist_idx += 1
            self._entry.delete(0, "end")
            self._entry.insert(0, self._cmd_history[self._hist_idx])
        else:
            self._hist_idx = len(self._cmd_history)
            self._entry.delete(0, "end")

    # ── Process Management ───────────────────────────────────

    def _refresh_procs(self):
        a = self._get_agent()
        if not a: return
        self._log("Fetching process list…", "dim")
        self.server.audit_cmd(a, "ps")

        def run():
            mid, _ = a.send_command("ps")
            resp = a.wait_response(mid, timeout=20)
            if resp and resp.get("status") == "ok":
                try:
                    procs = json.loads(resp["output"])
                    if isinstance(procs, dict): procs = [procs]
                    self.root.after(0, self._fill_procs, procs)
                except Exception as e:
                    self.root.after(0, self._log, f"Parse error: {e}", "error")
            else:
                self.root.after(0, self._log, "Failed to get process list", "error")

        threading.Thread(target=run, daemon=True).start()

    def _fill_procs(self, procs: List):
        self._proc_cache = procs
        self._render_procs(procs)
        self._log(f"Process list: {len(procs)} entries", "success")

    def _render_procs(self, procs: List):
        for iid in self._ptree.get_children(): self._ptree.delete(iid)
        for p in procs:
            cpu = p.get("CPU", 0) or 0
            ram = p.get("RAM", 0) or 0
            self._ptree.insert("", "end", values=(
                p.get("Id", ""),
                p.get("ProcessName", ""),
                f"{float(cpu):.1f}",
                f"{float(ram):.1f}",
            ))

    def _filter_procs(self, _=None):
        q = self._pf.get().lower()
        self._render_procs([p for p in self._proc_cache if q in p.get("ProcessName", "").lower()])

    def _kill_proc(self):
        a = self._get_agent()
        if not a: return
        sel = self._ptree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select a process first.")
            return
        vals = self._ptree.item(sel[0])["values"]
        pid, name = vals[0], vals[1]
        if not messagebox.askyesno("Confirm", f"Kill  '{name}'  (PID {pid})?"):
            return
        self.server.audit_cmd(a, "kill", str(pid))

        def run():
            mid, _ = a.send_command("kill", str(pid))
            resp = a.wait_response(mid, timeout=10)
            if resp:
                tag = "success" if resp.get("status") == "ok" else "error"
                self.root.after(0, self._log, resp.get("output", ""), tag)
                if resp.get("status") == "ok":
                    self.root.after(0, self._refresh_procs)
            else:
                self.root.after(0, self._log, "Kill timed out", "error")

        threading.Thread(target=run, daemon=True).start()

    # ── Remote Filesystem & In-Band Protection ────────────────

    @staticmethod
    def _strip_icon(s: str) -> str:
        for prefix in ("📁  ", "📄  "):
            if s.startswith(prefix):
                return s[len(prefix):]
        return s

    @staticmethod
    def _win_parent(path: str) -> str:
        p = path.rstrip("\\")
        if not p: return path
        idx = p.rfind("\\")
        if idx < 0: return path
        if idx == 2 and len(p) > 2 and p[1] == ":": return p[:2] + "\\"
        return p[:idx] if idx > 0 else path

    def _browse(self, _=None):
        a = self._get_agent()
        if not a: return
        path = self._path_e.get().strip()

        def run():
            mid, _ = a.send_command("ls", path)
            resp = a.wait_response(mid, timeout=15)
            if resp and resp.get("status") == "ok":
                try:
                    items = json.loads(resp["output"])
                    if not items: items = []
                    elif isinstance(items, dict): items = [items]
                    self.root.after(0, self._fill_files, items, path)
                except Exception as e:
                    self.root.after(0, self._log, f"Parse error: {e}", "error")
            else:
                err = (resp or {}).get("output", "Timeout")
                self.root.after(0, self._log, f"Browse error: {err}", "error")

        threading.Thread(target=run, daemon=True).start()

    def _fill_files(self, items: List, path: str):
        for iid in self._ftree.get_children(): self._ftree.delete(iid)
        dirs  = sorted([i for i in items if i.get("Type") == "dir"], key=lambda x: x.get("Name", "").lower())
        files = sorted([i for i in items if i.get("Type") != "dir"], key=lambda x: x.get("Name", "").lower())
        for it in dirs:
            self._ftree.insert("", "end", values=("📁  " + it["Name"], "DIR", "", str(it.get("LastWriteTime", ""))), tags=("dir",))
        for it in files:
            self._ftree.insert("", "end", values=("📄  " + it["Name"], "FILE", self._fmt_sz(it.get("Length") or 0), str(it.get("LastWriteTime", ""))), tags=("file",))
        self._path_e.delete(0, "end")
        self._path_e.insert(0, path)

    @staticmethod
    def _fmt_sz(n) -> str:
        try: n = int(n)
        except (TypeError, ValueError): return ""
        if n < 1024:    return f"{n} B"
        if n < 1024**2: return f"{n/1024:.1f} KB"
        if n < 1024**3: return f"{n/1024**2:.1f} MB"
        return f"{n/1024**3:.2f} GB"

    def _file_dbl(self, _):
        sel = self._ftree.selection()
        if not sel: return
        vals = self._ftree.item(sel[0])["values"]
        name, ftype = self._strip_icon(str(vals[0])), vals[1]
        if ftype == "DIR":
            a = self._get_agent(warn=False)
            cur = self._path_e.get()
            if a and a.os_type == "linux":
                cur = cur.rstrip("/")
                new_path = f"{cur}/{name}" if cur != "/" else f"/{name}"
            else:
                cur = cur.rstrip("\\")
                new_path = cur + "\\" + name
            self._path_e.delete(0, "end")
            self._path_e.insert(0, new_path)
            self._browse()

    def _go_up(self):
        a = self._get_agent(warn=False)
        current = self._path_e.get()
        if a and a.os_type == "linux":
            parent = current.rstrip("/")
            if "/" in parent:
                parent = parent.rsplit("/", 1)[0] or "/"
            else: parent = "/"
        else:
            parent = self._win_parent(current)
        self._path_e.delete(0, "end")
        self._path_e.insert(0, parent)
        self._browse()

    def _download(self):
        a = self._get_agent()
        if not a: return
        sel = self._ftree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select a file to download.")
            return
        vals = self._ftree.item(sel[0])["values"]
        name = self._strip_icon(str(vals[0]))
        ftype = vals[1] if len(vals) > 1 else ""
        if ftype == "DIR":
            messagebox.showwarning("Invalid Selection", "Cannot download a directory. Please select a file.")
            return
        cur = self._path_e.get()
        if a.os_type == "linux":
            cur = cur.rstrip("/")
            remote = f"{cur}/{name}" if cur != "/" else f"/{name}"
        else:
            remote = cur.rstrip("\\") + "\\" + name

        save = filedialog.asksaveasfilename(initialfile=name)
        if not save: return
        self.server.audit_cmd(a, "download", remote)

        def run():
            self.root.after(0, self._log, f"Downloading  {remote} …", "info")
            CHUNK_SIZE = 512 * 1024
            offset = 0
            use_chunked = True

            # Probe chunked transfer with offset 0
            mid, _ = a.send_command("download_chunk", path=remote, offset=0, chunk_size=CHUNK_SIZE)
            resp = a.wait_response(mid, timeout=30)

            if resp and resp.get("status") == "ok" and "data" in resp:
                try:
                    total_size = resp.get("total_size", 0)
                    with open(save, "wb") as fh:
                        while True:
                            chunk_bytes = base64.b64decode(resp.get("data", ""))
                            fh.write(chunk_bytes)
                            offset += len(chunk_bytes)
                            total_size = resp.get("total_size") or total_size or offset
                            pct = int((offset / total_size) * 100) if total_size > 0 else 100
                            self.root.after(0, self._log, f"Downloading {name} ({offset:,} / {total_size:,} bytes - {pct}%)", "info")

                            if resp.get("eof") or (total_size > 0 and offset >= total_size) or len(chunk_bytes) == 0:
                                break

                            # Request next chunk
                            mid, _ = a.send_command("download_chunk", path=remote, offset=offset, chunk_size=CHUNK_SIZE)
                            resp = a.wait_response(mid, timeout=30)
                            if not resp or resp.get("status") != "ok":
                                raise RuntimeError((resp or {}).get("output", "Chunk read failed or timed out"))

                    self.root.after(0, self._log, f"Saved {offset:,} bytes  →  {save}", "success")
                    violations = DLPEngine.scan_file(save)
                    if violations:
                        self.root.after(0, self._log, f"⚠️ [DLP Alert] Downloaded file contains sensitive data: {violations[0]['rule']}", "warn")
                    return
                except Exception as e:
                    self.root.after(0, self._log, f"Chunked download error: {e}, attempting single-frame fallback...", "warn")

            # Fallback to single-frame transfer
            mid, _ = a.send_command("download", remote)
            resp = a.wait_response(mid, timeout=120)
            if resp and resp.get("status") == "ok":
                try:
                    data = base64.b64decode(resp["output"])
                    with open(save, "wb") as fh: fh.write(data)
                    self.root.after(0, self._log, f"Saved {len(data):,} bytes  →  {save}", "success")
                    violations = DLPEngine.scan_file(save)
                    if violations:
                        self.root.after(0, self._log, f"⚠️ [DLP Alert] Downloaded file contains sensitive data: {violations[0]['rule']}", "warn")
                except Exception as e:
                    self.root.after(0, self._log, f"Save error: {e}", "error")
            else:
                err = (resp or {}).get("output", "Timeout")
                self.root.after(0, self._log, f"Download failed: {err}", "error")

        threading.Thread(target=run, daemon=True).start()

    def _upload(self):
        a = self._get_agent()
        if not a: return
        local = filedialog.askopenfilename()
        if not local: return
        fname = os.path.basename(local)

        # Server-side DLP verification before upload
        violations = DLPEngine.scan_file(local)
        if violations:
            msg = f"DLP WARNING: File '{fname}' contains sensitive content ({violations[0]['rule']}).\nProceed with upload anyway?"
            if not messagebox.askyesno("DLP Warning", msg):
                return

        cur = self._path_e.get()
        if a.os_type == "linux":
            cur = cur.rstrip("/")
            remote = f"{cur}/{fname}" if cur != "/" else f"/{fname}"
        else:
            remote = cur.rstrip("\\") + "\\" + fname

        self.server.audit_cmd(a, "upload", remote)

        def run():
            self.root.after(0, self._log, f"Uploading  {fname}  →  {remote} …", "info")
            CHUNK_SIZE = 512 * 1024
            file_size = os.path.getsize(local)

            # Use chunked transfer for files > CHUNK_SIZE
            if file_size > CHUNK_SIZE:
                try:
                    with open(local, "rb") as fh:
                        offset = 0
                        first_chunk = True
                        while offset < file_size:
                            chunk_data = fh.read(CHUNK_SIZE)
                            is_eof = (offset + len(chunk_data) >= file_size)
                            b64 = base64.b64encode(chunk_data).decode()

                            mid, _ = a.send_command("upload_chunk", path=remote, offset=offset, data=b64, total_size=file_size, eof=is_eof)
                            resp = a.wait_response(mid, timeout=45)

                            if not resp or resp.get("status") != "ok":
                                if first_chunk:
                                    raise NotImplementedError("Agent does not support upload_chunk")
                                raise RuntimeError((resp or {}).get("output", "Upload chunk failed"))

                            offset += len(chunk_data)
                            first_chunk = False
                            pct = int((offset / file_size) * 100)
                            self.root.after(0, self._log, f"Uploading {fname} ({offset:,} / {file_size:,} bytes - {pct}%)", "info")

                    self.root.after(0, self._log, f"Uploaded {file_size:,} bytes to {remote}", "success")
                    self.root.after(0, self._browse)
                    return
                except NotImplementedError:
                    self.root.after(0, self._log, "Agent lacks upload_chunk, falling back to standard upload...", "dim")
                except Exception as e:
                    self.root.after(0, self._log, f"Chunked upload failed: {e}", "error")
                    return

            # Single-shot upload fallback
            try:
                with open(local, "rb") as fh:
                    b64 = base64.b64encode(fh.read()).decode()
                mid, _ = a.send_command("upload", path=remote, data=b64)
                resp = a.wait_response(mid, timeout=120)
                if resp and resp.get("status") == "ok":
                    self.root.after(0, self._log, resp.get("output", "Uploaded"), "success")
                    self.root.after(0, self._browse)
                else:
                    err = (resp or {}).get("output", "Timeout")
                    self.root.after(0, self._log, f"Upload failed: {err}", "error")
            except Exception as e:
                self.root.after(0, self._log, f"Upload error: {e}", "error")

        threading.Thread(target=run, daemon=True).start()

    # ── Sysinfo ──────────────────────────────────────────────

    def _cmd_sysinfo(self):
        self._refresh_sysinfo()
        if self._sysinfo_tab_frame: self._nb.select(self._sysinfo_tab_frame)

    def _refresh_sysinfo(self):
        a = self._get_agent()
        if not a: return
        self.server.audit_cmd(a, "sysinfo")

        def run():
            mid, _ = a.send_command("sysinfo")
            resp = a.wait_response(mid, timeout=20)
            if resp and resp.get("status") == "ok":
                try:
                    info = json.loads(resp["output"])
                    self.root.after(0, self._render_sysinfo, info)
                except Exception as e:
                    self.root.after(0, self._log, f"Parse error: {e}", "error")
            else:
                self.root.after(0, self._log, "Sysinfo request failed", "error")

        threading.Thread(target=run, daemon=True).start()

    def _render_sysinfo(self, info: dict):
        t = self._si_text
        t.config(state="normal")
        t.delete("1.0", "end")

        def row(label: str, value: str, val_tag: str = "val"):
            t.insert("end", f"  {label:<22}", "key")
            t.insert("end", f"{value}\n", val_tag)

        t.insert("end", "\n  ENDPOINT INFORMATION & DEFENSE TELEMETRY\n", "head")
        t.insert("end", "  " + "─" * 54 + "\n\n")
        row("Hostname",     info.get("hostname", "N/A"))
        row("Username",     info.get("username", "N/A"))
        row("OS",           info.get("os",       "N/A"))
        row("Architecture", info.get("arch",     "N/A"))
        row("RAM (GB)",     str(info.get("ram_gb", "N/A")))
        row("Uptime",       info.get("uptime",   "N/A"))
        row("Working Dir",  info.get("cwd",      "N/A"))
        row("Local IP",     info.get("local_ip", "N/A"))

        defense = info.get("defense", {})
        t.insert("end", "\n  DEFENSE SUB-SYSTEMS\n", "head")
        t.insert("end", "  " + "─" * 54 + "\n\n")
        row("FIM Monitored",   str(defense.get("fim_monitored_paths", defense.get("fim_monitored", "N/A"))))
        row("Quarantined Files", str(defense.get("quarantined_files", "0")))
        row("OpenEDR Engine",    "Active (Running)" if defense.get("openedr_running") else "Inactive / Not Installed")

        t.insert("end", f"\n  {'Privileges':<22}", "key")
        if info.get("is_root") or info.get("is_admin"):
            label = "⚡  Root" if info.get("is_root") else "★  Administrator"
            t.insert("end", f"{label}\n", "admin_y")
        else:
            t.insert("end", "Standard User\n", "admin_n")

        a = self._get_agent()
        if a:
            t.insert("end", "\n  ANTI-TAMPER & ATTESTATION\n", "head")
            t.insert("end", "  " + "─" * 54 + "\n\n")
            stat = a.attestation_status
            val_tag = "verified" if "Verified" in stat else ("tamper" if "TAMPERED" in stat or "Mismatch" in stat else "admin_y")
            row("Attestation Status", stat, val_tag)
            if a.attestation_details:
                row("Attested Script", a.attestation_details.get("path", "N/A"))
                row("Agent PID", str(a.attestation_details.get("pid", "N/A")))
                row("Code Size", f"{a.attestation_details.get('bytes_len', 0):,} bytes")
                row("SHA-256 Digest", a.attestation_details.get("raw_sha256", "N/A")[:32] + "...")
            row("Last Seen", a.last_seen.strftime("%Y-%m-%d %H:%M:%S"))

        t.config(state="disabled")

    def _cmd_verify_integrity(self):
        a = self._get_agent()
        if not a:
            self._log("No agent selected", "warn")
            return
        self._log(f"Requesting cryptographic attestation from {a.hostname}...", "info")
        def run():
            ok, msg = self.server.verify_agent_attestation(a)
            lvl = "success" if ok else "error"
            self.root.after(0, self._log, f"Attestation [{a.hostname}]: {msg}", lvl)
            self.root.after(0, self._refresh_sysinfo)
        threading.Thread(target=run, daemon=True).start()

    # ── Defensive Commands: Malware & Quarantine ─────────────

    def _cmd_scan_malware(self):
        a = self._get_agent()
        if not a: return
        target = self._mal_path.get().strip() or "."
        self._log(f"Starting malware scan on {a.hostname}:{target}…", "info")

        def run():
            mid, _ = a.send_command("malware_scan", target)
            resp = a.wait_response(mid, timeout=60)
            if resp and resp.get("status") == "ok":
                try:
                    findings = json.loads(resp["output"])
                    if not findings:
                        self.root.after(0, self._log, f"✓ Scan complete: No threats found in {target}", "success")
                    else:
                        self.root.after(0, self._log, f"🚨 THREAT DETECTED: {len(findings)} malicious objects found!", "error")
                        for f in findings:
                            self.root.after(0, self._log, f"   Threat: {f.get('threat')} in {f.get('path')}", "error")
                except Exception as e:
                    self.root.after(0, self._log, f"Scan output parse error: {e}", "error")
            else:
                self.root.after(0, self._log, "Malware scan failed or timed out", "error")

        threading.Thread(target=run, daemon=True).start()

    def _refresh_quarantine(self):
        a = self._get_agent()
        if not a: return

        def run():
            mid, _ = a.send_command("quarantine_list")
            resp = a.wait_response(mid, timeout=20)
            if resp and resp.get("status") == "ok":
                try:
                    items = json.loads(resp["output"])
                    self.root.after(0, self._render_quarantine_items, items)
                except Exception:
                    pass

        threading.Thread(target=run, daemon=True).start()

    def _render_quarantine_items(self, items: List[dict]):
        for iid in self._qtree.get_children(): self._qtree.delete(iid)
        for it in items:
            ts = datetime.fromtimestamp(it.get("quarantine_time", 0)).strftime("%Y-%m-%d %H:%M:%S")
            self._qtree.insert("", "end", values=(
                it.get("quarantine_file", it.get("original_name", "")),
                it.get("original_path", ""),
                ts,
                it.get("hash", "")
            ))

    def _quarantine_file_dialog(self):
        a = self._get_agent()
        if not a: return
        target = self._mal_path.get().strip()
        if not target:
            messagebox.showwarning("Target Required", "Enter file path to quarantine in the target box.")
            return
        if not messagebox.askyesno("Confirm Quarantine", f"Quarantine and strip execution from '{target}' on {a.hostname}?"):
            return

        def run():
            mid, _ = a.send_command("quarantine", target)
            resp = a.wait_response(mid, timeout=20)
            if resp and resp.get("status") == "ok":
                self.root.after(0, self._log, f"✓ Quarantined {target}", "success")
                self.root.after(0, self._refresh_quarantine)
            else:
                err = (resp or {}).get("output", "Failed")
                self.root.after(0, self._log, f"Quarantine error: {err}", "error")

        threading.Thread(target=run, daemon=True).start()

    def _restore_quarantine(self):
        a = self._get_agent()
        if not a: return
        sel = self._qtree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select a quarantined file to restore.")
            return
        qfile = self._qtree.item(sel[0])["values"][0]
        if not messagebox.askyesno("Confirm Restore", f"Restore {qfile} to original location on {a.hostname}?"):
            return

        def run():
            mid, _ = a.send_command("quarantine_restore", qfile)
            resp = a.wait_response(mid, timeout=20)
            if resp and resp.get("status") == "ok":
                self.root.after(0, self._log, f"✓ Restored {qfile}", "success")
                self.root.after(0, self._refresh_quarantine)
            else:
                err = (resp or {}).get("output", "Failed")
                self.root.after(0, self._log, f"Restore error: {err}", "error")

        threading.Thread(target=run, daemon=True).start()

    # ── Defensive Commands: FIM ──────────────────────────────

    def _append_fim_log(self, text: str, tag: str = "INFO"):
        self._fim_log.config(state="normal")
        self._fim_log.insert("end", text + "\n", tag)
        self._fim_log.see("end")
        self._fim_log.config(state="disabled")

    def _cmd_fim_init(self):
        a = self._get_agent()
        if not a: return

        def run():
            mid, _ = a.send_command("fim_init")
            resp = a.wait_response(mid, timeout=30)
            if resp:
                self.root.after(0, self._append_fim_log, f"[+] {resp.get('output')}", "INFO")
                self.root.after(0, self._log, f"FIM Baseline: {resp.get('output')}", "success")

        threading.Thread(target=run, daemon=True).start()

    def _cmd_fim_check(self):
        a = self._get_agent()
        if not a: return

        def run():
            mid, _ = a.send_command("fim_check")
            resp = a.wait_response(mid, timeout=30)
            if resp and resp.get("status") == "ok":
                try:
                    changes = json.loads(resp["output"])
                    if not changes:
                        self.root.after(0, self._append_fim_log, "✓ Integrity audit passed: 0 modifications detected.", "ADDED")
                    else:
                        for c in changes:
                            self.root.after(0, self._append_fim_log,
                                           f"🚨 [{c.get('action')}] {c.get('path')} (Severity: {c.get('severity')})\n   {c.get('details')}",
                                           c.get("action", "MODIFIED"))
                except Exception as e:
                    self.root.after(0, self._append_fim_log, f"Error parsing FIM audit: {e}", "MODIFIED")

        threading.Thread(target=run, daemon=True).start()

    def _cmd_fim_add_path(self):
        a = self._get_agent()
        if not a: return
        p = self._fim_path_entry.get().strip()
        if not p: return

        def run():
            mid, _ = a.send_command("fim_add_path", p)
            resp = a.wait_response(mid, timeout=20)
            if resp:
                self.root.after(0, self._append_fim_log, f"[+] {resp.get('output')}", "INFO")
                self.root.after(0, self._fim_path_entry.delete, 0, "end")

        threading.Thread(target=run, daemon=True).start()

    # ── Defensive Commands: DLP ──────────────────────────────

    def _append_dlp_log(self, text: str, tag: str = "HIGH"):
        self._dlp_text.config(state="normal")
        self._dlp_text.insert("end", text + "\n", tag)
        self._dlp_text.see("end")
        self._dlp_text.config(state="disabled")

    def _cmd_dlp_scan(self):
        a = self._get_agent()
        if not a: return
        target = self._dlp_input.get().strip()
        if not target:
            messagebox.showwarning("Input Required", "Enter file path or buffer text to scan.")
            return

        def run():
            mid, _ = a.send_command("dlp_scan", target)
            resp = a.wait_response(mid, timeout=30)
            if resp and resp.get("status") == "ok":
                try:
                    findings = json.loads(resp["output"])
                    if not findings:
                        self.root.after(0, self._append_dlp_log, f"✓ DLP Clean: No sensitive patterns detected in '{target}'", "preview")
                    else:
                        self.root.after(0, self._append_dlp_log, f"🚨 DLP VIOLATIONS ({len(findings)}) in '{target}':", "CRITICAL")
                        for f in findings:
                            self.root.after(0, self._append_dlp_log, f"   [{f['severity']}] {f['rule']}: {f.get('preview')}", "HIGH")
                except Exception as e:
                    self.root.after(0, self._append_dlp_log, f"DLP Output parse error: {e}", "HIGH")

        threading.Thread(target=run, daemon=True).start()

    # ── Defensive Commands: OpenEDR & Host Containment ───────

    def _append_edr_log(self, text: str, tag: str = "event"):
        self._edr_log.config(state="normal")
        self._edr_log.insert("end", text, tag)
        self._edr_log.see("end")
        self._edr_log.config(state="disabled")

    def _cmd_openedr_status(self):
        a = self._get_agent()
        if not a: return

        def run():
            mid, _ = a.send_command("openedr_status")
            resp = a.wait_response(mid, timeout=15)
            if resp and resp.get("status") == "ok":
                try:
                    st = json.loads(resp["output"])
                    svc_status = "Active (Running)" if st.get("running") else ("Installed" if st.get("installed") else "Not Found")
                    sz_mb = round(st.get("log_size_bytes", 0) / (1024**2), 2)
                    summary = f"Service: {svc_status}  |  Kernel Filter: {'Loaded ✓' if st.get('minifilter') else 'Standard'}  |  Log: {sz_mb} MB ({st.get('log_path')})"
                    self.root.after(0, self._edr_status_lbl.config, {"text": summary, "fg": C["green"] if st.get("running") else C["peach"]})
                except Exception as e:
                    self.root.after(0, self._log, f"EDR status parse error: {e}", "error")

        threading.Thread(target=run, daemon=True).start()

    def _cmd_openedr_fetch_telemetry(self):
        a = self._get_agent()
        if not a: return

        def run():
            mid, _ = a.send_command("openedr_fetch_telemetry")
            resp = a.wait_response(mid, timeout=20)
            if resp and resp.get("status") == "ok":
                try:
                    events = json.loads(resp["output"])
                    self.root.after(0, self._append_edr_log, f"\n=== Fetched {len(events)} OpenEDR Telemetry Events from {a.hostname} ===\n", "info")
                    for ev in events:
                        self.root.after(0, self._append_edr_log, json.dumps(ev, indent=2) + "\n", "event")
                except Exception as e:
                    self.root.after(0, self._append_edr_log, f"Error reading telemetry: {e}\n", "info")

        threading.Thread(target=run, daemon=True).start()

    def _cmd_openedr_install(self):
        a = self._get_agent()
        if not a:
            self._log("No agent selected", "warn")
            return
        if not messagebox.askyesno(
            "Confirm Installation",
            f"Install / configure OpenEDR and endpoint security dependencies on '{a.hostname}' ({a.ip})?\n\n"
            f"This will deploy the OpenEDR service, configure telemetry logging, and install missing dependencies."
        ):
            return

        self._log(f"Initiating OpenEDR and dependency installation on {a.hostname}...", "info")
        self._append_edr_log(f"\n[*] Initiating remote OpenEDR installation on {a.hostname}...\n", "info")

        def run():
            mid, _ = a.send_command("install_openedr")
            resp = a.wait_response(mid, timeout=120)
            if resp and resp.get("status") == "ok":
                output = resp.get("output", "Completed")
                self.root.after(0, self._log, f"OpenEDR installation succeeded on {a.hostname}", "success")
                self.root.after(0, self._append_edr_log, f"[+] OpenEDR installation on {a.hostname}:\n{output}\n", "event")
                self.root.after(0, self._cmd_openedr_status)
                self.root.after(0, self._refresh_sysinfo)
            else:
                err = (resp or {}).get("output", "Timeout waiting for installer to complete")
                self.root.after(0, self._log, f"OpenEDR installation failed on {a.hostname}: {err}", "error")
                self.root.after(0, self._append_edr_log, f"[!] OpenEDR installation failed on {a.hostname}: {err}\n", "info")

        threading.Thread(target=run, daemon=True).start()

    def _cmd_host_isolation(self, enable: bool):
        a = self._get_agent()
        if not a: return
        action_name = "ISOLATE" if enable else "RESTORE NETWORK FOR"
        msg = f"Are you sure you want to {action_name} host '{a.hostname}'?\n\nIsolation drops all inbound and outbound traffic while strictly preserving the secure Server-EDR C2 channel."
        if not messagebox.askyesno("Emergency Containment", msg):
            return

        def run():
            mid, _ = a.send_command("isolate_host", "true" if enable else "false")
            resp = a.wait_response(mid, timeout=25)
            if resp:
                tag = "success" if resp.get("status") == "ok" else "error"
                self.root.after(0, self._log, f"Host Isolation: {resp.get('output')}", tag)
                if resp.get("status") == "ok":
                    self.root.after(0, messagebox.showinfo, "Host Isolation Status", resp.get("output"))
            else:
                self.root.after(0, self._log, "Isolation command timed out", "error")

        threading.Thread(target=run, daemon=True).start()

    # ── Miscellaneous ────────────────────────────────────────

    def _disconnect(self):
        a = self._get_agent()
        if not a: return
        if messagebox.askyesno("Disconnect", f"Close connection to {a.hostname}?"):
            AUDIT.info("MANUAL_DISCONNECT  user=%s  host=%s", a.username, a.hostname)
            try: a.conn.close()
            except Exception: pass

    def _start_clock(self):
        def tick():
            self._lbl_clock.config(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
            self.root.after(1000, tick)
        tick()

    def _show_config_dialog(self):
        ServerConfigDialog(self.root, self.config, on_reload=self._reload_config)

    def _show_enrollment_dialog(self):
        creds = (
            self.config.to_enrollment_credentials()
            if self.config
            else generate_enrollment_credentials(
                self._host, self._port, self.server._psk.decode("utf-8", errors="replace"),
                self._fingerprint or "", self._tls
            )
        )
        EnrollmentCredentialsDialog(self.root, creds)

    def _show_package_builder_dialog(self):
        creds = (
            self.config.to_enrollment_credentials()
            if self.config
            else generate_enrollment_credentials(
                self._host, self._port, self.server._psk.decode("utf-8", errors="replace"),
                self._fingerprint or "", self._tls
            )
        )
        AgentPackageBuilderDialog(self.root, credentials=creds, config=self.config)

    def _reload_config(self):
        try:
            cfg_path = self.config.config_path if self.config else DEFAULT_CONFIG_FILE
            new_cfg = reload_server_config(self.config, cfg_path)
            self.config = new_cfg
            self.server.update_credentials(psk=new_cfg.psk)
            self._log(f"[+] Reloaded configuration from {cfg_path}", "success")
            messagebox.showinfo("Configuration Reloaded", f"Successfully reloaded configuration from:\n{cfg_path}")
        except Exception as e:
            self._log(f"[!] Failed to reload configuration: {e}", "error")
            messagebox.showerror("Reload Error", f"Failed reloading configuration: {e}")


# ════════════════════════════════════════════════════════════════
#  Entry Point
# ════════════════════════════════════════════════════════════════

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
    p.add_argument("--host",   default=None, help=f"Bind address (default: {DEFAULT_HOST} or from config)")
    p.add_argument("--port",   type=int, default=None, help=f"TCP port (default: {DEFAULT_PORT} or from config)")
    p.add_argument("--psk",    default=None, help="Pre-shared key for agent auth (auto-generated if omitted)")
    p.add_argument("--cert",   default=None, help=f"TLS certificate PEM (default: {CERT_FILE} or from config)")
    p.add_argument("--key",    default=None, help=f"TLS private key PEM (default: {KEY_FILE} or from config)")
    p.add_argument("--no-tls", action="store_true", help="Disable TLS — NOT recommended for production")
    p.add_argument("--allow",  action="append", metavar="CIDR", help="Restrict incoming connections to CIDR (repeatable)")
    p.add_argument("--install-deps", action="store_true", help="Install missing server dependencies (e.g. cryptography)")
    p.add_argument("--config", default=DEFAULT_CONFIG_FILE, help=f"Configuration file path (default: {DEFAULT_CONFIG_FILE})")
    p.add_argument("--wizard", "--first-run", action="store_true", dest="wizard", help="Force launch first-run configuration wizard")
    p.add_argument("--headless", "--non-interactive", action="store_true", dest="headless", help="Run without interactive GUI prompts")
    p.add_argument("--reload", action="store_true", help="Validate and reload existing configuration from disk, then exit")
    p.add_argument("--build-package", choices=["linux", "windows", "all"], default=None, help="Build deployable agent package archive and exit")
    p.add_argument("--package-output", default=None, help="Target output file or directory for built package")
    p.add_argument("--package-host", default=None, help="Server host override for built package")
    p.add_argument("--package-port", type=int, default=None, help="Server port override for built package")
    p.add_argument("--package-psk", default=None, help="PSK override for built package")
    p.add_argument("--package-fingerprint", default=None, help="Certificate fingerprint override for built package")
    p.add_argument("--package-group", default=None, help="Group tag override for built package (e.g. servers)")
    p.add_argument("--package-interval", type=int, default=10, help="Polling/heartbeat interval override in seconds")
    args = p.parse_args()

    if args.install_deps:
        ensure_server_dependencies()

    config_path = args.config

    if args.reload:
        cfg = load_server_config(config_path)
        print(f"[+] Successfully loaded and validated configuration from {config_path}")
        print(f"    Server: {cfg.host}:{cfg.port}")
        print(f"    TLS: {cfg.use_tls}")
        print(f"    Fingerprint: {cfg.cert_fingerprint}")
        print(f"    PSK: {mask_credential(cfg.psk)}")
        return

    is_first_run = not os.path.exists(config_path) or args.wizard

    if is_first_run:
        interactive = not args.headless and not args.build_package
        if interactive and os.name == "posix" and not os.environ.get("DISPLAY"):
            interactive = False

        config = run_config_wizard(
            config_path=config_path,
            interactive=interactive,
            host=args.host or DEFAULT_HOST,
            port=args.port or DEFAULT_PORT,
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

    AUDIT.info("SERVER_START  host=%s  port=%d  tls=%s  allow=%s",
               config.host, config.port, tls_context is not None,
               [str(n) for n in allow_nets] or "any")

    if args.headless:
        print(f"[+] Headless server running on {config.host}:{config.port} (Ctrl+C to stop)...")
        server = EDRServer(config.host, config.port, psk, tls_context, allow_nets)
        server.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("[*] Server shutting down...")
        return

    root = tk.Tk()
    root.tk_setPalette(background=C["base"], foreground=C["text"])
    App(root, config.host, config.port, psk, tls_context, fingerprint, allow_nets, config=config)
    root.mainloop()


if __name__ == "__main__":
    main()
