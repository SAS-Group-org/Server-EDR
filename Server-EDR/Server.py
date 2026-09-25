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
import secrets, socket, ssl, struct, sys, threading, time, uuid
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from datetime import datetime
from ipaddress import ip_address, ip_network, IPv4Network
from logging.handlers import RotatingFileHandler
from typing import Callable, Dict, List, Optional, Tuple, Any

# ─────────────────────────────────────────────────────────────
DEFAULT_HOST      = "0.0.0.0"
DEFAULT_PORT      = 4444
MAX_MSG_BYTES     = 50 * 1024 * 1024   # 50 MB hard cap — prevents memory DoS
AUTH_TIMEOUT_SECS = 15                  # seconds to complete TLS + HMAC handshake
CERT_FILE         = "edr_server.crt" if os.path.exists("edr_server.crt") or not os.path.exists("rat_server.crt") else "rat_server.crt"
KEY_FILE          = "edr_server.key" if os.path.exists("edr_server.key") or not os.path.exists("rat_server.key") else "rat_server.key"
PSK_FILE          = "edr_psk.txt" if os.path.exists("edr_psk.txt") or not os.path.exists("rat_psk.txt") else "rat_psk.txt"
FPRINT_FILE       = "edr_fingerprint.txt" if os.path.exists("edr_fingerprint.txt") or not os.path.exists("rat_fingerprint.txt") else "rat_fingerprint.txt"
LOG_FILE          = "edr_audit.log"

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

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return _pem_fingerprint(cert_path)


def _gen_cert_openssl(cert_path: str, key_path: str) -> str:
    import subprocess
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:4096",
        "-keyout", key_path, "-out", cert_path,
        "-days", "3650", "-nodes", "-subj", "/CN=EDRServer"
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return _pem_fingerprint(cert_path)


def ensure_cert(cert_path: str, key_path: str) -> Optional[str]:
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return _pem_fingerprint(cert_path)
    print("[*] Generating TLS certificate (this may take a moment)...")
    for gen in (_gen_cert_cryptography, _gen_cert_openssl):
        try:
            fp = gen(cert_path, key_path)
            print(f"[+] Certificate generated  ({cert_path})")
            return fp
        except ImportError:
            pass
        except Exception as e:
            print(f"[!] cert gen failed: {e}")
    return None


def ensure_psk(psk_file: str, explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    if os.path.exists(psk_file):
        with open(psk_file) as f:
            return f.read().strip()
    psk = secrets.token_hex(32)
    with open(psk_file, "w") as f:
        f.write(psk)
    print(f"[+] Auto-generated PSK saved to {psk_file}")
    return psk


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
    ):
        self.root = root
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

        self._lbl_clock = tk.Label(topbar, text="", bg=C["crust"], fg=C["overlay0"],
                                    font=(MONO, 10))
        self._lbl_clock.pack(side="right", padx=16)

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
    p.add_argument("--host",   default=DEFAULT_HOST, help="Bind address (default: 0.0.0.0)")
    p.add_argument("--port",   type=int, default=DEFAULT_PORT, help="TCP port (default: 4444)")
    p.add_argument("--psk",    default=None, help="Pre-shared key for agent auth (auto-generated if omitted)")
    p.add_argument("--cert",   default=CERT_FILE, help=f"TLS certificate PEM (default: {CERT_FILE})")
    p.add_argument("--key",    default=KEY_FILE, help=f"TLS private key PEM (default: {KEY_FILE})")
    p.add_argument("--no-tls", action="store_true", help="Disable TLS — NOT recommended for production")
    p.add_argument("--allow",  action="append", metavar="CIDR", help="Restrict incoming connections to CIDR (repeatable)")
    p.add_argument("--install-deps", action="store_true", help="Install missing server dependencies (e.g. cryptography)")
    args = p.parse_args()

    if args.install_deps:
        ensure_server_dependencies()

    psk = ensure_psk(PSK_FILE, args.psk)
    print(f"\n{'='*60}")
    print(f"  PSK  →  {psk}")
    print("  Configure PSK in agents/windows/Agent-Core.ps1 or agents/linux/agent_core.py")

    tls_context: Optional[ssl.SSLContext] = None
    fingerprint: Optional[str] = None

    if not args.no_tls:
        fingerprint = ensure_cert(args.cert, args.key)
        if fingerprint:
            with open(FPRINT_FILE, "w") as f:
                f.write(fingerprint)
            print(f"\n  Cert fingerprint  →  {fingerprint}")
            print("  Configure $CertThumbprint or CERT_FINGERPRINT in agents")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(args.cert, args.key)
            tls_context = ctx
        else:
            print("\n  WARNING: TLS unavailable — traffic will be unencrypted")
    else:
        print("\n  WARNING: TLS disabled — traffic will be unencrypted")
    print(f"{'='*60}\n")

    allow_nets: List[IPv4Network] = []
    if args.allow:
        for cidr in args.allow:
            try:
                allow_nets.append(ip_network(cidr, strict=False))
                print(f"[*] IP restriction: {cidr}")
            except ValueError as e:
                print(f"[!] Invalid CIDR '{cidr}': {e}")

    AUDIT.info("SERVER_START  host=%s  port=%d  tls=%s  allow=%s",
               args.host, args.port, tls_context is not None,
               [str(n) for n in allow_nets] or "any")

    root = tk.Tk()
    root.tk_setPalette(background=C["base"], foreground=C["text"])
    App(root, args.host, args.port, psk, tls_context, fingerprint, allow_nets)
    root.mainloop()


if __name__ == "__main__":
    main()
