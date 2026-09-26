"""TLS identity and enrollment credential management.

Let's Encrypt is attempted first when a public DNS name is configured and a
supported Certbot installation is available.  If ACME enrollment cannot be
performed, a local self-signed certificate is generated so first-run setup
still produces a usable identity.  The fallback is deliberately explicit in
logs because clients must pin the resulting fingerprint.

This module does not install Certbot or open firewall ports.  Operators must
install/configure Certbot and ensure the selected challenge can reach the
server.  Certbot's systemd timer/cron job owns renewal; callers should invoke
``ensure_identity`` at startup to pick up renewed files.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence


@dataclass(frozen=True)
class TLSIdentity:
    cert_path: str
    key_path: str
    fingerprint: str
    issuer: str
    self_signed: bool


class TLSIdentityError(RuntimeError):
    """Raised when neither ACME nor self-signed identity creation succeeds."""


def pem_fingerprint(cert_path: str) -> str:
    """Return the uppercase SHA-256 fingerprint of the certificate DER."""
    pem = Path(cert_path).read_bytes()
    begin = pem.find(b"-----BEGIN CERTIFICATE-----")
    end = pem.find(b"-----END CERTIFICATE-----")
    if begin < 0 or end < 0 or end <= begin:
        raise TLSIdentityError(f"Invalid PEM certificate: {cert_path}")
    body = pem[begin + len(b"-----BEGIN CERTIFICATE-----"):end]
    der = base64.b64decode(b"".join(body.split()))
    return hashlib.sha256(der).hexdigest().upper()


def _write_private(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _self_signed(cert_path: Path, key_path: Path, names: Sequence[str]) -> TLSIdentity:
    """Generate a development/offline certificate using cryptography or openssl."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime as dt
        import ipaddress

        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        san = []
        for name in dict.fromkeys(["localhost", *names]):
            try:
                san.append(x509.IPAddress(ipaddress.ip_address(name)))
            except ValueError:
                san.append(x509.DNSName(name))
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0] if names else "EDRServer")]))
                .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0] if names else "EDRServer")]))
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=1))
                .not_valid_after(now + dt.timedelta(days=3650))
                .add_extension(x509.SubjectAlternativeName(san), critical=False)
                .sign(key, hashes.SHA256()))
        _write_private(key_path, key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode())
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    except ImportError:
        openssl = shutil.which("openssl")
        if not openssl:
            raise TLSIdentityError("cryptography and openssl are unavailable")
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as cfg:
            cfg.write("[req]\ndistinguished_name=req\nreq_extensions=v3\n[v3]\nsubjectAltName="
                      + ",".join(f"DNS:{n}" for n in dict.fromkeys(["localhost", *names])))
            cfg_path = cfg.name
        try:
            subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:3072", "-nodes",
                            "-days", "3650", "-keyout", str(key_path), "-out", str(cert_path),
                            "-subj", "/CN=EDRServer", "-config", cfg_path],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        finally:
            os.unlink(cfg_path)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
    return TLSIdentity(str(cert_path), str(key_path), pem_fingerprint(str(cert_path)),
                       "self-signed", True)


def _letsencrypt(cert_path: Path, key_path: Path, domain: str, email: Optional[str],
                 challenge: str, webroot: Optional[str]) -> TLSIdentity:
    certbot = shutil.which("certbot")
    if not certbot:
        raise TLSIdentityError("certbot is not installed")
    live = Path("/etc/letsencrypt/live") / domain
    cmd = [certbot, "certonly", "--non-interactive", "--agree-tos", "--keep-until-expiring",
           "--cert-name", domain, "-d", domain]
    if email:
        cmd += ["--email", email]
    else:
        cmd += ["--register-unsafely-without-email"]
    if challenge == "webroot":
        if not webroot:
            raise TLSIdentityError("webroot challenge requires --acme-webroot")
        cmd += ["--webroot", "-w", webroot]
    elif challenge == "standalone":
        cmd += ["--standalone"]
    else:
        raise TLSIdentityError("ACME challenge must be 'webroot' or 'standalone'")
    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    issued_cert, issued_key = live / "fullchain.pem", live / "privkey.pem"
    if not issued_cert.is_file() or not issued_key.is_file():
        raise TLSIdentityError("Certbot completed but certificate files are missing")
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(issued_cert, cert_path)
    _write_private(key_path, issued_key.read_text(encoding="utf-8"))
    return TLSIdentity(str(cert_path), str(key_path), pem_fingerprint(str(cert_path)),
                       "Let's Encrypt", False)


def ensure_identity(cert_path: str, key_path: str, domain: Optional[str] = None,
                    email: Optional[str] = None, challenge: str = "standalone",
                    webroot: Optional[str] = None, force_self_signed: bool = False) -> TLSIdentity:
    """Load existing identity, otherwise enroll with ACME then fall back locally."""
    cert, key = Path(cert_path), Path(key_path)
    if cert.is_file() and key.is_file():
        try:
            with ssl.create_default_context() as _:
                pass
            return TLSIdentity(str(cert), str(key), pem_fingerprint(str(cert)), "existing", False)
        except Exception:
            pass
    if domain and not force_self_signed:
        try:
            return _letsencrypt(cert, key, domain, email, challenge, webroot)
        except Exception as exc:
            print(f"[!] Let's Encrypt enrollment failed: {exc}")
            print("[*] Falling back to a self-signed TLS certificate")
    names = [domain] if domain else [socket.gethostname()]
    return _self_signed(cert, key, [n for n in names if n])


def ensure_enrollment_credentials(path: str, psk: Optional[str], identity: TLSIdentity) -> dict:
    """Create durable enrollment metadata without printing the PSK."""
    target = Path(path)
    if psk is None:
        if target.is_file():
            try:
                old = json.loads(target.read_text(encoding="utf-8"))
                psk = old.get("psk")
            except (OSError, ValueError):
                psk = None
        psk = psk or secrets.token_hex(32)
    data = {"version": 1, "psk": psk, "certificate_fingerprint": identity.fingerprint,
            "certificate": identity.cert_path, "issuer": identity.issuer,
            "self_signed": identity.self_signed}
    _write_private(target, json.dumps(data, indent=2) + "\n")
    return data
