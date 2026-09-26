#!/usr/bin/env python3
"""TLS-aware entry point for the Server-EDR management server.

This keeps the existing GUI/server implementation intact while wiring the
first-run identity manager into its startup path. Set EDR_ACME_DOMAIN to make
Let's Encrypt the preferred issuer; if enrollment is unavailable, startup
creates a self-signed identity instead.

Examples:
    python server_tls.py
    EDR_ACME_DOMAIN=edr.example.com EDR_ACME_EMAIL=admin@example.com \
      EDR_ACME_CHALLENGE=webroot EDR_ACME_WEBROOT=/var/www/acme python server_tls.py

Certbot renewal remains external to this process. Run ``certbot renew`` from
its systemd timer/cron job, then restart this server (or use a supervisor) so
the renewed certificate is loaded.
"""
from __future__ import annotations

import os
from pathlib import Path

import Server
from tls_identity import ensure_enrollment_credentials, ensure_identity


def _identity_cert(cert_path: str, key_path: str) -> str:
    domain = os.environ.get("EDR_ACME_DOMAIN", "").strip() or None
    email = os.environ.get("EDR_ACME_EMAIL", "").strip() or None
    challenge = os.environ.get("EDR_ACME_CHALLENGE", "standalone").strip().lower()
    webroot = os.environ.get("EDR_ACME_WEBROOT", "").strip() or None
    force_self_signed = os.environ.get("EDR_FORCE_SELF_SIGNED", "").lower() in ("1", "true", "yes")
    enrollment_file = os.environ.get("EDR_ENROLLMENT_FILE", "edr_enrollment.json")

    identity = ensure_identity(
        cert_path,
        key_path,
        domain=domain,
        email=email,
        challenge=challenge,
        webroot=webroot,
        force_self_signed=force_self_signed,
    )
    ensure_enrollment_credentials(enrollment_file, None, identity)
    issuer = "self-signed fallback" if identity.self_signed else identity.issuer
    print(f"[+] TLS identity: {issuer}; fingerprint {identity.fingerprint}")
    print(f"[*] Enrollment metadata: {Path(enrollment_file)}")
    return identity.fingerprint


def main() -> None:
    # Server.main already owns CLI parsing, GUI startup, TLS policy, and PSK
    # handling. Replacing its certificate-generation hook gives it the new
    # first-run behavior without duplicating or diverging from that logic.
    Server.ensure_cert = _identity_cert
    Server.main()


if __name__ == "__main__":
    main()
