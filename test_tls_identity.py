"""Tests for first-run TLS identity and enrollment credential creation."""
import json
from pathlib import Path

from tls_identity import ensure_enrollment_credentials, ensure_identity


def test_self_signed_fallback_and_credentials(tmp_path):
    identity = ensure_identity(str(tmp_path / "server.crt"), str(tmp_path / "server.key"),
                              force_self_signed=True)
    assert identity.self_signed
    assert len(identity.fingerprint) == 64
    data = ensure_enrollment_credentials(str(tmp_path / "enrollment.json"), None, identity)
    assert len(data["psk"]) == 64
    assert json.loads((tmp_path / "enrollment.json").read_text())["certificate_fingerprint"] == identity.fingerprint


def test_existing_identity_is_reused(tmp_path):
    cert = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    first = ensure_identity(str(cert), str(key), force_self_signed=True)
    second = ensure_identity(str(cert), str(key), force_self_signed=True)
    assert second.fingerprint == first.fingerprint
