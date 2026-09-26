"""Smoke tests for the TLS-aware server entry point."""
import json

import server_tls


def test_identity_hook_writes_enrollment_metadata(tmp_path, monkeypatch):
    monkeypatch.setenv("EDR_FORCE_SELF_SIGNED", "1")
    enrollment = tmp_path / "enrollment.json"
    monkeypatch.setenv("EDR_ENROLLMENT_FILE", str(enrollment))

    fingerprint = server_tls._identity_cert(str(tmp_path / "server.crt"), str(tmp_path / "server.key"))

    assert len(fingerprint) == 64
    data = json.loads(enrollment.read_text())
    assert data["self_signed"] is True
    assert data["certificate_fingerprint"] == fingerprint
