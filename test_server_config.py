"""Tests for secure configuration persistence."""
import os
import stat

import pytest

from server_config import ConfigurationError, load, merge_defaults, redact, save


def test_save_reload_and_permissions(tmp_path):
    path = tmp_path / "edr_config.json"
    save({"host": "127.0.0.1", "psk": "secret"}, str(path))
    assert load(str(path))["psk"] == "secret"
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_reload_and_overrides(tmp_path):
    path = tmp_path / "edr_config.json"
    save({"host": "old", "port": 4444}, str(path))
    result = merge_defaults(str(path), {"host": "default", "port": 1, "tls": True}, {"port": 5555})
    assert result == {"host": "old", "port": 5555, "tls": True, "version": 1}


def test_insecure_file_is_rejected(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX mode permissions are not available on Windows")
    path = tmp_path / "edr_config.json"
    save({"psk": "secret"}, str(path))
    os.chmod(path, 0o644)
    with pytest.raises(ConfigurationError):
        load(str(path))


def test_redaction():
    assert redact({"psk": "secret", "host": "localhost"}) == {"psk": "[REDACTED]", "host": "localhost"}
