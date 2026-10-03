#!/usr/bin/env python3
"""
test_linux_agent_config.py - Unit and Integration Tests for Linux Agent Dynamic Configuration

Tests:
1. Configuration loading from JSON files (explicit path, search order).
2. Fallback to default values when configuration is missing.
3. Loading and overrides via environment variables (EDR_* and RAT_*).
4. Graceful handling of corrupted/malformed JSON.
5. Configuration validation rules (host, port, TLS fingerprint, logging).
6. Application of configuration to agent runtime globals.
7. Socket-based connectivity probe.
8. Linux agent package creation, archive contents, and manifest validation.
9. agent_core.py CLI argument integration (--validate-config, --config, etc.).
"""

import os
import sys
import json
import socket
import tempfile
import unittest
import subprocess
import tarfile
from unittest.mock import patch

# Add agents/linux to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LINUX_AGENT_DIR = os.path.join(BASE_DIR, "agents", "linux")
if LINUX_AGENT_DIR not in sys.path:
    sys.path.insert(0, LINUX_AGENT_DIR)

from modules.common import (
    DEFAULT_AGENT_CONFIG,
    load_agent_config,
    validate_agent_config,
    save_agent_config,
    apply_agent_config,
    check_server_connectivity,
    MODULE_SERVER_HOST,
    MODULE_SERVER_PORT,
    MODULE_PSK,
    MODULE_USE_TLS,
    MODULE_CERT_FINGERPRINT,
)
from package_linux_agent import build_linux_package, REQUIRED_FILES, REQUIRED_DIRS


class TestLinuxAgentConfigLoading(unittest.TestCase):
    """Test configuration discovery, parsing, and precedence rules."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        # Clean relevant environment variables
        self.orig_env = os.environ.copy()
        for k in list(os.environ.keys()):
            if k.startswith("EDR_") or k.startswith("RAT_"):
                del os.environ[k]

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.clear()
        os.environ.update(self.orig_env)

    def test_load_default_config_when_no_file(self):
        """When no config file exists and no env vars set, returns default config."""
        non_existent_file = os.path.join(self.temp_dir.name, "none.json")
        cfg = load_agent_config(config_path=non_existent_file)
        self.assertEqual(cfg["server"]["host"], "127.0.0.1")
        self.assertEqual(cfg["server"]["port"], 4444)
        self.assertTrue(cfg["server"]["use_tls"])
        self.assertEqual(cfg["agent"]["log_level"], "INFO")

    def test_load_valid_json_config(self):
        """Loads configuration accurately from a valid JSON file."""
        cfg_file = os.path.join(self.temp_dir.name, "agent_config.json")
        custom_data = {
            "server": {
                "host": "10.0.0.5",
                "port": 9999,
                "use_tls": True,
                "cert_fingerprint": "a" * 64,
                "reconnect_interval": 10,
                "max_reconnect_delay": 120
            },
            "auth": {
                "psk": "my-secret-psk-123"
            },
            "agent": {
                "log_level": "DEBUG",
                "watchdog_enabled": False,
                "watchdog_interval": 5,
                "heartbeat_interval": 20
            }
        }
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump(custom_data, f)

        loaded = load_agent_config(config_path=cfg_file)
        self.assertEqual(loaded["server"]["host"], "10.0.0.5")
        self.assertEqual(loaded["server"]["port"], 9999)
        self.assertEqual(loaded["auth"]["psk"], "my-secret-psk-123")
        self.assertEqual(loaded["server"]["cert_fingerprint"], "a" * 64)
        self.assertEqual(loaded["agent"]["log_level"], "DEBUG")
        self.assertFalse(loaded["agent"]["watchdog_enabled"])

    def test_env_var_fallback(self):
        """Environment variables populate settings when config file is absent."""
        os.environ["EDR_SERVER_HOST"] = "edr.example.com"
        os.environ["EDR_SERVER_PORT"] = "8443"
        os.environ["EDR_PSK"] = "env-psk"
        os.environ["EDR_USE_TLS"] = "0"
        os.environ["EDR_LOG_LEVEL"] = "WARNING"

        cfg = load_agent_config(config_path=os.path.join(self.temp_dir.name, "nonexistent.json"))
        self.assertEqual(cfg["server"]["host"], "edr.example.com")
        self.assertEqual(cfg["server"]["port"], 8443)
        self.assertEqual(cfg["auth"]["psk"], "env-psk")
        self.assertFalse(cfg["server"]["use_tls"])
        self.assertEqual(cfg["agent"]["log_level"], "WARNING")

    def test_legacy_rat_env_var_fallback(self):
        """Legacy RAT_* environment variables are respected as secondary fallbacks."""
        os.environ["RAT_SERVER"] = "legacy.example.com"
        os.environ["RAT_PORT"] = "7777"
        os.environ["RAT_PSK"] = "legacy-psk"

        cfg = load_agent_config(config_path=os.path.join(self.temp_dir.name, "nonexistent.json"))
        self.assertEqual(cfg["server"]["host"], "legacy.example.com")
        self.assertEqual(cfg["server"]["port"], 7777)
        self.assertEqual(cfg["auth"]["psk"], "legacy-psk")

    def test_env_var_overrides_json_values(self):
        """Environment variables take precedence over values in the JSON config file."""
        cfg_file = os.path.join(self.temp_dir.name, "agent_config.json")
        file_data = {
            "server": {"host": "file.example.com", "port": 4444},
            "auth": {"psk": "file-psk"}
        }
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump(file_data, f)

        # Set env var overriding host and psk
        os.environ["EDR_SERVER_HOST"] = "override.example.com"
        os.environ["EDR_PSK"] = "override-psk"

        loaded = load_agent_config(config_path=cfg_file)
        self.assertEqual(loaded["server"]["host"], "override.example.com")  # Overridden by env
        self.assertEqual(loaded["server"]["port"], 4444)                   # From file
        self.assertEqual(loaded["auth"]["psk"], "override-psk")           # Overridden by env

    def test_corrupt_json_handled_gracefully(self):
        """Malformed JSON does not crash the loader, falling back to defaults/env."""
        cfg_file = os.path.join(self.temp_dir.name, "corrupt.json")
        with open(cfg_file, "w", encoding="utf-8") as f:
            f.write("{ invalid json content :::")

        os.environ["EDR_SERVER_HOST"] = "rescue.example.com"
        cfg = load_agent_config(config_path=cfg_file)
        self.assertEqual(cfg["server"]["host"], "rescue.example.com")
        self.assertEqual(cfg["server"]["port"], 4444)

    def test_save_and_reload_config(self):
        """Saving a config persists to disk with valid formatting and permissions."""
        target_file = os.path.join(self.temp_dir.name, "saved_config.json")
        cfg_to_save = {
            "server": {"host": "192.168.1.100", "port": 5555, "use_tls": True},
            "auth": {"psk": "saved-psk-key"},
            "agent": {"log_level": "DEBUG"}
        }
        success = save_agent_config(cfg_to_save, target_file)
        self.assertTrue(success)
        self.assertTrue(os.path.isfile(target_file))

        reloaded = load_agent_config(config_path=target_file)
        self.assertEqual(reloaded["server"]["host"], "192.168.1.100")
        self.assertEqual(reloaded["server"]["port"], 5555)
        self.assertEqual(reloaded["auth"]["psk"], "saved-psk-key")


class TestLinuxAgentConfigValidation(unittest.TestCase):
    """Test semantic validation rules on agent configuration."""

    def test_valid_config(self):
        cfg = {
            "server": {
                "host": "127.0.0.1",
                "port": 4444,
                "use_tls": True,
                "cert_fingerprint": "a" * 64,
                "reconnect_interval": 5,
                "max_reconnect_delay": 60,
            },
            "auth": {"psk": "valid-token"},
            "agent": {
                "log_level": "INFO",
                "watchdog_interval": 3,
                "heartbeat_interval": 10,
            }
        }
        is_valid, errors = validate_agent_config(cfg)
        self.assertTrue(is_valid)
        self.assertEqual(errors, [])

    def test_invalid_host(self):
        cfg = {"server": {"host": "", "port": 4444}}
        is_valid, errors = validate_agent_config(cfg)
        self.assertFalse(is_valid)
        self.assertTrue(any("host" in e.lower() for e in errors))

    def test_invalid_ports(self):
        for bad_port in [0, -1, 65536, 100000, "not_a_port"]:
            cfg = {"server": {"host": "127.0.0.1", "port": bad_port}}
            is_valid, errors = validate_agent_config(cfg)
            self.assertFalse(is_valid, f"Port {bad_port} should be invalid")
            self.assertTrue(any("port" in e.lower() for e in errors))

    def test_invalid_cert_fingerprint(self):
        # Must be 64-char hex string if non-empty
        cfg = {"server": {"host": "127.0.0.1", "port": 4444, "cert_fingerprint": "short_not_hex"}}
        is_valid, errors = validate_agent_config(cfg)
        self.assertFalse(is_valid)
        self.assertTrue(any("fingerprint" in e.lower() for e in errors))

    def test_invalid_intervals(self):
        cfg = {
            "server": {"host": "127.0.0.1", "port": 4444, "reconnect_interval": -5, "max_reconnect_delay": 2},
            "agent": {"watchdog_interval": 0, "heartbeat_interval": -1}
        }
        is_valid, errors = validate_agent_config(cfg)
        self.assertFalse(is_valid)
        self.assertTrue(len(errors) >= 3)


class TestLinuxAgentRuntimeApplication(unittest.TestCase):
    """Test applying configuration into module-level globals."""

    def test_apply_agent_config(self):
        cfg = {
            "server": {
                "host": "192.168.1.200",
                "port": 8888,
                "use_tls": False,
                "cert_fingerprint": "c" * 64,
            },
            "auth": {
                "psk": "applied-psk"
            }
        }
        apply_agent_config(cfg)

        import modules.common as mc
        self.assertEqual(mc.MODULE_SERVER_HOST, "192.168.1.200")
        self.assertEqual(mc.MODULE_SERVER_PORT, 8888)
        self.assertEqual(mc.MODULE_PSK, "applied-psk")
        self.assertFalse(mc.MODULE_USE_TLS)
        self.assertEqual(mc.MODULE_CERT_FINGERPRINT, "c" * 64)


class TestLinuxAgentConnectivityCheck(unittest.TestCase):
    """Test socket connectivity probe."""

    def test_connectivity_check_success(self):
        """Probe reports True when server port is listening."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        try:
            res = check_server_connectivity("127.0.0.1", port, timeout=2.0)
            self.assertTrue(res)
        finally:
            srv.close()

    def test_connectivity_check_failure(self):
        """Probe reports False when server port is closed."""
        # Find unused port
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.close()

        res = check_server_connectivity("127.0.0.1", port, timeout=0.5)
        self.assertFalse(res)


class TestLinuxAgentPackaging(unittest.TestCase):
    """Test Linux agent package builder functionality."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_package_builder_default(self):
        """Builds valid .tar.gz package with all required files and manifest."""
        out_pkg = os.path.join(self.temp_dir.name, "test_pkg.tar.gz")
        pkg_path = build_linux_package(
            output_path=out_pkg,
            source_dir=LINUX_AGENT_DIR
        )

        self.assertTrue(os.path.isfile(pkg_path))
        self.assertGreater(os.path.getsize(pkg_path), 1000)

        # Inspect tar contents
        with tarfile.open(pkg_path, "r:gz") as tar:
            names = tar.getnames()
            self.assertIn("server-edr-agent/agent_core.py", names)
            self.assertIn("server-edr-agent/install_agent.sh", names)
            self.assertIn("server-edr-agent/install_service.sh", names)
            self.assertIn("server-edr-agent/agent_config.template.json", names)
            self.assertIn("server-edr-agent/modules/common.py", names)
            self.assertIn("server-edr-agent/systemd/server-edr.service", names)
            self.assertIn("server-edr-agent/MANIFEST.json", names)

            # Check MANIFEST.json validity
            manifest_f = tar.extractfile("server-edr-agent/MANIFEST.json")
            self.assertIsNotNone(manifest_f)
            manifest_data = json.loads(manifest_f.read().decode("utf-8"))
            self.assertIn("server-edr-agent/agent_core.py", manifest_data)
            self.assertEqual(len(manifest_data["server-edr-agent/agent_core.py"]), 64)

    def test_package_builder_with_injected_config(self):
        """Builds package with embedded agent_config.json."""
        out_pkg = os.path.join(self.temp_dir.name, "injected_pkg.tar.gz")
        injected_cfg = {
            "server": {"host": "192.168.10.50", "port": 7777, "use_tls": True},
            "auth": {"psk": "injected-custom-token"}
        }

        pkg_path = build_linux_package(
            output_path=out_pkg,
            config_data=injected_cfg,
            source_dir=LINUX_AGENT_DIR
        )

        with tarfile.open(pkg_path, "r:gz") as tar:
            names = tar.getnames()
            self.assertIn("server-edr-agent/agent_config.json", names)
            cfg_file = tar.extractfile("server-edr-agent/agent_config.json")
            data = json.loads(cfg_file.read().decode("utf-8"))
            self.assertEqual(data["server"]["host"], "192.168.10.50")
            self.assertEqual(data["auth"]["psk"], "injected-custom-token")


class TestAgentCoreCLIIntegration(unittest.TestCase):
    """Test agent_core.py command-line options for configuration."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_agent_core_help(self):
        """agent_core.py --help succeeds and lists dynamic config options."""
        proc = subprocess.run(
            [sys.executable, os.path.join(LINUX_AGENT_DIR, "agent_core.py"), "--help"],
            capture_output=True,
            text=True
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--config", proc.stdout)
        self.assertIn("--validate-config", proc.stdout)
        self.assertIn("--server-host", proc.stdout)

    def test_agent_core_validate_config_cli(self):
        """agent_core.py --validate-config validates an explicit config file."""
        cfg_path = os.path.join(self.temp_dir.name, "test_config.json")
        cfg_data = {
            "server": {"host": "10.0.0.1", "port": 4444, "use_tls": True},
            "auth": {"psk": "valid-token"}
        }
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg_data, f)

        proc = subprocess.run(
            [sys.executable, os.path.join(LINUX_AGENT_DIR, "agent_core.py"),
             "--validate-config", "--config", cfg_path],
            capture_output=True,
            text=True
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("VALID", proc.stdout.upper())


if __name__ == "__main__":
    unittest.main()
