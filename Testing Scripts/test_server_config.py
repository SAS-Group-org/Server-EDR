#!/usr/bin/env python3
"""
Unit and integration test suite for Server-EDR first-run configuration wizard,
TLS identity generation, enrollment credentials, configuration persistence,
restrictive permissions, and configuration reloading.
"""

import json
import os
import shutil
import stat
import sys
import tempfile
import unittest

# Ensure project root is in sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import Server
from Server import (
    ServerConfig,
    generate_tls_identity,
    generate_enrollment_credentials,
    export_enrollment_credentials,
    generate_agent_config,
    save_server_config,
    load_server_config,
    reload_server_config,
    run_config_wizard,
    set_restrictive_permissions,
    check_restrictive_permissions,
    secure_write_file,
    mask_credential,
    EDRServer,
)


class TestTLSIdentityAndEnrollment(unittest.TestCase):
    """Tests for TLS certificate/key generation and enrollment credentials (Sub-issue 11)."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="edr_test_tls_")
        self.cert_path = os.path.join(self.test_dir, "test_server.crt")
        self.key_path = os.path.join(self.test_dir, "test_server.key")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_generate_tls_identity_creates_files_and_fingerprint(self):
        cert_out, key_out, fingerprint = generate_tls_identity(
            cert_path=self.cert_path,
            key_path=self.key_path,
            force=True
        )
        self.assertTrue(os.path.isfile(self.cert_path), "TLS certificate file was not created")
        self.assertTrue(os.path.isfile(self.key_path), "TLS private key file was not created")
        self.assertIsInstance(fingerprint, str)
        self.assertEqual(len(fingerprint), 64, "SHA-256 fingerprint should be 64 hex characters")

        # Verify key contains PEM private key header
        with open(self.key_path, "r", encoding="utf-8") as f:
            key_content = f.read()
        self.assertIn("PRIVATE KEY", key_content)

        # Verify cert contains PEM certificate header
        with open(self.cert_path, "r", encoding="utf-8") as f:
            cert_content = f.read()
        self.assertIn("CERTIFICATE", cert_content)

    def test_generate_enrollment_credentials_structure(self):
        creds = generate_enrollment_credentials(
            server_host="192.168.1.10",
            server_port=4444,
            psk="a" * 64,
            cert_fingerprint="B" * 64,
            use_tls=True,
            reconnect_secs=10
        )
        self.assertEqual(creds["server_host"], "192.168.1.10")
        self.assertEqual(creds["server_port"], 4444)
        self.assertEqual(creds["psk"], "a" * 64)
        self.assertEqual(creds["cert_fingerprint"], "B" * 64)
        self.assertTrue(creds["use_tls"])
        self.assertEqual(creds["reconnect_secs"], 10)
        self.assertIn("created_at", creds)

    def test_export_enrollment_credentials(self):
        creds = generate_enrollment_credentials(
            server_host="10.0.0.5",
            server_port=5555,
            psk="testpsk123",
            cert_fingerprint="FINGERPRINT123",
            use_tls=True
        )
        out_path = os.path.join(self.test_dir, "enrollment.json")
        res_path = export_enrollment_credentials(creds, out_path)
        self.assertEqual(res_path, out_path)
        self.assertTrue(os.path.isfile(out_path))

        with open(out_path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        self.assertEqual(loaded["server_host"], "10.0.0.5")
        self.assertEqual(loaded["server_port"], 5555)
        self.assertEqual(loaded["psk"], "testpsk123")

    def test_generate_agent_config(self):
        creds = generate_enrollment_credentials(
            server_host="192.168.1.50",
            server_port=4444,
            psk="mypsk",
            cert_fingerprint="FP123",
            use_tls=True
        )
        agent_cfg_path = os.path.join(self.test_dir, "agent_config.json")
        cfg = generate_agent_config(creds, output_path=agent_cfg_path, fim_check_interval_secs=15)
        self.assertEqual(cfg["server_host"], "192.168.1.50")
        self.assertEqual(cfg["server_port"], 4444)
        self.assertEqual(cfg["psk"], "mypsk")
        self.assertEqual(cfg["cert_fingerprint"], "FP123")
        self.assertEqual(cfg["fim_check_interval_secs"], 15)
        self.assertTrue(os.path.isfile(agent_cfg_path))


class TestRestrictivePermissions(unittest.TestCase):
    """Tests for restrictive permissions and security protection (Sub-issue 12)."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="edr_test_perms_")
        self.test_file = os.path.join(self.test_dir, "secret.key")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_set_and_check_restrictive_permissions(self):
        with open(self.test_file, "w", encoding="utf-8") as f:
            f.write("super_secret_private_key")

        success = set_restrictive_permissions(self.test_file)
        self.assertTrue(success)
        self.assertTrue(check_restrictive_permissions(self.test_file))

        if os.name == "posix":
            file_mode = os.stat(self.test_file).st_mode
            # Ensure no group or other permissions
            self.assertEqual(file_mode & 0o077, 0, f"Permissions {oct(file_mode)} not restricted to 0600 on POSIX")

    def test_secure_write_file(self):
        target = os.path.join(self.test_dir, "sub", "secure_config.json")
        secure_write_file(target, '{"secret": "test"}')
        self.assertTrue(os.path.isfile(target))
        self.assertTrue(check_restrictive_permissions(target))

        with open(target, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data.get("secret"), "test")

    def test_mask_credential(self):
        self.assertEqual(mask_credential(""), "")
        self.assertEqual(mask_credential("short"), "*****")
        self.assertEqual(mask_credential("1234567890abcdef"), "1234...cdef")


class TestServerConfigPersistenceAndLoading(unittest.TestCase):
    """Tests for configuration saving, loading, and validation (Sub-issue 12)."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="edr_test_cfg_")
        self.config_path = os.path.join(self.test_dir, "server_config.json")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_and_load_server_config(self):
        cfg = ServerConfig(
            host="127.0.0.1",
            port=5555,
            psk="secret_token_12345",
            use_tls=True,
            cert_file="server.crt",
            key_file="server.key",
            cert_fingerprint="A1B2C3D4",
            allow_cidrs=["10.0.0.0/8", "192.168.0.0/16"],
            config_path=self.config_path
        )
        saved_path = save_server_config(cfg)
        self.assertEqual(saved_path, self.config_path)
        self.assertTrue(os.path.isfile(self.config_path))

        loaded = load_server_config(self.config_path)
        self.assertEqual(loaded.host, "127.0.0.1")
        self.assertEqual(loaded.port, 5555)
        self.assertEqual(loaded.psk, "secret_token_12345")
        self.assertTrue(loaded.use_tls)
        self.assertEqual(loaded.cert_file, "server.crt")
        self.assertEqual(loaded.key_file, "server.key")
        self.assertEqual(loaded.cert_fingerprint, "A1B2C3D4")
        self.assertEqual(loaded.allow_cidrs, ["10.0.0.0/8", "192.168.0.0/16"])
        self.assertEqual(loaded.enrollment_credentials["server_port"], 5555)

    def test_config_validation_errors(self):
        # Invalid port
        cfg_bad_port = ServerConfig(port=70000, psk="valid_psk")
        with self.assertRaises(ValueError):
            cfg_bad_port.validate()

        # Empty PSK
        cfg_no_psk = ServerConfig(port=4444, psk="")
        with self.assertRaises(ValueError):
            cfg_no_psk.validate()

        # Invalid CIDR
        cfg_bad_cidr = ServerConfig(port=4444, psk="valid_psk", allow_cidrs=["999.999.999.999/99"])
        with self.assertRaises(ValueError):
            cfg_bad_cidr.validate()

    def test_missing_config_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            load_server_config(os.path.join(self.test_dir, "missing.json"))

    def test_corrupt_json_raises_value_error(self):
        bad_json_path = os.path.join(self.test_dir, "bad.json")
        with open(bad_json_path, "w", encoding="utf-8") as f:
            f.write("NOT_JSON{{{")
        with self.assertRaises(ValueError):
            load_server_config(bad_json_path)


class TestFirstRunWizardAndReload(unittest.TestCase):
    """Tests for First-Run Wizard flow and Runtime Configuration Reload (Sub-issues 10, 11, 12)."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="edr_test_wizard_")
        self.config_path = os.path.join(self.test_dir, "server_config.json")
        self.cert_path = os.path.join(self.test_dir, "edr_server.crt")
        self.key_path = os.path.join(self.test_dir, "edr_server.key")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_run_config_wizard_headless(self):
        cfg = run_config_wizard(
            config_path=self.config_path,
            interactive=False,
            host="127.0.0.1",
            port=6000,
            cert_file=self.cert_path,
            key_file=self.key_path,
            allow_cidrs=["127.0.0.1/32"]
        )
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.host, "127.0.0.1")
        self.assertEqual(cfg.port, 6000)
        self.assertTrue(cfg.use_tls)
        self.assertTrue(os.path.isfile(self.config_path))
        self.assertTrue(os.path.isfile(self.cert_path))
        self.assertTrue(os.path.isfile(self.key_path))
        self.assertTrue(len(cfg.psk) >= 32)
        self.assertTrue(len(cfg.cert_fingerprint) == 64)

    def test_reload_server_config(self):
        # 1. Run initial wizard to save config
        cfg = run_config_wizard(
            config_path=self.config_path,
            interactive=False,
            host="127.0.0.1",
            port=6001,
            psk="initial_psk_12345",
            cert_file=self.cert_path,
            key_file=self.key_path
        )
        self.assertEqual(cfg.port, 6001)

        # 2. Modify on-disk configuration
        with open(self.config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["server_port"] = 6002
        data["allow_cidrs"] = ["192.168.10.0/24"]
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        # 3. Reload config into the existing cfg instance
        reloaded = reload_server_config(current_config=cfg, config_path=self.config_path)
        self.assertEqual(reloaded.port, 6002)
        self.assertEqual(cfg.port, 6002, "In-memory configuration should be updated in-place")
        self.assertEqual(cfg.allow_cidrs, ["192.168.10.0/24"])

    def test_edr_server_dynamic_update_credentials(self):
        server = EDRServer("127.0.0.1", 0, "first_psk")
        self.assertEqual(server._psk, b"first_psk")
        server.update_credentials(psk="new_updated_psk")
        self.assertEqual(server._psk, b"new_updated_psk")


if __name__ == "__main__":
    unittest.main()
