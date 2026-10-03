"""
Unit and integration tests for GUI Agent Package Builder (Issue #5).
Tests Sub-issues #19 (Overrides), #20 (Server.py interface), and #21 (Linux .tar.gz & Windows .zip formats).
"""

import os
import sys
import json
import tarfile
import zipfile
import tempfile
import unittest
import subprocess
from unittest.mock import MagicMock, patch

from Server import build_agent_package, ServerConfig, DEFAULT_PORT


class TestPackageBuilder(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.out_dir = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_build_linux_package_with_overrides(self):
        """Test building Linux .tar.gz package with custom endpoint, polling interval, and group tag."""
        out_tar = os.path.join(self.out_dir, "test-linux.tar.gz")
        res = build_agent_package(
            os_type="linux",
            output_path=out_tar,
            server_host="10.20.30.40",
            server_port=8443,
            psk="test_psk_secret_12345",
            cert_fingerprint="AA:BB:CC:DD",
            use_tls=True,
            polling_interval=25,
            group_tag="db-servers"
        )
        self.assertTrue(os.path.exists(res))
        self.assertEqual(os.path.abspath(res), os.path.abspath(out_tar))
        self.assertTrue(tarfile.is_tarfile(res))

        with tarfile.open(res, "r:gz") as tar:
            names = [os.path.basename(n) for n in tar.getnames()]
            self.assertIn("agent_config.json", names)
            self.assertIn("MANIFEST.json", names)
            self.assertIn("agent_core.py", names)

            # Inspect config inside tarball
            cfg_member = next(m for m in tar.getmembers() if os.path.basename(m.name) == "agent_config.json")
            cfg_file = tar.extractfile(cfg_member)
            self.assertIsNotNone(cfg_file)
            cfg_data = json.loads(cfg_file.read().decode("utf-8"))
            self.assertEqual(cfg_data["server"]["host"], "10.20.30.40")
            self.assertEqual(cfg_data["server"]["port"], 8443)
            self.assertEqual(cfg_data["auth"]["psk"], "test_psk_secret_12345")
            self.assertEqual(cfg_data["agent"]["group_tag"], "db-servers")
            self.assertEqual(cfg_data["agent"]["polling_interval"], 25)

    def test_build_windows_package_with_overrides(self):
        """Test building Windows .zip package with custom endpoint, polling interval, and group tag."""
        out_zip = os.path.join(self.out_dir, "test-windows.zip")
        res = build_agent_package(
            os_type="windows",
            output_path=out_zip,
            server_host="192.168.1.50",
            server_port=9999,
            psk="win_psk_secret_67890",
            cert_fingerprint="11:22:33:44",
            use_tls=False,
            polling_interval=15,
            group_tag="finance-workstations"
        )
        self.assertTrue(os.path.exists(res))
        self.assertEqual(os.path.abspath(res), os.path.abspath(out_zip))
        self.assertTrue(zipfile.is_zipfile(res))

        with zipfile.ZipFile(res, "r") as zf:
            names = [os.path.basename(n) for n in zf.namelist() if os.path.basename(n)]
            self.assertIn("agent_config.json", names)
            self.assertIn("MANIFEST.json", names)
            self.assertIn("checksums.sha256", names)
            self.assertIn("Agent-Core.ps1", names)

            # Inspect config inside zip
            cfg_entry = next(n for n in zf.namelist() if os.path.basename(n) == "agent_config.json")
            with zf.open(cfg_entry) as f:
                cfg_data = json.loads(f.read().decode("utf-8"))
            self.assertEqual(cfg_data["server"]["host"], "192.168.1.50")
            self.assertEqual(cfg_data["server"]["port"], 9999)
            self.assertFalse(cfg_data["server"]["use_tls"])
            self.assertEqual(cfg_data["auth"]["psk"], "win_psk_secret_67890")
            self.assertEqual(cfg_data["agent"]["group_tag"], "finance-workstations")
            self.assertEqual(cfg_data["agent"]["polling_interval"], 15)

    def test_build_package_invalid_os(self):
        """Test that invalid OS type raises ValueError."""
        with self.assertRaises(ValueError):
            build_agent_package("macos", output_path=os.path.join(self.out_dir, "test.tar.gz"))

    def test_cli_build_package_linux(self):
        """Test invoking package builder via CLI flag --build-package linux."""
        out_tar = os.path.join(self.out_dir, "cli-linux.tar.gz")
        cmd = [
            sys.executable, "Server.py",
            "--build-package", "linux",
            "--package-output", out_tar,
            "--package-host", "172.16.0.1",
            "--package-port", "7777",
            "--package-psk", "cli_psk_test",
            "--package-group", "cli-linux-group",
            "--package-interval", "5",
            "--headless"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"CLI command failed:\n{res.stderr}\n{res.stdout}")
        self.assertTrue(os.path.exists(out_tar))
        self.assertTrue(tarfile.is_tarfile(out_tar))

    def test_cli_build_package_windows(self):
        """Test invoking package builder via CLI flag --build-package windows."""
        out_zip = os.path.join(self.out_dir, "cli-win.zip")
        cmd = [
            sys.executable, "Server.py",
            "--build-package", "windows",
            "--package-output", out_zip,
            "--package-host", "172.16.0.2",
            "--package-port", "8888",
            "--package-psk", "cli_win_psk",
            "--package-group", "cli-win-group",
            "--package-interval", "8",
            "--headless"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"CLI command failed:\n{res.stderr}\n{res.stdout}")
        self.assertTrue(os.path.exists(out_zip))
        self.assertTrue(zipfile.is_zipfile(out_zip))

    def test_cli_build_package_all(self):
        """Test invoking package builder via CLI flag --build-package all."""
        cmd = [
            sys.executable, "Server.py",
            "--build-package", "all",
            "--package-host", "192.168.10.100",
            "--package-port", "8443",
            "--package-group", "all-hosts",
            "--headless"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"CLI command failed:\n{res.stderr}\n{res.stdout}")
        self.assertIn("Building linux agent package", res.stdout)
        self.assertIn("Building windows agent package", res.stdout)

    def test_build_package_with_overrides_dict(self):
        """Test passing custom dictionary overrides to build_agent_package."""
        out_tar = os.path.join(self.out_dir, "custom-overrides.tar.gz")
        res = build_agent_package(
            os_type="linux",
            output_path=out_tar,
            server_host="127.0.0.1",
            overrides={"custom_feature": True, "environment": "production"}
        )
        self.assertTrue(os.path.exists(res))
        with tarfile.open(res, "r:gz") as tar:
            cfg_member = next(m for m in tar.getmembers() if os.path.basename(m.name) == "agent_config.json")
            cfg_data = json.loads(tar.extractfile(cfg_member).read().decode("utf-8"))
            self.assertTrue(cfg_data["custom_feature"])
            self.assertEqual(cfg_data["environment"], "production")


if __name__ == "__main__":
    unittest.main()
