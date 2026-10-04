"""
Unit and integration tests for Windows installation automation (Issue #7).
Tests:
  - Issue #25: Register the agent with preconfigured settings
  - Issue #26: Update the Windows service installation scripts
"""

import os
import sys
import json
import zipfile
import tempfile
import unittest
import subprocess

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
WIN_AGENT_DIR = os.path.join(BASE_DIR, "agents", "windows")
if WIN_AGENT_DIR not in sys.path:
    sys.path.insert(0, WIN_AGENT_DIR)

from package_windows_agent import build_windows_package, REQUIRED_SERVICES


class TestWindowsInstallationAutomation(unittest.TestCase):
    """Tests Windows agent automated installation, preconfigured settings registration, and service scripts."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_dry_run_preconfigured_settings_registration(self):
        """Issue #25: Validate preconfigured settings resolution, validation, and registration in DryRun mode."""
        ps_script = os.path.join(WIN_AGENT_DIR, "Service", "Install-Service.ps1")
        self.assertTrue(os.path.isfile(ps_script), "Install-Service.ps1 must exist")

        cmd = [
            "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", ps_script,
            "-DryRun",
            "-ServerHost", "10.0.1.50",
            "-ServerPort", "9443",
            "-PSK", "enrollment_psk_secret_key_12345",
            "-CertThumbprint", "C0:53:DB:9E:D5:1A:5A:4C:DB:DF:E9:31:59:63:94:79:E0:64:70:63:F2:8F:C0:AF:DD:D4:5A:47:88:00:A9:C4",
            "-GroupTag", "corp-endpoints",
            "-PollingInterval", "20"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Install-Service.ps1 DryRun failed:\n{res.stderr}\n{res.stdout}")
        self.assertIn("Preconfigured settings successfully validated", res.stdout)
        self.assertIn("10.0.1.50", res.stdout)
        self.assertIn("9443", res.stdout)
        self.assertIn("corp-endpoints", res.stdout)
        self.assertIn("20s", res.stdout)
        self.assertIn("DryRun mode active", res.stdout)

    def test_dry_run_with_custom_config_file(self):
        """Issue #25: Validate registration with a preconfigured JSON config file."""
        cfg_file = os.path.join(self.temp_dir.name, "custom_preconfig.json")
        custom_data = {
            "server": {
                "host": "edr-primary.corp.local",
                "port": 7443,
                "use_tls": True,
                "cert_fingerprint": "A" * 64,
                "reconnect_interval": 15
            },
            "auth": {
                "psk": "custom_file_psk_token"
            },
            "agent": {
                "log_level": "DEBUG",
                "group_tag": "domain-controllers",
                "polling_interval": 15
            }
        }
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump(custom_data, f)

        ps_script = os.path.join(WIN_AGENT_DIR, "Service", "Install-Service.ps1")
        cmd = [
            "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", ps_script,
            "-DryRun",
            "-ConfigFile", cfg_file
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Failed with custom config file:\n{res.stderr}\n{res.stdout}")
        self.assertIn("edr-primary.corp.local", res.stdout)
        self.assertIn("7443", res.stdout)
        self.assertIn("domain-controllers", res.stdout)

    def test_dry_run_validation_failure_on_invalid_settings(self):
        """Issue #25: Validate that invalid port or invalid settings fail gracefully."""
        ps_script = os.path.join(WIN_AGENT_DIR, "Service", "Install-Service.ps1")
        cmd = [
            "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", ps_script,
            "-DryRun",
            "-ServerHost", "10.0.1.1",
            "-ServerPort", "99999"  # Invalid TCP port
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertIn("validation failed", res.stderr + res.stdout)

    def test_install_agent_top_level_wrapper(self):
        """Issue #26: Validate agents/windows/Install-Agent.ps1 delegates to Install-Service.ps1."""
        top_script = os.path.join(WIN_AGENT_DIR, "Install-Agent.ps1")
        self.assertTrue(os.path.isfile(top_script), "Install-Agent.ps1 must exist at root of agents/windows/")

        cmd = [
            "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", top_script,
            "-DryRun",
            "-ServerHost", "172.16.1.10",
            "-ServerPort", "5555",
            "-PSK", "test_psk"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Install-Agent.ps1 failed:\n{res.stderr}\n{res.stdout}")
        self.assertIn("Server-EDR Windows Agent - Service Installer", res.stdout)
        self.assertIn("172.16.1.10", res.stdout)

    def test_service_wrapper_config_path_passing(self):
        """Issue #26: Validate ServiceWrapper.ps1 script configuration and watchdog logic."""
        wrapper_path = os.path.join(WIN_AGENT_DIR, "Service", "ServiceWrapper.ps1")
        self.assertTrue(os.path.isfile(wrapper_path))

        with open(wrapper_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("ConfigPath", content, "ServiceWrapper must resolve ConfigPath")
        self.assertIn("-ConfigPath", content, "ServiceWrapper must pass -ConfigPath to Agent-Core.ps1")
        self.assertIn("Agent-Core.ps1", content)
        self.assertIn("Register-EngineEvent", content)
        self.assertIn("Watchdog Recovery", content)

    def test_uninstall_service_script_options(self):
        """Issue #26: Validate Uninstall-Service.ps1 options and cleanup logic."""
        uninst_path = os.path.join(WIN_AGENT_DIR, "Service", "Uninstall-Service.ps1")
        self.assertTrue(os.path.isfile(uninst_path))

        with open(uninst_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("ServerEdrDefenseSensor", content)
        self.assertIn("ServerRatDefenseSensor", content)
        self.assertIn("EDR_SERVER_HOST", content, "Uninstall-Service must clean environment variables")
        self.assertIn("Purge", content, "Uninstall-Service must support Purge switch")
        self.assertIn("sc.exe delete", content)

    def test_package_builder_includes_all_service_scripts(self):
        """Issue #26: Verify that package builder bundles all updated service scripts."""
        out_zip = os.path.join(self.temp_dir.name, "test_pkg.zip")
        res_zip = build_windows_package(
            output_path=out_zip,
            source_dir=WIN_AGENT_DIR
        )
        self.assertTrue(os.path.isfile(res_zip))
        with zipfile.ZipFile(res_zip, "r") as zf:
            names = [os.path.basename(n) for n in zf.namelist() if os.path.basename(n)]
            for s in REQUIRED_SERVICES:
                self.assertIn(s, names, f"Windows package archive must contain {s}")
            self.assertIn("Install-Agent.ps1", names, "Windows package archive must contain Install-Agent.ps1")


if __name__ == "__main__":
    unittest.main()
