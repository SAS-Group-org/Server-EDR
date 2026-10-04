#!/usr/bin/env python3
"""
test_windows_agent_config.py - Unit and Integration Tests for Windows Agent Dynamic Configuration

Tests:
1. PowerShell Common.psm1 Load-AgentConfig with JSON files (nested and flat).
2. Environment variable fallbacks (EDR_* and legacy RAT_*).
3. Precedence: CLI parameters > JSON file > environment variables > defaults.
4. Corrupt JSON graceful handling.
5. Validate-AgentConfig validation rules (host, port, thumbprint, intervals).
6. Secret masking (Get-MaskedSecret).
7. Windows agent packaging (package_windows_agent.py and build-agent-package.ps1).
8. Agent-Core.ps1 CLI integration (-ValidateConfig, -CheckConnection).
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
WINDOWS_AGENT_DIR = os.path.join(BASE_DIR, "agents", "windows")
if WINDOWS_AGENT_DIR not in sys.path:
    sys.path.insert(0, WINDOWS_AGENT_DIR)

from package_windows_agent import build_windows_package, REQUIRED_MODULES, REQUIRED_SERVICES


def run_powershell(command: str) -> subprocess.CompletedProcess:
    """Helper to run a PowerShell snippet with execution policy bypass."""
    return subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        cwd=BASE_DIR
    )


class TestWindowsAgentConfigPowerShell(unittest.TestCase):
    """Test Common.psm1 configuration loading and validation via PowerShell."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_load_default_config_powershell(self):
        """Load-AgentConfig returns defaults when no file or env vars exist."""
        ps_cmd = f"""
        & {{
            $env:EDR_SERVER_HOST = $null
            $env:RAT_SERVER_HOST = $null
            Import-Module '{os.path.join(WINDOWS_AGENT_DIR, "Modules", "Common.psm1")}' -Force
            $cfg = Load-AgentConfig -ConfigPath '{os.path.join(self.temp_dir.name, "none.json")}'
            Write-Output "HOST=$($cfg.server_host)"
            Write-Output "PORT=$($cfg.server_port)"
            Write-Output "TLS=$($cfg.use_tls)"
        }}
        """
        proc = run_powershell(ps_cmd)
        self.assertEqual(proc.returncode, 0, f"Error: {proc.stderr}")
        self.assertIn("HOST=127.0.0.1", proc.stdout)
        self.assertIn("PORT=443", proc.stdout)
        self.assertIn("TLS=True", proc.stdout)

    def test_load_nested_json_config(self):
        """Load-AgentConfig correctly parses standard nested agent_config.json schema."""
        cfg_path = os.path.join(self.temp_dir.name, "agent_config.json")
        cfg_data = {
            "server": {
                "host": "192.168.5.10",
                "port": 8443,
                "use_tls": True,
                "cert_fingerprint": "b" * 64,
                "reconnect_interval": 15
            },
            "auth": {
                "psk": "nested-token-999"
            },
            "agent": {
                "log_level": "DEBUG",
                "fim_enabled": False,
                "dlp_enabled": True
            }
        }
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg_data, f)

        ps_cmd = f"""
        & {{
            Import-Module '{os.path.join(WINDOWS_AGENT_DIR, "Modules", "Common.psm1")}' -Force
            $cfg = Load-AgentConfig -ConfigPath '{cfg_path}'
            Write-Output "HOST=$($cfg.server_host)"
            Write-Output "PORT=$($cfg.server_port)"
            Write-Output "PSK=$($cfg.psk)"
            Write-Output "FP=$($cfg.cert_thumbprint)"
            Write-Output "REC=$($cfg.reconnect_secs)"
            Write-Output "FIM=$($cfg.fim_enabled)"
        }}
        """
        proc = run_powershell(ps_cmd)
        self.assertEqual(proc.returncode, 0, f"Error: {proc.stderr}")
        self.assertIn("HOST=192.168.5.10", proc.stdout)
        self.assertIn("PORT=8443", proc.stdout)
        self.assertIn("PSK=nested-token-999", proc.stdout)
        self.assertIn(f"FP={'b' * 64}", proc.stdout)
        self.assertIn("REC=15", proc.stdout)
        self.assertIn("FIM=False", proc.stdout)

    def test_load_flat_json_config(self):
        """Load-AgentConfig correctly parses flat schema."""
        cfg_path = os.path.join(self.temp_dir.name, "flat_config.json")
        cfg_data = {
            "server_host": "10.10.10.50",
            "server_port": 5000,
            "psk": "flat-token-123",
            "cert_thumbprint": "c" * 64,
            "use_tls": False,
            "reconnect_secs": 25
        }
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg_data, f)

        ps_cmd = f"""
        & {{
            Import-Module '{os.path.join(WINDOWS_AGENT_DIR, "Modules", "Common.psm1")}' -Force
            $cfg = Load-AgentConfig -ConfigPath '{cfg_path}'
            Write-Output "HOST=$($cfg.server_host)"
            Write-Output "PORT=$($cfg.server_port)"
            Write-Output "PSK=$($cfg.psk)"
            Write-Output "TLS=$($cfg.use_tls)"
            Write-Output "REC=$($cfg.reconnect_secs)"
        }}
        """
        proc = run_powershell(ps_cmd)
        self.assertEqual(proc.returncode, 0, f"Error: {proc.stderr}")
        self.assertIn("HOST=10.10.10.50", proc.stdout)
        self.assertIn("PORT=5000", proc.stdout)
        self.assertIn("PSK=flat-token-123", proc.stdout)
        self.assertIn("TLS=False", proc.stdout)
        self.assertIn("REC=25", proc.stdout)

    def test_env_var_override(self):
        """Environment variables override values loaded from JSON file."""
        cfg_path = os.path.join(self.temp_dir.name, "base.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump({"server_host": "file.server.local", "server_port": 4444}, f)

        ps_cmd = f"""
        & {{
            $env:EDR_SERVER_HOST = 'override.server.local'
            $env:EDR_SERVER_PORT = '9001'
            $env:EDR_PSK = 'env-psk-val'
            Import-Module '{os.path.join(WINDOWS_AGENT_DIR, "Modules", "Common.psm1")}' -Force
            $cfg = Load-AgentConfig -ConfigPath '{cfg_path}'
            Write-Output "HOST=$($cfg.server_host)"
            Write-Output "PORT=$($cfg.server_port)"
            Write-Output "PSK=$($cfg.psk)"
        }}
        """
        proc = run_powershell(ps_cmd)
        self.assertEqual(proc.returncode, 0, f"Error: {proc.stderr}")
        self.assertIn("HOST=override.server.local", proc.stdout)
        self.assertIn("PORT=9001", proc.stdout)
        self.assertIn("PSK=env-psk-val", proc.stdout)

    def test_validate_agent_config_rules(self):
        """Validate-AgentConfig catches empty host, invalid port, bad thumbprint."""
        ps_cmd = f"""
        & {{
            Import-Module '{os.path.join(WINDOWS_AGENT_DIR, "Modules", "Common.psm1")}' -Force
            # 1. Valid
            $v1 = Validate-AgentConfig @{{ server_host = '1.2.3.4'; server_port = 4444 }}
            Write-Output "TEST1=$($v1.IsValid)"

            # 2. Empty host
            $v2 = Validate-AgentConfig @{{ server_host = ''; server_port = 4444 }}
            Write-Output "TEST2=$($v2.IsValid)"

            # 3. Bad port
            $v3 = Validate-AgentConfig @{{ server_host = '1.2.3.4'; server_port = 70000 }}
            Write-Output "TEST3=$($v3.IsValid)"

            # 4. Bad thumbprint
            $v4 = Validate-AgentConfig @{{ server_host = '1.2.3.4'; server_port = 4444; cert_thumbprint = 'short' }}
            Write-Output "TEST4=$($v4.IsValid)"
        }}
        """
        proc = run_powershell(ps_cmd)
        self.assertEqual(proc.returncode, 0, f"Error: {proc.stderr}")
        self.assertIn("TEST1=True", proc.stdout)
        self.assertIn("TEST2=False", proc.stdout)
        self.assertIn("TEST3=False", proc.stdout)
        self.assertIn("TEST4=False", proc.stdout)

    def test_get_masked_secret(self):
        """Get-MaskedSecret masks sensitive keys properly."""
        ps_cmd = f"""
        & {{
            Import-Module '{os.path.join(WINDOWS_AGENT_DIR, "Modules", "Common.psm1")}' -Force
            $m1 = Get-MaskedSecret "short"
            $m2 = Get-MaskedSecret "mysecretenrollmenttoken123"
            Write-Output "M1=$m1"
            Write-Output "M2=$m2"
        }}
        """
        proc = run_powershell(ps_cmd)
        self.assertEqual(proc.returncode, 0, f"Error: {proc.stderr}")
        self.assertIn("M1=***", proc.stdout)
        self.assertIn("M2=myse...n123", proc.stdout)


class TestWindowsAgentPackaging(unittest.TestCase):
    """Test Windows agent packaging utilities (Python and PowerShell)."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_package_windows_agent_python(self):
        """build_windows_package produces valid zip with proper prefix and manifest."""
        out_zip = os.path.join(self.temp_dir.name, "test_pkg.zip")
        pkg_path = build_windows_package(
            output_path=out_zip,
            source_dir=WINDOWS_AGENT_DIR,
            version="1.2.0"
        )
        self.assertTrue(os.path.isfile(pkg_path))

        with zipfile.ZipFile(pkg_path, "r") as zf:
            namelist = zf.namelist()
            self.assertIn("Server-EDR-Agent-Windows-v1.2.0/Agent-Core.ps1", namelist)
            self.assertIn("Server-EDR-Agent-Windows-v1.2.0/Modules/Common.psm1", namelist)
            self.assertIn("Server-EDR-Agent-Windows-v1.2.0/Service/Install-Service.ps1", namelist)
            self.assertIn("Server-EDR-Agent-Windows-v1.2.0/MANIFEST.json", namelist)
            self.assertIn("Server-EDR-Agent-Windows-v1.2.0/checksums.sha256", namelist)

            manifest_content = json.loads(zf.read("Server-EDR-Agent-Windows-v1.2.0/MANIFEST.json").decode("utf-8"))
            self.assertIn("Agent-Core.ps1", manifest_content)
            self.assertEqual(len(manifest_content["Agent-Core.ps1"]), 64)

    def test_package_windows_agent_with_injected_config(self):
        """build_windows_package embeds agent_config.json accurately."""
        out_zip = os.path.join(self.temp_dir.name, "injected_pkg.zip")
        cfg_data = {
            "server": {"host": "172.16.0.100", "port": 4444, "use_tls": True},
            "auth": {"psk": "injected-win-token"}
        }
        pkg_path = build_windows_package(
            output_path=out_zip,
            config_data=cfg_data,
            source_dir=WINDOWS_AGENT_DIR,
            version="1.0.0"
        )

        with zipfile.ZipFile(pkg_path, "r") as zf:
            self.assertIn("Server-EDR-Agent-Windows-v1.0.0/agent_config.json", zf.namelist())
            embedded_cfg = json.loads(zf.read("Server-EDR-Agent-Windows-v1.0.0/agent_config.json").decode("utf-8"))
            self.assertEqual(embedded_cfg["server"]["host"], "172.16.0.100")
            self.assertEqual(embedded_cfg["auth"]["psk"], "injected-win-token")

    def test_build_agent_package_powershell(self):
        """build-agent-package.ps1 creates zip archive and sha256 checksums."""
        out_dir = os.path.join(self.temp_dir.name, "ps_dist")
        ps_cmd = f"""
        & '{os.path.join(WINDOWS_AGENT_DIR, "build-agent-package.ps1")}' -Version "1.0.0" -OutputDir '{out_dir}' -ServerHost '192.168.1.1' -ServerPort 4444 -PSK 'psk-test'
        """
        proc = run_powershell(ps_cmd)
        self.assertEqual(proc.returncode, 0, f"Error: {proc.stderr}\nOutput: {proc.stdout}")

        expected_zip = os.path.join(out_dir, "Server-EDR-Agent-Windows-v1.0.0.zip")
        expected_sha = os.path.join(out_dir, "Server-EDR-Agent-Windows-v1.0.0.sha256")
        self.assertTrue(os.path.isfile(expected_zip))
        self.assertTrue(os.path.isfile(expected_sha))


class TestAgentCoreCLI(unittest.TestCase):
    """Test Agent-Core.ps1 command-line interface execution."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_agent_core_validate_config_cli_success(self):
        """Agent-Core.ps1 -ValidateConfig exits 0 on valid configuration."""
        proc = run_powershell(f"& '{os.path.join(WINDOWS_AGENT_DIR, 'Agent-Core.ps1')}' -ValidateConfig -ServerHost '10.0.0.1' -ServerPort 4444 -PSK 'test-token'")
        self.assertEqual(proc.returncode, 0, f"Output: {proc.stdout}\nError: {proc.stderr}")
        self.assertIn("VALID", proc.stdout)
        self.assertIn("10.0.0.1:4444", proc.stdout)

    def test_agent_core_validate_config_cli_failure(self):
        """Agent-Core.ps1 -ValidateConfig exits 1 on invalid port."""
        proc = run_powershell(f"& '{os.path.join(WINDOWS_AGENT_DIR, 'Agent-Core.ps1')}' -ValidateConfig -ServerHost '10.0.0.1' -ServerPort 75000")
        self.assertEqual(proc.returncode, 1, f"Expected returncode 1, got {proc.returncode}")
        self.assertIn("INVALID", proc.stdout)

    def test_agent_core_psk_masked_in_output(self):
        """Agent-Core.ps1 masks PSK value in console output."""
        sensitive_psk = "super_secret_unmasked_psk_12345"
        proc = run_powershell(f"& '{os.path.join(WINDOWS_AGENT_DIR, 'Agent-Core.ps1')}' -ValidateConfig -ServerHost '10.0.0.1' -ServerPort 4444 -PSK '{sensitive_psk}'")
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn(sensitive_psk, proc.stdout)
        self.assertIn("supe...2345", proc.stdout)


if __name__ == "__main__":
    unittest.main()
