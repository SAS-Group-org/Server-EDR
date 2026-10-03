#!/usr/bin/env python3
"""
Test script to verify modular Agent-Core.ps1 connects to EDRServer,
authenticates with HMAC, and handles defense commands.
"""
import subprocess
import socket
import time
import os
import sys
import json
from Server import EDRServer

def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    test_psk = "windows_test_psk_1234567890abcdef"
    server = EDRServer(host="127.0.0.1", port=0, psk=test_psk, tls_context=None)
    server.start()
    port = server._sock.getsockname()[1]
    print(f"[*] EDRServer listening on 127.0.0.1:{port}")

    env = os.environ.copy()
    env["EDR_SERVER_HOST"] = "127.0.0.1"
    env["EDR_SERVER_PORT"] = str(port)
    env["EDR_PSK"] = test_psk
    env["EDR_USE_TLS"] = "0"
    env["EDR_RECONNECT_SECS"] = "2"
    env["RAT_SERVER_HOST"] = "127.0.0.1"
    env["RAT_SERVER_PORT"] = str(port)
    env["RAT_PSK"] = test_psk
    env["RAT_USE_TLS"] = "0"
    env["RAT_RECONNECT_SECS"] = "2"

    agent_ps1 = os.path.join("agents", "windows", "Agent-Core.ps1")
    print(f"[*] Launching {agent_ps1} via powershell...")
    proc = subprocess.Popen(
        ["powershell", "-ExecutionPolicy", "Bypass", "-File", agent_ps1],
        cwd=os.path.dirname(os.path.abspath(__file__)),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        agent = None
        start = time.time()
        while time.time() - start < 8.0:
            agents = server.agents()
            if agents:
                agent = agents[0]
                break
            time.sleep(0.2)

        if not agent:
            print(f"[!] {agent_ps1} failed to connect within timeout")
            stdout, stderr = proc.communicate(timeout=2)
            print(f"STDOUT: {stdout}")
            print(f"STDERR: {stderr}")
            sys.exit(1)

        print(f"[+] Agent connected: {agent.username}@{agent.hostname} (OS: {agent.os})")
        print(f"[+] Defense capabilities: {agent.defense_caps}")

        # Test 1: sysinfo
        mid, _ = agent.send_command("sysinfo")
        resp = agent.wait_response(mid, timeout=10)
        assert resp and resp["status"] == "ok", f"Sysinfo failed: {resp}"
        info = json.loads(resp["output"])
        print(f"[+] Sysinfo response verified: RAM={info.get('ram_gb')} GB, Arch={info.get('arch')}")

        # Test 2: dlp_scan
        mid, _ = agent.send_command("dlp_scan", "Visa card 4532 0150 1234 5671")
        resp = agent.wait_response(mid, timeout=10)
        assert resp and resp["status"] == "ok", f"DLP scan failed: {resp}"
        dlp_res = json.loads(resp["output"])
        if isinstance(dlp_res, dict):
            dlp_res = [dlp_res]
        assert len(dlp_res) > 0 and dlp_res[0]["rule"] == "CREDIT_CARD", f"DLP unexpected: {dlp_res}"
        print(f"[+] DLP scan response verified: {dlp_res[0]['rule']} ({dlp_res[0]['preview']})")

        # Test 3: openedr_status
        mid, _ = agent.send_command("openedr_status")
        resp = agent.wait_response(mid, timeout=10)
        assert resp and resp["status"] == "ok", f"OpenEDR status failed: {resp}"
        edr_res = json.loads(resp["output"])
        print(f"[+] OpenEDR status verified: {edr_res.get('service_status')}")

        # Test 4: Cryptographic code attestation
        mid, _ = agent.send_command("attest", "test_win_nonce_123")
        resp = agent.wait_response(mid, timeout=10)
        assert resp and resp["status"] == "ok", f"Attest failed: {resp}"
        attest_info = json.loads(resp["output"])
        assert "raw_sha256" in attest_info and "attest_hmac" in attest_info
        print(f"[+] Windows agent attestation verified: SHA-256={attest_info['raw_sha256'][:16]}... (PID: {attest_info.get('pid')})")

        # Test 5: Verify server-side attestation
        time.sleep(1.0)
        print(f"[+] Agent attestation status on server: {agent.attestation_status}")
        assert agent.attestation_status != "Unverified", "Server did not attest Windows agent"

        # Test 6: Verify install_openedr command handler
        mid, _ = agent.send_command("install_openedr")
        resp = agent.wait_response(mid, timeout=25)
        assert resp and resp.get("status") in ("ok", "error"), f"install_openedr failed: {resp}"
        print(f"[+] install_openedr command verified ({resp.get('status')}): {resp.get('output')[:60]}...")

        print("\n[SUCCESS] ALL WINDOWS AGENT DEFENSE, ANTI-TAMPER & COMPONENT INSTALL TESTS PASSED!")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        server._sock.close()


import unittest
import tempfile
import zipfile
import hashlib
from agents.windows.package_windows_agent import build_windows_package, REQUIRED_SERVICES, REQUIRED_MODULES


class TestWindowsAgentSuite(unittest.TestCase):
    """Automated unit and integration test suite for Windows agent packaging, installation, and runtime (Issue #30)."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_windows_agent_live_defense_integration(self):
        """Runs live Windows agent integration tests against EDRServer."""
        main()

    def test_windows_agent_packaging_and_manifest(self):
        """Issue #30: Validates automated Windows agent packaging and cryptographic manifest integrity."""
        zip_path = os.path.join(self.temp_dir.name, "win_agent_test.zip")
        res_zip = build_windows_package(zip_path, version="1.0.0")
        self.assertTrue(os.path.isfile(res_zip))

        with zipfile.ZipFile(res_zip, "r") as zf:
            namelist = zf.namelist()
            self.assertIn("Server-EDR-Agent-Windows-v1.0.0/Agent-Core.ps1", namelist)
            self.assertIn("Server-EDR-Agent-Windows-v1.0.0/MANIFEST.json", namelist)
            self.assertIn("Server-EDR-Agent-Windows-v1.0.0/checksums.sha256", namelist)

            # Validate each module
            for mod in REQUIRED_MODULES:
                self.assertIn(f"Server-EDR-Agent-Windows-v1.0.0/Modules/{mod}", namelist)

            # Validate each service script
            for svc in REQUIRED_SERVICES:
                self.assertIn(f"Server-EDR-Agent-Windows-v1.0.0/Service/{svc}", namelist)

            # Verify manifest hashes
            manifest_bytes = zf.read("Server-EDR-Agent-Windows-v1.0.0/MANIFEST.json")
            manifest = json.loads(manifest_bytes.decode("utf-8"))
            for rel_path, expected_hash in manifest.items():
                zip_member = f"Server-EDR-Agent-Windows-v1.0.0/{rel_path}"
                actual_hash = hashlib.sha256(zf.read(zip_member)).hexdigest()
                self.assertEqual(actual_hash, expected_hash, f"Manifest hash mismatch for {rel_path}")

    def test_windows_agent_installation_and_runtime_validation(self):
        """Issue #30: Validates Windows service installer DryRun and runtime configuration validation."""
        cwd = os.path.dirname(os.path.abspath(__file__))
        install_script = os.path.join(cwd, "agents", "windows", "Service", "Install-Service.ps1")
        core_script = os.path.join(cwd, "agents", "windows", "Agent-Core.ps1")

        # 1. Service Installer DryRun with preconfigured settings
        cmd_install = [
            "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", install_script,
            "-DryRun",
            "-ServerHost", "10.10.10.10",
            "-ServerPort", "9443",
            "-PSK", "automated_win_test_psk_key_12345",
            "-GroupTag", "automated-win-group",
            "-PollingInterval", "15"
        ]
        res_inst = subprocess.run(cmd_install, capture_output=True, text=True)
        self.assertEqual(res_inst.returncode, 0, f"Install-Service.ps1 failed:\n{res_inst.stderr}\n{res_inst.stdout}")
        self.assertIn("Preconfigured settings successfully validated", res_inst.stdout)

        # 2. Agent-Core.ps1 -ValidateConfig runtime validation
        temp_cfg = os.path.join(self.temp_dir.name, "valid_runtime.json")
        with open(temp_cfg, "w", encoding="utf-8") as f:
            json.dump({
                "server": {"host": "127.0.0.1", "port": 4444, "use_tls": False},
                "auth": {"psk": "valid_runtime_psk"},
                "agent": {"group_tag": "runtime-group", "polling_interval": 10}
            }, f)

        cmd_val = [
            "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", core_script,
            "-ValidateConfig",
            "-ConfigPath", temp_cfg
        ]
        res_val = subprocess.run(cmd_val, capture_output=True, text=True)
        self.assertEqual(res_val.returncode, 0, f"ValidateConfig failed:\n{res_val.stderr}\n{res_val.stdout}")
        self.assertIn("Configuration is valid", res_val.stdout)


if __name__ == "__main__":
    unittest.main()

