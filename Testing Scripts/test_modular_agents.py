#!/usr/bin/env python3
"""
Integration test suite for Modular Agents:
1. Modular Windows Agent: agents/windows/Agent-Core.ps1
2. Modular Linux Agent: agents/linux/agent_core.py
"""
import json
import os
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from Server import EDRServer

def run_test_agent(name, launch_cmd, script_rel_path):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    test_psk = f"test_psk_{name}_1234567890abcdef"
    server = EDRServer(host="127.0.0.1", port=0, psk=test_psk, tls_context=None)
    server.start()
    port = server._sock.getsockname()[1]
    print(f"\n{'='*60}\n[*] Testing {name} on port {port}\n{'='*60}")

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

    cwd = REPO_ROOT
    proc = subprocess.Popen(
        launch_cmd,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        agent = None
        start = time.time()
        while time.time() - start < 10.0:
            agents = server.agents()
            if agents:
                agent = agents[0]
                break
            time.sleep(0.2)

        if not agent:
            print(f"[!] {name} failed to connect within timeout")
            try:
                proc.terminate()
                stdout, stderr = proc.communicate(timeout=3)
                print(f"STDOUT: {stdout}")
                print(f"STDERR: {stderr}")
            except Exception as e:
                print(f"Error capturing output: {e}")
            return False

        print(f"[+] Agent connected: {agent.username}@{agent.hostname} (OS: {agent.os})")
        print(f"[+] Defense capabilities: {agent.defense_caps}")

        # 1. ping
        mid, _ = agent.send_command("ping")
        resp = agent.wait_response(mid, timeout=10)
        assert resp and resp["status"] == "ok" and resp["output"] == "pong", f"Ping failed: {resp}"
        print("[+] Ping response: pong")

        # 2. sysinfo
        mid, _ = agent.send_command("sysinfo")
        resp = agent.wait_response(mid, timeout=10)
        assert resp and resp["status"] == "ok", f"Sysinfo failed: {resp}"
        info = json.loads(resp["output"])
        print(f"[+] Sysinfo verified: RAM={info.get('ram_gb')} GB, Arch={info.get('arch')}")

        # 3. dlp_scan
        mid, _ = agent.send_command("dlp_scan", "Visa 4532 0150 1234 5671 and AKIAIOSFODNN7EXAMPLE")
        resp = agent.wait_response(mid, timeout=10)
        assert resp and resp["status"] == "ok", f"DLP failed: {resp}"
        dlp_res = json.loads(resp["output"])
        rules = [item["rule"] for item in dlp_res]
        assert "CREDIT_CARD" in rules or "AWS_KEY" in rules, f"Expected DLP rules: {dlp_res}"
        print(f"[+] DLP scan detected: {rules}")

        # 4. openedr_status
        mid, _ = agent.send_command("openedr_status")
        resp = agent.wait_response(mid, timeout=10)
        assert resp and resp["status"] == "ok", f"OpenEDR status failed: {resp}"
        print(f"[+] OpenEDR status verified")

        # 5. Attestation
        mid, _ = agent.send_command("attest", "test_nonce_xyz")
        resp = agent.wait_response(mid, timeout=10)
        assert resp and resp["status"] == "ok", f"Attest failed: {resp}"
        attest_info = json.loads(resp["output"])
        assert "raw_sha256" in attest_info and "attest_hmac" in attest_info
        print(f"[+] Attestation returned hash: {attest_info['raw_sha256'][:16]}...")

        # 6. Verify Server-Side Attestation
        time.sleep(1.0)
        print(f"[+] Server attestation verdict: {agent.attestation_status}")
        assert agent.attestation_status == "Verified ✓", f"Attestation status was not Verified: {agent.attestation_status}"

        # 7. Chunked Upload & Download (Phase 4 Streaming Wire Transfer)
        import base64
        test_payload = b"StreamingChunkedTransferValidationData_1234567890_ABCDEF"
        b64_payload = base64.b64encode(test_payload).decode()
        target_remote_file = os.path.join(cwd, f"test_chunk_transfer_{name[:3]}.tmp")

        # Upload chunk
        mid, _ = agent.send_command("upload_chunk", path=target_remote_file, offset=0, data=b64_payload, total_size=len(test_payload), eof=True)
        resp = agent.wait_response(mid, timeout=15)
        assert resp and resp.get("status") == "ok", f"upload_chunk failed: {resp}"
        print(f"[+] upload_chunk verified: offset={resp.get('offset')}, bytes_written={resp.get('bytes_written')}")

        # Download chunk
        mid, _ = agent.send_command("download_chunk", path=target_remote_file, offset=0, chunk_size=len(test_payload))
        resp = agent.wait_response(mid, timeout=15)
        assert resp and resp.get("status") == "ok", f"download_chunk failed: {resp}"
        read_bytes = base64.b64decode(resp.get("data", ""))
        assert read_bytes == test_payload, f"Downloaded chunk payload mismatch: {read_bytes} != {test_payload}"
        assert resp.get("eof") is True, f"Expected EOF=True, got {resp.get('eof')}"
        print(f"[+] download_chunk verified: total_size={resp.get('total_size')}, eof={resp.get('eof')}")

        try:
            os.remove(target_remote_file)
        except Exception:
            pass

        print(f"[SUCCESS] {name} ALL CHECKS PASSED!\n")
        return True

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        server._sock.close()


import unittest
import tempfile
import tarfile
import zipfile
from agents.linux.package_linux_agent import build_linux_package
from agents.windows.package_windows_agent import build_windows_package


class TestModularAgents(unittest.TestCase):
    """Automated unit and integration test suite for modular agents and packaging (Issue #29)."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_modular_agents_live_communication(self):
        """Validates that modular Windows and Linux agents connect, authenticate, and execute defense commands."""
        cwd = REPO_ROOT
        win_agent = os.path.join(cwd, "agents", "windows", "Agent-Core.ps1")
        win_ok = run_test_agent(
            "Modular Windows Agent (Agent-Core.ps1)",
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", win_agent],
            win_agent
        )
        self.assertTrue(win_ok, "Modular Windows Agent test failed")

        linux_agent = os.path.join(cwd, "agents", "linux", "agent_core.py")
        linux_ok = run_test_agent(
            "Modular Linux Agent (agent_core.py)",
            [sys.executable, linux_agent, "--no-watchdog"],
            linux_agent
        )
        self.assertTrue(linux_ok, "Modular Linux Agent test failed")

    def test_modular_agent_packaging_and_configuration(self):
        """Issue #29: Validates packaging, injected configuration, and standalone execution of modular agents."""
        cwd = REPO_ROOT

        # 1. Package Linux Modular Agent
        linux_tar = os.path.join(self.temp_dir.name, "mod-linux.tar.gz")
        linux_cfg = {
            "server": {"host": "127.0.0.1", "port": 4444, "use_tls": False},
            "auth": {"psk": "mod_linux_psk_token"},
            "agent": {"group_tag": "modular-linux-fleet", "polling_interval": 6}
        }
        res_tar = build_linux_package(linux_tar, config_data=linux_cfg)
        self.assertTrue(os.path.isfile(res_tar))

        # Extract and verify configuration
        linux_extract_dir = os.path.join(self.temp_dir.name, "extracted_linux")
        with tarfile.open(res_tar, "r:gz") as tar:
            if hasattr(tarfile, "data_filter"):
                tar.extractall(linux_extract_dir, filter="data")
            else:
                tar.extractall(linux_extract_dir)

        deployed_linux_cfg = os.path.join(linux_extract_dir, "server-edr-agent", "agent_config.json")
        self.assertTrue(os.path.isfile(deployed_linux_cfg))
        with open(deployed_linux_cfg, "r", encoding="utf-8") as f:
            cfg_data = json.load(f)
        self.assertEqual(cfg_data["agent"]["group_tag"], "modular-linux-fleet")
        self.assertEqual(cfg_data["agent"]["polling_interval"], 6)

        # 2. Package Windows Modular Agent
        win_zip = os.path.join(self.temp_dir.name, "mod-win.zip")
        win_cfg = {
            "server": {"host": "127.0.0.1", "port": 4444, "use_tls": False},
            "auth": {"psk": "mod_win_psk_token"},
            "agent": {"group_tag": "modular-win-fleet", "polling_interval": 8}
        }
        res_zip = build_windows_package(win_zip, config_data=win_cfg)
        self.assertTrue(os.path.isfile(res_zip))

        # Extract and verify configuration
        win_extract_dir = os.path.join(self.temp_dir.name, "extracted_win")
        with zipfile.ZipFile(res_zip, "r") as zf:
            zf.extractall(win_extract_dir)

        pkg_root_entry = [d for d in os.listdir(win_extract_dir) if os.path.isdir(os.path.join(win_extract_dir, d))][0]
        deployed_win_cfg = os.path.join(win_extract_dir, pkg_root_entry, "agent_config.json")
        self.assertTrue(os.path.isfile(deployed_win_cfg))
        with open(deployed_win_cfg, "r", encoding="utf-8") as f:
            cfg_data_win = json.load(f)
        self.assertEqual(cfg_data_win["agent"]["group_tag"], "modular-win-fleet")
        self.assertEqual(cfg_data_win["agent"]["polling_interval"], 8)


def main():
    unittest.main()


if __name__ == "__main__":
    main()

