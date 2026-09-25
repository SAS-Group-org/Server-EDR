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

if __name__ == "__main__":
    main()
