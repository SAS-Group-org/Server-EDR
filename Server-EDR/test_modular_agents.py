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

    cwd = os.path.dirname(os.path.abspath(__file__))
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

def main():
    results = {}
    
    cwd = os.path.dirname(os.path.abspath(__file__))
    win_agent = os.path.join(cwd, "agents", "windows", "Agent-Core.ps1")
    results["Modular Windows Agent"] = run_test_agent(
        "Modular Windows Agent (Agent-Core.ps1)",
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", win_agent],
        win_agent
    )

    # 2. Modular Linux Agent
    results["Modular Linux Agent"] = run_test_agent(
        "Modular Linux Agent (agent_core.py)",
        [sys.executable, "agents/linux/agent_core.py", "--no-watchdog"],
        "agents/linux/agent_core.py"
    )

    print("="*60)
    print("MODULAR AGENT TEST RESULTS SUMMARY:")
    for k, v in results.items():
        print(f"  {k}: {'PASS' if v else 'FAIL'}")
    print("="*60)

    if not all(results.values()):
        sys.exit(1)

if __name__ == "__main__":
    main()
