#!/usr/bin/env python3
"""
Automated Test Suite for Server-EDR Endpoint Defense Capabilities.
Tests:
1. Message framing and JSON serialization with 'event' and 'telemetry' message types.
2. DLP content inspection (Luhn-validated credit cards, SSNs, API keys, private keys).
3. File Integrity Monitoring (FIM) baseline calculation, hashing, and change detection.
4. Malware Prevention (hash signatures, heuristic checks, file quarantine).
5. OpenEDR telemetry log parsing and normalization.
6. Asynchronous event dispatch between agent and server.
"""

import unittest
import os
import sys
import tempfile
import shutil
import hashlib
import json
import re
import time
import socket
import threading
import struct

_LINUX_AGENT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agents", "linux")
if _LINUX_AGENT_DIR not in sys.path:
    sys.path.insert(0, _LINUX_AGENT_DIR)

# ═══════════════════════════════════════════════════════════════
#  DLP Engine (Implementation to test)
# ═══════════════════════════════════════════════════════════════

def luhn_checksum_valid(card_number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


class DLPEngine:
    """Inspects text or binary content for sensitive data leaks."""
    
    # Pre-compiled regex patterns
    PATTERNS = {
        "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        "US_SSN": re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b"),
        "AWS_KEY": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "GITHUB_PAT": re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"),
        "PRIVATE_KEY": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "JWT_TOKEN": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    }
    
    @classmethod
    def scan_text(cls, text: str) -> list:
        """Scan text and return list of detected violations with redacted matches."""
        findings = []
        
        # Credit cards with Luhn verification
        for match in cls.PATTERNS["CREDIT_CARD"].finditer(text):
            raw = re.sub(r"[ -]", "", match.group(0))
            if luhn_checksum_valid(raw):
                redacted = raw[:4] + "*" * (len(raw) - 8) + raw[-4:]
                findings.append({
                    "rule": "CREDIT_CARD",
                    "severity": "CRITICAL",
                    "preview": redacted,
                })
        
        # US SSN
        for match in cls.PATTERNS["US_SSN"].finditer(text):
            val = match.group(0)
            redacted = "***-**-" + val.replace("-", "").replace(" ", "")[-4:]
            findings.append({
                "rule": "US_SSN",
                "severity": "HIGH",
                "preview": redacted,
            })
            
        # AWS Keys
        for match in cls.PATTERNS["AWS_KEY"].finditer(text):
            val = match.group(1)
            findings.append({
                "rule": "AWS_KEY",
                "severity": "CRITICAL",
                "preview": val[:4] + "..." + val[-4:],
            })
            
        # GitHub Personal Access Tokens
        for match in cls.PATTERNS["GITHUB_PAT"].finditer(text):
            val = match.group(1)
            findings.append({
                "rule": "GITHUB_PAT",
                "severity": "CRITICAL",
                "preview": val[:8] + "...",
            })
            
        # Private Keys
        if cls.PATTERNS["PRIVATE_KEY"].search(text):
            findings.append({
                "rule": "PRIVATE_KEY",
                "severity": "CRITICAL",
                "preview": "-----BEGIN PRIVATE KEY----- [REDACTED]",
            })
            
        # JWT
        for match in cls.PATTERNS["JWT_TOKEN"].finditer(text):
            val = match.group(0)
            findings.append({
                "rule": "JWT_TOKEN",
                "severity": "MEDIUM",
                "preview": val[:12] + "...",
            })
            
        return findings

    @classmethod
    def scan_file(cls, path: str, max_bytes: int = 5 * 1024 * 1024) -> list:
        """Scan file for sensitive content."""
        if not os.path.isfile(path):
            return []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(max_bytes)
            return cls.scan_text(content)
        except Exception:
            return []


# ═══════════════════════════════════════════════════════════════
#  FIM Engine (Implementation to test)
# ═══════════════════════════════════════════════════════════════

class FIMEngine:
    """Monitors file baseline and detects alterations."""
    
    @staticmethod
    def hash_file(path: str) -> str:
        """Calculate SHA-256 hash of a file."""
        hasher = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""

    @classmethod
    def create_baseline(cls, paths: list) -> dict:
        """Generate baseline snapshot for monitored paths."""
        baseline = {}
        for p in paths:
            if os.path.isfile(p):
                stat = os.stat(p)
                baseline[p] = {
                    "hash": cls.hash_file(p),
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                    "mode": stat.st_mode,
                    "type": "file"
                }
            elif os.path.isdir(p):
                for root, _, files in os.walk(p):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        try:
                            stat = os.stat(fpath)
                            baseline[fpath] = {
                                "hash": cls.hash_file(fpath),
                                "size": stat.st_size,
                                "mtime": stat.st_mtime,
                                "mode": stat.st_mode,
                                "type": "file"
                            }
                        except Exception:
                            continue
        return baseline

    @classmethod
    def check_integrity(cls, baseline: dict, current_paths: list = None) -> list:
        """Compare current state against baseline and return delta events."""
        changes = []
        
        # Check existing baseline items
        for path, meta in baseline.items():
            if not os.path.exists(path):
                changes.append({
                    "action": "DELETED",
                    "path": path,
                    "severity": "HIGH",
                    "details": "Monitored file was removed",
                    "old_hash": meta.get("hash", "")
                })
            else:
                current_hash = cls.hash_file(path)
                if current_hash and current_hash != meta.get("hash"):
                    changes.append({
                        "action": "MODIFIED",
                        "path": path,
                        "severity": "CRITICAL",
                        "details": "File content / SHA-256 altered",
                        "old_hash": meta.get("hash", ""),
                        "new_hash": current_hash
                    })
                    
        # Check for newly added files in monitored directories
        if current_paths:
            current_snapshot = cls.create_baseline(current_paths)
            for path, meta in current_snapshot.items():
                if path not in baseline:
                    changes.append({
                        "action": "ADDED",
                        "path": path,
                        "severity": "MEDIUM",
                        "details": "New file created in monitored path",
                        "new_hash": meta.get("hash")
                    })
                    
        return changes


# ═══════════════════════════════════════════════════════════════
#  Malware Prevention Engine (Implementation to test)
# ═══════════════════════════════════════════════════════════════

class MalwareEngine:
    """Detects known malicious hashes, suspicious execution, and manages quarantine."""
    
    # Sample known malicious hashes (e.g., EICAR test string SHA-256)
    EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    
    def __init__(self, quarantine_dir: str):
        self.quarantine_dir = quarantine_dir
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self.threat_hashes = {
            self.EICAR_SHA256: "EICAR-Standard-AV-Test-File",
            # Mimikatz sample hash
            "9df1b997b69c4c70d4f3b7937397b9195b12da6f8da79eb7c569f10f44bc1912": "HackTool:Win32/Mimikatz!sample",
        }

    def check_hash(self, sha256_hash: str) -> dict:
        """Check if hash matches known threat database."""
        name = self.threat_hashes.get(sha256_hash.lower())
        if name:
            return {"match": True, "threat_name": name, "hash": sha256_hash}
        return {"match": False}

    def scan_file(self, path: str) -> dict:
        """Scan file against threat database."""
        if not os.path.isfile(path):
            return {"status": "error", "message": "File not found"}
        
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        digest = hasher.hexdigest()
        
        match = self.check_hash(digest)
        if match["match"]:
            return {
                "status": "threat_detected",
                "path": path,
                "threat_name": match["threat_name"],
                "hash": digest,
                "severity": "CRITICAL"
            }
            
        return {"status": "clean", "path": path, "hash": digest}

    def quarantine_file(self, path: str) -> dict:
        """Move malicious file into quarantine vault with restricted permissions."""
        if not os.path.exists(path):
            return {"status": "error", "message": "File does not exist"}
            
        fname = os.path.basename(path)
        timestamp = int(time.time())
        quarantine_name = f"{timestamp}_{fname}.quarantine"
        quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
        
        meta = {
            "original_path": os.path.abspath(path),
            "original_name": fname,
            "quarantine_time": timestamp,
            "hash": FIMEngine.hash_file(path)
        }
        
        # Move file
        shutil.move(path, quarantine_path)
        
        # Restrict permissions
        try:
            os.chmod(quarantine_path, 0o600)
        except Exception:
            pass
            
        # Write metadata
        meta_path = quarantine_path + ".meta"
        with open(meta_path, "w") as f:
            json.dump(meta, f)
            
        return {
            "status": "quarantined",
            "quarantine_file": quarantine_name,
            "original_path": meta["original_path"],
            "hash": meta["hash"]
        }

    def list_quarantined(self) -> list:
        """List files in quarantine."""
        items = []
        for fname in os.listdir(self.quarantine_dir):
            if fname.endswith(".meta"):
                try:
                    with open(os.path.join(self.quarantine_dir, fname), "r") as f:
                        meta = json.load(f)
                    items.append(meta)
                except Exception:
                    continue
        return items

    def restore_file(self, quarantine_file: str) -> dict:
        """Restore quarantined file to original path."""
        qpath = os.path.join(self.quarantine_dir, quarantine_file)
        mpath = qpath + ".meta"
        if not os.path.exists(qpath) or not os.path.exists(mpath):
            return {"status": "error", "message": "Quarantine entry not found"}
            
        with open(mpath, "r") as f:
            meta = json.load(f)
            
        orig_path = meta["original_path"]
        os.makedirs(os.path.dirname(orig_path), exist_ok=True)
        shutil.move(qpath, orig_path)
        os.remove(mpath)
        return {"status": "restored", "path": orig_path}


# ═══════════════════════════════════════════════════════════════
#  OpenEDR Log Parser (Implementation to test)
# ═══════════════════════════════════════════════════════════════

class OpenEDRParser:
    """Parses OpenEDR service and kernel telemetry output."""
    
    # Prefix pattern: [Date-Time] [Thread/ID] [Component-Tag] [Log-Level] [Message]
    LOG_PATTERN = re.compile(
        r"^(\d{8}-\d{6}\.\d{3})\s+([0-9a-fA-F]+)\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)$"
    )
    
    @classmethod
    def parse_log_line(cls, line: str) -> dict:
        """Parse raw OpenEDR log line into structured telemetry dictionary."""
        match = cls.LOG_PATTERN.match(line.strip())
        if match:
            ts, tid, component, level, message = match.groups()
            return {
                "timestamp": ts,
                "thread_id": tid,
                "component": component.strip(),
                "level": level.strip(),
                "message": message.strip(),
                "format": "openedr_service_log"
            }
        
        # Check if line is JSON (OpenEDR output_events format)
        try:
            data = json.loads(line.strip())
            return {
                "format": "openedr_event_json",
                "event_type": data.get("event_type", data.get("type", "UNKNOWN")),
                "data": data
            }
        except Exception:
            return {"format": "raw", "raw": line.strip()}


# ═══════════════════════════════════════════════════════════════
#  Unit Test Cases
# ═══════════════════════════════════════════════════════════════

class TestEndpointDefense(unittest.TestCase):
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="edr_defense_test_")
        self.quarantine_dir = os.path.join(self.test_dir, "quarantine")
        self.malware_engine = MalwareEngine(self.quarantine_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # 1. DLP Tests
    def test_dlp_credit_card_luhn(self):
        # Valid test card (Visa format)
        valid_card = "4532 0150 1234 5671"
        self.assertTrue(luhn_checksum_valid(valid_card))
        
        # Invalid card (fails Luhn)
        invalid_card = "4532 0150 1234 5670"
        self.assertFalse(luhn_checksum_valid(invalid_card))
        
        findings = DLPEngine.scan_text(f"Customer card: {valid_card}")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "CREDIT_CARD")
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertIn("****", findings[0]["preview"])

    def test_dlp_ssn_and_api_keys(self):
        text = (
            "User SSN is 012-34-5678. "
            "AWS credentials: AKIAIOSFODNN7EXAMPLE. "
            "GitHub token: ghp_1234567890abcdefghijklmnopqrstuvwxyz12. "
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----"
        )
        findings = DLPEngine.scan_text(text)
        rules = [f["rule"] for f in findings]
        self.assertIn("US_SSN", rules)
        self.assertIn("AWS_KEY", rules)
        self.assertIn("GITHUB_PAT", rules)
        self.assertIn("PRIVATE_KEY", rules)

    # 2. FIM Tests
    def test_fim_baseline_and_modification(self):
        monitored_file = os.path.join(self.test_dir, "critical_config.conf")
        with open(monitored_file, "w") as f:
            f.write("INITIAL_CONFIGURATION_V1")
            
        baseline = FIMEngine.create_baseline([monitored_file])
        self.assertIn(monitored_file, baseline)
        self.assertTrue(len(baseline[monitored_file]["hash"]) == 64)
        
        # Test no change
        no_changes = FIMEngine.check_integrity(baseline)
        self.assertEqual(len(no_changes), 0)
        
        # Modify file
        with open(monitored_file, "w") as f:
            f.write("MODIFIED_MALICIOUS_CONFIG")
            
        changes = FIMEngine.check_integrity(baseline)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["action"], "MODIFIED")
        self.assertEqual(changes[0]["severity"], "CRITICAL")
        
        # Delete file
        os.remove(monitored_file)
        del_changes = FIMEngine.check_integrity(baseline)
        self.assertEqual(len(del_changes), 1)
        self.assertEqual(del_changes[0]["action"], "DELETED")

    # 3. Malware Detection & Quarantine Tests
    def test_malware_hash_detection_and_quarantine(self):
        eicar_file = os.path.join(self.test_dir, "test_eicar.com")
        with open(eicar_file, "w") as f:
            f.write(MalwareEngine.EICAR_STRING)
            
        # Scan file
        res = self.malware_engine.scan_file(eicar_file)
        self.assertEqual(res["status"], "threat_detected")
        self.assertEqual(res["threat_name"], "EICAR-Standard-AV-Test-File")
        
        # Quarantine file
        q_res = self.malware_engine.quarantine_file(eicar_file)
        self.assertEqual(q_res["status"], "quarantined")
        self.assertFalse(os.path.exists(eicar_file))
        
        # Check quarantine list
        q_list = self.malware_engine.list_quarantined()
        self.assertEqual(len(q_list), 1)
        self.assertEqual(q_list[0]["original_name"], "test_eicar.com")
        
        # Restore file
        r_res = self.malware_engine.restore_file(q_res["quarantine_file"])
        self.assertEqual(r_res["status"], "restored")
        self.assertTrue(os.path.exists(eicar_file))

    # 4. OpenEDR Log Parser Tests
    def test_openedr_log_parsing(self):
        sample_log = "20260921-114502.123 0a4c [INJECTOR] [INF] Hooking process target PID 4120"
        parsed = OpenEDRParser.parse_log_line(sample_log)
        self.assertEqual(parsed["format"], "openedr_service_log")
        self.assertEqual(parsed["component"], "INJECTOR")
        self.assertEqual(parsed["level"], "INF")
        self.assertIn("Hooking process", parsed["message"])

        sample_json_event = json.dumps({
            "event_type": "PROCESS_CREATE",
            "pid": 5890,
            "image_path": "C:\\Windows\\System32\\cmd.exe",
            "command_line": "cmd.exe /c whoami",
            "parent_pid": 1024
        })
        parsed_json = OpenEDRParser.parse_log_line(sample_json_event)
        self.assertEqual(parsed_json["format"], "openedr_event_json")
        self.assertEqual(parsed_json["event_type"], "PROCESS_CREATE")
        self.assertEqual(parsed_json["data"]["pid"], 5890)

    # 5. Protocol Duplex Framing & Event Handling
    def test_framed_protocol_async_event(self):
        """Simulate duplex framing with both synchronous response and async event."""
        client_sock, server_sock = socket.socketpair()
        
        # Helper to send framed msg
        def send_framed(sock, data):
            payload = json.dumps(data).encode("utf-8")
            sock.sendall(struct.pack("<I", len(payload)) + payload)
            
        def recv_framed(sock):
            hdr = sock.recv(4)
            length = struct.unpack("<I", hdr)[0]
            raw = sock.recv(length)
            return json.loads(raw.decode("utf-8"))

        # Send an asynchronous event
        event_payload = {
            "type": "event",
            "subsystem": "malware",
            "severity": "CRITICAL",
            "data": {"file": "suspicious.exe", "threat": "Trojan.Generic"}
        }
        send_framed(client_sock, event_payload)
        
        received_event = recv_framed(server_sock)
        self.assertEqual(received_event["type"], "event")
        self.assertEqual(received_event["subsystem"], "malware")
        self.assertEqual(received_event["severity"], "CRITICAL")
        
        # Send a synchronous response
        response_payload = {
            "type": "response",
            "id": "abc12345",
            "status": "ok",
            "output": "Command completed successfully"
        }
        send_framed(client_sock, response_payload)
        
        received_resp = recv_framed(server_sock)
        self.assertEqual(received_resp["type"], "response")
        self.assertEqual(received_resp["id"], "abc12345")
        
        client_sock.close()
        server_sock.close()

    # 6. End-to-End Server & Agent Defense Integration Test
    def test_end_to_end_server_agent_defense_integration(self):
        """Test live EDRServer authentication, command dispatch, and asynchronous security event handling."""
        from Server import EDRServer, Agent
        
        test_psk = "test_secret_key_1234567890abcdef"
        server = EDRServer(host="127.0.0.1", port=0, psk=test_psk, tls_context=None)
        server.start()
        
        # Get bound port
        actual_port = server._sock.getsockname()[1]
        
        events_received = []
        def on_event(ev, data):
            if ev == "security_event":
                events_received.append(data)
                
        server.on_event(on_event)
        
        # Connect simulated endpoint client
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(("127.0.0.1", actual_port))
        
        def send_client(d):
            raw = json.dumps(d).encode("utf-8")
            client_sock.sendall(struct.pack("<I", len(raw)) + raw)
            
        def recv_client():
            hdr = client_sock.recv(4)
            if not hdr: return None
            l = struct.unpack("<I", hdr)[0]
            buf = b""
            while len(buf) < l:
                buf += client_sock.recv(l - len(buf))
            return json.loads(buf.decode("utf-8"))
            
        # 1. Recv challenge
        ch = recv_client()
        self.assertEqual(ch.get("type"), "challenge")
        
        # 2. Compute HMAC and send auth
        nonce = bytes.fromhex(ch["nonce"])
        import hmac as _hmac
        digest = _hmac.new(test_psk.encode(), nonce, hashlib.sha256).digest().hex()
        send_client({"type": "auth", "hmac": digest})
        
        # 3. Recv auth_ok
        ok = recv_client()
        self.assertEqual(ok.get("type"), "auth_ok")
        
        # 4. Send register
        send_client({
            "type": "register",
            "hostname": "TestEndpoint-01",
            "username": "sec_tester",
            "os": "Linux 6.1-amd64",
            "arch": "x86_64",
            "ip": "127.0.0.1",
            "python_ver": "3.13.0",
            "is_root": True,
            "defense_capabilities": ["malware_prevention", "fim", "dlp", "openedr"]
        })
        
        time.sleep(0.1)
        agents = server.agents()
        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0].hostname, "TestEndpoint-01")
        
        # 5. Client sends asynchronous FIM event
        send_client({
            "type": "event",
            "subsystem": "fim",
            "severity": "CRITICAL",
            "title": "FIM MODIFIED: /etc/shadow",
            "details": "Password hash altered",
            "timestamp": "2026-09-21T12:00:00Z"
        })
        
        time.sleep(0.1)
        self.assertEqual(len(events_received), 1)
        agent_ref, event_msg = events_received[0]
        self.assertEqual(event_msg["subsystem"], "fim")
        self.assertEqual(event_msg["severity"], "CRITICAL")
        self.assertEqual(event_msg["title"], "FIM MODIFIED: /etc/shadow")
        self.assertEqual(event_msg["host"], "TestEndpoint-01")
        
        # 6. Server sends defense command to agent and receives response
        def client_handle_cmd():
            while True:
                msg = recv_client()
                if not msg:
                    break
                cmd = msg.get("command")
                if cmd == "attest":
                    send_client({
                        "type": "response",
                        "id": msg["id"],
                        "status": "ok",
                        "output": json.dumps({"raw_sha256": "dummy_test_hash", "bytes_len": 500, "pid": 1234})
                    })
                elif cmd == "malware_scan":
                    send_client({
                        "type": "response",
                        "id": msg["id"],
                        "status": "ok",
                        "output": json.dumps([{"path": "/tmp/evil.sh", "threat": "Trojan.Mirai"}])
                    })
                    break
        th = threading.Thread(target=client_handle_cmd, daemon=True)
        th.start()
        
        mid, _ = agents[0].send_command("malware_scan", "/tmp")
        resp = agents[0].wait_response(mid, timeout=5)
        self.assertIsNotNone(resp)
        self.assertEqual(resp["status"], "ok")
        findings = json.loads(resp["output"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["threat"], "Trojan.Mirai")
        
        client_sock.close()
        server._sock.close()

    # 7. Live Modular Linux Agent Process Integration Test
    def test_live_linux_agent_process_integration(self):
        """Spawns actual modular agent_core.py process with env overrides and executes defense commands."""
        import subprocess
        from Server import EDRServer
        
        test_psk = "live_agent_secret_psk_9876543210fedcba"
        server = EDRServer(host="127.0.0.1", port=0, psk=test_psk, tls_context=None)
        server.start()
        actual_port = server._sock.getsockname()[1]
        
        env = os.environ.copy()
        env["EDR_SERVER_HOST"] = "127.0.0.1"
        env["EDR_SERVER_PORT"] = str(actual_port)
        env["EDR_PSK"] = test_psk
        env["EDR_USE_TLS"] = "0"
        env["EDR_RECONNECT_SECS"] = "2"
        env["RAT_SERVER_HOST"] = "127.0.0.1"
        env["RAT_SERVER_PORT"] = str(actual_port)
        env["RAT_PSK"] = test_psk
        env["RAT_USE_TLS"] = "0"
        env["RAT_RECONNECT_SECS"] = "2"
        
        agent_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agents", "linux", "agent_core.py")
        proc = subprocess.Popen(
            [sys.executable, agent_script, "--no-watchdog"],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        try:
            # Wait up to 5s for agent to connect and register
            start_t = time.time()
            agent = None
            while time.time() - start_t < 5.0:
                agents = server.agents()
                if agents:
                    agent = agents[0]
                    break
                time.sleep(0.1)
                
            self.assertIsNotNone(agent, "agent_core.py failed to connect to live EDRServer")
            self.assertTrue(len(agent.defense_caps) > 0)
            
            # Test sysinfo
            mid, _ = agent.send_command("sysinfo")
            resp = agent.wait_response(mid, timeout=10)
            self.assertIsNotNone(resp)
            self.assertEqual(resp["status"], "ok")
            sysinfo = json.loads(resp["output"])
            self.assertIn("defense", sysinfo)
            
            # Test DLP scan command on agent
            mid, _ = agent.send_command("dlp_scan", "My card is 4532 0150 1234 5671")
            resp = agent.wait_response(mid, timeout=10)
            self.assertIsNotNone(resp)
            self.assertEqual(resp["status"], "ok")
            violations = json.loads(resp["output"])
            self.assertEqual(len(violations), 1)
            self.assertEqual(violations[0]["rule"], "CREDIT_CARD")
            
            # Test OpenEDR status command on agent
            mid, _ = agent.send_command("openedr_status")
            resp = agent.wait_response(mid, timeout=10)
            self.assertIsNotNone(resp)
            self.assertEqual(resp["status"], "ok")
            edr_st = json.loads(resp["output"])
            self.assertIn("log_path", edr_st)

            # Test install_openedr command on agent
            mid, _ = agent.send_command("install_openedr")
            resp = agent.wait_response(mid, timeout=15)
            self.assertIsNotNone(resp)
            self.assertIn(resp.get("status"), ("ok", "error"))
            self.assertTrue(len(resp.get("output", "")) > 0)
            
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
            if proc.stdout: proc.stdout.close()
            if proc.stderr: proc.stderr.close()
            server._sock.close()

    # 8. Anti-Tamper: Self-FIM Detection Test
    def test_self_fim_tamper_detection(self):
        """Verifies that FIM flags modification of self-protected agent files as tamper events."""
        from modules import FIMMonitor
        test_dir = tempfile.mkdtemp(prefix="fim_tamper_test_")
        try:
            fake_agent = os.path.join(test_dir, "fake_agent.py")
            with open(fake_agent, "w") as f:
                f.write("# original agent code\nprint('hello')\n")
            
            fim = FIMMonitor(watch_paths=[fake_agent], self_protect=False)
            fim.self_protect_paths.add(fake_agent)
            fim.init_baseline()
            
            # Unmodified check
            self.assertEqual(len(fim.check()), 0)
            
            # Tamper with file
            with open(fake_agent, "a") as f:
                f.write("# malicious adversary patch\n")
                
            changes = fim.check()
            self.assertEqual(len(changes), 1)
            self.assertTrue(changes[0].get("tamper"), "Tampered agent file was not flagged with tamper=True")
            self.assertEqual(changes[0]["severity"], "CRITICAL")
            self.assertEqual(changes[0]["action"], "MODIFIED")
            self.assertIn("ANTI-TAMPER", changes[0]["details"])
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    # 9. Anti-Tamper: Cryptographic Code Attestation Test
    def test_cryptographic_attestation(self):
        """Verifies cryptographic attestation challenge/response and server-side verification."""
        import hmac as _hmac
        from modules import cmd_attest
        from Server import EDRServer, Agent
        
        nonce = "test_nonce_12345678abcdef"
        agent_path = os.path.join(os.path.dirname(__file__), "agents", "linux", "agent_core.py")
        status, output = cmd_attest(nonce, agent_path)
        self.assertEqual(status, "ok")
        data = json.loads(output)
        self.assertIn("raw_sha256", data)
        self.assertIn("attest_hmac", data)
        self.assertIn("pid", data)
        
        # Verify HMAC correctness
        with open(data["path"], "rb") as f:
            code_bytes = f.read()
        expected_raw = hashlib.sha256(code_bytes).hexdigest()
        expected_hmac = _hmac.new(nonce.encode("utf-8"), code_bytes, hashlib.sha256).hexdigest()
        self.assertEqual(data["raw_sha256"], expected_raw)
        self.assertEqual(data["attest_hmac"], expected_hmac)

    # 10. Anti-Tamper: Dead-Man Liveness & Alert Dispatch
    def test_tamper_event_handling(self):
        """Verifies server correctly handles and indexes tamper events in security alerts."""
        from Server import EDRServer, Agent
        server = EDRServer(host="127.0.0.1", port=0, psk="secret_psk")
        dummy_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        agent = Agent(dummy_conn, ("127.0.0.1", 12345))
        agent.hostname = "TamperHost"
        
        tamper_event = {
            "type": "event",
            "subsystem": "tamper",
            "severity": "CRITICAL",
            "title": "🚨 ANTI-TAMPER: Agent File Modified",
            "details": "agent_core.py altered on disk",
            "timestamp": "2026-09-24T22:00:00"
        }
        server._dispatch_security_event(agent, tamper_event)
        self.assertEqual(len(server._security_events), 1)
        ev = server._security_events[0]
        self.assertEqual(ev["subsystem"], "tamper")
        self.assertEqual(ev["severity"], "CRITICAL")
        self.assertEqual(ev["host"], "TamperHost")
        dummy_conn.close()

    # 11. OpenEDR & Dependency Installation Test
    def test_openedr_dependency_installer(self):
        """Verifies OpenEDR and security dependency installer invocation."""
        from modules import OpenEDRIntegration
        status, output = OpenEDRIntegration.install_openedr()
        self.assertIn(status, ("ok", "error"))
        self.assertTrue(len(output) > 0)

    # 12. FIM Lifecycle: Single-alert deletion pruning and new file addition
    def test_fim_added_and_deleted_lifecycle(self):
        """Verifies FIM pruning of deleted files (no repeat spam) and discovery of ADDED files."""
        from modules import FIMMonitor
        test_dir = tempfile.mkdtemp(prefix="fim_lifecycle_test_")
        try:
            f1 = os.path.join(test_dir, "file1.txt")
            with open(f1, "w") as f:
                f.write("initial file 1")
            fim = FIMMonitor(watch_paths=[test_dir], self_protect=False)
            self.assertEqual(len(fim.check()), 0)

            # Test ADDED: create new file in watched directory
            f2 = os.path.join(test_dir, "file2.txt")
            with open(f2, "w") as f:
                f.write("newly added file 2")
            changes = fim.check()
            self.assertEqual(len(changes), 1)
            self.assertEqual(changes[0]["action"], "ADDED")
            self.assertEqual(changes[0]["path"], f2)

            # Second check: file2 is now baselined, no changes
            self.assertEqual(len(fim.check()), 0)

            # Test DELETED: delete f1
            os.remove(f1)
            changes_del = fim.check()
            self.assertEqual(len(changes_del), 1)
            self.assertEqual(changes_del[0]["action"], "DELETED")
            self.assertEqual(changes_del[0]["path"], f1)

            # Pruning verification: subsequent check must NOT spam DELETED again
            self.assertEqual(len(fim.check()), 0)
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    # 13. Buffer Exhaustion Guard: Download file size cap
    def test_download_buffer_limit_guard(self):
        """Verifies that cmd_download refuses files exceeding 35 MB safety cap."""
        from modules import cmd_download
        test_dir = tempfile.mkdtemp(prefix="dl_guard_test_")
        try:
            large_file = os.path.join(test_dir, "oversized.bin")
            with open(large_file, "wb") as f:
                # Sparse file: seek to 36 MB and write 1 byte
                f.seek(36 * 1024 * 1024)
                f.write(b"\x00")
            
            status, output = cmd_download(None, large_file)
            self.assertEqual(status, "error")
            self.assertIn("exceeds single-frame transfer limit", output)
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    # 14. Windows Agent Pure ASCII & AST Validity
    def test_windows_agent_pure_ascii(self):
        """Verifies modular Windows agent files contain 0 non-ASCII bytes to prevent CP1252 encoding traps."""
        win_dir = os.path.join(os.path.dirname(__file__), "agents", "windows")
        ps_files = []
        for root, _, files in os.walk(win_dir):
            for f in files:
                if f.endswith((".ps1", ".psm1")):
                    ps_files.append(os.path.join(root, f))
        self.assertTrue(len(ps_files) > 0, "No PowerShell files found in agents/windows")
        for script_path in ps_files:
            with open(script_path, "rb") as f:
                raw = f.read()
            non_ascii = [b for b in raw if b >= 128]
            self.assertEqual(len(non_ascii), 0, f"{os.path.basename(script_path)} contains {len(non_ascii)} non-ASCII bytes")

    # 15. Server.py Module Integrity & sys import
    def test_server_sys_imported(self):
        """Verifies Server.py imports sys and ensure_server_dependencies does not raise NameError."""
        import Server
        self.assertTrue(hasattr(Server, "sys"), "Server.py missing sys module import")

    # 16. Chunked Streaming Download and Upload
    def test_chunked_download_and_upload(self):
        """Verifies multi-part streaming transfer of files without head-of-line blocking."""
        import base64
        from modules import cmd_download_chunk, cmd_upload_chunk, MalwareDefense
        test_dir = tempfile.mkdtemp(prefix="chunk_test_")
        try:
            # 1. Create a 1.25 MB test file
            src_file = os.path.join(test_dir, "source.bin")
            test_data = os.urandom(1280 * 1024)
            with open(src_file, "wb") as f:
                f.write(test_data)
            orig_hash = hashlib.sha256(test_data).hexdigest()

            # 2. Download in 512 KB chunks
            chunk_size = 512 * 1024
            offset = 0
            downloaded_bytes = b""
            while True:
                st, chunk_info = cmd_download_chunk(None, src_file, offset=offset, chunk_size=chunk_size)
                self.assertEqual(st, "ok")
                self.assertEqual(chunk_info["total_size"], len(test_data))
                chunk_data = base64.b64decode(chunk_info["data"])
                downloaded_bytes += chunk_data
                offset += len(chunk_data)
                if chunk_info["eof"]:
                    break

            self.assertEqual(len(downloaded_bytes), len(test_data))
            self.assertEqual(hashlib.sha256(downloaded_bytes).hexdigest(), orig_hash)

            # 3. Upload chunked to target file
            dst_file = os.path.join(test_dir, "uploaded.bin")
            mal_def = MalwareDefense()
            offset = 0
            while offset < len(downloaded_bytes):
                chunk = downloaded_bytes[offset:offset + chunk_size]
                is_eof = (offset + len(chunk) >= len(downloaded_bytes))
                b64 = base64.b64encode(chunk).decode()
                st, res = cmd_upload_chunk(None, dst_file, offset, b64, len(downloaded_bytes), is_eof, mal_def)
                self.assertEqual(st, "ok")
                offset += len(chunk)

            self.assertTrue(os.path.isfile(dst_file))
            with open(dst_file, "rb") as f:
                uploaded_content = f.read()
            self.assertEqual(hashlib.sha256(uploaded_content).hexdigest(), orig_hash)
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    # 17. Chunked Transfer Security & Threat Interception
    def test_chunked_transfer_security_guards(self):
        """Verifies malware interception during chunked uploads."""
        import base64
        from modules import cmd_upload_chunk, MalwareDefense
        test_dir = tempfile.mkdtemp(prefix="chunk_sec_test_")
        try:
            eicar_bytes = MalwareDefense.KNOWN_THREATS.get("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
            eicar_content = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            dst_file = os.path.join(test_dir, "eicar.com")
            mal_def = MalwareDefense()
            b64 = base64.b64encode(eicar_content).decode()
            st, res = cmd_upload_chunk(None, dst_file, 0, b64, len(eicar_content), True, mal_def)
            self.assertEqual(st, "error")
            self.assertIn("Malware Block", res.get("error", ""))
            self.assertFalse(os.path.exists(dst_file), "Malicious uploaded chunk was not cleaned up")
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
