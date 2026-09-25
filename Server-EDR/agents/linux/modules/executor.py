import base64
import hashlib
import hmac
import json
import os
import platform
import shutil
import signal
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

from .common import get_hostname, get_username, get_local_ip, get_uptime, get_ram_gb, is_root, send_event, DLP_ENABLED, DLP_BLOCK_TRANSFERS
from .dlp import DLPScanner
from .fim import FIMMonitor
from .malware import MalwareDefense
from .openedr import OpenEDRIntegration

def cmd_shell(args: str) -> Tuple[str, str]:
    try:
        sh = shutil.which("bash") or "/bin/sh"
        res = subprocess.run(
            args, shell=True, executable=sh,
            capture_output=True, timeout=30, text=True
        )
        return ("ok", res.stdout + res.stderr)
    except subprocess.TimeoutExpired:
        return ("error", "Command timed out after 30 seconds")
    except Exception as e:
        return ("error", str(e))

def cmd_sysinfo(fim_mon: FIMMonitor, mal_def: MalwareDefense) -> Tuple[str, str]:
    try:
        uname = platform.uname()
        openedr_st = OpenEDRIntegration.get_status()
        info = {
            "hostname": get_hostname(),
            "username": get_username(),
            "os": f"{uname.system} {uname.release}",
            "arch": uname.machine,
            "ram_gb": get_ram_gb(),
            "uptime": get_uptime(),
            "cwd": os.getcwd(),
            "local_ip": get_local_ip(),
            "python_ver": platform.python_version(),
            "is_root": is_root(),
            "defense": {
                "fim_monitored_paths": len(fim_mon.watch_paths),
                "quarantined_files": len(mal_def.list_quarantined()),
                "openedr_running": openedr_st["running"],
            }
        }
        return ("ok", json.dumps(info))
    except Exception as e:
        return ("error", str(e))

def cmd_ls(path: str) -> Tuple[str, str]:
    try:
        p = Path(path or ".")
        items = []
        for entry in sorted(p.iterdir(), key=lambda x: x.name.lower()):
            try:
                stat = entry.stat()
                is_dir = entry.is_dir()
                size = stat.st_size if entry.is_file() else 0
                mtime = datetime.fromtimestamp(stat.st_mtime).isoformat()
            except Exception:
                is_dir = False
                size = 0
                mtime = ""
            items.append({
                "Name": entry.name,
                "Type": "dir" if is_dir else "file",
                "Length": size,
                "LastWriteTime": mtime,
            })
        return ("ok", json.dumps(items))
    except Exception as e:
        return ("error", str(e))

def cmd_cd(path: str) -> Tuple[str, str]:
    try:
        os.chdir(path)
        return ("ok", os.getcwd())
    except Exception as e:
        return ("error", str(e))

def cmd_ps() -> Tuple[str, str]:
    try:
        res = subprocess.run(["ps", "aux", "--no-headers"], capture_output=True, text=True, timeout=10)
        if res.returncode != 0:
            res = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=10)
        procs = []
        for line in res.stdout.strip().split("\n"):
            if not line or line.startswith("USER"):
                continue
            parts = line.split(None, 10)
            if len(parts) >= 11:
                try: cpu = float(parts[2])
                except ValueError: cpu = 0.0
                try: ram = float(parts[3])
                except ValueError: ram = 0.0
                procs.append({
                    "Id": parts[1],
                    "ProcessName": parts[10][:50],
                    "CPU": cpu,
                    "RAM": ram,
                })
        return ("ok", json.dumps(procs))
    except Exception as e:
        return ("error", str(e))

def cmd_kill(pid: str) -> Tuple[str, str]:
    try:
        p_int = int(pid)
        if hasattr(os, "kill"):
            sig = getattr(signal, "SIGKILL", 9)
            os.kill(p_int, sig)
        else:
            subprocess.run(["kill", "-9", pid], check=True, timeout=5)
        return ("ok", f"Process {pid} terminated.")
    except Exception as e:
        return ("error", str(e))

def cmd_download(stream, path: str) -> Tuple[str, str]:
    """Read file with pre-transfer DLP inspection."""
    try:
        if not os.path.isfile(path):
            return ("error", f"File not found: {path}")

        sz = os.path.getsize(path)
        if sz > 35 * 1024 * 1024:
            return ("error", f"File size ({round(sz / (1024*1024), 2)} MB) exceeds single-frame transfer limit of 35 MB.")

        # DLP pre-transfer inspection
        if DLP_ENABLED:
            violations = DLPScanner.scan_file(path)
            if violations:
                send_event(
                    stream, "dlp", "HIGH",
                    "DLP Sensitive Data Transfer Detected",
                    f"File '{path}' flagged with sensitive patterns: " + ", ".join(v["rule"] for v in violations),
                    file_path=path,
                    violations=violations
                )
                if DLP_BLOCK_TRANSFERS:
                    return ("error", f"DLP Block: Exfiltration policy prevented transfer of {path}")

        with open(path, "rb") as f:
            data = f.read()
        return ("ok", base64.b64encode(data).decode())
    except Exception as e:
        return ("error", str(e))

def cmd_upload(stream, path: str, b64_data: str, mal_def: MalwareDefense) -> Tuple[str, str]:
    """Write uploaded file with malware signature & DLP inspection."""
    try:
        content = base64.b64decode(b64_data)
        # Pre-write malware hash scan
        digest = hashlib.sha256(content).hexdigest()
        if digest in mal_def.KNOWN_THREATS:
            threat_name = mal_def.KNOWN_THREATS[digest]
            send_event(
                stream, "malware", "CRITICAL",
                "Malicious Payload Ingress Blocked",
                f"Blocked upload to '{path}' matching threat '{threat_name}'",
                hash=digest, threat=threat_name
            )
            return ("error", f"Malware Block: File matches known threat '{threat_name}'")

        # Write file
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "wb") as f:
            f.write(content)

        # Post-write DLP check
        if DLP_ENABLED:
            violations = DLPScanner.scan_file(path)
            if violations:
                send_event(
                    stream, "dlp", "MEDIUM",
                    "DLP Notice: Uploaded File Contains Sensitive Patterns",
                    f"File '{path}' uploaded with patterns: " + ", ".join(v["rule"] for v in violations),
                    file_path=path,
                    violations=violations
                )

        return ("ok", f"Uploaded {len(content)} bytes to {path}")
    except Exception as e:
        return ("error", str(e))

def cmd_download_chunk(stream, path: str, offset: int = 0, chunk_size: int = 524288) -> Tuple[str, dict]:
    """Read a specific chunk from a file with DLP pre-scan on initial offset."""
    try:
        if not os.path.isfile(path):
            return ("error", {"error": f"File not found: {path}"})

        total_size = os.path.getsize(path)

        # On initial chunk, perform DLP pre-transfer inspection if enabled
        if offset == 0 and DLP_ENABLED:
            violations = DLPScanner.scan_file(path)
            if violations:
                send_event(
                    stream, "dlp", "HIGH",
                    "DLP Sensitive Data Transfer Detected",
                    f"File '{path}' flagged with sensitive patterns: " + ", ".join(v["rule"] for v in violations),
                    file_path=path,
                    violations=violations
                )
                if DLP_BLOCK_TRANSFERS:
                    return ("error", {"error": f"DLP Block: Exfiltration policy prevented transfer of {path}"})

        with open(path, "rb") as f:
            if offset > 0:
                f.seek(offset)
            data = f.read(chunk_size)

        read_len = len(data)
        is_eof = (offset + read_len >= total_size)
        return ("ok", {
            "total_size": total_size,
            "offset": offset,
            "chunk_size": read_len,
            "eof": is_eof,
            "data": base64.b64encode(data).decode(),
            "filename": os.path.basename(path)
        })
    except Exception as e:
        return ("error", {"error": str(e)})

def cmd_upload_chunk(stream, path: str, offset: int, b64_data: str, total_size: int, eof: bool, mal_def: MalwareDefense) -> Tuple[str, dict]:
    """Write an uploaded chunk with malware & DLP inspection upon completion."""
    try:
        content = base64.b64decode(b64_data)
        parent_dir = os.path.dirname(os.path.abspath(path))
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)

        mode = "wb" if offset == 0 else "r+b"
        if not os.path.exists(path) and mode == "r+b":
            mode = "wb"

        with open(path, mode) as f:
            if offset > 0 and mode == "r+b":
                f.seek(offset)
            f.write(content)

        # On EOF, perform post-write security scans
        if eof:
            # Malware hash verification
            hasher = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            digest = hasher.hexdigest().lower()
            if digest in mal_def.KNOWN_THREATS:
                threat_name = mal_def.KNOWN_THREATS[digest]
                try:
                    os.remove(path)
                except Exception:
                    pass
                send_event(
                    stream, "malware", "CRITICAL",
                    "Malicious Payload Ingress Blocked",
                    f"Blocked chunked upload to '{path}' matching threat '{threat_name}'",
                    hash=digest, threat=threat_name
                )
                return ("error", {"error": f"Malware Block: File matches known threat '{threat_name}'"})

            # DLP check
            if DLP_ENABLED:
                violations = DLPScanner.scan_file(path)
                if violations:
                    send_event(
                        stream, "dlp", "MEDIUM",
                        "DLP Notice: Uploaded File Contains Sensitive Patterns",
                        f"File '{path}' uploaded with patterns: " + ", ".join(v["rule"] for v in violations),
                        file_path=path,
                        violations=violations
                    )

        return ("ok", {
            "bytes_written": len(content),
            "offset": offset,
            "eof": eof,
            "output": f"Chunk at {offset} written ({len(content)} bytes)"
        })
    except Exception as e:
        return ("error", {"error": str(e)})

def cmd_attest(nonce: str, script_path: str) -> Tuple[str, str]:
    """Cryptographic code attestation: hashes self script and signs with server nonce."""
    try:
        with open(script_path, "rb") as f:
            code_bytes = f.read()
        raw_hash = hashlib.sha256(code_bytes).hexdigest()
        attest_hmac = hmac.new(nonce.encode("utf-8"), code_bytes, hashlib.sha256).hexdigest()
        info = {
            "path": script_path,
            "raw_sha256": raw_hash,
            "attest_hmac": attest_hmac,
            "bytes_len": len(code_bytes),
            "pid": os.getpid(),
        }
        return ("ok", json.dumps(info))
    except Exception as e:
        return ("error", str(e))

def harden_agent_files(vault_dir: Optional[str] = None):
    """Restricts file permissions on agent script and quarantine directory."""
    try:
        import sys
        self_path = os.path.abspath(sys.argv[0])
        if is_root():
            os.chmod(self_path, 0o700)
        if vault_dir and os.path.exists(vault_dir):
            os.chmod(vault_dir, 0o700)
    except Exception:
        pass
