#!/usr/bin/env python3
"""
Secure Endpoint Detection, Response & Defense Agent — Linux/Python version (Modular)
"""

import json
import os
import platform
import queue
import signal
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from modules import (
    SERVER_HOST, SERVER_PORT, PSK, CERT_FINGERPRINT, USE_TLS, RECONNECT_SECS,
    FIM_ENABLED, FIM_CHECK_INTERVAL_SECS, AUTO_INSTALL_OPENEDR,
    send_msg, recv_msg, send_event, authenticate, get_secure_stream,
    get_hostname, get_username, get_local_ip, is_root,
    FIMMonitor, USBMonitor, MalwareDefense, OpenEDRIntegration,
    cmd_shell, cmd_sysinfo, cmd_ls, cmd_cd, cmd_ps, cmd_kill,
    cmd_download, cmd_upload, cmd_download_chunk, cmd_upload_chunk,
    cmd_attest, harden_agent_files
)

def background_defense_worker(stream, fim_mon: FIMMonitor, mal_def: MalwareDefense, stop_event: threading.Event):
    """Periodically checks FIM, scans running processes, checks USB insertion, and guards EDR service."""
    usb_mon = USBMonitor()
    last_fim_check = time.time()
    last_proc_check = time.time()
    last_edr_check = time.time()
    edr_initial_status = OpenEDRIntegration.get_status().get("running", False)

    while not stop_event.is_set():
        try:
            now = time.time()

            # 1. Periodic FIM integrity check
            if FIM_ENABLED and (now - last_fim_check >= FIM_CHECK_INTERVAL_SECS):
                last_fim_check = now
                changes = fim_mon.check()
                for c in changes:
                    subsystem = "tamper" if c.get("tamper") else "fim"
                    title = f"🚨 ANTI-TAMPER: {c['action']} on Agent File!" if c.get("tamper") else f"FIM {c['action']}: {c['path']}"
                    send_event(
                        stream, subsystem, c["severity"],
                        title,
                        c["details"],
                        action=c["action"],
                        path=c["path"],
                        old_hash=c.get("old_hash"),
                        new_hash=c.get("new_hash"),
                        tamper=c.get("tamper", False)
                    )

            # 2. Heuristic check on suspicious processes (every 45s)
            if now - last_proc_check >= 45:
                last_proc_check = now
                proc_alerts = mal_def.scan_running_processes()
                for a in proc_alerts:
                    send_event(
                        stream, "malware", a["severity"],
                        f"Suspicious Process: {a['threat']}",
                        f"PID {a['pid']} executing: {a['path']}",
                        pid=a["pid"],
                        path=a["path"],
                        threat=a["threat"]
                    )

            # 3. Removable USB media monitoring
            new_mounts = usb_mon.check_new_mounts()
            for dev, target, fstype in new_mounts:
                send_event(
                    stream, "dlp", "MEDIUM",
                    "DLP: Removable Storage Attached",
                    f"Device '{dev}' mounted at '{target}' (type: {fstype})",
                    device=dev, mountpoint=target, fstype=fstype
                )

            # 4. OpenEDR service & driver impairment check (every 30s)
            if now - last_edr_check >= 30:
                last_edr_check = now
                cur_edr = OpenEDRIntegration.get_status().get("running", False)
                if edr_initial_status and not cur_edr:
                    send_event(
                        stream, "tamper", "CRITICAL",
                        "OpenEDR Service Impairment Detected",
                        "The OpenEDR security service (edrsvc) was active at sensor launch but has stopped unexpectedly or was terminated.",
                        subsystem="openedr", status="stopped"
                    )
                    edr_initial_status = False
                elif not edr_initial_status and cur_edr:
                    edr_initial_status = True

        except Exception:
            pass

        # Sleep briefly
        stop_event.wait(5.0)


def execute_command_task(cmd, mid, msg, stream, fim_mon, mal_def, response_queue):
    """Executes a command and puts the result in the response queue."""
    resp = {"type": "response", "id": mid, "status": "ok", "output": ""}
    
    try:
        # ── Core Administrative Commands ──
        if cmd == "shell":
            resp["status"], resp["output"] = cmd_shell(msg.get("args", ""))
        elif cmd == "sysinfo":
            resp["status"], resp["output"] = cmd_sysinfo(fim_mon, mal_def)
        elif cmd == "ls":
            resp["status"], resp["output"] = cmd_ls(msg.get("args", ""))
        elif cmd == "cd":
            resp["status"], resp["output"] = cmd_cd(msg.get("args", ""))
        elif cmd == "ps":
            resp["status"], resp["output"] = cmd_ps()
        elif cmd == "kill":
            resp["status"], resp["output"] = cmd_kill(msg.get("args", ""))
        elif cmd == "download":
            resp["status"], resp["output"] = cmd_download(stream, msg.get("args", ""))
        elif cmd == "download_chunk":
            path = msg.get("path") or msg.get("args") or ""
            offset = int(msg.get("offset", 0))
            chunk_size = int(msg.get("chunk_size", 524288))
            st, chunk_info = cmd_download_chunk(stream, path, offset, chunk_size)
            resp["status"] = st
            if st == "ok":
                resp.update(chunk_info)
            else:
                resp["output"] = chunk_info.get("error", "Download chunk failed")
        elif cmd == "upload":
            resp["status"], resp["output"] = cmd_upload(
                stream, msg.get("path", ""), msg.get("data", ""), mal_def
            )
        elif cmd == "upload_chunk":
            path = msg.get("path") or ""
            offset = int(msg.get("offset", 0))
            b64_data = msg.get("data", "")
            total_size = int(msg.get("total_size", 0))
            eof = bool(msg.get("eof", False))
            st, res_info = cmd_upload_chunk(stream, path, offset, b64_data, total_size, eof, mal_def)
            resp["status"] = st
            if st == "ok":
                resp.update(res_info)
            else:
                resp["output"] = res_info.get("error", "Upload chunk failed")
        elif cmd == "ping":
            resp["output"] = "pong"

        # ── Defense: Malware Prevention & Quarantine ──
        elif cmd == "malware_scan":
            target = msg.get("args", ".")
            findings = mal_def.scan_path(target)
            resp["output"] = json.dumps(findings)
        elif cmd == "quarantine":
            target = msg.get("args", "")
            q_res = mal_def.quarantine(target)
            resp["status"] = q_res.get("status", "error")
            resp["output"] = json.dumps(q_res)
        elif cmd == "quarantine_list":
            resp["output"] = json.dumps(mal_def.list_quarantined())
        elif cmd == "quarantine_restore":
            q_res = mal_def.restore_quarantined(msg.get("args", ""))
            resp["status"] = q_res.get("status", "error")
            resp["output"] = json.dumps(q_res)

        # ── Defense: File Integrity Monitoring (FIM) ──
        elif cmd == "fim_init":
            fim_mon.init_baseline()
            resp["output"] = f"Baseline initialized for {len(fim_mon.baseline)} monitored files."
        elif cmd == "fim_check":
            changes = fim_mon.check()
            resp["output"] = json.dumps(changes)
        elif cmd == "fim_add_path":
            fim_mon.add_path(msg.get("args", ""))
            resp["output"] = f"Added '{msg.get('args')}' to FIM scope. Baseline updated."

        # ── Defense: Data Loss Prevention (DLP) ──
        elif cmd == "dlp_scan":
            from modules.dlp import DLPScanner
            target = msg.get("args", "")
            violations = DLPScanner.scan_file(target) if os.path.isfile(target) else DLPScanner.scan_text(target)
            resp["output"] = json.dumps(violations)

        # ── Defense: OpenEDR & Host Containment ──
        elif cmd == "openedr_status":
            resp["output"] = json.dumps(OpenEDRIntegration.get_status())
        elif cmd == "openedr_fetch_telemetry":
            events = OpenEDRIntegration.fetch_recent_events(50)
            resp["output"] = json.dumps(events)
        elif cmd == "isolate_host":
            enable = str(msg.get("args", "true")).lower() in ("true", "1", "yes")
            resp["status"], resp["output"] = OpenEDRIntegration.isolate_host(enable)
        elif cmd == "install_openedr":
            resp["status"], resp["output"] = OpenEDRIntegration.install_openedr()

        # ── Anti-Tamper: Cryptographic Attestation ──
        elif cmd == "attest":
            script_path = os.path.abspath(__file__)
            resp["status"], resp["output"] = cmd_attest(msg.get("args", ""), script_path)

        else:
            resp["status"] = "error"
            resp["output"] = f"Unknown command: {cmd}"
            
    except Exception as e:
        resp["status"] = "error"
        resp["output"] = f"Task execution failed: {e}"

    response_queue.put(resp)


def main():
    print("[*] Python EDR & Endpoint Defense Agent starting...")
    print(f"[*] Target: {SERVER_HOST}:{SERVER_PORT}")
    print(f"[*] TLS: {'enabled' if USE_TLS else 'DISABLED'}")
    if CERT_FINGERPRINT:
        print(f"[*] Cert pinning: {CERT_FINGERPRINT[:16]}...")

    fim_mon = FIMMonitor()
    mal_def = MalwareDefense()

    # Harden filesystem permissions on agent script & quarantine vault
    harden_agent_files(mal_def.vault_dir)

    # Dying-gasp handler: attempt to send an alert before being killed
    _dying_gasp_stream = None  # will be set when connected

    def _dying_gasp(signum, frame):
        """Send emergency tamper alert on external termination signal."""
        sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
        print(f"\n[!] DYING GASP: Received {sig_name} (PID {os.getpid()}) — attempting final alert")
        s = _dying_gasp_stream
        if s is not None:
            try:
                send_event(
                    s, "tamper", "CRITICAL",
                    f"🚨 ANTI-TAMPER: Agent received {sig_name}",
                    f"Agent process (PID {os.getpid()}) received external termination signal {sig_name}. "
                    f"This may indicate adversary kill of the defense sensor.",
                    signal=sig_name, pid=os.getpid()
                )
            except Exception:
                pass
        sys.exit(128 + signum)

    _sigs = [signal.SIGTERM]
    if hasattr(signal, "SIGHUP"):
        _sigs.append(signal.SIGHUP)
    for _sig in _sigs:
        try:
            signal.signal(_sig, _dying_gasp)
        except (OSError, ValueError):
            pass

    # Auto-install OpenEDR if configured and missing
    if AUTO_INSTALL_OPENEDR:
        if not OpenEDRIntegration.get_status().get("installed"):
            print("[*] OpenEDR missing and AUTO_INSTALL_OPENEDR enabled — installing dependencies...")
            st, out = OpenEDRIntegration.install_openedr()
            print(f"[*] OpenEDR install status ({st}):\n{out}")

    executor = ThreadPoolExecutor(max_workers=4)
    response_queue = queue.Queue()

    while True:
        sock = None
        stream = None
        stop_bg = threading.Event()
        bg_thread = None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            sock.connect((SERVER_HOST, SERVER_PORT))

            stream = get_secure_stream(sock)
            stream.settimeout(15)

            authenticate(stream, PSK)
            stream.settimeout(0.5)  # Short timeout for non-blocking poll

            uname = platform.uname()
            reg = {
                "type": "register",
                "hostname": get_hostname(),
                "username": get_username(),
                "os": f"{uname.system} {uname.release}",
                "arch": uname.machine,
                "ip": get_local_ip(),
                "python_ver": platform.python_version(),
                "is_root": is_root(),
                "defense_capabilities": ["malware_prevention", "fim", "dlp", "openedr"],
            }
            send_msg(stream, reg)
            print("[+] Connected and authenticated as Endpoint Defense Sensor")
            _dying_gasp_stream = stream  # enable dying-gasp alerting

            # Launch background defense monitors
            bg_thread = threading.Thread(
                target=background_defense_worker,
                args=(stream, fim_mon, mal_def, stop_bg),
                daemon=True,
                name="defense-monitor"
            )
            bg_thread.start()

            # Command loop
            while True:
                # 1. Drain response queue
                while not response_queue.empty():
                    resp = response_queue.get_nowait()
                    try:
                        send_msg(stream, resp)
                    except Exception as e:
                        print(f"[!] Failed to send response: {e}")
                
                # 2. Poll for incoming messages
                try:
                    msg = recv_msg(stream)
                    cmd = msg.get("command")
                    mid = msg.get("id", "")
                    
                    if cmd:
                        executor.submit(execute_command_task, cmd, mid, msg, stream, fim_mon, mal_def, response_queue)
                        
                except socket.timeout:
                    # Expected timeout, just continue loop
                    continue

        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            break
        except Exception as e:
            if not isinstance(e, socket.timeout):
                print(f"[!] Connection error: {e}")
        finally:
            _dying_gasp_stream = None  # disable dying-gasp before cleanup
            stop_bg.set()
            if stream:
                try:
                    stream.close()
                except Exception:
                    pass
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        print(f"[*] Reconnecting in {RECONNECT_SECS} seconds...")
        time.sleep(RECONNECT_SECS)


def _watchdog_supervisor():
    """Supervisor process that auto-respawns the worker agent if killed."""
    import argparse
    parser = argparse.ArgumentParser(description="Endpoint Defense Agent")
    parser.add_argument("--no-watchdog", action="store_true",
                        help="Run agent directly without supervisor (for debugging)")
    parser.add_argument("--install-openedr", "--install-deps", action="store_true", dest="install_deps",
                        help="Install and configure OpenEDR and endpoint security dependencies")
    args = parser.parse_args()

    if args.install_deps:
        print("[*] Installing and verifying OpenEDR and security dependencies...")
        status, output = OpenEDRIntegration.install_openedr()
        print(f"[*] Result ({status}):\n{output}")
        return

    if args.no_watchdog:
        main()
        return

    print("[*] WATCHDOG: Supervisor mode active (PID %d)" % os.getpid())
    python_exe = sys.executable
    script_path = os.path.abspath(__file__)

    active_proc = None

    def _sigterm_handler(signum, frame):
        nonlocal active_proc
        print("\n[*] WATCHDOG: Supervisor received termination signal. Stopping worker...")
        if active_proc:
            try:
                active_proc.terminate()
                active_proc.wait(timeout=5)
            except Exception:
                try:
                    active_proc.kill()
                except Exception:
                    pass
        sys.exit(0)

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _sigterm_handler)

    while True:
        cmd = [python_exe, script_path, "--no-watchdog"]
        try:
            active_proc = subprocess.Popen(cmd)
            exit_code = active_proc.wait()
        except KeyboardInterrupt:
            print("\n[!] WATCHDOG: Supervisor interrupted by operator")
            if active_proc:
                try:
                    active_proc.terminate()
                    active_proc.wait(timeout=5)
                except Exception:
                    pass
            break

        if exit_code == 0:
            print("[*] WATCHDOG: Worker exited cleanly (code 0). Stopping supervisor.")
            break

        # Non-zero exit = likely killed externally — respawn
        print(f"[!] WATCHDOG: Worker exited with code {exit_code} — respawning in 3 seconds")
        print(f"[!] WATCHDOG: Possible adversary kill or crash detected")
        time.sleep(3)


if __name__ == "__main__":
    _watchdog_supervisor()
