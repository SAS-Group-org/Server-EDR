import json
import os
import shutil
import socket
import subprocess
import time
from typing import List, Tuple

from .common import OPENEDR_LOG_PATH, SERVER_HOST, SERVER_PORT, is_root

class OpenEDRIntegration:
    """Interfaces with OpenEDR Linux service and provides host isolation."""

    @staticmethod
    def get_status() -> dict:
        """Check OpenEDR service, eBPF/auditd presence, and log file status."""
        status = {
            "installed": False,
            "running": False,
            "service_name": "openedr / edrsvc",
            "log_path": OPENEDR_LOG_PATH,
            "log_exists": os.path.exists(OPENEDR_LOG_PATH),
            "log_size_bytes": os.path.getsize(OPENEDR_LOG_PATH) if os.path.exists(OPENEDR_LOG_PATH) else 0,
        }

        # Check systemctl service
        try:
            res = subprocess.run(
                ["systemctl", "is-active", "edrsvc"],
                capture_output=True, text=True, timeout=3
            )
            if res.returncode == 0 and "active" in res.stdout:
                status["installed"] = True
                status["running"] = True
        except Exception:
            pass

        # Check process table for edrsvc
        if not status["running"]:
            try:
                res = subprocess.run(["pgrep", "-f", "edrsvc"], capture_output=True, text=True)
                if res.stdout.strip():
                    status["installed"] = True
                    status["running"] = True
            except Exception:
                pass

        return status

    @staticmethod
    def fetch_recent_events(max_lines: int = 50) -> List[dict]:
        """Read and parse recent OpenEDR event lines."""
        if not os.path.exists(OPENEDR_LOG_PATH):
            return []
        events = []
        try:
            with open(OPENEDR_LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[-max_lines:]
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except Exception:
                    events.append({"raw": line})
        except Exception:
            pass
        return events

    @staticmethod
    def isolate_host(enable: bool) -> Tuple[str, str]:
        """Apply emergency host isolation firewall rules, preserving C2 port."""
        if not is_root():
            return ("error", "Host isolation requires root privileges")

        resolved_host = SERVER_HOST
        try:
            resolved_host = socket.gethostbyname(SERVER_HOST)
        except Exception:
            pass

        if enable:
            # Block traffic except loopback and Server C2 port
            cmds = [
                "iptables -F",
                "iptables -A INPUT -i lo -j ACCEPT",
                "iptables -A OUTPUT -o lo -j ACCEPT",
                f"iptables -A OUTPUT -p tcp --dport {SERVER_PORT} -d {resolved_host} -j ACCEPT",
                f"iptables -A INPUT -p tcp --sport {SERVER_PORT} -s {resolved_host} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --sport {SERVER_PORT} -s {resolved_host} -m state --state ESTABLISHED -j ACCEPT",
                "iptables -P INPUT DROP",
                "iptables -P FORWARD DROP",
                "iptables -P OUTPUT DROP",
            ]
            try:
                for cmd in cmds:
                    subprocess.run(cmd, shell=True, check=True)
                return ("ok", f"Host successfully ISOLATED. Only C2 connection to {resolved_host}:{SERVER_PORT} permitted.")
            except Exception as e:
                return ("error", f"Isolation failed: {e}")
        else:
            # Restore open policy
            restore_cmds = [
                "iptables -P INPUT ACCEPT",
                "iptables -P FORWARD ACCEPT",
                "iptables -P OUTPUT ACCEPT",
                "iptables -F",
            ]
            try:
                for cmd in restore_cmds:
                    subprocess.run(cmd, shell=True, check=True)
                return ("ok", "Host isolation REMOVED. Standard network routing restored.")
            except Exception as e:
                return ("error", f"Un-isolation failed: {e}")

    @classmethod
    def install_openedr(cls) -> Tuple[str, str]:
        """Ensures OpenEDR, auditd, and security defense dependencies are installed and active."""
        if not is_root():
            return ("error", "Root privileges required to install OpenEDR and endpoint dependencies.")

        results = []
        log_dir = os.path.dirname(OPENEDR_LOG_PATH)
        try:
            os.makedirs(log_dir, exist_ok=True)
            results.append(f"Ensured telemetry directory exists: {log_dir}")
        except Exception as e:
            results.append(f"Directory creation notice: {e}")

        # Package manager installation
        pkg_mgr = None
        if shutil.which("apt-get"):
            pkg_mgr = "apt-get"
        elif shutil.which("dnf"):
            pkg_mgr = "dnf"
        elif shutil.which("yum"):
            pkg_mgr = "yum"

        if pkg_mgr == "apt-get":
            try:
                env = os.environ.copy()
                env["DEBIAN_FRONTEND"] = "noninteractive"
                subprocess.run(["apt-get", "update", "-qq"], env=env, timeout=60, capture_output=True)
                res = subprocess.run(
                    ["apt-get", "install", "-y", "-qq", "auditd", "iptables", "clamav", "curl"],
                    env=env, timeout=120, capture_output=True, text=True
                )
                if res.returncode == 0:
                    results.append("Installed security dependencies via apt (auditd, iptables, clamav, curl)")
                else:
                    results.append(f"Apt notice: {res.stderr[:160]}")
            except Exception as e:
                results.append(f"Apt installation notice: {e}")
        elif pkg_mgr in ("dnf", "yum"):
            try:
                res = subprocess.run(
                    [pkg_mgr, "install", "-y", "-q", "audit", "iptables", "clamav", "curl"],
                    timeout=120, capture_output=True, text=True
                )
                if res.returncode == 0:
                    results.append(f"Installed security dependencies via {pkg_mgr} (audit, iptables, clamav, curl)")
                else:
                    results.append(f"{pkg_mgr} notice: {res.stderr[:160]}")
            except Exception as e:
                results.append(f"{pkg_mgr} installation notice: {e}")
        else:
            results.append("No supported package manager detected (apt-get, dnf, yum)")

        # Enable & start audit/edr service
        for svc in ("edrsvc", "auditd"):
            try:
                res = subprocess.run(["systemctl", "enable", "--now", svc], capture_output=True, timeout=10)
                if res.returncode == 0:
                    results.append(f"Service '{svc}' enabled and active.")
            except Exception:
                pass

        # Initialize telemetry log file with restricted permissions
        if not os.path.exists(OPENEDR_LOG_PATH):
            try:
                with open(OPENEDR_LOG_PATH, "a", encoding="utf-8") as f:
                    f.write(json.dumps({
                        "event_type": "INITIALIZATION",
                        "timestamp": time.time(),
                        "message": "OpenEDR Telemetry Sensor Initialized"
                    }) + "\n")
                os.chmod(OPENEDR_LOG_PATH, 0o600)
                results.append(f"Created telemetry log file at {OPENEDR_LOG_PATH}")
            except Exception as e:
                results.append(f"Log file initialization notice: {e}")

        st = cls.get_status()
        if st.get("running"):
            results.append("OpenEDR/Telemetry service is ACTIVE.")
            return ("ok", "\n".join(results))
        else:
            results.append("Dependencies and telemetry channels configured.")
            return ("ok", "\n".join(results))
