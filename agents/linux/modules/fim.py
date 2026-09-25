import hashlib
import os
import sys
from typing import Dict, List, Optional

class FIMMonitor:
    """Manages file integrity baselines and change detection."""

    DEFAULT_WATCH_PATHS = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/hosts",
        "/etc/crontab",
        "/etc/pam.d",
    ]

    def __init__(self, watch_paths: Optional[List[str]] = None, self_protect: bool = True):
        self.watch_paths = list(watch_paths or self.DEFAULT_WATCH_PATHS)
        self.self_protect_paths = set()
        if self_protect:
            try:
                # Need to resolve the actual agent_core.py, but __file__ here is fim.py
                # Let's add the directory as a fallback, or expect the main script to add itself
                agent_core_path = os.path.abspath(sys.argv[0])
                if agent_core_path not in self.watch_paths:
                    self.watch_paths.append(agent_core_path)
                self.self_protect_paths.add(agent_core_path)
            except Exception:
                pass
        self.baseline: Dict[str, dict] = {}
        self.init_baseline()

    @staticmethod
    def hash_file(path: str) -> str:
        hasher = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""

    def init_baseline(self):
        self.baseline = {}
        for p in self.watch_paths:
            if os.path.isfile(p):
                try:
                    stat = os.stat(p)
                    self.baseline[p] = {
                        "hash": self.hash_file(p),
                        "size": stat.st_size,
                        "mtime": stat.st_mtime,
                        "mode": oct(stat.st_mode),
                    }
                except Exception:
                    pass
            elif os.path.isdir(p):
                for root, _, files in os.walk(p):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        try:
                            stat = os.stat(fpath)
                            self.baseline[fpath] = {
                                "hash": self.hash_file(fpath),
                                "size": stat.st_size,
                                "mtime": stat.st_mtime,
                                "mode": oct(stat.st_mode),
                            }
                        except Exception:
                            continue

    def add_path(self, path: str):
        if path not in self.watch_paths:
            self.watch_paths.append(path)
            self.init_baseline()

    def check(self) -> List[dict]:
        changes = []
        try:
            self_script = os.path.abspath(sys.argv[0])
        except Exception:
            self_script = ""

        # 1. Check for modifications and deletions of existing baseline files
        for path, meta in list(self.baseline.items()):
            is_self = (path in self.self_protect_paths) or (bool(self_script) and path == self_script)
            if not os.path.exists(path):
                changes.append({
                    "action": "DELETED",
                    "path": path,
                    "severity": "CRITICAL" if is_self else "HIGH",
                    "details": "🚨 ANTI-TAMPER: Agent binary or script was deleted from disk!" if is_self else "Monitored file was removed",
                    "old_hash": meta.get("hash", ""),
                    "tamper": is_self,
                })
                # Remove from baseline so the alert is emitted once, not spammed indefinitely
                self.baseline.pop(path, None)
            else:
                cur_hash = self.hash_file(path)
                if cur_hash and cur_hash != meta.get("hash"):
                    changes.append({
                        "action": "MODIFIED",
                        "path": path,
                        "severity": "CRITICAL",
                        "details": "🚨 ANTI-TAMPER: Agent script modified on disk (SHA-256 mismatch)!" if is_self else "File content / SHA-256 altered",
                        "old_hash": meta.get("hash", ""),
                        "new_hash": cur_hash,
                        "tamper": is_self,
                    })
                    # Update baseline to prevent repeat spam
                    meta["hash"] = cur_hash

        # 2. Check for newly added files in monitored directories
        for p in self.watch_paths:
            if os.path.isdir(p):
                for root, _, files in os.walk(p):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        if fpath not in self.baseline:
                            new_hash = self.hash_file(fpath)
                            try:
                                stat = os.stat(fpath)
                                size = stat.st_size
                                mtime = stat.st_mtime
                                mode = oct(stat.st_mode)
                            except Exception:
                                size, mtime, mode = 0, 0, ""
                            self.baseline[fpath] = {
                                "hash": new_hash,
                                "size": size,
                                "mtime": mtime,
                                "mode": mode,
                            }
                            changes.append({
                                "action": "ADDED",
                                "path": fpath,
                                "severity": "MEDIUM",
                                "details": "New file created in monitored directory",
                                "new_hash": new_hash,
                                "tamper": False,
                            })
        return changes
