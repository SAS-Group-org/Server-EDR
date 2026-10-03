#!/usr/bin/env python3
"""
package_linux_agent.py - Package Builder for Server-EDR Linux Agent

Bundles the Linux agent runtime, modules, service scripts, templates,
and optional injected configuration into a deployable .tar.gz archive.
Can be used via CLI or imported programmatically by the Server GUI
or CI/CD validation pipelines.
"""

import os
import sys
import json
import tarfile
import argparse
import tempfile
import hashlib
from typing import Dict, Any, Optional, List

# Default paths relative to this script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUTPUT_NAME = "server-edr-agent-linux.tar.gz"

REQUIRED_FILES = [
    "agent_core.py",
    "install_agent.sh",
    "install_service.sh",
    "agent_config.template.json",
]

REQUIRED_DIRS = [
    "modules",
    "systemd",
]


def generate_package_manifest(file_list: List[str], base_dir: str) -> Dict[str, str]:
    """Computes SHA-256 checksums for files included in the package."""
    manifest = {}
    for rel_path in sorted(file_list):
        full_path = os.path.join(base_dir, rel_path)
        if os.path.isfile(full_path):
            h = hashlib.sha256()
            with open(full_path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            manifest[rel_path.replace("\\", "/")] = h.hexdigest()
    return manifest


def build_linux_package(
    output_path: str,
    config_data: Optional[Dict[str, Any]] = None,
    config_file: Optional[str] = None,
    source_dir: Optional[str] = None,
    include_manifest: bool = True,
    archive_prefix: str = "server-edr-agent"
) -> str:
    """
    Builds a tar.gz package containing the Linux agent files.

    Args:
        output_path: Target .tar.gz file path.
        config_data: Optional dictionary representing agent_config.json to inject.
        config_file: Optional path to an existing agent_config.json to inject.
        source_dir: Directory containing agent files (defaults to SCRIPT_DIR).
        include_manifest: Whether to include MANIFEST.json in the archive.
        archive_prefix: Root directory prefix inside the archive (empty for flat).

    Returns:
        Absolute path to the created .tar.gz archive.
    """
    source_dir = os.path.abspath(source_dir or SCRIPT_DIR)
    output_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Validate source files exist
    for req_file in REQUIRED_FILES:
        path = os.path.join(source_dir, req_file)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Required package file not found: {path}")

    for req_dir in REQUIRED_DIRS:
        path = os.path.join(source_dir, req_dir)
        if not os.path.isdir(path):
            raise FileNotFoundError(f"Required package directory not found: {path}")

    # Gather files to package
    files_to_pack: List[tuple[str, str, int]] = []  # (disk_path, arcname, mode)

    # 1. Base files
    for f in REQUIRED_FILES:
        disk_path = os.path.join(source_dir, f)
        arcname = os.path.join(archive_prefix, f) if archive_prefix else f
        mode = 0o755 if f.endswith(".sh") or f == "agent_core.py" else 0o644
        files_to_pack.append((disk_path, arcname, mode))

    # 2. Directory contents
    for d in REQUIRED_DIRS:
        dir_disk_path = os.path.join(source_dir, d)
        for root, _, files in os.walk(dir_disk_path):
            for file in files:
                if file.endswith(".pyc") or "__pycache__" in root:
                    continue
                disk_path = os.path.join(root, file)
                rel_to_source = os.path.relpath(disk_path, source_dir)
                arcname = os.path.join(archive_prefix, rel_to_source) if archive_prefix else rel_to_source
                mode = 0o755 if file.endswith(".sh") else 0o644
                files_to_pack.append((disk_path, arcname, mode))

    # Handle temporary injected config & manifest
    with tempfile.TemporaryDirectory() as temp_dir:
        # Injected agent_config.json
        final_config_data = None
        if config_file:
            with open(config_file, "r", encoding="utf-8") as f:
                final_config_data = json.load(f)
        elif config_data:
            final_config_data = config_data

        if final_config_data:
            temp_config_path = os.path.join(temp_dir, "agent_config.json")
            with open(temp_config_path, "w", encoding="utf-8") as f:
                json.dump(final_config_data, f, indent=2)
            arcname = os.path.join(archive_prefix, "agent_config.json") if archive_prefix else "agent_config.json"
            files_to_pack.append((temp_config_path, arcname, 0o600))

        # Generate manifest if requested
        if include_manifest:
            manifest_dict = {}
            for disk_path, arcname, _ in files_to_pack:
                h = hashlib.sha256()
                with open(disk_path, "rb") as f:
                    while chunk := f.read(65536):
                        h.update(chunk)
                manifest_dict[arcname.replace("\\", "/")] = h.hexdigest()

            temp_manifest_path = os.path.join(temp_dir, "MANIFEST.json")
            with open(temp_manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest_dict, f, indent=2)
            arcname = os.path.join(archive_prefix, "MANIFEST.json") if archive_prefix else "MANIFEST.json"
            files_to_pack.append((temp_manifest_path, arcname, 0o644))

        # Build tar.gz
        with tarfile.open(output_path, "w:gz") as tar:
            for disk_path, arcname, mode in files_to_pack:
                normalized_arcname = arcname.replace("\\", "/")
                tarinfo = tar.gettarinfo(disk_path, arcname=normalized_arcname)
                tarinfo.mode = mode
                tarinfo.uid = 0
                tarinfo.gid = 0
                tarinfo.uname = "root"
                tarinfo.gname = "root"
                with open(disk_path, "rb") as f:
                    tar.addfile(tarinfo, f)

    return output_path


def main():
    parser = argparse.ArgumentParser(description="Package builder for Server-EDR Linux Agent")
    parser.add_argument("-o", "--output", help="Output path for .tar.gz archive", default=DEFAULT_OUTPUT_NAME)
    parser.add_argument("-c", "--config", help="Path to custom agent_config.json to inject", default=None)
    parser.add_argument("--server-host", help="Server host IP/domain to embed in config", default=None)
    parser.add_argument("--server-port", help="Server port to embed in config", type=int, default=None)
    parser.add_argument("--psk", help="Pre-shared key to embed in config", default=None)
    parser.add_argument("--cert-fingerprint", help="Server TLS SHA-256 fingerprint", default=None)
    parser.add_argument("--no-tls", help="Disable TLS encryption in embedded config", action="store_true")
    parser.add_argument("--dry-run", help="List files to be packaged without writing archive", action="store_true")
    parser.add_argument("--source-dir", help="Source directory containing agent files", default=SCRIPT_DIR)

    args = parser.parse_args()

    # Build config data if individual parameters given
    config_data = None
    if any([args.server_host, args.server_port, args.psk, args.cert_fingerprint, args.no_tls]):
        config_data = {
            "server": {
                "host": args.server_host or "127.0.0.1",
                "port": args.server_port or 4444,
                "use_tls": not args.no_tls,
                "cert_fingerprint": args.cert_fingerprint or "",
                "reconnect_interval": 5,
                "max_reconnect_delay": 60
            },
            "auth": {
                "psk": args.psk or ""
            },
            "agent": {
                "log_level": "INFO",
                "watchdog_enabled": True,
                "watchdog_interval": 3,
                "heartbeat_interval": 10
            }
        }

    if args.dry_run:
        print("[*] Dry run - listing package contents:")
        for rf in REQUIRED_FILES:
            print(f"  + {rf}")
        for rd in REQUIRED_DIRS:
            dp = os.path.join(args.source_dir, rd)
            for root, _, files in os.walk(dp):
                for f in files:
                    if not f.endswith(".pyc") and "__pycache__" not in root:
                        print(f"  + {os.path.relpath(os.path.join(root, f), args.source_dir)}")
        if args.config or config_data:
            print("  + agent_config.json (injected)")
        print("  + MANIFEST.json")
        return 0

    print(f"[*] Packaging Linux Agent to {args.output}...")
    try:
        pkg_path = build_linux_package(
            output_path=args.output,
            config_data=config_data,
            config_file=args.config,
            source_dir=args.source_dir
        )
        size_bytes = os.path.getsize(pkg_path)
        print(f"[+] Package created successfully: {pkg_path} ({size_bytes:,} bytes)")
        return 0
    except Exception as e:
        print(f"[-] Packaging failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
