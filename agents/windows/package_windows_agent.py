#!/usr/bin/env python3
"""
package_windows_agent.py - Package Builder for Server-EDR Windows Agent

Bundles the Windows agent PowerShell scripts, modules, service wrappers,
templates, and optional injected configuration into a deployable .zip archive.
Can be used via CLI or imported programmatically by the Server GUI
or CI/CD validation pipelines.
"""

import os
import sys
import json
import zipfile
import argparse
import tempfile
import hashlib
from typing import Dict, Any, Optional, List

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUTPUT_NAME = "Server-EDR-Agent-Windows-v1.0.0.zip"

REQUIRED_FILES = [
    "Agent-Core.ps1",
    "agent_config.json.template",
    "README.md",
    "build-agent-package.ps1",
]

REQUIRED_MODULES = [
    "Common.psm1",
    "FIM.psm1",
    "DLP.psm1",
    "Malware.psm1",
    "OpenEDR.psm1",
    "Executor.psm1",
]

REQUIRED_SERVICES = [
    "ServiceWrapper.ps1",
    "Install-Service.ps1",
    "Uninstall-Service.ps1",
]


def build_windows_package(
    output_path: str,
    config_data: Optional[Dict[str, Any]] = None,
    config_file: Optional[str] = None,
    source_dir: Optional[str] = None,
    version: str = "1.0.0",
    package_type: str = "Full",
    include_manifest: bool = True
) -> str:
    """
    Builds a .zip package containing the Windows agent files.

    Args:
        output_path: Target .zip file path.
        config_data: Optional dict representing agent_config.json to inject.
        config_file: Optional path to an existing agent_config.json to inject.
        source_dir: Directory containing Windows agent files.
        version: Package version string.
        package_type: "Full", "Minimal", or "Service".
        include_manifest: Whether to include MANIFEST.json and checksums.sha256.

    Returns:
        Absolute path to the created .zip archive.
    """
    source_dir = os.path.abspath(source_dir or SCRIPT_DIR)
    output_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    archive_prefix = f"Server-EDR-Agent-Windows-v{version}"

    files_to_pack: List[tuple[str, str]] = []  # (disk_path, arcname)

    # 1. Core script
    if package_type in ("Full", "Minimal"):
        core_path = os.path.join(source_dir, "Agent-Core.ps1")
        if not os.path.isfile(core_path):
            raise FileNotFoundError(f"Missing core script: {core_path}")
        files_to_pack.append((core_path, f"{archive_prefix}/Agent-Core.ps1"))

        # Modules
        mod_dir = os.path.join(source_dir, "Modules")
        for m in REQUIRED_MODULES:
            mp = os.path.join(mod_dir, m)
            if not os.path.isfile(mp):
                raise FileNotFoundError(f"Missing module: {mp}")
            files_to_pack.append((mp, f"{archive_prefix}/Modules/{m}"))

    # 2. Service scripts
    if package_type in ("Full", "Service"):
        svc_dir = os.path.join(source_dir, "Service")
        for s in REQUIRED_SERVICES:
            sp = os.path.join(svc_dir, s)
            if not os.path.isfile(sp):
                raise FileNotFoundError(f"Missing service script: {sp}")
            files_to_pack.append((sp, f"{archive_prefix}/Service/{s}"))

    # 3. Documentation & templates
    if package_type == "Full":
        for doc_file in ["Install-Agent.ps1", "agent_config.json.template", "README.md", "build-agent-package.ps1"]:
            dp = os.path.join(source_dir, doc_file)
            if os.path.isfile(dp):
                files_to_pack.append((dp, f"{archive_prefix}/{doc_file}"))

    with tempfile.TemporaryDirectory() as temp_dir:
        # Injected configuration
        final_config_data = None
        if config_file:
            with open(config_file, "r", encoding="utf-8") as f:
                final_config_data = json.load(f)
        elif config_data:
            final_config_data = config_data

        if final_config_data:
            cfg_path = os.path.join(temp_dir, "agent_config.json")
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(final_config_data, f, indent=2)
            files_to_pack.append((cfg_path, f"{archive_prefix}/agent_config.json"))

        # Compute checksums & manifest
        if include_manifest:
            manifest_dict = {}
            checksum_lines = []
            for disk_path, arcname in files_to_pack:
                h = hashlib.sha256()
                with open(disk_path, "rb") as f:
                    while chunk := f.read(65536):
                        h.update(chunk)
                hex_digest = h.hexdigest()
                # Relative to archive prefix
                rel_inside = arcname.split("/", 1)[1] if "/" in arcname else arcname
                manifest_dict[rel_inside] = hex_digest
                checksum_lines.append(f"{hex_digest}  {rel_inside}")

            manifest_path = os.path.join(temp_dir, "MANIFEST.json")
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest_dict, f, indent=2)
            files_to_pack.append((manifest_path, f"{archive_prefix}/MANIFEST.json"))

            sha_path = os.path.join(temp_dir, "checksums.sha256")
            with open(sha_path, "w", encoding="utf-8") as f:
                f.write("\n".join(checksum_lines) + "\n")
            files_to_pack.append((sha_path, f"{archive_prefix}/checksums.sha256"))

        # Build ZIP archive
        with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for disk_path, arcname in files_to_pack:
                zf.write(disk_path, arcname)

    return output_path


def main():
    parser = argparse.ArgumentParser(description="Package builder for Server-EDR Windows Agent")
    parser.add_argument("-o", "--output", help="Output path for .zip archive", default=DEFAULT_OUTPUT_NAME)
    parser.add_argument("-v", "--version", help="Agent version", default="1.0.0")
    parser.add_argument("-t", "--type", help="Package type (Full, Minimal, Service)", choices=["Full", "Minimal", "Service"], default="Full")
    parser.add_argument("-c", "--config", help="Path to custom agent_config.json to inject", default=None)
    parser.add_argument("--server-host", help="Server host IP/domain to embed in config", default=None)
    parser.add_argument("--server-port", help="Server port to embed in config", type=int, default=None)
    parser.add_argument("--psk", help="Pre-shared key to embed in config", default=None)
    parser.add_argument("--cert-thumbprint", help="Server TLS certificate thumbprint", default=None)
    parser.add_argument("--no-tls", help="Disable TLS encryption in embedded config", action="store_true")
    parser.add_argument("--source-dir", help="Source directory containing Windows agent files", default=SCRIPT_DIR)
    parser.add_argument("--dry-run", help="Verify files without creating zip archive", action="store_true")

    args = parser.parse_args()

    config_data = None
    if any([args.server_host, args.server_port, args.psk, args.cert_thumbprint, args.no_tls]):
        config_data = {
            "server": {
                "host": args.server_host or "127.0.0.1",
                "port": args.server_port or 443,
                "use_tls": not args.no_tls,
                "cert_fingerprint": args.cert_thumbprint or "",
                "reconnect_interval": 10,
                "max_reconnect_delay": 60
            },
            "auth": {
                "psk": args.psk or ""
            },
            "agent": {
                "log_level": "INFO",
                "fim_enabled": True,
                "dlp_enabled": True,
                "dlp_block_transfers": False
            }
        }

    if args.dry_run:
        print(f"[*] Dry run - Windows Agent Package ({args.type}):")
        if args.type in ("Full", "Minimal"):
            print("  + Agent-Core.ps1")
            for m in REQUIRED_MODULES:
                print(f"  + Modules/{m}")
        if args.type in ("Full", "Service"):
            for s in REQUIRED_SERVICES:
                print(f"  + Service/{s}")
        if args.type == "Full":
            print("  + agent_config.json.template")
            print("  + README.md")
        if args.config or config_data:
            print("  + agent_config.json (injected)")
        print("  + MANIFEST.json")
        print("  + checksums.sha256")
        return 0

    print(f"[*] Packaging Windows Agent to {args.output}...")
    try:
        pkg_path = build_windows_package(
            output_path=args.output,
            config_data=config_data,
            config_file=args.config,
            source_dir=args.source_dir,
            version=args.version,
            package_type=args.type
        )
        size_bytes = os.path.getsize(pkg_path)
        print(f"[+] Package created successfully: {pkg_path} ({size_bytes:,} bytes)")
        return 0
    except Exception as e:
        print(f"[-] Packaging failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
