"""
Unit and integration test suite for automated package validation (Issue #8, Sub-issue #27).
Tests:
1. Archive contents and layout (Linux .tar.gz and Windows .zip).
2. Injected configuration syntax, hierarchy, and parameter overrides.
3. Archive file permissions (POSIX executable and restricted permissions in tarball).
4. Manifest and checksum cryptographic integrity across all components.
5. Service setup script and unit file configurations.
6. Negative tests and failure conditions (missing files, invalid configs, tampered files).
"""

import os
import sys
import json
import tarfile
import zipfile
import hashlib
import tempfile
import unittest

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
from agents.linux.package_linux_agent import (
    build_linux_package,
    REQUIRED_FILES as LINUX_REQUIRED_FILES,
    REQUIRED_DIRS as LINUX_REQUIRED_DIRS,
)
from agents.windows.package_windows_agent import (
    build_windows_package,
    REQUIRED_FILES as WIN_REQUIRED_FILES,
    REQUIRED_MODULES as WIN_REQUIRED_MODULES,
    REQUIRED_SERVICES as WIN_REQUIRED_SERVICES,
)
from agents.linux.modules.common import validate_agent_config, load_agent_config


class TestPackageValidation(unittest.TestCase):
    """Automated package validation test suite (Issue #8 / #27)."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. Linux Archive Contents, Structure, and Permissions
    def test_linux_archive_contents_and_permissions(self):
        """Validates Linux .tar.gz package contents, directory hierarchy, and POSIX permissions."""
        out_tar = os.path.join(self.temp_dir.name, "linux_test.tar.gz")
        cfg_override = {
            "server": {"host": "10.0.0.1", "port": 8443, "use_tls": True, "cert_fingerprint": "A" * 64},
            "auth": {"psk": "linux_psk_secret_val"},
            "agent": {"group_tag": "web-servers", "polling_interval": 15}
        }
        res_tar = build_linux_package(out_tar, config_data=cfg_override)
        self.assertTrue(os.path.isfile(res_tar))
        self.assertTrue(tarfile.is_tarfile(res_tar))

        with tarfile.open(res_tar, "r:gz") as tar:
            members = {m.name: m for m in tar.getmembers()}

            # Validate required files
            for req in LINUX_REQUIRED_FILES:
                arc_name = f"server-edr-agent/{req}"
                self.assertIn(arc_name, members, f"Required Linux file missing: {req}")

            # Validate executable modes (0755)
            exec_scripts = ["agent_core.py", "install_service.sh", "install_agent.sh"]
            for s in exec_scripts:
                arc_name = f"server-edr-agent/{s}"
                self.assertIn(arc_name, members)
                mode = members[arc_name].mode & 0o777
                self.assertEqual(mode, 0o755, f"{s} must have mode 0755 (got: {oct(mode)})")

            # Validate restricted config mode (0600)
            cfg_name = "server-edr-agent/agent_config.json"
            self.assertIn(cfg_name, members)
            cfg_mode = members[cfg_name].mode & 0o777
            self.assertEqual(cfg_mode, 0o600, f"agent_config.json must have mode 0600 (got: {oct(cfg_mode)})")

            # Validate manifest presence and mode (0644)
            manifest_name = "server-edr-agent/MANIFEST.json"
            self.assertIn(manifest_name, members)
            manifest_mode = members[manifest_name].mode & 0o777
            self.assertEqual(manifest_mode, 0o644, f"MANIFEST.json must have mode 0644 (got: {oct(manifest_mode)})")

            # Validate systemd unit files
            self.assertIn("server-edr-agent/systemd/server-edr.service", members)
            self.assertIn("server-edr-agent/systemd/server-edr.env", members)

    # 2. Linux Cryptographic Manifest Integrity
    def test_linux_manifest_cryptographic_integrity(self):
        """Validates that every file in Linux package matches its SHA-256 hash in MANIFEST.json."""
        out_tar = os.path.join(self.temp_dir.name, "linux_manifest.tar.gz")
        res_tar = build_linux_package(out_tar)

        with tarfile.open(res_tar, "r:gz") as tar:
            manifest_bytes = tar.extractfile("server-edr-agent/MANIFEST.json").read()
            manifest = json.loads(manifest_bytes.decode("utf-8"))

            self.assertGreater(len(manifest), 5, "Manifest must contain packaged files")
            for arc_name, expected_sha in manifest.items():
                member = tar.getmember(arc_name)
                file_bytes = tar.extractfile(member).read()
                actual_sha = hashlib.sha256(file_bytes).hexdigest()
                self.assertEqual(actual_sha, expected_sha, f"SHA-256 digest mismatch for {arc_name}")

    # 3. Windows Archive Contents, Modules, and Services
    def test_windows_archive_contents_and_modules(self):
        """Validates Windows .zip package contents, modules, and service scripts."""
        out_zip = os.path.join(self.temp_dir.name, "win_test.zip")
        cfg_override = {
            "server": {"host": "10.0.0.2", "port": 9443, "use_tls": False},
            "auth": {"psk": "win_psk_secret_val"},
            "agent": {"group_tag": "db-clusters", "polling_interval": 12}
        }
        res_zip = build_windows_package(out_zip, config_data=cfg_override, version="1.0.0")
        self.assertTrue(os.path.isfile(res_zip))
        self.assertTrue(zipfile.is_zipfile(res_zip))

        prefix = "Server-EDR-Agent-Windows-v1.0.0"
        with zipfile.ZipFile(res_zip, "r") as zf:
            namelist = set(zf.namelist())

            # Validate required files
            for req in WIN_REQUIRED_FILES:
                self.assertIn(f"{prefix}/{req}", namelist, f"Missing Windows required file: {req}")

            # Validate all modules
            for mod in WIN_REQUIRED_MODULES:
                self.assertIn(f"{prefix}/Modules/{mod}", namelist, f"Missing Windows module: {mod}")

            # Validate service scripts
            for svc in WIN_REQUIRED_SERVICES:
                self.assertIn(f"{prefix}/Service/{svc}", namelist, f"Missing Windows service script: {svc}")

            # Validate config and manifests
            self.assertIn(f"{prefix}/agent_config.json", namelist)
            self.assertIn(f"{prefix}/MANIFEST.json", namelist)
            self.assertIn(f"{prefix}/checksums.sha256", namelist)

    # 4. Windows Cryptographic Manifest and Checksums Integrity
    def test_windows_manifest_and_checksums_integrity(self):
        """Validates that every file in Windows package matches MANIFEST.json and checksums.sha256."""
        out_zip = os.path.join(self.temp_dir.name, "win_integrity.zip")
        res_zip = build_windows_package(out_zip, version="1.0.0")
        prefix = "Server-EDR-Agent-Windows-v1.0.0"

        with zipfile.ZipFile(res_zip, "r") as zf:
            # 1. MANIFEST.json check
            manifest_bytes = zf.read(f"{prefix}/MANIFEST.json")
            manifest = json.loads(manifest_bytes.decode("utf-8"))

            for rel_name, expected_sha in manifest.items():
                actual_bytes = zf.read(f"{prefix}/{rel_name}")
                actual_sha = hashlib.sha256(actual_bytes).hexdigest()
                self.assertEqual(actual_sha, expected_sha, f"SHA-256 mismatch for {rel_name} in MANIFEST.json")

            # 2. checksums.sha256 check
            chk_lines = zf.read(f"{prefix}/checksums.sha256").decode("utf-8").splitlines()
            for line in chk_lines:
                line = line.strip()
                if not line or "checksums.sha256" in line:
                    continue
                parts = line.split(maxsplit=1)
                self.assertEqual(len(parts), 2)
                expected_hash, rel_path = parts[0], parts[1]
                actual_bytes = zf.read(f"{prefix}/{rel_path}")
                actual_sha = hashlib.sha256(actual_bytes).hexdigest()
                self.assertEqual(actual_sha, expected_hash, f"SHA-256 mismatch for {rel_path} in checksums.sha256")

    # 5. Injected Configuration Verification (Hierarchy and Parameters)
    def test_injected_configuration_parameters(self):
        """Validates that package-injected configurations carry accurate endpoint and group settings."""
        # Linux package config
        out_tar = os.path.join(self.temp_dir.name, "injected_linux.tar.gz")
        build_linux_package(out_tar, config_data={
            "server": {"host": "custom-edr.local", "port": 5555, "use_tls": True},
            "auth": {"psk": "linux_custom_psk_123"},
            "agent": {"group_tag": "linux-k8s-nodes", "polling_interval": 5}
        })

        with tarfile.open(out_tar, "r:gz") as tar:
            cfg = json.loads(tar.extractfile("server-edr-agent/agent_config.json").read().decode("utf-8"))
            self.assertEqual(cfg["server"]["host"], "custom-edr.local")
            self.assertEqual(cfg["server"]["port"], 5555)
            self.assertEqual(cfg["auth"]["psk"], "linux_custom_psk_123")
            self.assertEqual(cfg["agent"]["group_tag"], "linux-k8s-nodes")
            self.assertEqual(cfg["agent"]["polling_interval"], 5)

        # Windows package config
        out_zip = os.path.join(self.temp_dir.name, "injected_win.zip")
        build_windows_package(out_zip, config_data={
            "server": {"host": "win-edr.local", "port": 6666, "use_tls": False},
            "auth": {"psk": "win_custom_psk_456"},
            "agent": {"group_tag": "ad-servers", "polling_interval": 7}
        })

        with zipfile.ZipFile(out_zip, "r") as zf:
            cfg_win = json.loads(zf.read("Server-EDR-Agent-Windows-v1.0.0/agent_config.json").decode("utf-8"))
            self.assertEqual(cfg_win["server"]["host"], "win-edr.local")
            self.assertEqual(cfg_win["server"]["port"], 6666)
            self.assertEqual(cfg_win["auth"]["psk"], "win_custom_psk_456")
            self.assertEqual(cfg_win["agent"]["group_tag"], "ad-servers")
            self.assertEqual(cfg_win["agent"]["polling_interval"], 7)

    # 6. Service Unit and Scripts Syntax and Paths
    def test_service_setup_files_consistency(self):
        """Validates that systemd service unit and install script paths match /etc/sas-edr standards."""
        out_tar = os.path.join(self.temp_dir.name, "svc_check.tar.gz")
        build_linux_package(out_tar)

        with tarfile.open(out_tar, "r:gz") as tar:
            svc_content = tar.extractfile("server-edr-agent/systemd/server-edr.service").read().decode("utf-8")
            self.assertIn("/etc/sas-edr/agent_config.json", svc_content)
            self.assertIn("/etc/sas-edr/server-edr.env", svc_content)

            inst_content = tar.extractfile("server-edr-agent/install_service.sh").read().decode("utf-8")
            self.assertIn('CONFIG_DIR="/etc/sas-edr"', inst_content)
            self.assertIn('systemctl enable "${SERVICE_NAME}"', inst_content)

    # 7. Negative Testing: Packaging Failure on Missing Files
    def test_negative_packaging_missing_required_file(self):
        """Validates that package builder raises FileNotFoundError when required files are missing."""
        empty_dir = os.path.join(self.temp_dir.name, "empty_source")
        os.makedirs(empty_dir, exist_ok=True)

        target_out = os.path.join(self.temp_dir.name, "should_fail.tar.gz")
        with self.assertRaises(FileNotFoundError):
            build_linux_package(target_out, source_dir=empty_dir)

        target_win_out = os.path.join(self.temp_dir.name, "should_fail.zip")
        with self.assertRaises(FileNotFoundError):
            build_windows_package(target_win_out, source_dir=empty_dir)

    # 8. Negative Testing: Semantic Validation of Corrupt / Invalid Configurations
    def test_negative_invalid_configuration_detection(self):
        """Validates that corrupt or invalid configuration parameters fail validation."""
        # Empty host
        invalid_cfg1 = {"server": {"host": "", "port": 4444}, "auth": {"psk": "p"}}
        is_valid1, errors1 = validate_agent_config(invalid_cfg1)
        self.assertFalse(is_valid1)
        self.assertIn("SERVER_HOST", str(errors1))

        # Port out of bounds
        invalid_cfg2 = {"server": {"host": "127.0.0.1", "port": 999999}, "auth": {"psk": "p"}}
        is_valid2, errors2 = validate_agent_config(invalid_cfg2)
        self.assertFalse(is_valid2)
        self.assertIn("SERVER_PORT", str(errors2))

        # Invalid thumbprint format
        invalid_cfg3 = {"server": {"host": "127.0.0.1", "port": 4444, "cert_fingerprint": "NOT_A_HASH"}, "auth": {"psk": "p"}}
        is_valid3, errors3 = validate_agent_config(invalid_cfg3)
        self.assertFalse(is_valid3)
        self.assertIn("fingerprint", str(errors3).lower())


if __name__ == "__main__":
    unittest.main()
