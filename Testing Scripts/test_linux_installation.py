"""
Unit and integration tests for Linux installation automation (Issue #6).
Tests Sub-issues:
  - Issue #24: Install configuration under /etc/sas-edr/
  - Issue #23: Update agents/linux/install_service.sh
  - Issue #22: Enable and start the systemd service
"""

import os
import re
import sys
import unittest
import tempfile
import configparser

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LINUX_DIR = os.path.join(BASE_DIR, "agents", "linux")
if LINUX_DIR not in sys.path:
    sys.path.insert(0, LINUX_DIR)

from modules.common import DEFAULT_CONFIG_LOCATIONS


class TestLinuxInstallationAutomation(unittest.TestCase):
    """Test suite validating Linux installation automation, scripts, and service definitions."""

    def test_default_config_locations_includes_etc_sas_edr(self):
        """Issue #24: Validate /etc/sas-edr paths in DEFAULT_CONFIG_LOCATIONS and their priority."""
        self.assertIn("/etc/sas-edr/agent_config.json", DEFAULT_CONFIG_LOCATIONS)
        self.assertIn("/etc/sas-edr/agent.config.json", DEFAULT_CONFIG_LOCATIONS)

        # /etc/sas-edr must be prioritized before /etc/server-edr
        sas_idx = DEFAULT_CONFIG_LOCATIONS.index("/etc/sas-edr/agent_config.json")
        legacy_idx = DEFAULT_CONFIG_LOCATIONS.index("/etc/server-edr/agent_config.json")
        self.assertLess(sas_idx, legacy_idx, "/etc/sas-edr must be searched before legacy /etc/server-edr")

    def test_install_service_script_structure_and_options(self):
        """Issue #23: Validate agents/linux/install_service.sh options, defaults, and error checks."""
        script_path = os.path.join(LINUX_DIR, "install_service.sh")
        self.assertTrue(os.path.isfile(script_path), "install_service.sh must exist")

        with open(script_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Check default paths
        self.assertIn('CONFIG_DIR="/etc/sas-edr"', content, "Default CONFIG_DIR must be /etc/sas-edr")
        self.assertIn('INSTALL_DIR="/opt/server-edr/agent"', content)
        self.assertIn('SYSTEMD_DIR="/etc/systemd/system"', content)
        self.assertIn('SERVICE_NAME="server-edr"', content)

        # Check options parsing
        expected_options = [
            "--server-host",
            "--server-port",
            "--psk",
            "--cert-fingerprint",
            "--use-tls",
            "--no-tls",
            "--config-file",
            "--install-dir",
            "--config-dir",
            "--log-dir",
            "--service-name",
            "--no-start",
            "--force",
            "--dry-run",
            "--help",
        ]
        for opt in expected_options:
            self.assertIn(opt, content, f"install_service.sh must support option '{opt}'")

        # Check root privilege check
        self.assertIn('EUID', content, "Must verify EUID / root privileges")
        self.assertIn('DRY_RUN', content, "Must respect DRY_RUN mode")

        # Check Python 3.6+ verification
        self.assertIn("python3", content)
        self.assertIn("3.6", content)

        # Check restrictive permissions on config directory & config file
        self.assertIn('chmod 0700 "$CONFIG_DIR"', content, "Config dir must be chmod 0700")
        self.assertIn('chmod 0600 "$TARGET_CONFIG"', content, "Config file must be chmod 0600")
        self.assertIn('chmod 0600 "$TARGET_ENV"', content, "Env file must be chmod 0600")

    def test_install_agent_script_delegation(self):
        """Issue #23: Validate agents/linux/install_agent.sh exists and delegates cleanly."""
        script_path = os.path.join(LINUX_DIR, "install_agent.sh")
        self.assertTrue(os.path.isfile(script_path), "install_agent.sh must exist")

        with open(script_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("install_service.sh", content, "install_agent.sh must delegate to install_service.sh")

    def test_systemd_service_file_specifications(self):
        """Issue #22 & #24: Validate systemd service unit file configuration."""
        service_file = os.path.join(LINUX_DIR, "systemd", "server-edr.service")
        self.assertTrue(os.path.isfile(service_file), "server-edr.service must exist")

        with open(service_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        content = "".join(lines)

        # Unit section
        self.assertIn("network.target", content)
        self.assertIn("network-online.target", content)
        self.assertIn("Wants=network-online.target", content)

        # Service section: path points to /etc/sas-edr/agent_config.json
        self.assertIn("/etc/sas-edr/agent_config.json", content, "ExecStart must point to /etc/sas-edr/agent_config.json")
        self.assertIn("Restart=always", content)
        self.assertIn("RestartSec=5s", content)

        # Environment files include /etc/sas-edr
        self.assertIn("EnvironmentFile=-/etc/sas-edr/server-edr.env", content)

        # Hardening and resource limits
        self.assertIn("ProtectSystem=full", content)
        self.assertIn("ProtectHome=read-only", content)
        self.assertIn("PrivateTmp=true", content)
        self.assertIn("TasksMax=", content)
        self.assertIn("MemoryMax=", content)

        # Install section: automatic boot start
        self.assertIn("[Install]", content)
        self.assertIn("WantedBy=multi-user.target", content)

    def test_systemd_environment_file(self):
        """Issue #24: Validate systemd environment file default configuration path."""
        env_file = os.path.join(LINUX_DIR, "systemd", "server-edr.env")
        self.assertTrue(os.path.isfile(env_file), "server-edr.env must exist")

        with open(env_file, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("EDR_CONFIG_FILE=/etc/sas-edr/agent_config.json", content)

    def test_systemd_enable_and_start_logic(self):
        """Issue #22: Validate that install_service.sh enables and starts systemd service."""
        script_path = os.path.join(LINUX_DIR, "install_service.sh")
        with open(script_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Must reload daemon
        self.assertIn("systemctl daemon-reload", content)

        # Must enable service for boot startup
        self.assertIn('systemctl enable "${SERVICE_NAME}"', content)

        # Must support starting / restarting and verifying active status
        self.assertIn('systemctl restart "${SERVICE_NAME}"', content)
        self.assertIn('systemctl is-active', content)

        # Must support --no-start flag
        self.assertIn('START_SERVICE=0', content)

    def test_uninstall_service_script_cleans_sas_edr(self):
        """Issue #24: Validate that uninstall_service.sh cleans /etc/sas-edr."""
        script_path = os.path.join(LINUX_DIR, "uninstall_service.sh")
        self.assertTrue(os.path.isfile(script_path), "uninstall_service.sh must exist")

        with open(script_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("/etc/sas-edr", content, "uninstall_service.sh must clean /etc/sas-edr")


if __name__ == "__main__":
    unittest.main()
