# Server-EDR Release Notes

## Version 1.1.0 — Enterprise Configuration, Automated Packaging & Endpoint Deployment

**Release Date:** October 2026  
**License:** GNU General Public License v3.0  
**Status:** Stable / Production-Ready  

---

### Executive Summary

Server-EDR version 1.1.0 transforms the platform from a manually configured laboratory EDR prototype into a production-grade, enterprise-ready Endpoint Detection and Response system. This release introduces interactive and headless server configuration wizards, dynamic agent configuration subsystems for Windows and Linux, automated GUI and CLI agent distribution package builders, hardened operating system service installers (systemd and Windows SCM), and a comprehensive automated validation test suite.

---

### Key Features & Architectural Enhancements

#### 1. First-Run Server Configuration Wizard ([Issue #2](https://github.com/SAS-Group-org/Server-EDR/issues/2))
- **Interactive First-Run Wizard ([#10](https://github.com/SAS-Group-org/Server-EDR/issues/10)):** Automatically detects when Server-EDR is executed without pre-existing configuration and launches a guided wizard to configure listen IP, listen port, PSK generation, and TLS identity settings.
- **Headless & Automation Support ([#10](https://github.com/SAS-Group-org/Server-EDR/issues/10)):** Supports non-interactive CI/CD and containerized deployments via `--init`, `--non-interactive`, `--listen-host`, `--listen-port`, `--psk`, `--cert`, `--key`, and `--force-wizard` flags.
- **Automated TLS Certificate Generation ([#11](https://github.com/SAS-Group-org/Server-EDR/issues/11)):** Generates 4096-bit RSA self-signed certificates with SHA-256 signatures and SAN extensions (with a pure-Python fallback when `cryptography` is unavailable). Calculates and logs the SHA-256 certificate thumbprint for client-side pinning.
- **Cryptographically Secure PSK Generation:** Automatically creates 32-byte (256-bit) cryptographically strong pre-shared keys for HMAC-SHA256 agent authentication.
- **Hardened Configuration Storage ([#12](https://github.com/SAS-Group-org/Server-EDR/issues/12)):** Persists server settings to `server_config.json` with restrictive access controls: POSIX `0600` on Linux/Unix systems and Windows NTFS ACLs restricting access exclusively to `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`.

#### 2. Dynamic Linux Agent Configuration Subsystem ([Issue #3](https://github.com/SAS-Group-org/Server-EDR/issues/3))
- **Dynamic Configuration Loader ([#13](https://github.com/SAS-Group-org/Server-EDR/issues/13)):** Linux agents (`agent_core.py`) now dynamically resolve configuration via a prioritized cascade:
  1. Command-line arguments (`--server-host`, `--server-port`, `--psk`, `--cert-fingerprint`, `--group`, `--poll-interval`).
  2. Environment variables (`EDR_SERVER_HOST`, `EDR_SERVER_PORT`, `EDR_PSK`, `EDR_CERT_FINGERPRINT`, `EDR_AGENT_GROUP`, `EDR_POLL_INTERVAL`).
  3. JSON configuration files (`--config <path>`, local `./agent_config.json`, or `/etc/sas-edr/agent_config.json`).
  4. Hardcoded secure defaults.
- **Semantic Configuration Validation ([#14](https://github.com/SAS-Group-org/Server-EDR/issues/14)):** Validates port numbers (1–65535), certificate fingerprints (64-character hexadecimal SHA-256), PSK presence, and polling intervals with clear, actionable diagnostics.
- **Distribution Packaging Tool ([#15](https://github.com/SAS-Group-org/Server-EDR/issues/15)):** Provides `agents/linux/package_linux_agent.py` to bundle all agent modules, defense plugins, configuration files, and installer scripts into self-contained `.tar.gz` archives with SHA-256 integrity manifests.

#### 3. Dynamic Windows Agent Configuration Subsystem ([Issue #4](https://github.com/SAS-Group-org/Server-EDR/issues/4))
- **PowerShell Module Integration ([#16](https://github.com/SAS-Group-org/Server-EDR/issues/16)):** Updated `agents/windows/Modules/Common.psm1` with `Get-AgentConfig`, `Set-AgentConfig`, and `Validate-AgentConfig` cmdlets supporting `$env:ProgramData\Server-EDR\agent_config.json`, `-ConfigPath`, and environment variables.
- **Precedence Hierarchy & Parameter Binding ([#17](https://github.com/SAS-Group-org/Server-EDR/issues/17)):** Refactored `Agent-Core.ps1` to resolve configuration hierarchically without requiring file edits, binding command-line parameters, environment variables, and configuration files.
- **Cross-Platform Packaging Utilities ([#18](https://github.com/SAS-Group-org/Server-EDR/issues/18)):** Introduced `agents/windows/package_windows_agent.py` and `agents/windows/build-agent-package.ps1` to assemble production Windows distribution `.zip` archives with pre-populated configuration and checksum manifests.

#### 4. Server GUI & Headless Agent Package Builder ([Issue #5](https://github.com/SAS-Group-org/Server-EDR/issues/5))
- **Programmatic Backend API ([#19](https://github.com/SAS-Group-org/Server-EDR/issues/19)):** Implemented `build_agent_package()` in `Server.py` for headless or UI-driven generation of Linux `.tar.gz` and Windows `.zip` bundles with injected connection profiles.
- **Interactive Tkinter Package Builder Modal ([#20](https://github.com/SAS-Group-org/Server-EDR/issues/20)):** Added a "Build Agent Package..." dialog to the Server management console toolbar, allowing operators to select target platforms, auto-populate live server IP/port/PSK/fingerprint, specify agent groups and polling intervals, and output production packages with one click.
- **Headless CLI Packaging Options ([#21](https://github.com/SAS-Group-org/Server-EDR/issues/21)):** Added command-line packaging flags to `Server.py`:
  - `--build-package {linux,windows,all}`
  - `--package-output <directory>`
  - `--package-host <host>`, `--package-port <port>`, `--package-psk <psk>`, `--package-fingerprint <sha256>`, `--package-group <name>`, `--package-interval <seconds>`.

#### 5. Automated Linux Endpoint Installation ([Issue #6](https://github.com/SAS-Group-org/Server-EDR/issues/6))
- **Standardized Configuration & Runtime Paths ([#24](https://github.com/SAS-Group-org/Server-EDR/issues/24)):** Established `/etc/sas-edr/` as the standard configuration directory (`agent_config.json`, `server-edr.env`, and `agent_config.template.json`), locked down with `chmod 0700` and `chmod 0600` permissions.
- **Automated Service Installer ([#23](https://github.com/SAS-Group-org/Server-EDR/issues/23)):** Created `agents/linux/install_service.sh` and root wrapper `agents/linux/install_agent.sh` providing pre-flight dependency checks (Python 3.6+), argument overrides (`--server-host`, `--server-port`, `--psk`, `--fingerprint`, `--group`, `--interval`), and pre-flight connectivity verification.
- **Hardened Systemd Service ([#22](https://github.com/SAS-Group-org/Server-EDR/issues/22)):** Hardened `agents/linux/systemd/server-edr.service` with strict sandboxing:
  - `After=network-online.target` with `Wants=network-online.target`
  - `ProtectSystem=strict` and `ProtectHome=true`
  - `PrivateTmp=true` and `NoNewPrivileges=true`
  - `ReadWritePaths=/var/log /var/run /tmp`
  - Resource control limits: `MemoryMax=512M`, `CPUQuota=50%`, `Restart=always`, `RestartSec=10`.

#### 6. Automated Windows Endpoint Installation ([Issue #7](https://github.com/SAS-Group-org/Server-EDR/issues/7))
- **Automated SCM Service Installer ([#25](https://github.com/SAS-Group-org/Server-EDR/issues/25)):** Enhanced `agents/windows/Service/Install-Service.ps1` and root wrapper `agents/windows/Install-Agent.ps1` to resolve settings from preconfigured files or CLI switches, validate configuration, verify network connectivity to the Server, and register the service.
- **Hardened NTFS Access Controls ([#25](https://github.com/SAS-Group-org/Server-EDR/issues/25)):** Stores production configuration in `$env:ProgramData\Server-EDR\agent_config.json` with inheritance disabled and full control granted strictly to `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`.
- **Deployment Flexibility & Service Watchdog ([#26](https://github.com/SAS-Group-org/Server-EDR/issues/26)):**
  - Added `-InstallDir`, `-ConfigDir`, `-InPlace`, `-NoStart`, `-Force`, and `-DryRun` deployment options.
  - Configured Windows Service Controller (`sc.exe failure`) recovery actions: restart on first failure (60s), restart on second failure (60s), with automatic daily failure count reset.
  - Updated `ServiceWrapper.ps1` to pass registered `-ConfigPath` directly to `Agent-Core.ps1`.
  - Added `-Purge` support to `Uninstall-Service.ps1` to cleanly remove binaries, configuration, and registry entries.

#### 7. Automated Package & Architecture Validation Suite ([Issue #8](https://github.com/SAS-Group-org/Server-EDR/issues/8))
- **End-to-End Package Validation ([#27](https://github.com/SAS-Group-org/Server-EDR/issues/27)):** Created `test_package_validation.py` verifying archive formats (`.tar.gz` and `.zip`), file permissions, checksum manifests, dynamic configuration loading, and negative failure modes (corrupted JSON, invalid ports, missing files).
- **Defense Suite Packaging Integration ([#28](https://github.com/SAS-Group-org/Server-EDR/issues/28)):** Added tests 18, 19, and 20 to `test_defense_suite.py` validating defense module packaging, manifest verification, and dynamic configuration loading (21/21 tests passing).
- **Modular Agent Verification ([#29](https://github.com/SAS-Group-org/Server-EDR/issues/29)):** Added `TestModularAgents` to `test_modular_agents.py` ensuring modular Linux and Windows agents establish live C2 sessions under injected packages.
- **Windows Agent Architecture Verification ([#30](https://github.com/SAS-Group-org/Server-EDR/issues/30)):** Added `TestWindowsAgentSuite` to `test_windows_agent.py` verifying package creation, checksum validation, and dry-run service installation.

---

### Release & Pre-Deployment Checklist

Before deploying Server-EDR v1.1.0 into production environments, complete the following verification steps:

- [ ] **1. Attestation Integrity Verification**
  - Run cryptographic SHA-256 verification against the `Checksums` file:
    ```bash
    sha256sum -c Checksums
    ```
  - Verify that `Server.py`, `agents/linux/agent_core.py`, and `agents/windows/Agent-Core.ps1` match their authorized baseline digests.
- [ ] **2. Full Automated Test Suite Execution**
  - Execute all repository unit and integration tests:
    ```bash
    python -m unittest discover -s . -p "test_*.py" -v
    ```
  - Confirm that all 100 tests pass without failures or errors.
- [ ] **3. Server Initialization & Hardening**
  - Initialize the server configuration:
    ```bash
    python Server.py --init --non-interactive --listen-host 0.0.0.0 --listen-port 4444
    ```
  - Verify that `server_config.json`, `edr_server.crt`, `edr_server.key`, `edr_psk.txt`, and `edr_fingerprint.txt` are generated.
  - Verify restrictive permissions (`0600` on Linux, `SYSTEM`/`Administrators` on Windows) on `server_config.json` and `edr_server.key`.
  - Securely record the SHA-256 certificate fingerprint for endpoint pinning.
- [ ] **4. Distribution Package Generation**
  - Build deployment packages using the CLI or GUI builder:
    ```bash
    python Server.py --build-package all --package-output ./dist --package-host <SERVER_IP> --package-port 4444
    ```
  - Inspect `./dist` to ensure `server-edr-linux.tar.gz` and `server-edr-windows.zip` are generated with valid manifests.
- [ ] **5. Linux Endpoint Staging Verification**
  - Extract `server-edr-linux.tar.gz` on a test Linux host.
  - Run the installer in pre-flight mode:
    ```bash
    sudo ./install_agent.sh --test-only
    ```
  - Perform service installation:
    ```bash
    sudo ./install_agent.sh
    sudo systemctl status server-edr.service
    ```
  - Confirm the agent establishes a TLS connection to the Server and passes attestation.
- [ ] **6. Windows Endpoint Staging Verification**
  - Extract `server-edr-windows.zip` on a test Windows host.
  - Run the installer in dry-run mode:
    ```powershell
    powershell -ExecutionPolicy Bypass -File Install-Agent.ps1 -DryRun
    ```
  - Perform service installation:
    ```powershell
    powershell -ExecutionPolicy Bypass -File Install-Agent.ps1
    Get-Service Server-EDR
    ```
  - Confirm the agent establishes a TLS connection to the Server and passes attestation.
- [ ] **7. Network & Firewall Egress**
  - Confirm that endpoint firewalls allow outbound TCP traffic to the Server IP on port 4444 (or configured custom port).
  - Confirm that the Server host firewall allows inbound TCP traffic on port 4444 exclusively from authorized agent subnets.

---

### Upgrade & Migration Guide

#### Upgrading from v1.0.0 to v1.1.0

1. **Server Configuration Migration:**
   - Previous versions of Server-EDR read configuration from command-line arguments or defaults on each launch.
   - Version 1.1.0 introduces `server_config.json`. Existing deployments can migrate by running:
     ```bash
     python Server.py --init --non-interactive --listen-host <EXISTING_HOST> --listen-port <EXISTING_PORT> --cert edr_server.crt --key edr_server.key --psk <EXISTING_PSK>
     ```
2. **Endpoint Configuration Migration:**
   - Linux agents no longer require editing `agent_core.py`. Existing installations can place their configuration into `/etc/sas-edr/agent_config.json` or `/etc/sas-edr/server-edr.env`.
   - Windows agents no longer require modifying `Agent-Core.ps1`. Existing installations can place their configuration into `$env:ProgramData\Server-EDR\agent_config.json`.
3. **Service Management:**
   - Upgrade legacy systemd services by deploying the new unit file `agents/linux/systemd/server-edr.service` and reloading systemd (`systemctl daemon-reload && systemctl restart server-edr`).
   - Upgrade Windows services by running `Uninstall-Service.ps1` followed by `Install-Service.ps1`.
