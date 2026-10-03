# SAS-EDR Secure Endpoint Detection, Response & Defense Platform — Multi-OS

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8+-brightgreen.svg)](https://www.python.org/)
[![PowerShell: 5.1+](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://microsoft.com/powershell)
[![Platform: Linux%20|%20Windows](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey.svg)](#capabilities--feature-matrix)
[![Tests: 100/100 Passing](https://img.shields.io/badge/Tests-100%2F100%20Passing-success.svg)](#running-the-automated-test-suite)

Production-grade Remote Administration and Endpoint Detection & Defense platform featuring TLS 1.2+ encryption with SHA-256 certificate pinning, HMAC-SHA256 mutual authentication, duplex asynchronous security telemetry, cryptographic script attestation, automated distribution package builders, and production system services for Windows (`SCM`) and Linux (`systemd`).

---

## Table of Contents
1. [Capabilities & Feature Matrix](#capabilities--feature-matrix)
2. [Architecture & Protocol](#architecture--protocol)
3. [Server First-Run Setup](#server-first-run-setup)
4. [Agent Package Builder (GUI & CLI)](#agent-package-builder-gui--cli)
5. [Linux Endpoint Deployment](#linux-endpoint-deployment)
6. [Windows Endpoint Deployment](#windows-endpoint-deployment)
7. [Defensive Subsystems](#defensive-subsystems)
8. [Defensive Command Reference](#defensive-command-reference)
9. [Management Console UI](#management-console-ui)
10. [Cryptographic Attestation & Anti-Tamper](#cryptographic-attestation--anti-tamper)
11. [Running the Automated Test Suite](#running-the-automated-test-suite)
12. [Documentation & Security Policies](#documentation--security-policies)
13. [Requirements & License](#requirements--license)

---

## Capabilities & Feature Matrix

| Feature | Windows Endpoint | Linux Endpoint | Management Server |
| :--- | :---: | :---: | :---: |
| **Encrypted C2 Transport** | TLS 1.2+ (Pinned Thumbprint) | TLS 1.2+ (Pinned Thumbprint) | Multi-threaded TLS Server |
| **Authentication** | HMAC-SHA256 Challenge | HMAC-SHA256 Challenge | Constant-time `compare_digest` |
| **Configuration Subsystem** | Dynamic Hierarchical Loader | Dynamic Hierarchical Loader | Interactive & Headless Wizard |
| **Package Builder** | Standalone Script & ZIP Archive | Standalone Script & TAR.GZ | Tkinter GUI Modal & CLI flags |
| **Service Automation** | Windows SCM + Recovery Watchdog | Hardened `systemd` Sandboxed | Native background daemon |
| **Remote Admin Shell** | Interactive PowerShell | Interactive Bash | Terminal tab with history |
| **Process Management** | Live inspection & Kill | Live inspection & Kill | Processes tab |
| **Remote File Explorer** | Windows paths, upload/download | Linux paths, upload/download | Remote Files tab |
| **Asynchronous Event Bus** | Streaming `event` frames | Streaming `event` frames | Real-time Security Alerts tab |
| **Malware Prevention** | Windows Defender + Hashes | Hash DB + Heuristics + ClamAV | Scanner & Threat feed |
| **Quarantine Vault** | Stripped ACLs & `.meta` | `chmod 0600` & `.meta` | Vault browser & Restore |
| **File Integrity (FIM)** | Registry & Critical files | `/etc` configuration baseline | Baseline Init & Delta Audits |
| **Data Loss Prevention (DLP)**| Cards (Luhn), SSN, Keys, JWT | Cards (Luhn), SSN, Keys, JWT | In-band transfer inspection |
| **Removable Media** | WMI Device Arrival Events | `/proc/mounts` USB Detection | Real-time USB attach alerts |
| **OpenEDR Integration** | `edrsvc` Minifilter Driver | eBPF / Service log tailer | Telemetry stream viewer |
| **Host Containment** | `netsh` C2-Pinning Firewall | `iptables` C2-Pinning Rules | One-click Host Isolation |
| **Cryptographic Attestation**| SHA-256 Memory & Script Hash | SHA-256 Memory & Script Hash | Verified against `Checksums` |

---

## Architecture & Protocol

Server-EDR utilizes an outbound-only C2 architecture where endpoints initiate connections to the management server over a single TCP port (default `4444`). 

```
+-------------------------------------------------------------+
|                     Endpoints (Outbound Only)               |
|                                                             |
|   +-----------------------+     +-----------------------+   |
|   |   Linux Endpoint      |     |   Windows Endpoint    |   |
|   |   (systemd Service)   |     |   (Windows SCM)       |   |
|   +-----------+-----------+     +-----------+-----------+   |
|               |                             |               |
|               +--------------+--------------+               |
|                              |                              |
|                              | TLS 1.2+ (Pinned Thumbprint) |
|                              | HMAC-SHA256 Auth Challenge   |
|                              | Duplex 4-byte Length-Prefix  |
|                              v                              |
|                 +-------------------------+                 |
|                 | Server-EDR Management   |                 |
|                 | Console & Telemetry Hub |                 |
|                 +-------------------------+                 |
+-------------------------------------------------------------+
```

### Wire Framing & Event Multiplexing
All communication is framed using a 4-byte Little-Endian length-prefixed JSON wire protocol:
- `type: "response"`: Synchronous command replies correlated by request `id`.
- `type: "event"`: Unsolicited real-time security alerts (FIM alterations, malware signatures, DLP exfiltration, removable media).
- `type: "telemetry"`: Batched system telemetry and OpenEDR kernel event logs.

---

## Server First-Run Setup

### 1. Interactive First-Run Setup Wizard
On its initial run without pre-existing configuration, the server detects missing credentials and launches an interactive wizard:

```bash
python Server.py
```

The wizard prompts for:
- **Listen Host:** `0.0.0.0` (all interfaces) or specific network interface.
- **Listen Port:** Default `4444`.
- **Pre-Shared Key (PSK):** Generates a 32-byte (256-bit) cryptographically strong PSK, or accepts an existing key.
- **TLS Certificate & Key:** Generates a 4096-bit self-signed RSA certificate and private key with SAN extensions, or accepts custom certificate paths.

### 2. Headless & Automated CI/CD Setup
For automated or containerized deployments, execute the setup non-interactively:

```bash
# Automated setup with generated credentials:
python Server.py --init --non-interactive --listen-host 0.0.0.0 --listen-port 4444

# Automated setup with custom pre-existing credentials:
python Server.py \
  --init \
  --non-interactive \
  --listen-host 192.168.1.100 \
  --listen-port 4444 \
  --psk 4f8a9b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a \
  --cert /path/to/server.crt \
  --key /path/to/server.key
```

### 3. Server Configuration & Security
Configuration and security files generated on first run:
- `server_config.json`: Master server configuration (POSIX `0600` on Linux, restricted DACL on Windows).
- `edr_server.crt`: 4096-bit TLS certificate presented to agents.
- `edr_server.key`: Private key (permissions restricted strictly to administrator).
- `edr_psk.txt`: Pre-shared authentication key.
- `edr_fingerprint.txt`: SHA-256 certificate thumbprint used for client-side pinning.

---

## Agent Package Builder (GUI & CLI)

Server-EDR includes an automated package generator that creates standalone, pre-configured distribution archives for Linux and Windows endpoints.

### GUI Package Builder Dialog
1. In the Server management console, click the **"Build Agent Package..."** button in the top toolbar.
2. Select target platform: **Linux (.tar.gz)**, **Windows (.zip)**, or **Both Platforms**.
3. Live server parameters (Host, Port, PSK, and Fingerprint) are automatically pre-populated.
4. Set optional **Agent Group** tags and **Polling Intervals**.
5. Select the destination directory and click **"Generate Package(s)"**.

### Headless CLI Package Builder
Build deployment bundles directly from the command line:

```bash
# Generate both Linux and Windows packages into ./dist:
python Server.py --build-package all --package-output ./dist

# Generate a Linux package for a specific server address and group:
python Server.py \
  --build-package linux \
  --package-output ./dist \
  --package-host 192.168.1.100 \
  --package-port 4444 \
  --package-group "Web-Servers"

# Generate a Windows package:
python Server.py \
  --build-package windows \
  --package-output ./dist \
  --package-host 192.168.1.100 \
  --package-port 4444 \
  --package-group "Workstations"
```

---

## Linux Endpoint Deployment

### 1. Dynamic Configuration Precedence
The Linux agent (`agent_core.py`) resolves its configuration dynamically using the following precedence:
1. Command-line flags (`--server-host`, `--server-port`, `--psk`, `--cert-fingerprint`, `--group`, `--poll-interval`).
2. Environment variables (`EDR_SERVER_HOST`, `EDR_SERVER_PORT`, `EDR_PSK`, `EDR_CERT_FINGERPRINT`, `EDR_AGENT_GROUP`, `EDR_POLL_INTERVAL`).
3. JSON configuration files (`--config <path>`, `./agent_config.json`, or `/etc/sas-edr/agent_config.json`).
4. Built-in defaults.

### 2. Standalone / Interactive Execution
```bash
# Run with explicit command-line flags:
python3 agents/linux/agent_core.py \
  --server-host 192.168.1.100 \
  --server-port 4444 \
  --psk <PASTE_PSK> \
  --cert-fingerprint <PASTE_FINGERPRINT>

# Or run with environment variables:
export EDR_SERVER_HOST="192.168.1.100"
export EDR_SERVER_PORT="4444"
export EDR_PSK="<PASTE_PSK>"
export EDR_CERT_FINGERPRINT="<PASTE_FINGERPRINT>"
python3 agents/linux/agent_core.py
```

### 3. Automated Systemd Service Installation
Deploy the agent as a production, sandboxed `systemd` service:

```bash
# From extracted distribution archive:
tar -xzf server-edr-linux.tar.gz
cd server-edr-linux

# Test connectivity and configuration without modifying system:
sudo ./install_agent.sh --test-only

# Install and activate the systemd service:
sudo ./install_agent.sh
```

**Service Hardening:** The installed systemd unit (`server-edr.service`) enforces:
- `ProtectSystem=strict` and `ProtectHome=true`
- `PrivateTmp=true` and `NoNewPrivileges=true`
- `MemoryMax=512M` and `CPUQuota=50%`
- Automatic restart on failure (`Restart=always`, `RestartSec=10`).

---

## Windows Endpoint Deployment

### 1. Dynamic Configuration Precedence
The Windows agent (`Agent-Core.ps1`) resolves configuration dynamically:
1. Script parameters (`-ServerHost`, `-ServerPort`, `-PSK`, `-CertThumbprint`, `-AgentGroup`, `-PollInterval`).
2. Environment variables (`$env:EDR_SERVER_HOST`, `$env:EDR_SERVER_PORT`, `$env:EDR_PSK`, etc.).
3. Configuration files (`-ConfigPath <path>`, `.\agent_config.json`, or `$env:ProgramData\Server-EDR\agent_config.json`).
4. Built-in defaults.

### 2. Standalone / Interactive Execution
```powershell
powershell -ExecutionPolicy Bypass -File agents\windows\Agent-Core.ps1 `
  -ServerHost "192.168.1.100" `
  -ServerPort 4444 `
  -PSK "<PASTE_PSK>" `
  -CertThumbprint "<PASTE_FINGERPRINT>"
```

### 3. Automated Windows SCM Service Installation
Deploy the agent as a managed Windows Service:

```powershell
# From extracted distribution zip:
Expand-Archive -Path server-edr-windows.zip -DestinationPath C:\Temp\server-edr-windows
cd C:\Temp\server-edr-windows

# Validate in DryRun mode:
powershell -ExecutionPolicy Bypass -File Install-Agent.ps1 -DryRun

# Install and start the service:
powershell -ExecutionPolicy Bypass -File Install-Agent.ps1
```

**Security & Watchdog Features:**
- Hardened NTFS permissions on `$env:ProgramData\Server-EDR\agent_config.json` (accessible strictly by `SYSTEM` and `Administrators`).
- SCM Watchdog: Configured with automated recovery actions (`restart/60000/restart/60000/none/60000`).
- Clean removal: `Uninstall-Service.ps1 -Purge` removes binaries, configuration, and registry settings.

---

## Defensive Subsystems

### 1. Malware Prevention & Quarantine Vault
- **Signature Scanning:** Scans file paths and running processes against SHA-256 malware databases.
- **Heuristic Auditing:** Detects unauthorized executions from world-writable directories (`/tmp`, `/dev/shm`, `C:\Windows\Temp`) or deleted executable images.
- **Quarantine Isolation:** Isolates threats to a secure vault (`/var/run/.server_edr_quarantine` or `C:\ProgramData\Server-EDR\Quarantine`), strips execute permissions, appends `.quarantine`, and generates forensic `.meta` sidecars.

### 2. File Integrity Monitoring (FIM)
- **Baseline Generator:** Creates SHA-256 baselines of critical operating system files (Linux: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/hosts`; Windows: `hosts`, Registry Run keys, Startup folders).
- **Integrity Audits:** Identifies `MODIFIED`, `DELETED`, and `ADDED` files, raising real-time alerts.

### 3. Data Loss Prevention (DLP)
- **Regex & Checksum Engine:** Scans text streams and files for sensitive data patterns:
  - Credit Cards (validated with Luhn checksum algorithm)
  - US Social Security Numbers (SSN)
  - Cloud API Keys (AWS `AKIA...`, GitHub PAT `ghp_...`)
  - RSA / OpenSSH Private Keys
  - JSON Web Tokens (JWT)
- **In-Band Transfer Protection:** Prevents staging or exfiltrating sensitive data through C2 upload/download channels.
- **Removable Media Tracking:** Real-time alerting upon detection of USB mass storage devices.

### 4. OpenEDR & Emergency Host Containment
- **Kernel Telemetry:** Ingests events from OpenEDR minifilters and drivers.
- **Host Containment:** Instantly isolates compromised endpoints via `isolate_host true`. Drops all external network traffic using local firewalls while preserving the Server-EDR C2 channel.

---

## Defensive Command Reference

| Command | Arguments | Description |
| :--- | :--- | :--- |
| `malware_scan` | `<path>` | Scans path for known malware signatures and heuristic anomalies |
| `quarantine` | `<path>` | Isolates file into quarantine vault and strips execution rights |
| `quarantine_list` | - | Lists all isolated files and quarantine metadata |
| `quarantine_restore` | `<quarantine_id>` | Restores quarantined file back to its original location |
| `fim_init` | - | Generates or rebuilds the SHA-256 file integrity baseline |
| `fim_check` | - | Runs an immediate file integrity audit against baseline |
| `fim_add_path` | `<path>` | Adds an additional file or directory to the FIM scope |
| `dlp_scan` | `<path or text>` | Inspects file or string buffer for sensitive data patterns |
| `openedr_status` | - | Queries OpenEDR service status, minifilter, and log telemetry |
| `openedr_fetch_telemetry` | - | Fetches latest OpenEDR kernel event logs |
| `isolate_host` | `"true" / "false"` | Enforces or releases emergency network containment |
| `psk_rotate` | `<new_psk>` | Dispatches dynamic pre-shared key rotation |

---

## Management Console UI

1. **Terminal Tab:** Remote interactive shell (`PS >` for Windows, `$ >` for Linux) with full history.
2. **Processes Tab:** Live process inspection, memory metrics, filter bar, and process termination (`kill`).
3. **Files Tab:** OS-aware remote file explorer with secure upload and download capabilities.
4. **Sysinfo Tab:** Hardware specs, operating system details, administrative privileges, and defense statuses.
5. **Security Alerts Tab:** Central real-time feed for FIM, DLP, Malware, and OpenEDR alerts with severity tags.
6. **Malware & Quarantine Tab:** On-demand path scanner, quarantine vault manager, and file restoration interface.
7. **FIM Tab:** Baseline management, manual audit triggers, and real-time modification log.
8. **DLP Tab:** Sensitive data inspection, exfiltration attempt logs, and removable USB tracking.
9. **OpenEDR Tab:** OpenEDR service health, live kernel telemetry viewer, and Emergency Host Isolation button.
10. **Agent Package Builder Dialog:** Accessible via the top toolbar button **"Build Agent Package..."**.

---

## Cryptographic Attestation & Anti-Tamper

To protect against agent tampering or supply-chain trojanization, Server-EDR maintains authoritative SHA-256 digests in [`Checksums`](./Checksums):
- `agents/linux/agent_core.py`
- `agents/windows/Agent-Core.ps1`
- `Server.py`

When an endpoint connects, it computes its active script/memory digest and submits it during attestation. The server validates the digest against `Checksums`. Any discrepancy immediately triggers a high-severity security alert and marks the endpoint as `Tampered`.

---

## Running the Automated Test Suite

The platform includes an automated unit, integration, and security validation test suite:

```bash
# Execute the complete test suite (100 tests):
python -m unittest discover -s . -p "test_*.py" -v

# Individual Test Suites:
python test_defense_suite.py        # Defense capabilities & framing (21 tests)
python test_server_config.py        # Server setup wizard & TLS generation (9 tests)
python test_linux_agent_config.py   # Linux dynamic config & validation (14 tests)
python test_windows_agent_config.py # Windows dynamic config & validation (13 tests)
python test_package_builder_gui.py  # Server GUI & CLI package builders (7 tests)
python test_linux_installation.py   # Linux service installer & systemd (7 tests)
python test_windows_installation.py # Windows service installer & SCM (7 tests)
python test_package_validation.py   # Archive structure & negative tests (8 tests)
python test_modular_agents.py       # Modular live agent integration (10 tests)
python test_windows_agent.py        # Windows agent integration & anti-tamper (4 tests)
```

---

## Documentation & Security Policies

- [Enterprise Deployment Guide](./docs/DEPLOYMENT_GUIDE.md) — Comprehensive runbook for enterprise rollouts, mass deployments, and troubleshooting.
- [Operational Security Guide (OpSec)](./docs/OPERATIONAL_SECURITY.md) — Threat models, attestation verification, key rotation, and incident playbooks.
- [Release Notes & Checklist](./RELEASE_NOTES.md) — Release notes for v1.1.0 and pre-deployment release verification checklists.
- [Security Policy](./SECURITY.md) — Vulnerability reporting guidelines and coordinated disclosure policy.

---

## Requirements & License

- **Management Server:** Python 3.8+ (Linux or Windows; optional `cryptography` library).
- **Linux Endpoints:** Python 3.6+ (pure standard library; zero third-party packages required).
- **Windows Endpoints:** Windows 10/11 or Windows Server 2016+ with PowerShell 5.1+.
- **License:** GNU General Public License v3.0 (GPL-3.0). For authorized defensive and administrative operations only.
