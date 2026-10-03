# Server-EDR Enterprise Deployment & Operations Guide

This guide provides step-by-step instructions for deploying, configuring, and operating Server-EDR across enterprise server and workstation fleets.

---

## 1. Prerequisites & System Requirements

### Management Server
- **Operating System:** Linux (Ubuntu 20.04+, Debian 11+, RHEL/Rocky 8+) or Windows Server 2016+ / Windows 10/11.
- **Python Runtime:** Python 3.8+ with standard libraries (`tkinter`, `ssl`, `json`, `hashlib`, `secrets`, `socket`).
- **Cryptographic Library (Recommended):** `pip install cryptography` for native 4096-bit RSA certificate generation (pure-Python fallback available).
- **Network Connectivity:** Static IPv4/IPv6 address or resolvable FQDN. Inbound TCP port 4444 (or custom port) open to agent networks.

### Linux Endpoint Agent
- **Operating System:** Any modern Linux distribution (Ubuntu, Debian, CentOS, RHEL, Fedora, Rocky, Alpine).
- **Python Runtime:** Python 3.6+ (pure standard library; zero third-party `pip` dependencies).
- **Init System:** Systemd (or standalone background process).
- **Privileges:** `root` (required for FIM, process termination, OpenEDR logs, and firewall isolation).

### Windows Endpoint Agent
- **Operating System:** Windows 10, Windows 11, Windows Server 2016, 2019, 2022, 2025.
- **PowerShell Runtime:** Windows PowerShell 5.1+ or PowerShell Core 7+.
- **Privileges:** Local Administrator / `NT AUTHORITY\SYSTEM` (required for service installation, minifilter hooks, and firewall rules).

---

## 2. Server First-Run Setup

### 2.1 Interactive Setup Wizard
On the initial launch without pre-existing configuration, the server automatically enters setup wizard mode:

```bash
python Server.py
```

The wizard will prompt for:
1. **Listen Host:** `0.0.0.0` (all interfaces) or specific IP.
2. **Listen Port:** Default `4444`.
3. **Pre-Shared Key (PSK):** Press Enter to auto-generate a secure 32-byte hex key, or enter an existing key.
4. **TLS Certificates:** Auto-generate self-signed 4096-bit RSA identity, or specify paths to existing `.crt` and `.key` files.

### 2.2 Headless / Automated Deployment
For automated deployments (Docker, Ansible, Terraform), use the non-interactive CLI flags:

```bash
python Server.py \
  --init \
  --non-interactive \
  --listen-host 0.0.0.0 \
  --listen-port 4444
```

To supply specific pre-existing credentials:
```bash
python Server.py \
  --init \
  --non-interactive \
  --listen-host 192.168.1.100 \
  --listen-port 4444 \
  --psk 4f8a9b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a \
  --cert /path/to/server.crt \
  --key /path/to/server.key
```

### 2.3 Generated Files & Permissions
The server generates:
- `server_config.json`: Master server configuration (permissions set to `0600` on Linux, restricted DACL on Windows).
- `edr_server.crt`: TLS certificate presented during endpoint handshakes.
- `edr_server.key`: Private key (keep secure, never distribute to endpoints).
- `edr_psk.txt`: Pre-shared key for HMAC authentication.
- `edr_fingerprint.txt`: SHA-256 certificate thumbprint used by agents for pinning.

---

## 3. Generating Agent Distribution Packages

Server-EDR includes an automated package builder that packages agent code, dependencies, and pre-injected server settings into production-ready deployment archives.

### 3.1 GUI Package Builder
1. Launch the Server console: `python Server.py`.
2. Click the **"Build Agent Package..."** button in the toolbar.
3. Select the target platform: **Linux (.tar.gz)**, **Windows (.zip)**, or **Both Platforms**.
4. The dialog automatically pre-fills the Server Host, Port, PSK, and Certificate Fingerprint.
5. Optionally specify an **Agent Group** (e.g., `Production-Web`, `Database-Cluster`) and **Polling Interval**.
6. Select the output destination directory and click **"Generate Package(s)"**.

### 3.2 Headless CLI Package Builder
Packages can be built from the command line without opening the GUI:

```bash
# Build both Linux and Windows packages:
python Server.py --build-package all --package-output ./dist

# Build Linux package with custom group and server address:
python Server.py \
  --build-package linux \
  --package-output ./dist \
  --package-host 192.168.1.100 \
  --package-port 4444 \
  --package-group "Linux-Servers"

# Build Windows package:
python Server.py \
  --build-package windows \
  --package-output ./dist \
  --package-host 192.168.1.100 \
  --package-port 4444 \
  --package-group "Workstations"
```

---

## 4. Linux Endpoint Deployment

### 4.1 Quick Deployment from Distribution Archive
Transfer `server-edr-linux.tar.gz` to the target Linux host:

```bash
# Extract the distribution bundle:
tar -xzf server-edr-linux.tar.gz
cd server-edr-linux

# Test connectivity and dependencies without modifying system:
sudo ./install_agent.sh --test-only

# Install and start the hardened systemd service:
sudo ./install_agent.sh
```

### 4.2 Automated Installation Options
The installer script `install_agent.sh` (or `install_service.sh`) accepts flexible CLI overrides:

```bash
sudo ./install_agent.sh \
  --server-host 192.168.1.100 \
  --server-port 4444 \
  --psk 4f8a9b2c3d... \
  --fingerprint E3B0C44298FC1C14... \
  --group "Production" \
  --interval 5 \
  --install-dir /opt/sas-edr \
  --config-dir /etc/sas-edr
```

### 4.3 Service Management & Verification
```bash
# Check service status:
sudo systemctl status server-edr.service

# View live service logs:
sudo journalctl -u server-edr.service -f

# Stop / Start service:
sudo systemctl stop server-edr.service
sudo systemctl start server-edr.service

# Clean uninstallation:
cd /opt/sas-edr/agents/linux
sudo ./uninstall_service.sh
```

---

## 5. Windows Endpoint Deployment

### 5.1 Quick Deployment from Distribution Archive
Transfer `server-edr-windows.zip` to the target Windows host:

```powershell
# Extract the distribution zip:
Expand-Archive -Path server-edr-windows.zip -DestinationPath C:\Temp\server-edr-windows
cd C:\Temp\server-edr-windows

# Validate in DryRun mode:
powershell -ExecutionPolicy Bypass -File Install-Agent.ps1 -DryRun

# Install as Windows SCM Service:
powershell -ExecutionPolicy Bypass -File Install-Agent.ps1
```

### 5.2 Automated Installation Options
The PowerShell installer accepts CLI parameters for enterprise deployment tools (GPO, SCCM, Intune, Ansible):

```powershell
powershell -ExecutionPolicy Bypass -File Install-Agent.ps1 `
  -ServerHost "192.168.1.100" `
  -ServerPort 4444 `
  -PSK "4f8a9b2c3d..." `
  -CertThumbprint "E3B0C44298FC1C14..." `
  -AgentGroup "Corporate-Workstations" `
  -PollInterval 5 `
  -InstallDir "C:\Program Files\Server-EDR" `
  -ConfigDir "C:\ProgramData\Server-EDR"
```

### 5.3 Service Management & Verification
```powershell
# Verify service status:
Get-Service Server-EDR

# Inspect service configuration:
sc.exe qc Server-EDR

# Query service watchdog recovery settings:
sc.exe qfailure Server-EDR

# Clean uninstallation:
cd "C:\Program Files\Server-EDR\agents\windows\Service"
powershell -ExecutionPolicy Bypass -File Uninstall-Service.ps1 -Purge
```

---

## 6. Mass Deployment Examples

### 6.1 Ansible Playbook (Linux Fleet)
```yaml
---
- name: Deploy Server-EDR Linux Agent
  hosts: linux_servers
  become: yes
  tasks:
    - name: Copy EDR distribution archive
      ansible.builtin.copy:
        src: ./dist/server-edr-linux.tar.gz
        dest: /tmp/server-edr-linux.tar.gz
        mode: '0600'

    - name: Extract EDR archive
      ansible.builtin.unarchive:
        src: /tmp/server-edr-linux.tar.gz
        dest: /tmp/
        remote_src: yes

    - name: Install and activate EDR service
      ansible.builtin.command:
        cmd: ./install_agent.sh --no-test
        chdir: /tmp/server-edr-linux

    - name: Clean up temporary installer
      ansible.builtin.file:
        path: /tmp/server-edr-linux
        state: absent
```

### 6.2 PowerShell Script (Windows Fleet via GPO / Intune)
```powershell
$PackagePath = "\\fileserver\deployment\server-edr-windows.zip"
$TempDir     = "$env:TEMP\server-edr-windows"

if (!(Get-Service -Name "Server-EDR" -ErrorAction SilentlyContinue)) {
    Expand-Archive -Path $PackagePath -DestinationPath $TempDir -Force
    & powershell.exe -ExecutionPolicy Bypass -File "$TempDir\Install-Agent.ps1"
    Remove-Item -Recurse -Force $TempDir
}
```

---

## 7. Troubleshooting & Diagnostics

| Symptom | Probable Cause | Diagnostic / Resolution Step |
| :--- | :--- | :--- |
| `[!] TLS Pinning Failure: thumbprint mismatch` | The agent's pinned fingerprint does not match the server's TLS certificate. | Verify `edr_fingerprint.txt` on the server and update `agent_config.json` on the endpoint. |
| `[!] Authentication Rejected: PSK mismatch` | Endpoint PSK differs from server PSK. | Compare `edr_psk.txt` on server with `"psk"` entry in endpoint configuration. |
| Connection refused or timeout | Firewall blocking TCP port 4444 or wrong listen IP. | Check `netstat -tlpn \| grep 4444` on server; check local firewalls (`ufw`, `firewalld`, Windows Defender Firewall). |
| Linux agent fails with permissions error | Not running as `root`. | Run installer with `sudo` or execute systemd unit under `User=root`. |
| Windows service fails to start | ExecutionPolicy restriction or missing PowerShell wrapper. | Run `Set-ExecutionPolicy -Scope LocalMachine RemoteSigned -Force` and inspect event logs in `Application` log. |
| Server flags agent as `Tampered` | `agent_core.py` or `Agent-Core.ps1` hash does not match `Checksums`. | Ensure deployed scripts are authentic; verify digests using `sha256sum Checksums`. |
