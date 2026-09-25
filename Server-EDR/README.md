# SAS-EDR Secure Endpoint Detection, Response & Defense Platform — Multi-OS

Production-grade Remote Administration and Endpoint Detection & Defense platform with TLS 1.2+ encryption, HMAC authentication, asynchronous duplex security telemetry, and cross-platform support for Windows (PowerShell/.NET) and Linux (pure Python stdlib) sensors.

---

## Capabilities & Feature Matrix

| Feature | Windows Endpoint | Linux Endpoint | Management Server |
| :--- | :---: | :---: | :---: |
| **Encrypted C2 Transport** | TLS 1.2+ (Pinned) | TLS 1.2+ (Pinned) | Multi-threaded TLS Server |
| **Authentication** | HMAC-SHA256 Challenge | HMAC-SHA256 Challenge | Constant-time `compare_digest` |
| **Remote Admin Shell** | Interactive PowerShell | Interactive Bash | Terminal tab with history |
| **Process & File Management** | Live inspection & Kill | Live inspection & Kill | Processes & Remote Files tabs |
| **Asynchronous Event Bus** | Streaming `event` frames | Streaming `event` frames | Real-time Security Alerts tab |
| **Malware Prevention** | Windows Defender + Hashes | Hash DB + Heuristics + ClamAV | Remote Scanner & Threat Feed |
| **Quarantine Isolation Vault** | Stripped ACLs & `.meta` | `chmod 0600` & `.meta` | Quarantine Browser & Restore |
| **File Integrity Monitoring (FIM)** | Registry & Critical files | `/etc` configurations baseline | Baseline Init & Delta Audits |
| **Data Loss Prevention (DLP)** | Credit Card (Luhn), SSN, Keys | Credit Card (Luhn), SSN, Keys | In-band transfer inspection |
| **Removable Media Monitoring** | WMI Device Arrival Events | `/proc/mounts` USB Detection | Real-time USB attachment alert |
| **OpenEDR Integration** | `edrsvc` Minifilter Driver | eBPF / Service log tailer | Telemetry stream viewer |
| **Emergency Host Containment** | `netsh` C2-Pinning Firewall | `iptables` C2-Pinning Rules | One-click Host Isolation |

---

## Quick Start

### 1. Start the Server

```bash
python Server.py
# Or customize host/port/allowlist:
python Server.py --host 0.0.0.0 --port 4444
```

On first run, the server auto-generates:
- `edr_server.crt` / `edr_server.key` — Self-signed TLS certificate (10-year validity)
- `edr_psk.txt` — Pre-shared key (32-byte hex) for HMAC authentication
- `edr_fingerprint.txt` — SHA-256 certificate fingerprint for client-side pinning
- `edr_audit.log` — Rotating audit log (10 MB cap)

**Console Output:**
```text
============================================================
  PSK  →  4f8a9b2c3d...
  Cert fingerprint  →  E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
============================================================
```

### 2. Deploy Windows Defense Sensor (`agents/windows/`)

Edit configuration at the top of `agents/windows/Agent-Core.ps1` (or pass via environment variables):

```powershell
$ServerHost      = "192.168.1.50"    # Server IP / hostname
$ServerPort      = 4444
$PSK             = "PASTE_PSK_HERE"  # From edr_psk.txt
$CertThumbprint  = "PASTE_FP_HERE"   # From edr_fingerprint.txt
```

Launch the endpoint sensor interactively:
```powershell
powershell -ExecutionPolicy Bypass -File agents\windows\Agent-Core.ps1
```

*Automated / Headless Deployment via Environment Variables:*
```powershell
$env:EDR_SERVER_HOST = "192.168.1.50"
$env:EDR_SERVER_PORT = "4444"
$env:EDR_PSK         = "PASTE_PSK_HERE"
$env:EDR_CERT_FINGERPRINT = "PASTE_FP_HERE"
powershell -ExecutionPolicy Bypass -File agents\windows\Agent-Core.ps1
```

*Install as a Windows Service (SCM background service):*
```powershell
powershell -ExecutionPolicy Bypass -File agents\windows\Install-Service.ps1
# To remove:
# powershell -ExecutionPolicy Bypass -File agents\windows\Uninstall-Service.ps1
```

### 3. Deploy Linux Defense Sensor (`agents/linux/`)

Edit configuration in `agents/linux/agent_core.py` or `/etc/server-edr/agent.env`:

```python
SERVER_HOST      = "192.168.1.50"
SERVER_PORT      = 4444
PSK              = "PASTE_PSK_HERE"
CERT_FINGERPRINT = "PASTE_FP_HERE"
```

Run interactively on the Linux endpoint:
```bash
python3 agents/linux/agent_core.py
```

*Automated / Headless Deployment via Environment Variables:*
```bash
export EDR_SERVER_HOST="192.168.1.50"
export EDR_SERVER_PORT="4444"
export EDR_PSK="PASTE_PSK_HERE"
export EDR_CERT_FINGERPRINT="PASTE_FP_HERE"
python3 agents/linux/agent_core.py
```

*Install as a production systemd Service:*
```bash
cd agents/linux
sudo ./install_service.sh
# To uninstall:
# sudo ./uninstall_service.sh
```

---

## Defensive Subsystems & Security Architecture

### 1. Asynchronous Duplex Event Protocol
The wire protocol uses 4-byte Little-Endian length-prefixed JSON payloads over TLS 1.2+. The message bus multiplexes:
- `type: "response"`: Synchronous RPC replies correlated by `id`.
- `type: "event"`: Unsolicited real-time security alerts (FIM alterations, malware signatures, DLP exfiltration).
- `type: "telemetry"`: Batched system and OpenEDR kernel event logs.

### 2. Malware Prevention & Quarantine Vault
- **Hash Signature Scanning:** Compares file SHA-256 hashes against high-fidelity threat databases (e.g., EICAR, Mimikatz, common web shells).
- **Heuristic Process Auditing:** Flags processes executing from world-writable paths (`/tmp`, `/dev/shm`, `C:\Windows\Temp`) or running from unlinked/deleted binaries (`/proc/<pid>/exe (deleted)`).
- **Native AV Integrations:** Hooks into Windows Defender (`Get-MpThreatDetection` / `Start-MpScan`) on Windows and ClamAV on Linux.
- **Quarantine Vault:** Quarantining isolates malicious files into a restricted vault (`C:\ProgramData\Server-EDR\Quarantine` or `/var/run/.server_edr_quarantine`), strips execute permissions, appends `.quarantine`, and stores metadata (`.meta`) for forensic analysis or safe restoration.

### 3. File Integrity Monitoring (FIM)
- **Baseline Generator:** Indexes critical system paths (Linux: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/etc/hosts`; Windows: `hosts`, Registry Run keys, Startup folder).
- **Integrity Audits:** Detects `MODIFIED`, `DELETED`, and `ADDED` events using SHA-256 digests and emits immediate critical alerts.
- **Dynamic Scope:** Operators can add custom files or web directories to the FIM scope on the fly.

### 4. Data Loss Prevention (DLP)
- **Content Inspection Engine:** Analyzes text and file transfers for:
  - Credit Card numbers (Luhn-checksum validated)
  - US Social Security Numbers (SSN)
  - AWS Access Keys (`AKIA...`)
  - GitHub Personal Access Tokens (`ghp_...`)
  - RSA / OpenSSH Private Keys (`BEGIN PRIVATE KEY`)
  - JSON Web Tokens (JWT)
- **In-Band Transfer Protection:** Pre-transfer inspection hooks on `download` and `upload` prevent the C2 channel from being exploited for data exfiltration or malware staging.
- **Removable Media Detection:** Monitors WMI volume arrival events (Windows) and mount points (Linux) to detect unauthorized USB mass storage devices.

### 5. OpenEDR Integration & Incident Containment
- **Service & Driver Status:** Monitors the OpenEDR service (`edrsvc`) and kernel minifilter drivers (`fltmc filters`).
- **Telemetry Streaming:** Tails and ingests OpenEDR JSON event logs (`output_events`), streaming process creation, network, and file system activity back to the console.
- **Emergency Host Containment:** Operators can trigger **Host Isolation** with a single click. The agent applies firewall rules (`netsh` on Windows, `iptables` on Linux) dropping all network ingress/egress while strictly maintaining the secure Server-EDR C2 channel.

---

## Defensive Command Reference

| Command | Arguments | Description |
| :--- | :--- | :--- |
| `malware_scan` | `<path>` | Scans path for known malware signatures and heuristics |
| `quarantine` | `<path>` | Isolates file into quarantine vault and disables execute bits |
| `quarantine_list` | - | Lists all isolated files and quarantine metadata |
| `quarantine_restore` | `<quarantine_id>` | Restores quarantined file back to its original location |
| `fim_init` | - | Generates or rebuilds the SHA-256 integrity baseline |
| `fim_check` | - | Runs an immediate file integrity audit against the baseline |
| `fim_add_path` | `<path>` | Adds an additional file or directory to the FIM monitor scope |
| `dlp_scan` | `<path or text>` | Inspects file or string buffer for sensitive data patterns |
| `openedr_status` | - | Queries OpenEDR service status, driver, and log file size |
| `openedr_fetch_telemetry` | - | Fetches latest OpenEDR kernel event logs |
| `isolate_host` | `"true" / "false"` | Enforces or removes emergency network containment |

---

## Management Console UI Tabs

1. **Terminal Tab:** Remote interactive shell (`PS >` for Windows, `$ >` for Linux) with command history.
2. **Processes Tab:** Live process inspection, CPU/RAM usage, filter bar, and process termination (`kill`).
3. **Files Tab:** OS-aware remote file explorer, directory navigation, and secure upload/download.
4. **Sysinfo Tab:** Endpoint hardware specs, privileges (Root/Admin), and defense subsystem statuses.
5. **Security Alerts Tab:** Real-time unified feed of FIM, DLP, Malware, and OpenEDR alerts with severity color coding.
6. **Malware & Quarantine Tab:** On-demand path scanner, quarantine vault manager, and file restoration.
7. **FIM Tab:** Baseline management, manual audit triggers, and real-time modification log.
8. **DLP Tab:** Sensitive data inspection, leak logs, and removable USB storage tracking.
9. **OpenEDR Tab:** OpenEDR service health, live kernel telemetry viewer, and Emergency Host Isolation.

---

## Running the Automated Test Suite

A complete test suite is included to verify all endpoint defense capabilities, framing, and live sensor integration:

```bash
# Run unit & integration test suite:
python test_defense_suite.py

# Run live Windows agent integration test:
python test_windows_agent.py
```

---

## Requirements

- **Server:** Python 3.8+ (Tkinter included in standard library; optional `cryptography` package).
- **Windows Endpoint Sensor:** Windows 10/11 or Windows Server 2016+ with PowerShell 5.1+.
- **Linux Endpoint Sensor:** Python 3.6+ (pure standard library; zero external pip dependencies).

---

## License

GNU General Public License v3.0 / For authorized administrative and defensive security operations only.
