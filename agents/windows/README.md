# Server-EDR Windows Endpoint Defense Sensor

## Overview
The Server-EDR Windows Agent is a lightweight, modular endpoint defense sensor implemented in PowerShell. It streams telemetry, enforces File Integrity Monitoring (FIM), provides Data Loss Prevention (DLP), scans for suspicious malware processes, and optionally integrates with OpenEDR.

## Directory Structure
```
Server-EDR-Agent-Windows-v1.0.0/
├── Agent-Core.ps1              # Main agent sensor engine
├── agent_config.json.template  # Reference configuration schema
├── agent_config.json           # Injected configuration (optional)
├── Modules/                    # PowerShell subsystem modules
│   ├── Common.psm1             # Protocol, crypto, and dynamic config loader
│   ├── FIM.psm1                # File integrity monitoring and self-protection
│   ├── DLP.psm1                # Removable drive tracking and data loss prevention
│   ├── Malware.psm1            # Process inspection and heuristic threat scanner
│   ├── OpenEDR.psm1            # OpenEDR security service integration
│   └── Executor.psm1           # Remote command execution and telemetry sink
├── Service/                    # Windows Service integration
│   ├── ServiceWrapper.ps1      # Process supervisor and watchdog runner
│   ├── Install-Service.ps1     # Automated Windows service installer
│   └── Uninstall-Service.ps1   # Clean uninstaller script
├── MANIFEST.json               # SHA-256 package manifest
├── checksums.sha256            # Cryptographic component checksums
└── README.md                   # This documentation
```

## Configuration

The agent dynamically resolves configuration parameters with the following precedence:
1. **Command-Line Arguments** (`-ServerHost`, `-ServerPort`, `-PSK`, `-CertThumbprint`, `-UseTLSStr`, `-ConfigPath`)
2. **Configuration File** (`agent_config.json` in script directory, or at `$env:EDR_CONFIG_FILE` / `ProgramData\Server-EDR\agent_config.json`)
3. **Environment Variables** (`EDR_SERVER_HOST`, `EDR_SERVER_PORT`, `EDR_PSK`, `EDR_CERT_FINGERPRINT`, `EDR_USE_TLS`, or legacy `RAT_*`)
4. **Hardcoded Defaults** (`127.0.0.1:443`, TLS enabled, 10s reconnection interval)

### Standalone Validation and Connectivity Probe
```powershell
# Validate configuration file without connecting
powershell -ExecutionPolicy Bypass -File .\Agent-Core.ps1 -ValidateConfig -ConfigPath .\agent_config.json

# Probe connectivity to server endpoint
powershell -ExecutionPolicy Bypass -File .\Agent-Core.ps1 -CheckConnection -ServerHost 192.168.1.50 -ServerPort 443
```

## Running as a Background Windows Service
Run from an elevated PowerShell console (Run as Administrator):
```powershell
powershell -ExecutionPolicy Bypass -File .\Service\Install-Service.ps1 -ServerHost 192.168.1.50 -ServerPort 443 -PSK "YourEnrollmentKey"
```

To uninstall:
```powershell
powershell -ExecutionPolicy Bypass -File .\Service\Uninstall-Service.ps1
```
