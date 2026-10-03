# Server-EDR Operational Security (OpSec) & Incident Playbook

This document details operational security standards, key management policies, attestation verification, and incident response playbooks for operators running Server-EDR.

---

## 1. Network Architecture & Segmentation

Server-EDR endpoints establish outbound TLS 1.2+ connections to the management server over a single TCP port (default: `4444`). Endpoints never listen on network ports, minimizing external attack surface.

```
+-----------------------------------------------------------+
|                    Enterprise Network                     |
|                                                           |
|   +--------------------+          +-------------------+   |
|   | Linux Endpoint     |          | Windows Endpoint  |   |
|   | (systemd service)  |          | (SCM Service)     |   |
|   +---------+----------+          +---------+---------+   |
|             |                               |             |
|             | Outbound TLS 1.2+ (Pinned)    |             |
|             | HMAC-SHA256 Auth              |             |
|             +--------------+----------------+             |
|                            |                              |
|                            v (TCP 4444)                   |
|                 +----------------------+                  |
|                 | Server-EDR Console   |                  |
|                 | (Management Daemon)  |                  |
|                 +----------------------+                  |
+-----------------------------------------------------------+
```

### Firewall Configuration Best Practices
1. **Server Ingress:** Restrict inbound TCP 4444 on the server host exclusively to authorized internal subnets or VPN gateways using OS firewalls (`iptables` / `nftables` or Windows Advanced Firewall).
2. **Endpoint Egress:** Ensure egress filtering policies permit outbound connections from endpoints to the Server IP on TCP 4444.
3. **No Inbound Endpoint Ports:** Deny all incoming connections to endpoints by default; Server-EDR requires zero inbound listener ports.

---

## 2. Cryptographic Attestation & Supply Chain Defense

To prevent malicious tampering or unauthorized modification of agent scripts, Server-EDR implements cryptographic attestation:

### 2.1 The Baseline Checksums Store
The file `Checksums` at the repository root contains the authorized SHA-256 digests:
```text
a0463f0af790026f59197fdf06288521cccc41ba04f081c8ecb4c2026a612d60  agent_core.py
984af459b58a8dda14176dfc4c805e1ae0adc7738efdbf81087d73e14b77a069  Agent-Core.ps1
1c861e0bea3688b0c2e9142be318b32638a02f233a87894125b792617d48c8d6  Server.py
```

### 2.2 Verification Procedure
Before deploying or after updating:
```bash
# Verify all components match authorized baseline:
sha256sum -c Checksums
```

### 2.3 Runtime Attestation Verification
- When an agent connects, the server requests an attestation token.
- The agent hashes its active memory/script image and returns the digest.
- If the digest matches `Checksums`, the server marks the agent as `Verified`.
- If the digest differs, the server logs an alert:
  ```text
  [!] SECURITY WARNING: Agent at 192.168.1.150 failed cryptographic attestation!
      Expected: 984af459b58a8dda...
      Received: e3b0c44298fc1c14...
  ```
  The agent is flagged as `Tampered`, triggering an immediate investigation.

---

## 3. Pre-Shared Key (PSK) & Identity Lifecycle

### 3.1 PSK Storage & Protection
- Never commit `edr_psk.txt` or `server_config.json` to public version control repositories.
- On Windows endpoints, ensure NTFS permissions on `$env:ProgramData\Server-EDR\agent_config.json` only permit `SYSTEM` and `Administrators`.
- On Linux endpoints, verify permissions on `/etc/sas-edr/agent_config.json` are `0600` owned by `root:root`.

### 3.2 Zero-Downtime PSK Rotation Runbook
When rotating the authentication PSK across a running fleet:
1. **Prepare New Key:** Generate a new 32-byte hex string:
   ```python
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
2. **Update Fleet Configurations:** Push the new PSK to endpoints via Ansible/GPO into the configuration files.
3. **Restart Endpoints:** Restart endpoint services so they reload the new configuration.
4. **Update Server:** Update the `psk` entry in `server_config.json` and `edr_psk.txt`, then restart `Server.py`.

---

## 4. Incident Response & Emergency Host Isolation

When a high-severity incident is detected (e.g. ransomware staging, unauthorized credential dumping, data exfiltration), operators can immediately isolate the affected host.

### 4.1 Triggering Emergency Host Containment
1. Navigate to the **OpenEDR** tab or **Terminal** tab in the Server-EDR console.
2. Click **"Isolate Host"** (or execute command `isolate_host true`).
3. The endpoint firewall immediately drops all network traffic except the established C2 session to the Server-EDR management server.

### 4.2 Security Invariant: C2 Preservation
Host isolation enforces:
- Inbound traffic: `DROP ALL` (except TCP connection from Server IP).
- Outbound traffic: `DROP ALL` (except TCP traffic to Server IP on port 4444).
- DNS / NetBIOS / SMB: `DROP`.
- Lateral Movement: Completely blocked across LAN/WAN.

### 4.3 Post-Remediation Restoration
Once threat containment, forensic memory acquisition, and file remediation are completed:
1. Click **"Restore Network"** in the OpenEDR tab (or execute `isolate_host false`).
2. The agent restores original firewall rules and network connectivity.

---

## 5. Audit Logging & Forensics Preservation

1. **Log Location:** `edr_audit.log` records all operator actions, console commands, connection handshakes, and quarantine operations.
2. **Integrity Protection:** Set append-only flags on the audit log where supported (`chattr +a edr_audit.log`).
3. **Quarantine Vault Forensics:**
   - Isolated binaries are stored with execute permissions stripped and metadata sidecars (`.meta`) preserving:
     - Original file path
     - Timestamp of quarantine
     - SHA-256 hash of malicious payload
     - User/Process responsible for staging
   - Never inspect quarantined binaries directly on the endpoint; export them to an isolated sandbox analysis VM.
