# Security Policy & Operational Security Guidance

## 1. Supported Versions

### | Version | Supported          | Security Updates |
### | 2.0.0   | :white_check_mark: | Active support   |
### | 1.1.x    | :x:                | Unsupported      |
### | 1.0.x    | :x:                | Unsupported      |
### | < 1.0   | :x:                | Unsupported      |

---

## 2. Reporting a Vulnerability

If you discover a security vulnerability in the Server-EDR platform or its endpoint sensors, please report it via encrypted email to:

**Security Team:** `whitehat@SAS-Group.org`

- Please include a detailed description of the vulnerability, reproduction steps, affected operating systems, and proof-of-concept payloads or packet captures.
- We aim to acknowledge receipt within 24 hours and provide an initial assessment within 72 hours.
- Coordinated vulnerability disclosure (CVD) timelines typically observe a 90-day grace period before public announcement.

---

## 3. Threat Model & Security Architecture

Server-EDR is built on a zero-trust endpoint-to-server security architecture designed to operate effectively in untrusted or adversarial network environments.

### 3.1 Trust Boundaries
- **C2 Network Boundary:** Untrusted network transport between endpoint agents and the management server. All communication is wrapped in TLS 1.2+ with pinned server certificates and authenticated using mutual HMAC-SHA256 challenges.
- **Endpoint Agent Execution Boundary:** Operates with elevated privileges (`root` on Linux, `NT AUTHORITY\SYSTEM` on Windows) to perform defense operations (memory scanning, minifilter hooks, process termination, packet filtering). Configuration files and scripts must be protected against local privilege escalation and tampering.
- **Server Administration Boundary:** The management console has administrative control over all connected endpoints. The server listening port, configuration store (`server_config.json`), TLS private keys, and pre-shared keys must be isolated from unauthorized network and user access.

---

## 4. Operational Security Guidance

### 4.1 Cryptographic Identity & Transport Security

1. **Certificate Pinning:**
   - Server-EDR uses explicit SHA-256 certificate thumbprint pinning rather than relying on public certificate authorities (CAs).
   - This eliminates risks associated with rogue CAs, expired intermediate chains, or TLS-intercepting enterprise forward proxies.
   - Always ensure the pinned fingerprint deployed to endpoints matches the output of `edr_fingerprint.txt` on the management server.

2. **Pre-Shared Key (PSK) Management:**
   - The PSK is used for HMAC-SHA256 mutual challenge-response authentication.
   - The server automatically generates a 32-byte (256-bit) cryptographically strong PSK on first run using `secrets.token_hex(32)`.
   - **Rotation Procedure:**
     1. Generate a new PSK on the server.
     2. Update the endpoint configurations (`/etc/sas-edr/agent_config.json` or `$env:ProgramData\Server-EDR\agent_config.json`).
     3. Restart the endpoint services.
     4. Update `server_config.json` and restart the management server.

3. **TLS Certificate Rotation:**
   - Standard generated certificates are valid for 10 years. In enterprise environments requiring annual rotation:
     1. Generate new certificate/key pairs via `Server.py --force-wizard` or an internal PKI.
     2. Pre-stage the new SHA-256 fingerprint in agent configurations.
     3. Deploy the new certificate on the server and reload.

### 4.2 Local Filesystem Security & Least Privilege

1. **Linux File System Permissions:**
   - Configuration Directory: `/etc/sas-edr/` must be owned by `root:root` with mode `0700` (`drwx------`).
   - Configuration Files: `/etc/sas-edr/agent_config.json` and `server-edr.env` must be mode `0600` (`-rw-------`).
   - Systemd Service: `/etc/systemd/system/server-edr.service` must be owned by `root:root` mode `0644`.

2. **Windows NTFS Discretionary Access Controls (DACLs):**
   - Configuration Directory: `C:\ProgramData\Server-EDR\` must disable DACL inheritance.
   - Access Permissions: Explicitly grant Full Control (`(F)`) exclusively to:
     - `NT AUTHORITY\SYSTEM` (`*S-1-5-18`)
     - `BUILTIN\Administrators` (`*S-1-5-32-544`)
   - Standard user accounts, `Users`, and `Authenticated Users` must have all read, write, and execute permissions removed.

3. **Management Server Storage:**
   - The server configuration `server_config.json`, `edr_server.key`, and `edr_psk.txt` contain critical security secrets.
   - Restrict access strictly to the administrative user running the management server daemon.

### 4.3 Script Integrity & Cryptographic Attestation

To prevent attacker-induced tampering or trojanization of EDR agent scripts:
- **Baseline Digests:** Official cryptographic SHA-256 hashes are maintained in `Checksums`.
- **Runtime Attestation:** During registration, endpoints compute their in-memory/on-disk SHA-256 digests and submit them to the server for verification against `Checksums`.
- **Tamper Detection:** If an agent's hash does not match the baseline, the server issues a high-priority security tamper alert and flags the agent as `Tampered` in the console.

### 4.4 Emergency Network Containment (Host Isolation)

Server-EDR provides emergency host containment (`isolate_host`) to sever an endpoint's network connectivity during active security incidents:
- **Containment Rules:** Drops all inbound and outbound traffic via `netsh advfirewall` (Windows) or `iptables` (Linux).
- **C2 Invariant:** The agent explicitly allows bidirectional traffic to the management server IP and port, preserving remote investigation and response capabilities.
- **Fail-Safe Restoration:** Reversing isolation (`isolate_host false`) restores normal network routing and firewall states without rebooting the host.

### 4.5 Audit Logging & Monitoring

- **Audit Trail:** All administrative actions, commands dispatched, and authentication attempts are logged to `edr_audit.log`.
- **Log Rotation:** The audit log automatically rotates when it reaches 10 MB, maintaining up to 5 historical archives.
- **SIEM Forwarding:** Forward `edr_audit.log` and endpoint security event alerts to an enterprise SIEM (Splunk, Elastic, Microsoft Sentinel) via Syslog, Fluentbit, or Windows Event Forwarding.
