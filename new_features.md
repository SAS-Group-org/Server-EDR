# **EDR Platform Engineering Plan: Web Portal (Port 8443\) & C2 Port Migration (Port 443\)**

This engineering document details the technical design, architectural modifications, and step-by-step implementation plan to migrate the Secure Endpoint Detection, Response & Defense platform from its desktop GUI to a headless Web Portal on port 8443 and shift default C2 agent communications to port 443\.

## **1\. Executive Summary & Goals**

### **Objectives**

> 1. **Server GUI Migration (Feature 1\)**: Transition the legacy desktop interface (App class using tkinter in Server.py) to an embedded, headless HTTPS REST and WebSocket Web Portal listening on port 8443\.  
> 2. **C2 Port Realignment (Feature 2\)**: Update the default listening and outgoing agent socket connection port across the server and all endpoint sensors (Linux and Windows) from port 4444 to HTTPS default port 443\.

## **2\. Target Network Architecture**

                                  \+-----------------------------------+  
                                  |         Web Browser Admin         |  
                                  \+-----------------------------------+  
                                                    |  
                                             HTTPS (Port 8443\)  
                                                    v  
\+---------------------------------------------------------------------------------------------------+  
| EDR Central Server (Server.py)                                                                    |  
|                                                                                                   |  
|  \+---------------------------------------+   \+-------------------------------------------------+  |  
|  | Web Portal Engine (HTTPS / WS / REST)  |   | Dual-Listener Infrastructure                    |  |  
|  | Port 8443                             |   | \- Web UI: 0.0.0.0:8443                          |  |  
|  | REST API & WebSocket Live Stream      |   | \- Agent C2 Server: 0.0.0.0:443                  |  |  
|  \+---------------------------------------+   \+-------------------------------------------------+  |  
|                                           |                                                       |  
|  \+---------------------------------------------------------------------------------------------+  |  
|  | Multi-Agent C2 Handler Engine                                                               |  |  
|  | TLS 1.2+ / HMAC-SHA256 Auth / Duplex Multiplexed Dispatcher                               |  |  
|  \+---------------------------------------------------------------------------------------------+  |  
\+---------------------------------------------------------------------------------------------------+  
                                     |            |  
                       TLS (Port 443)|            |TLS (Port 443\)  
                     \+---------------+            \+---------------+  
                     |                                            |  
                     v                                            v  
\+--------------------------------------+        \+--------------------------------------+  
| Linux Endpoint Sensor                |        | Windows Endpoint Sensor              |  
| (/opt/server-edr)                    |        | (C:\\Program Files\\Server-EDR)        |  
| \- Service: server-edr.service        |        | \- Service: ServerEdrDefenseSensor    |  
\+--------------------------------------+        \+--------------------------------------+

## **3\. Feature 1: Server GUI Migration to HTTPS Web Portal (Port 8443\)**

### **Architectural Changes**

* **Headless Decoupling**: Remove all tkinter imports and desktop window management loops (tk.Tk(), ttk.Treeview, scrolledtext) in Server.py to allow execution on headless Linux server hosts.  
* **Embedded Web Framework**: Integrate an async ASGI/WSGI web engine (such as FastAPI with Uvicorn or Flask with gevent) embedded directly into Server.py.  
* **Shared TLS Context**: Share the server's generated TLS certificate (edr\_server.crt) and key (edr\_server.key) across both the Web Portal (port 8443\) and the C2 socket engine (port 443).  
* **Console Feature Parity**: Port all 5 core endpoint defense management tabs to an HTML5/JavaScript Single Page Application (SPA) dashboard:  
  1. **Security Alerts**: Real-time unified feed for FIM, DLP, Malware, and OpenEDR alerts.  
  2. **Malware & Quarantine**: On-demand file system scanner and quarantine vault manager.  
  3. **File Integrity Monitoring (FIM)**: Baseline generation, manual integrity audits, and scope customization.  
  4. **Data Loss Prevention (DLP)**: Credit card (Luhn), SSN, API key detection, and exfiltration tracking.  
  5. **OpenEDR & Host Containment**: Kernel telemetry viewer, status health checks, and emergency host network isolation.

### **Server Configuration Updates (Server.py)**

Python  
\# Server.py Constants  
DEFAULT\_HOST      \= "0.0.0.0"  
DEFAULT\_C2\_PORT   \= 443       \# Migrated from 4444  
DEFAULT\_WEB\_PORT  \= 8443      \# Web Portal binding port  
MAX\_MSG\_BYTES     \= 50 \* 1024 \* 1024  
CERT\_FILE         \= "edr\_server.crt"  
KEY\_FILE          \= "edr\_server.key"  
PSK\_FILE          \= "edr\_psk.txt"

### **Web API & WebSocket Route Specifications**

| Protocol | Method | Route Path | Purpose / Description |
| :---- | :---- | :---- | :---- |
| **HTTP** | POST | /api/v1/auth/login | Authenticates administrator credentials and issues JWT token. |
| **HTTP** | GET | /api/v1/agents | Retrieves list of active registered endpoints, OS details, IP, and attestation status. |
| **HTTP** | GET | /api/v1/alerts | Queries security events with filtering by severity (CRITICAL, HIGH, MEDIUM) or subsystem. |
| **HTTP** | POST | /api/v1/commands/dispatch | Dispatches execution commands (isolate\_host, malware\_scan, fim\_init, quarantine) to targeted agents. |
| **HTTP** | GET | /api/v1/quarantine | Lists files currently isolated in endpoint quarantine vaults. |
| **WebSocket** | WS | /ws/live-stream | Real-time bi-directional streaming for live alerts, telemetry events, and agent heartbeats. |

## **4\. Feature 2: Default C2 Communication Port Migration (Port 443\)**

### **Required Code Modifications**

#### **1\. Server Core (Server.py)**

Modify the default command-line argument parser to bind port 443 for C2 agent connections:

Python  
\# Server.py  
def main():  
    p \= argparse.ArgumentParser(description="Secure Endpoint Detection, Response & Defense Server")  
    p.add\_argument("--host", default=DEFAULT\_HOST, help\="Bind address (default: 0.0.0.0)")  
    p.add\_argument("--port", type\=int, default=443, help\="C2 TCP port (default: 443)") \# Updated from 4444  
    p.add\_argument("--web-port", type\=int, default=8443, help\="Web Portal port (default: 8443)")

#### **2\. Linux Agent Core (agents/linux/modules/common.py)**

Update fallback environment configuration constants:

Python  
\# agents/linux/modules/common.py  
SERVER\_HOST \= os.environ.get("EDR\_SERVER\_HOST", os.environ.get("RAT\_SERVER\_HOST", "127.0.0.1"))  
SERVER\_PORT \= int(os.environ.get("EDR\_SERVER\_PORT", os.environ.get("RAT\_SERVER\_PORT", "443"))) \# Updated default from 4444 to 443

#### **3\. Windows Agent Core (agents/windows/Agent-Core.ps1)**

Update parameter defaults and environment variable resolution logic:

PowerShell  
\# agents/windows/Agent-Core.ps1  
param(  
    \[string\]\$ServerHost \= "",  
    \[int\]\$ServerPort    \= 443,  \# Updated default from 0 / 4444 to 443  
    \[string\]\$PSK        \= ""  
)

if (\$ServerPort \-le 0) {  
    \$ServerPort \= if (\$env:EDR\_SERVER\_PORT) { \[int\]\$env:EDR\_SERVER\_PORT } else { 443 } \# Updated default to 443  
}

#### **4\. Service Deployments & Low-Port Socket Binding**

* **Linux Service Configuration (/etc/server-edr/agent.env)**:  
  Ini, TOML  
  EDR\_SERVER\_HOST\=127.0.0.1  
  EDR\_SERVER\_PORT\=443  
  EDR\_PSK\=PASTE\_PSK\_HERE  
  EDR\_USE\_TLS\=1

* **Linux Low-Port Privilege Grant**: Because port 443 is a privileged system port (\<1024), configure network capabilities on the Python runtime or execute the server process with root privileges:  
  Bash  
  sudo setcap 'cap\_net\_bind\_service=+ep' \$(which python3)

* **Windows Service Environment Setting (agents/windows/Service/Install-Service.ps1)**: Ensure default system environment variables are registered during service installation:  
  PowerShell  
  if (\$ServerPort \-gt 0) {   
      \[Environment\]::SetEnvironmentVariable("EDR\_SERVER\_PORT", \[string\]\$ServerPort, "Machine")   
  } else {  
      \[Environment\]::SetEnvironmentVariable("EDR\_SERVER\_PORT", "443", "Machine")  
  }

## **5\. Implementation Roadmap & Milestones**

Phase 1: Port 443 C2 Migration (Week 1\)  
 ├── Update C2 default listening port in Server.py to 443  
 ├── Update default port constants in Linux common.py and Windows Agent-Core.ps1\[cite: 9, 21\]  
 ├── Modify install scripts (install\_service.sh, Install-Service.ps1) for Port 443\[cite: 11, 15\]  
 └── Configure socket privileges (cap\_net\_bind\_service) for non-root execution

Phase 2: Web Portal Backend Development (Week 2\)  
 ├── Remove Tkinter GUI components (App class) from Server.py\[cite: 6\]  
 ├── Integrate async HTTP server framework bound to port 8443  
 ├── Implement JWT authentication and session management  
 └── Build REST endpoints for agent listing, command dispatch, and alerts\[cite: 6\]

Phase 3: Web Portal Frontend & WebSockets (Week 3\)  
 ├── Build HTML5/CSS3/JS Single Page Application (SPA)  
 ├── Implement 5 core management tabs (Alerts, Malware, FIM, DLP, OpenEDR)\[cite: 6, 8\]  
 ├── Integrate WebSocket client for real-time alert and telemetry streaming\[cite: 6\]  
 └── Conduct multi-browser compatibility testing

Phase 4: End-to-End Validation & Verification (Week 4\)  
 ├── Test agent registration and authentication over Port 443\[cite: 6\]  
 ├── Verify Web UI access over HTTPS on Port 8443\[cite: 6\]  
 ├── Validate TLS certificate pinning and fingerprint verification\[cite: 6, 8\]  
 └── Perform firewall and network isolation testing\[cite: 6, 8\]

## **6\. Component Modification Summary**

| Target File | Feature | Modification Required |
| :---- | :---- | :---- |
| Server.py | Features 1 & 2 | Remove tkinter GUI; add embedded HTTP/WS server on port 8443; update default C2 port to 443\[cite: 6\]. |
| agents/linux/modules/common.py | Feature 2 | Update SERVER\_PORT default value from 4444 to 443\. |
| agents/windows/Agent-Core.ps1 | Feature 2 | Update \$ServerPort parameter default and env variable fallback to 443\. |
| agents/linux/install\_service.sh | Feature 2 | Update sample environment file default port to 443\[cite: 11\]. |
| agents/windows/Service/Install-Service.ps1 | Feature 2 | Update default machine environment variable registration for port 443\. |
| README.md | Features 1 & 2 | Update operational documentation and port reference matrix. |

