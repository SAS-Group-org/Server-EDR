#!/usr/bin/env bash
# ==============================================================================
# Server-EDR Linux Agent - Service Installation & Automation Script
#
# Automated installation, configuration under /etc/sas-edr/, and systemd service
# registration for the Server-EDR Linux Agent.
# ==============================================================================

set -e

# Default installation configuration
INSTALL_DIR="/opt/server-edr/agent"
CONFIG_DIR="/etc/sas-edr"
LOG_DIR="/var/log/server-edr"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_NAME="server-edr"

CONFIG_FILE=""
SERVER_HOST=""
SERVER_PORT=""
PSK=""
CERT_FINGERPRINT=""
USE_TLS=1
START_SERVICE=1
FORCE=0
DRY_RUN=0

print_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Server-EDR Linux Agent - Service Installer & Automation

Options:
  -H, --server-host HOST       Server-EDR server hostname or IP address
  -p, --server-port PORT       Server-EDR server port (default: 443)
  -k, --psk KEY                Pre-shared authentication key (PSK)
  -f, --cert-fingerprint FP    Server TLS SHA-256 certificate fingerprint
      --use-tls                Enable TLS transport encryption (default: enabled)
      --no-tls                 Disable TLS transport encryption
  -c, --config-file FILE       Path to existing agent_config.json to install
      --install-dir DIR        Agent binaries & modules path (default: /opt/server-edr/agent)
      --config-dir DIR         Configuration directory (default: /etc/sas-edr)
      --log-dir DIR            Log output directory (default: /var/log/server-edr)
      --service-name NAME      systemd service unit name (default: server-edr)
      --no-start               Install and enable service without immediately starting it
      --force                  Overwrite existing configuration file if present
      --dry-run                Validate arguments and environment without changing system
  -h, --help                   Display this help message and exit

Examples:
  sudo $0 --server-host 192.168.1.50 --server-port 443 --psk "secret-token"
  sudo $0 -c /path/to/agent_config.json
  sudo $0 --dry-run
EOF
}

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -H|--server-host)
            SERVER_HOST="$2"
            shift 2
            ;;
        -p|--server-port)
            SERVER_PORT="$2"
            shift 2
            ;;
        -k|--psk)
            PSK="$2"
            shift 2
            ;;
        -f|--cert-fingerprint)
            CERT_FINGERPRINT="$2"
            shift 2
            ;;
        --use-tls)
            USE_TLS=1
            shift
            ;;
        --no-tls)
            USE_TLS=0
            shift
            ;;
        -c|--config-file)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --config-dir)
            CONFIG_DIR="$2"
            shift 2
            ;;
        --log-dir)
            LOG_DIR="$2"
            shift 2
            ;;
        --service-name)
            SERVICE_NAME="$2"
            shift 2
            ;;
        --no-start)
            START_SERVICE=0
            shift
            ;;
        --force)
            FORCE=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "[-] Error: Unknown option: $1" >&2
            print_usage
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=================================================================="
echo "    Server-EDR Linux Agent - Service Installer & Automation      "
echo "=================================================================="

# 1. Privilege Verification
if [[ "$EUID" -ne 0 && "$DRY_RUN" -eq 0 ]]; then
    echo "[-] Error: Root privileges required. Please execute with sudo or as root." >&2
    exit 1
fi

# 2. Python Runtime Discovery & Verification (>= 3.6 required)
echo "[*] Checking Python runtime..."
PYTHON_BIN=""
for cand in python3 /usr/bin/python3 /usr/local/bin/python3; do
    if command -v "$cand" >/dev/null 2>&1; then
        PYTHON_BIN="$cand"
        break
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    echo "[-] Error: python3 is not installed or not in PATH." >&2
    exit 1
fi

PY_VERSION=$("$PYTHON_BIN" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$("$PYTHON_BIN" -c "import sys; print(sys.version_info.major)")
PY_MINOR=$("$PYTHON_BIN" -c "import sys; print(sys.version_info.minor)")

echo "[+] Discovered Python $PY_VERSION at $PYTHON_BIN"

if [[ "$PY_MAJOR" -lt 3 ]] || [[ "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 6 ]]; then
    echo "[-] Error: Python 3.6 or higher is required. Found Python $PY_VERSION." >&2
    exit 1
fi

# 3. Dry-Run early exit if requested
if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[+] Dry-run environment checks completed successfully."
    echo "    Install dir: $INSTALL_DIR"
    echo "    Config dir:  $CONFIG_DIR"
    echo "    Service:     ${SERVICE_NAME}.service"
    exit 0
fi

# 4. Stop existing service if active
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        echo "[*] Stopping currently running ${SERVICE_NAME} service..."
        systemctl stop "${SERVICE_NAME}" || true
    fi
fi

# 5. Directory structure setup with hardened POSIX permissions
echo "[*] Initializing system directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"

# Security permissions:
# - Install dir: readable/executable by system
# - Config dir: strictly 0700 root only (protecting PSK and private credentials)
# - Log dir: 0750
chmod 0755 "$INSTALL_DIR"
chmod 0700 "$CONFIG_DIR"
chmod 0750 "$LOG_DIR"

# 6. Copy runtime agent files
echo "[*] Installing agent runtime files to $INSTALL_DIR..."
if [[ -f "$SCRIPT_DIR/agent_core.py" ]]; then
    cp -f "$SCRIPT_DIR/agent_core.py" "$INSTALL_DIR/"
    chmod 0755 "$INSTALL_DIR/agent_core.py"
else
    echo "[-] Error: agent_core.py not found in $SCRIPT_DIR" >&2
    exit 1
fi

if [[ -d "$SCRIPT_DIR/modules" ]]; then
    mkdir -p "$INSTALL_DIR/modules"
    cp -rf "$SCRIPT_DIR/modules/"* "$INSTALL_DIR/modules/"
    chmod -R 0755 "$INSTALL_DIR/modules"
fi

if [[ -f "$SCRIPT_DIR/agent_config.template.json" ]]; then
    cp -f "$SCRIPT_DIR/agent_config.template.json" "$CONFIG_DIR/"
    chmod 0644 "$CONFIG_DIR/agent_config.template.json"
fi

# 7. Install Configuration under /etc/sas-edr/ (Sub-issue #24)
TARGET_CONFIG="$CONFIG_DIR/agent_config.json"
TARGET_ENV="$CONFIG_DIR/server-edr.env"

echo "[*] Setting up configuration in $CONFIG_DIR..."

if [[ -n "$CONFIG_FILE" ]]; then
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "[-] Error: Specified config file '$CONFIG_FILE' does not exist." >&2
        exit 1
    fi
    echo "[*] Deploying configuration from $CONFIG_FILE to $TARGET_CONFIG..."
    cp -f "$CONFIG_FILE" "$TARGET_CONFIG"
    chmod 0600 "$TARGET_CONFIG"
elif [[ -f "$SCRIPT_DIR/agent_config.json" && ( ! -f "$TARGET_CONFIG" || "$FORCE" -eq 1 ) ]]; then
    echo "[*] Deploying package configuration to $TARGET_CONFIG..."
    cp -f "$SCRIPT_DIR/agent_config.json" "$TARGET_CONFIG"
    chmod 0600 "$TARGET_CONFIG"
elif [[ -f "$TARGET_CONFIG" && "$FORCE" -eq 0 ]]; then
    echo "[*] Preserving existing configuration at $TARGET_CONFIG (use --force to overwrite)."
else
    echo "[*] Generating $TARGET_CONFIG from deployment parameters..."
    HOST_VAL="${SERVER_HOST:-127.0.0.1}"
    PORT_VAL="${SERVER_PORT:-443}"
    PSK_VAL="${PSK:-PASTE_PSK_HERE}"
    FINGERPRINT_VAL="${CERT_FINGERPRINT:-}"
    TLS_BOOL="true"
    if [[ "$USE_TLS" -eq 0 ]]; then
        TLS_BOOL="false"
    fi

    cat <<EOF > "$TARGET_CONFIG"
{
  "server": {
    "host": "$HOST_VAL",
    "port": $PORT_VAL,
    "use_tls": $TLS_BOOL,
    "cert_fingerprint": "$FINGERPRINT_VAL",
    "reconnect_interval": 10,
    "max_reconnect_delay": 60
  },
  "auth": {
    "psk": "$PSK_VAL"
  },
  "agent": {
    "log_level": "INFO",
    "group_tag": "default",
    "polling_interval": 10,
    "heartbeat_interval": 10,
    "watchdog_enabled": true,
    "watchdog_interval": 3,
    "fim_enabled": true,
    "dlp_enabled": true,
    "dlp_block_transfers": false
  },
  "server_host": "$HOST_VAL",
  "server_port": $PORT_VAL,
  "psk": "$PSK_VAL",
  "cert_fingerprint": "$FINGERPRINT_VAL",
  "use_tls": $TLS_BOOL,
  "reconnect_secs": 10,
  "group_tag": "default"
}
EOF
    chmod 0600 "$TARGET_CONFIG"
fi

# Write systemd environment file with restrictive permissions (0600)
echo "[*] Writing service environment file to $TARGET_ENV..."
cat <<EOF > "$TARGET_ENV"
# Server-EDR Linux Agent Systemd Environment
EDR_CONFIG_FILE=$TARGET_CONFIG
EOF

if [[ -n "$SERVER_HOST" ]]; then
    echo "EDR_SERVER_HOST=$SERVER_HOST" >> "$TARGET_ENV"
fi
if [[ -n "$SERVER_PORT" ]]; then
    echo "EDR_SERVER_PORT=$SERVER_PORT" >> "$TARGET_ENV"
fi
if [[ -n "$PSK" ]]; then
    echo "EDR_PSK=$PSK" >> "$TARGET_ENV"
fi
if [[ -n "$CERT_FINGERPRINT" ]]; then
    echo "EDR_CERT_FINGERPRINT=$CERT_FINGERPRINT" >> "$TARGET_ENV"
fi
if [[ "$USE_TLS" -eq 0 ]]; then
    echo "EDR_USE_TLS=0" >> "$TARGET_ENV"
fi

chmod 0600 "$TARGET_ENV"

# 8. Validate configuration semantics
echo "[*] Validating agent configuration..."
if ! "$PYTHON_BIN" "$INSTALL_DIR/agent_core.py" --validate-config --config "$TARGET_CONFIG"; then
    echo "[!] Warning: Configuration validation reported issues. Review $TARGET_CONFIG." >&2
fi

# 9. Configure, Enable and Start systemd service (Sub-issue #22)
SERVICE_DEST="$SYSTEMD_DIR/${SERVICE_NAME}.service"

if command -v systemctl >/dev/null 2>&1; then
    echo "[*] Installing systemd service unit to $SERVICE_DEST..."
    cat <<EOF > "$SERVICE_DEST"
[Unit]
Description=Server-EDR Linux Agent Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$PYTHON_BIN -u $INSTALL_DIR/agent_core.py --config $TARGET_CONFIG
Restart=always
RestartSec=5s

# Security and Isolation Hardening
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=true

# Resource Limits
CPUQuota=30%
MemoryMax=512M
TasksMax=100

EnvironmentFile=-$CONFIG_DIR/server-edr.env
EnvironmentFile=-$CONFIG_DIR/agent.env
EnvironmentFile=-/etc/server-edr/server-edr.env
EnvironmentFile=-/etc/server-edr/agent.env
KillMode=mixed
TimeoutStopSec=10s

[Install]
WantedBy=multi-user.target
EOF

    chmod 0644 "$SERVICE_DEST"
    echo "[*] Reloading systemd manager configuration..."
    systemctl daemon-reload

    echo "[*] Enabling ${SERVICE_NAME}.service to automatically start on boot..."
    systemctl enable "${SERVICE_NAME}"

    if [[ "$START_SERVICE" -eq 1 ]]; then
        echo "[*] Starting ${SERVICE_NAME}.service..."
        systemctl restart "${SERVICE_NAME}" || systemctl start "${SERVICE_NAME}"
        sleep 1
        if systemctl is-active --quiet "${SERVICE_NAME}"; then
            echo "[+] Service ${SERVICE_NAME} is active and running!"
            systemctl status "${SERVICE_NAME}" --no-pager || true
        else
            echo "[!] Warning: Service ${SERVICE_NAME} failed to start or exited." >&2
            echo "    Recent logs from journalctl:"
            journalctl -u "${SERVICE_NAME}" -n 20 --no-pager 2>/dev/null || true
        fi
    else
        echo "[*] Service enabled to start on system boot (--no-start specified; service not started)."
    fi
else
    echo "[!] Notice: systemd not detected on this system. Agent is installed at $INSTALL_DIR."
    echo "    You can run the agent manually or with your supervisor:"
    echo "    $PYTHON_BIN $INSTALL_DIR/agent_core.py --config $TARGET_CONFIG"
fi

echo "=================================================================="
echo " [+] Server-EDR Linux Agent installation completed successfully! "
echo "     Config:  $TARGET_CONFIG"
echo "     Runtime: $INSTALL_DIR/agent_core.py"
if command -v systemctl >/dev/null 2>&1; then
    echo "     Service: ${SERVICE_NAME}.service (systemctl status ${SERVICE_NAME})"
fi
echo "=================================================================="
