#!/bin/bash
# One-step installer for Server-EDR Agent

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

echo "[*] Stopping existing server-edr service if running..."
systemctl stop server-edr 2>/dev/null || true

echo "[*] Creating directories..."
mkdir -p /opt/server-edr
mkdir -p /etc/server-edr

echo "[*] Copying agent files..."
cp -r . /opt/server-edr/
chmod -R 0700 /opt/server-edr

echo "[*] Creating sample env file..."
if [ ! -f /etc/server-edr/agent.env ]; then
    cat <<EOF > /etc/server-edr/agent.env
EDR_SERVER_HOST=127.0.0.1
EDR_SERVER_PORT=4444
EDR_PSK=PASTE_PSK_HERE
EDR_USE_TLS=1
EOF
fi
chmod 0600 /etc/server-edr/agent.env

echo "[*] Installing systemd service..."
cp systemd/server-edr.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now server-edr

echo "[+] Install complete. Service status:"
systemctl status server-edr --no-pager
