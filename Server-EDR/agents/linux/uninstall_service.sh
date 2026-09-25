#!/bin/bash
# Clean removal script for Server-EDR Agent

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

echo "[*] Stopping and disabling server-edr service..."
systemctl stop server-edr 2>/dev/null
systemctl disable server-edr 2>/dev/null

echo "[*] Removing systemd service..."
rm -f /etc/systemd/system/server-edr.service
systemctl daemon-reload

echo "[*] Do you want to remove agent files and config? (y/N)"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])+$ ]]; then
    echo "[*] Removing /opt/server-edr and /etc/server-edr..."
    rm -rf /opt/server-edr
    rm -rf /etc/server-edr
else
    echo "[*] Retaining agent files and config."
fi

echo "[+] Uninstall complete."
