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

FORCE=0
for arg in "$@"; do
    if [[ "$arg" == "-y" || "$arg" == "--yes" || "$arg" == "--force" ]]; then
        FORCE=1
    fi
done

if [[ "$FORCE" -eq 1 ]]; then
    response="y"
else
    echo "[*] Do you want to remove agent files and config? (y/N)"
    read -r response
fi

if [[ "$response" =~ ^([yY][eE][sS]|[yY])+$ ]]; then
    echo "[*] Removing /opt/server-edr, /etc/sas-edr, and /etc/server-edr..."
    rm -rf /opt/server-edr
    rm -rf /etc/sas-edr
    rm -rf /etc/server-edr
    rm -rf /var/log/server-edr
else
    echo "[*] Retaining agent files and config."
fi

echo "[+] Uninstall complete."
