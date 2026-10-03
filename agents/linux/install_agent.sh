#!/usr/bin/env bash
# ==============================================================================
# Server-EDR Linux Agent Installer
# Automated installation wrapper delegating to install_service.sh
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SCRIPT_DIR/install_service.sh" ]]; then
    exec bash "$SCRIPT_DIR/install_service.sh" "$@"
else
    echo "[-] Error: install_service.sh not found in $SCRIPT_DIR" >&2
    exit 1
fi
