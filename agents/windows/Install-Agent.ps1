# ============================================================
#  Install-Agent.ps1 - Top-Level Server-EDR Windows Agent Installer
#  Delegates to Service\Install-Service.ps1 for complete registration and setup
# ============================================================

$PSScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ServiceInstaller = Join-Path $PSScriptDir "Service\Install-Service.ps1"

if (Test-Path $ServiceInstaller) {
    & $ServiceInstaller @args
} else {
    Write-Error "[-] Install-Service.ps1 not found at $ServiceInstaller"
    exit 1
}
