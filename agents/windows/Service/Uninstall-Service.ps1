# ============================================================
#  Uninstall-Service.ps1 - Unregisters and Removes Windows Service
# ============================================================

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ServiceName = "ServerEdrDefenseSensor",
    [string]$InstallDir  = "$env:ProgramFiles\Server-EDR\Agent",
    [string]$ConfigDir   = "$env:ProgramData\Server-EDR",
    [switch]$Purge,
    [switch]$Force
)

Write-Host "============================================================"
Write-Host "    Server-EDR Windows Agent - Service Uninstaller          "
Write-Host "============================================================"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
               [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[-] Administrator privileges are required to uninstall Windows Services."
    exit 1
}

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    # Check legacy name
    $svc = Get-Service -Name "ServerRatDefenseSensor" -ErrorAction SilentlyContinue
    if ($svc) { $ServiceName = "ServerRatDefenseSensor" }
}

if ($svc) {
    Write-Host "[*] Stopping Windows Service '$ServiceName'..."
    try {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    } catch {}

    Write-Host "[*] Deleting service '$ServiceName' from SCM..."
    $res = sc.exe delete $ServiceName
    Write-Host $res
    Write-Host "[+] Windows Service '$ServiceName' successfully removed from Service Control Manager."
} else {
    Write-Host "[*] Service '$ServiceName' is not currently registered in SCM."
}

# Clean environment variables
Write-Host "[*] Cleaning machine environment variables..."
try {
    [Environment]::SetEnvironmentVariable("EDR_SERVER_HOST", $null, "Machine")
    [Environment]::SetEnvironmentVariable("EDR_SERVER_PORT", $null, "Machine")
    [Environment]::SetEnvironmentVariable("EDR_PSK", $null, "Machine")
    [Environment]::SetEnvironmentVariable("EDR_CERT_FINGERPRINT", $null, "Machine")
    [Environment]::SetEnvironmentVariable("EDR_USE_TLS", $null, "Machine")
    [Environment]::SetEnvironmentVariable("EDR_CONFIG_FILE", $null, "Machine")
} catch {
    Write-Warning "[!] Could not clean machine environment variables: $($_.Exception.Message)"
}

# Clean files if Purge is requested
if ($Purge -or $Force) {
    Write-Host "[*] Purging installed agent files and configuration..."
    $progFilesRoot = Split-Path -Parent $InstallDir
    if (Test-Path $InstallDir) {
        try { Remove-Item -Path $InstallDir -Recurse -Force | Out-Null } catch {}
    }
    if ($progFilesRoot -and (Test-Path $progFilesRoot) -and (Get-ChildItem $progFilesRoot).Count -eq 0) {
        try { Remove-Item -Path $progFilesRoot -Recurse -Force | Out-Null } catch {}
    }
    if (Test-Path $ConfigDir) {
        try { Remove-Item -Path $ConfigDir -Recurse -Force | Out-Null } catch {}
    }
    Write-Host "[+] Removed agent files and configuration directories."
}

Write-Host "============================================================"
Write-Host " [+] Server-EDR Windows Agent uninstallation complete.       "
Write-Host "============================================================"
