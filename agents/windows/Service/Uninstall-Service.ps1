# ============================================================
#  Uninstall-Service.ps1 - Unregisters and Removes Windows Service
# ============================================================

param(
    [string]$ServiceName = "ServerEdrDefenseSensor"
)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
               [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Administrator privileges are required to uninstall Windows Services."
    exit 1
}

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    # Check legacy name
    $svc = Get-Service -Name "ServerRatDefenseSensor" -ErrorAction SilentlyContinue
    if ($svc) { $ServiceName = "ServerRatDefenseSensor" }
}

if (-not $svc) {
    Write-Host "[*] Service '$ServiceName' is not installed."
    return
}

Write-Host "[*] Stopping Windows Service '$ServiceName'..."
try {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
} catch {}

Write-Host "[*] Deleting service '$ServiceName' from SCM..."
$res = sc.exe delete $ServiceName
Write-Host $res
Write-Host "[+] Windows Service '$ServiceName' successfully removed."
