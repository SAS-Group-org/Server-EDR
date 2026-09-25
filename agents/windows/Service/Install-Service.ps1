# ============================================================
#  Install-Service.ps1 - Registers Server-EDR as a Windows Service (Option A)
# ============================================================

param(
    [string]$ServiceName = "ServerEdrDefenseSensor",
    [string]$DisplayName = "Server-EDR Endpoint Defense Sensor",
    [string]$ServerHost  = "",
    [int]$ServerPort     = 0,
    [string]$PSK         = ""
)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
               [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Administrator privileges are required to install Windows Services."
    exit 1
}

$PSScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$WrapperScript = Join-Path $PSScriptDir "ServiceWrapper.ps1"

if (-not (Test-Path $WrapperScript)) {
    Write-Error "ServiceWrapper.ps1 not found at $WrapperScript"
    exit 1
}

# Persist environment variables if specified
if ($ServerHost) { [Environment]::SetEnvironmentVariable("EDR_SERVER_HOST", $ServerHost, "Machine") }
if ($ServerPort -gt 0) { [Environment]::SetEnvironmentVariable("EDR_SERVER_PORT", [string]$ServerPort, "Machine") }
if ($PSK) { [Environment]::SetEnvironmentVariable("EDR_PSK", $PSK, "Machine") }

# Stop existing service if already running
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "[*] Service '$ServiceName' already exists. Stopping and removing old instance..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

$pwshExe = (Get-Process -Id $PID).Path
$binPath = "`"$pwshExe`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$WrapperScript`""

Write-Host "[*] Creating Windows Service '$ServiceName' via sc.exe (Option A)..."
$createOutput = sc.exe create $ServiceName binPath= $binPath start= auto DisplayName= $DisplayName
Write-Host $createOutput

Write-Host "[*] Configuring service description..."
sc.exe description $ServiceName "Continuous OpenEDR telemetry streaming, FIM, DLP, and threat defense sensor." | Out-Null

Write-Host "[*] Configuring service watchdog failure recovery actions..."
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/60000 | Out-Null

Write-Host "[*] Starting Windows Service '$ServiceName'..."
try {
    Start-Service -Name $ServiceName -ErrorAction Stop
    $st = (Get-Service -Name $ServiceName).Status
    Write-Host "[+] Service successfully installed and started! Status: $st"
} catch {
    Write-Warning "[!] Service created, but start returned: $($_.Exception.Message)"
}
