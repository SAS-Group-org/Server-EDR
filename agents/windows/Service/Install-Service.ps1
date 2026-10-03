# ============================================================
#  Install-Service.ps1 - Automated Windows Service Installer & Preconfigured Agent Registration
# ============================================================

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ServiceName       = "ServerEdrDefenseSensor",
    [string]$DisplayName       = "Server-EDR Endpoint Defense Sensor",
    [string]$InstallDir        = "$env:ProgramFiles\Server-EDR\Agent",
    [string]$ConfigDir         = "$env:ProgramData\Server-EDR",
    [string]$ConfigFile        = "",
    [string]$ServerHost        = "",
    [int]$ServerPort           = 0,
    [string]$PSK               = "",
    [string]$CertThumbprint    = "",
    [string]$GroupTag          = "",
    [int]$PollingInterval      = 0,
    [int]$ReconnectSecs        = 0,
    [switch]$NoTLS,
    [switch]$NoStart,
    [switch]$InPlace,
    [switch]$ValidateConfig,
    [switch]$CheckConnection,
    [switch]$Force,
    [switch]$DryRun
)

Write-Host "============================================================"
Write-Host "    Server-EDR Windows Agent - Service Installer & Setup    "
Write-Host "============================================================"

# 1. Administrator Privilege Check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
               [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    if ($DryRun) {
        Write-Warning "[!] Running without Administrator privileges (DryRun mode)."
    } else {
        Write-Error "[-] Administrator privileges are required to install and register Windows Services."
        exit 1
    }
}

$PSScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceAgent  = Split-Path -Parent $PSScriptDir

# Import Common module for validation, config loading, and crypto functions
$CommonModPath = Join-Path $SourceAgent "Modules\Common.psm1"
if (-not (Test-Path $CommonModPath)) {
    # Check relative to PSScriptDir
    $CommonModPath = Join-Path $PSScriptDir "..\Modules\Common.psm1"
}

if (Test-Path $CommonModPath) {
    Import-Module $CommonModPath -Force -ErrorAction SilentlyContinue
}

# 2. Preconfigured Settings Resolution (Sub-issue #25)
Write-Host "[*] Resolving preconfigured agent settings..."
$sourceCfgPath = $null

if ($ConfigFile -and (Test-Path $ConfigFile)) {
    $sourceCfgPath = (Resolve-Path $ConfigFile).Path
    Write-Host "[*] Using specified configuration file: $sourceCfgPath"
} elseif (Test-Path (Join-Path $SourceAgent "agent_config.json")) {
    $sourceCfgPath = (Join-Path $SourceAgent "agent_config.json")
    Write-Host "[*] Discovered package preconfigured settings: $sourceCfgPath"
} elseif (Test-Path (Join-Path $PSScriptDir "agent_config.json")) {
    $sourceCfgPath = (Join-Path $PSScriptDir "agent_config.json")
    Write-Host "[*] Discovered local preconfigured settings: $sourceCfgPath"
} elseif ((Test-Path (Join-Path $ConfigDir "agent_config.json")) -and (-not $Force)) {
    $sourceCfgPath = (Join-Path $ConfigDir "agent_config.json")
    Write-Host "[*] Found existing system configuration: $sourceCfgPath"
}

# Load base configuration
if (Get-Command Load-AgentConfig -ErrorAction SilentlyContinue) {
    $cfg = Load-AgentConfig -ConfigPath $sourceCfgPath
} else {
    $cfg = [ordered]@{
        server_host     = "127.0.0.1"
        server_port     = 443
        psk             = ""
        cert_thumbprint = ""
        use_tls         = $true
        reconnect_secs  = 10
        group_tag       = "default"
        log_level       = "INFO"
    }
}

# Apply command line parameter overrides to preconfigured settings
if ($ServerHost)          { $cfg.server_host = $ServerHost }
if ($ServerPort -gt 0)    { $cfg.server_port = $ServerPort }
if ($PSK)                 { $cfg.psk = $PSK }
if ($CertThumbprint)      { $cfg.cert_thumbprint = $CertThumbprint }
if ($NoTLS)               { $cfg.use_tls = $false }
if ($GroupTag)            { $cfg.group_tag = $GroupTag }
if ($PollingInterval -gt 0) {
    $cfg.reconnect_secs = $PollingInterval
    $cfg.polling_interval = $PollingInterval
}
if ($ReconnectSecs -gt 0) { $cfg.reconnect_secs = $ReconnectSecs }

# 3. Semantic Validation of Preconfigured Settings
if (Get-Command Validate-AgentConfig -ErrorAction SilentlyContinue) {
    $val = Validate-AgentConfig -Config $cfg
    if (-not $val.IsValid) {
        Write-Error "[-] Configuration validation failed: $($val.Errors -join '; ')"
        if (-not $DryRun) { exit 1 }
    } else {
        Write-Host "[+] Preconfigured settings successfully validated."
    }
}

# 4. Optional Server Connectivity Verification
if ($CheckConnection) {
    Write-Host "[*] Testing connectivity to preconfigured server endpoint ${cfg.server_host}:${cfg.server_port}..."
    if (Get-Command Test-ServerConnectivity -ErrorAction SilentlyContinue) {
        $conn = Test-ServerConnectivity -ServerHost $cfg.server_host -ServerPort $cfg.server_port -TimeoutMs 4000
        if ($conn.Success) {
            Write-Host "[+] Connection test succeeded: $($conn.Message)"
        } else {
            Write-Warning "[!] Connection test warning: $($conn.Message)"
        }
    }
}

$maskedKey = if (Get-Command Get-MaskedSecret -ErrorAction SilentlyContinue) {
    Get-MaskedSecret $cfg.psk
} else {
    if ($cfg.psk.Length -gt 8) { $cfg.psk.Substring(0, 4) + "..." + $cfg.psk.Substring($cfg.psk.Length - 4) } else { "***" }
}

Write-Host "    Server Host:       $($cfg.server_host)"
Write-Host "    Server Port:       $($cfg.server_port)"
Write-Host "    TLS Enabled:       $($cfg.use_tls)"
Write-Host "    Cert Thumbprint:   $($cfg.cert_thumbprint)"
Write-Host "    PSK:               $maskedKey"
Write-Host "    Group Tag:         $($cfg.group_tag)"
Write-Host "    Reconnect Delay:   $($cfg.reconnect_secs)s"

if ($DryRun) {
    Write-Host "[+] DryRun mode active: configuration and validation verified without modifying system."
    exit 0
}

# 5. Determine Target Installation Directory & Deploy Files
if ($InPlace) {
    $TargetAgentDir = $SourceAgent
    Write-Host "[*] InPlace installation: using current directory: $TargetAgentDir"
} else {
    $TargetAgentDir = $InstallDir
    Write-Host "[*] Installing agent binaries and modules to $TargetAgentDir..."
    if (-not (Test-Path $TargetAgentDir)) {
        New-Item -ItemType Directory -Path $TargetAgentDir -Force | Out-Null
    }

    # Copy Core script
    Copy-Item (Join-Path $SourceAgent "Agent-Core.ps1") -Destination $TargetAgentDir -Force

    # Copy Modules
    $targetModules = Join-Path $TargetAgentDir "Modules"
    if (-not (Test-Path $targetModules)) {
        New-Item -ItemType Directory -Path $targetModules -Force | Out-Null
    }
    Copy-Item (Join-Path $SourceAgent "Modules\*") -Destination $targetModules -Recurse -Force

    # Copy Service folder
    $targetService = Join-Path $TargetAgentDir "Service"
    if (-not (Test-Path $targetService)) {
        New-Item -ItemType Directory -Path $targetService -Force | Out-Null
    }
    Copy-Item (Join-Path $PSScriptDir "*") -Destination $targetService -Recurse -Force

    # Copy template
    if (Test-Path (Join-Path $SourceAgent "agent_config.json.template")) {
        Copy-Item (Join-Path $SourceAgent "agent_config.json.template") -Destination $TargetAgentDir -Force
    }

    # Secure installation directory with NTFS ACLs
    try {
        & icacls.exe "`"$TargetAgentDir`"" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" "*S-1-5-32-545:(OI)(CI)(RX)" | Out-Null
    } catch {}
}

# 6. Save Registered Preconfigured Settings to ProgramData
if (-not (Test-Path $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
}

$targetCfg = Join-Path $ConfigDir "agent_config.json"
Write-Host "[*] Saving registered agent configuration to $targetCfg..."
if (Get-Command Save-AgentConfig -ErrorAction SilentlyContinue) {
    Save-AgentConfig -Config $cfg -FilePath $targetCfg | Out-Null
} else {
    $cfgJson = $cfg | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText($targetCfg, $cfgJson, [System.Text.Encoding]::UTF8)
    try {
        & icacls.exe "`"$targetCfg`"" /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" | Out-Null
    } catch {}
}

# Secondary fallback: Machine Environment Variables
try {
    [Environment]::SetEnvironmentVariable("EDR_CONFIG_FILE", $targetCfg, "Machine")
    if ($cfg.server_host) { [Environment]::SetEnvironmentVariable("EDR_SERVER_HOST", [string]$cfg.server_host, "Machine") }
    if ($ServerPort -gt 0) {
        [Environment]::SetEnvironmentVariable("EDR_SERVER_PORT", [string]$ServerPort, "Machine")
    } elseif ($cfg.server_port) {
        [Environment]::SetEnvironmentVariable("EDR_SERVER_PORT", [string]$cfg.server_port, "Machine")
    } else {
        [Environment]::SetEnvironmentVariable("EDR_SERVER_PORT", "443", "Machine")
    }
    if ($cfg.psk)         { [Environment]::SetEnvironmentVariable("EDR_PSK", [string]$cfg.psk, "Machine") }
    if ($cfg.cert_thumbprint) { [Environment]::SetEnvironmentVariable("EDR_CERT_FINGERPRINT", [string]$cfg.cert_thumbprint, "Machine") }
    [Environment]::SetEnvironmentVariable("EDR_USE_TLS", $(if ($cfg.use_tls) { "1" } else { "0" }), "Machine")
} catch {}

# 7. Configure Windows Service (Sub-issue #26)
$InstalledWrapper = Join-Path $TargetAgentDir "Service\ServiceWrapper.ps1"
if (-not (Test-Path $InstalledWrapper)) {
    $InstalledWrapper = Join-Path $PSScriptDir "ServiceWrapper.ps1"
}

# Stop and remove existing service if present
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $existing) {
    $existing = Get-Service -Name "ServerRatDefenseSensor" -ErrorAction SilentlyContinue
    if ($existing) { $ServiceName = "ServerRatDefenseSensor" }
}

if ($existing) {
    Write-Host "[*] Stopping and removing previous service instance '$ServiceName'..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

# Path to powershell.exe executable
$pwshExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
if (-not (Test-Path $pwshExe)) {
    $pwshExe = (Get-Process -Id $PID).Path
}

$binPath = "`"$pwshExe`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$InstalledWrapper`""

Write-Host "[*] Creating Windows Service '$ServiceName'..."
$createOutput = sc.exe create $ServiceName binPath= $binPath start= auto DisplayName= $DisplayName
Write-Host $createOutput

Write-Host "[*] Setting service description and recovery watchdog..."
sc.exe description $ServiceName "Continuous Server-EDR endpoint telemetry streaming, FIM, DLP, and threat defense sensor." | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/60000 | Out-Null

# 8. Start Service if requested
if (-not $NoStart) {
    Write-Host "[*] Starting Windows Service '$ServiceName'..."
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop
        Start-Sleep -Seconds 2
        $st = (Get-Service -Name $ServiceName).Status
        Write-Host "[+] Service successfully registered and started! Status: $st"
    } catch {
        Write-Warning "[!] Service created, but start reported: $($_.Exception.Message)"
    }
} else {
    Write-Host "[*] Service registered and enabled for boot start (-NoStart specified)."
}

Write-Host "============================================================"
Write-Host " [+] Server-EDR Windows Agent installation complete!         "
Write-Host "     Service: $ServiceName"
Write-Host "     BinPath: $binPath"
Write-Host "     Config:  $targetCfg"
Write-Host "============================================================"
