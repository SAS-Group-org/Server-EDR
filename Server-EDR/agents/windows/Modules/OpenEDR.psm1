# ============================================================
#  OpenEDR.psm1 - OpenEDR Health, Telemetry & Host Containment
# ============================================================

$global:OpenEDRLogPath = "$env:ProgramData\edrsvc\log\output_events"

function Get-OpenEDRStatus {
    param([string]$LogPath = "")
    $lp = if ($LogPath) { $LogPath } else { $global:OpenEDRLogPath }
    $svc = Get-Service -Name "edrsvc" -ErrorAction SilentlyContinue
    $logExists = Test-Path $lp
    $logSize = if ($logExists) { (Get-Item $lp).Length } else { 0 }

    # Check for OpenEDR filesystem minifilter
    $hasFilter = $false
    try {
        $filters = fltmc filters 2>&1 | Out-String
        if ($filters -match 'openedr|edr') { $hasFilter = $true }
    } catch {}

    return @{
        installed      = ($null -ne $svc)
        running        = if ($svc) { $svc.Status -eq 'Running' } else { $false }
        service_status = if ($svc) { $svc.Status.ToString() } else { "NotInstalled" }
        minifilter     = $hasFilter
        log_path       = $lp
        log_exists     = $logExists
        log_size_bytes = $logSize
    }
}

function Get-OpenEDRTelemetry {
    param(
        [int]$MaxLines = 50,
        [string]$LogPath = ""
    )
    $lp = if ($LogPath) { $LogPath } else { $global:OpenEDRLogPath }
    if (-not (Test-Path $lp)) { return @() }
    try {
        $lines = Get-Content $lp -Tail $MaxLines -ErrorAction Stop
        $events = @()
        foreach ($line in $lines) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try {
                $events += ($line | ConvertFrom-Json)
            } catch {
                $events += @{ raw = $line }
            }
        }
        return $events
    } catch { return @() }
}

function Set-HostIsolation {
    param(
        [bool]$Enable,
        [string]$ServerHost = "127.0.0.1",
        [int]$ServerPort = 4444
    )
    try {
        $resolvedIp = $ServerHost
        try {
            $ipAddrs = [System.Net.Dns]::GetHostAddresses($ServerHost) | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
            if ($ipAddrs -and $ipAddrs.Count -gt 0) { $resolvedIp = $ipAddrs[0].IPAddressToString }
        } catch {}

        if ($Enable) {
            # Firewall rule to ensure EDR C2 connection persists
            netsh advfirewall firewall add rule name="Server-EDR_C2_Rule" dir=out action=allow protocol=TCP remoteport=$ServerPort remoteip=$resolvedIp | Out-Null
            netsh advfirewall firewall add rule name="Server-EDR_C2_In" dir=in action=allow protocol=TCP remoteport=$ServerPort remoteip=$resolvedIp | Out-Null
            netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound | Out-Null
            return @{ status = "ok"; message = "Host ISOLATED. All traffic dropped except Server-EDR C2 channel to ${resolvedIp}:$ServerPort." }
        } else {
            netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null
            netsh advfirewall firewall delete rule name="Server-EDR_C2_Rule" 2>$null | Out-Null
            netsh advfirewall firewall delete rule name="Server-EDR_C2_In" 2>$null | Out-Null
            netsh advfirewall firewall delete rule name="Server-RAT_C2_Rule" 2>$null | Out-Null
            netsh advfirewall firewall delete rule name="Server-RAT_C2_In" 2>$null | Out-Null
            return @{ status = "ok"; message = "Host isolation REMOVED. Standard network access restored." }
        }
    } catch {
        return @{ status = "error"; message = $_.Exception.Message }
    }
}

function Install-OpenEDR {
    param(
        [string]$MsiUrl = "https://github.com/ComodoSecurity/openedr/releases/download/v2.5.1.0/OpenEDR-Installation-2.5.1-Win64.msi",
        [string]$FallbackMsiUrl = "https://github.com/ComodoSecurity/openedr/releases/download/2.5.1/OpenEDR-Installation-2.5.1-Win64.msi"
    )

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                   [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        return @{ status = "error"; message = "Administrator privileges required to install OpenEDR." }
    }

    # Check if already installed
    $existing = Get-Service -Name "edrsvc" -ErrorAction SilentlyContinue
    if ($existing) {
        if ($existing.Status -ne "Running") {
            try { Start-Service -Name "edrsvc" -ErrorAction SilentlyContinue } catch {}
        }
        return @{ status = "ok"; message = "OpenEDR is already installed. Service status: $($existing.Status)" }
    }

    # Ensure log output directory exists
    $logDir = "$env:ProgramData\edrsvc\log"
    if (-not (Test-Path $logDir)) {
        try { New-Item -ItemType Directory -Path $logDir -Force | Out-Null } catch {}
    }

    $tempDir = [System.IO.Path]::GetTempPath()
    $msiPath = Join-Path $tempDir "OpenEDR_Install.msi"

    $downloadSuccess = $false
    $stagedPaths = @(
        "$PSScriptRoot\OpenEDR.msi",
        "$env:TEMP\OpenEDR.msi",
        "$env:ProgramData\Server-EDR\OpenEDR.msi",
        "$env:ProgramData\Server-RAT\OpenEDR.msi"
    )
    foreach ($sp in $stagedPaths) {
        if ($sp -and (Test-Path $sp)) {
            try {
                Copy-Item -Path $sp -Destination $msiPath -Force
                $downloadSuccess = $true
                break
            } catch {}
        }
    }

    if (-not $downloadSuccess) {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        $urls = @($MsiUrl, $FallbackMsiUrl)
        foreach ($url in $urls) {
            try {
                $wc = New-Object System.Net.WebClient
                $wc.Headers.Add("User-Agent", "Server-EDR-EndpointDefense/1.0")
                $wc.DownloadFile($url, $msiPath)
                if ((Test-Path $msiPath) -and (Get-Item $msiPath).Length -gt 100000) {
                    $downloadSuccess = $true
                    break
                }
            } catch {}
        }
    }

    if (-not $downloadSuccess -or -not (Test-Path $msiPath)) {
        return @{
            status = "error"
            message = "Unable to download OpenEDR MSI automatically from GitHub releases. Telemetry directory configured at $logDir. Please place OpenEDR.msi into $env:TEMP\OpenEDR.msi to complete offline installation."
        }
    }

    try {
        $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$msiPath`" /qn /norestart" -Wait -PassThru -NoNewWindow
        Start-Sleep -Seconds 2
        $svc = Get-Service -Name "edrsvc" -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -ne "Running") {
                Start-Service -Name "edrsvc" -ErrorAction SilentlyContinue
            }
            return @{ status = "ok"; message = "OpenEDR installed successfully! Service status: Running. Telemetry logging active." }
        } else {
            return @{ status = "ok"; message = "OpenEDR installer executed (exit code: $($proc.ExitCode)). Telemetry directory configured." }
        }
    } catch {
        return @{ status = "error"; message = "OpenEDR MSI execution failed: $($_.Exception.Message)" }
    } finally {
        if (Test-Path $msiPath) {
            Remove-Item -Path $msiPath -Force -ErrorAction SilentlyContinue
        }
    }
}

Export-ModuleMember -Function Get-OpenEDRStatus, Get-OpenEDRTelemetry, Set-HostIsolation, Install-OpenEDR -Variable OpenEDRLogPath
