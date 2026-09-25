# ============================================================
#  Agent-Core.ps1 - Modular Windows Endpoint Defense Sensor
# ============================================================

param(
    [string]$ServerHost      = "",
    [int]$ServerPort         = 0,
    [string]$PSK             = "",
    [string]$CertThumbprint  = "",
    [string]$UseTLSStr       = "",
    [int]$ReconnectSecs      = 0,
    [switch]$InstallOpenEDR,
    [switch]$InstallDeps
)

$PSScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ModulesDir  = Join-Path $PSScriptDir "Modules"

# Import all subsystem modules
Import-Module (Join-Path $ModulesDir "Common.psm1")   -Force
Import-Module (Join-Path $ModulesDir "FIM.psm1")      -Force
Import-Module (Join-Path $ModulesDir "DLP.psm1")      -Force
Import-Module (Join-Path $ModulesDir "Malware.psm1")  -Force
Import-Module (Join-Path $ModulesDir "OpenEDR.psm1")  -Force
Import-Module (Join-Path $ModulesDir "Executor.psm1") -Force

# Resolve configurations with env var fallbacks
if (-not $ServerHost) {
    $ServerHost = if ($env:EDR_SERVER_HOST) { $env:EDR_SERVER_HOST } elseif ($env:RAT_SERVER_HOST) { $env:RAT_SERVER_HOST } else { "127.0.0.1" }
}
if ($ServerPort -le 0) {
    $ServerPort = if ($env:EDR_SERVER_PORT) { [int]$env:EDR_SERVER_PORT } elseif ($env:RAT_SERVER_PORT) { [int]$env:RAT_SERVER_PORT } else { 4444 }
}
if (-not $PSK) {
    $PSK = if ($env:EDR_PSK) { $env:EDR_PSK } elseif ($env:RAT_PSK) { $env:RAT_PSK } else { "PASTE_PSK_HERE" }
}
if (-not $CertThumbprint) {
    $CertThumbprint = if ($env:EDR_CERT_FINGERPRINT) { $env:EDR_CERT_FINGERPRINT } elseif ($env:RAT_CERT_FINGERPRINT) { $env:RAT_CERT_FINGERPRINT } else { "" }
}
$UseTLS = if ($UseTLSStr -eq "0" -or $UseTLSStr -eq "false" -or $env:EDR_USE_TLS -eq "0" -or $env:EDR_USE_TLS -eq "false" -or $env:RAT_USE_TLS -eq "0" -or $env:RAT_USE_TLS -eq "false") { $false } else { $true }
if ($ReconnectSecs -le 0) {
    $ReconnectSecs = if ($env:EDR_RECONNECT_SECS) { [int]$env:EDR_RECONNECT_SECS } elseif ($env:RAT_RECONNECT_SECS) { [int]$env:RAT_RECONNECT_SECS } else { 10 }
}

$FIMEnabled         = $true
$DLPEnabled         = $true
$DLPBlockTransfer   = $false
$QuarantineDir      = Get-QuarantineDir
Ensure-QuarantineDir $QuarantineDir

Register-FIMSelfProtect $PSCommandPath
Register-FIMSelfProtect $QuarantineDir

# Direct installation flags
if ($InstallOpenEDR -or $InstallDeps) {
    Write-Host "[*] Installing and verifying OpenEDR dependencies..."
    $res = Install-OpenEDR
    Write-Host "[*] Result ($($res.status)): $($res.message)"
    return
}

# Auto-install OpenEDR if configured and missing
$autoInstall = if ($env:EDR_AUTO_INSTALL_OPENEDR -eq "1" -or $env:EDR_AUTO_INSTALL_OPENEDR -eq "true" -or $env:RAT_AUTO_INSTALL_OPENEDR -eq "1" -or $env:RAT_AUTO_INSTALL_OPENEDR -eq "true") { $true } else { $false }
if ($autoInstall) {
    $st = Get-OpenEDRStatus
    if (-not $st.installed) {
        Write-Host "[*] OpenEDR missing and AUTO_INSTALL enabled - installing..."
        $res = Install-OpenEDR
        Write-Host "[*] OpenEDR install status ($($res.status)): $($res.message)"
    }
}

# Dying-gasp handler
$global:DyingGaspStream = $null
Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action {
    if ($global:DyingGaspStream) {
        try {
            Send-Event -Stream $global:DyingGaspStream -Subsystem "tamper" -Severity "CRITICAL" `
                -Title "[TAMPER] ANTI-TAMPER: Windows Agent Process Exiting" `
                -Details "Agent process (PID $PID) received exit/termination event. Possible adversary stop." `
                -Extra @{ pid = $PID }
        } catch {}
    }
} | Out-Null

Write-Host "[*] Windows EDR Defense Sensor starting..."
Write-Host "[*] Target: ${ServerHost}:${ServerPort}"
Write-Host "[*] TLS: $(if ($UseTLS) { 'enabled' } else { 'DISABLED' })"

while ($true) {
    $client = $null
    $stream = $null

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $connectTask = $client.ConnectAsync($ServerHost, $ServerPort)
        if (-not $connectTask.Wait(15000)) { throw "Connection timeout" }

        $stream = Get-SecureStream -TcpClient $client -ServerHost $ServerHost -CertThumbprint $CertThumbprint -UseTLS $UseTLS

        # HMAC Handshake
        $challenge = Recv-Msg -Stream $stream
        if ($null -eq $challenge -or $challenge.type -ne "challenge") { throw "Expected auth challenge" }

        $nonceHex = $challenge.nonce
        $hmacStr  = Compute-HMAC -Key $PSK -NonceHex $nonceHex
        Send-Msg -Stream $stream -Data @{ type = "auth"; hmac = $hmacStr }

        $authResp = Recv-Msg -Stream $stream
        if ($null -eq $authResp -or $authResp.type -ne "auth_ok") { throw "Authentication failed" }

        # Baseline FIM
        Init-FIMBaseline

        # Registration
        $osInfo = $null
        if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
            try { $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch {}
        } else {
            try { $osInfo = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop } catch {}
        }

        $reg = @{
            type                 = "register"
            hostname             = $env:COMPUTERNAME
            username             = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            os                   = if ($osInfo) { $osInfo.Caption } else { "Windows" }
            arch                 = if ($osInfo) { $osInfo.OSArchitecture } else { $env:PROCESSOR_ARCHITECTURE }
            ip                   = Get-LocalIP
            ps_ver               = $PSVersionTable.PSVersion.ToString()
            is_admin             = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                                      [Security.Principal.WindowsBuiltInRole]::Administrator)
            defense_capabilities = @("malware_prevention", "fim", "dlp", "openedr")
        }
        Send-Msg -Stream $stream -Data $reg
        $global:DyingGaspStream = $stream
        Write-Host "[+] Connected and authenticated as Windows Defense Sensor"

        # Apply NTFS ACL protection
        Protect-AgentFiles @($PSCommandPath, $QuarantineDir)

        $lastFIMCheck      = [datetime]::UtcNow
        $lastDefenderCheck = [datetime]::UtcNow
        $lastUSBCheck      = [datetime]::UtcNow

        $edrInitial = $false
        try { $edrInitial = (Get-Service -Name "edrsvc" -ErrorAction SilentlyContinue).Status -eq "Running" } catch {}

        # -- Non-Blocking Command & Event Loop --
        while ($true) {
            if ($null -eq $client -or -not $client.Connected) { break }

            $now = [datetime]::UtcNow

            # 1. Flush queued events
            $queuedEvt = $null
            while ($global:EventQueue.TryDequeue([ref]$queuedEvt)) {
                try { Send-Msg -Stream $stream -Data $queuedEvt } catch { break }
            }

            # 2. Flush queued responses from background tasks
            $queuedResp = $null
            while ($global:ResponseQueue.TryDequeue([ref]$queuedResp)) {
                try { Send-Msg -Stream $stream -Data $queuedResp } catch { break }
            }

            # 3. Periodic FIM check (every 30s)
            if ($FIMEnabled -and (($now - $lastFIMCheck).TotalSeconds -ge 30)) {
                $lastFIMCheck = $now
                $changes = Check-FIMIntegrity
                foreach ($c in $changes) {
                    $sub = if ($c.tamper) { "tamper" } else { "fim" }
                    $ttl = if ($c.tamper) { "[TAMPER] ANTI-TAMPER: $($c.action) on Agent File!" } else { "FIM $($c.action): $($c.path)" }
                    Send-Event -Stream $stream -Subsystem $sub -Severity $c.severity -Title $ttl -Details $c.details -Extra @{
                        action   = $c.action
                        path     = $c.path
                        old_hash = $c.old_hash
                        new_hash = $c.new_hash
                        tamper   = $c.tamper
                    }
                }
            }

            # 4. Periodic Defender / OpenEDR health check (every 30s)
            if (($now - $lastDefenderCheck).TotalSeconds -ge 30) {
                $lastDefenderCheck = $now
                try {
                    $curEdr = (Get-Service -Name "edrsvc" -ErrorAction SilentlyContinue).Status -eq "Running"
                    if ($edrInitial -and -not $curEdr) {
                        Send-Event -Stream $stream -Subsystem "tamper" -Severity "CRITICAL" `
                            -Title "OpenEDR Service Impairment Detected" `
                            -Details "The OpenEDR security service (edrsvc) was active at sensor launch but has stopped unexpectedly." `
                            -Extra @{ subsystem = "openedr"; status = "stopped" }
                        $edrInitial = $false
                    } elseif (-not $edrInitial -and $curEdr) {
                        $edrInitial = $true
                    }
                } catch {}

                try {
                    $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
                    if ($mpPref -and $mpPref.DisableRealtimeMonitoring -eq $true) {
                        Send-Event -Stream $stream -Subsystem "tamper" -Severity "HIGH" `
                            -Title "Windows Defender Real-Time Protection Disabled" `
                            -Details "Windows Defender real-time monitoring has been disabled. This may indicate security evasion." `
                            -Extra @{ subsystem = "defender"; status = "disabled" }
                    }
                } catch {}
            }

            # 5. Periodic Removable USB media check (every 5s)
            if (($now - $lastUSBCheck).TotalSeconds -ge 5) {
                $lastUSBCheck = $now
                $newDrives = Check-RemovableDrives
                foreach ($d in $newDrives) {
                    Send-Event -Stream $stream -Subsystem "dlp" -Severity "MEDIUM" `
                        -Title "Removable USB Storage Attached" `
                        -Details "A new removable volume '$d' was mounted on the endpoint." `
                        -Extra @{ drive = $d; rule = "REMOVABLE_STORAGE" }
                }
            }

            # 6. Poll socket with short 100ms timeout for non-blocking responsiveness
            try {
                if (-not $client.Client.Poll(100000, [System.Net.Sockets.SelectMode]::SelectRead)) {
                    continue
                }
            } catch {
                break
            }

            # 7. Read incoming message
            $msg = Recv-Msg -Stream $stream
            if ($null -eq $msg) { break }

            # Execute command using modular executor
            $resp = Invoke-AgentCommand -Msg $msg `
                -DlpScanFunc { param($p) Scan-DLPFile $p } `
                -MalwareScanFunc { param($p) Scan-MalwarePath $p (Get-Command Get-FileSHA256).ScriptBlock } `
                -QuarantineFunc { param($p) Quarantine-File $p $QuarantineDir (Get-Command Get-FileSHA256).ScriptBlock } `
                -QuarantineListFunc { List-Quarantine $QuarantineDir } `
                -QuarantineRestoreFunc { param($q) Restore-Quarantine $q $QuarantineDir } `
                -FimInitFunc { Init-FIMBaseline } `
                -FimCheckFunc { Check-FIMIntegrity } `
                -FimAddPathFunc { param($p) Add-FIMTarget $p } `
                -OpenEDRStatusFunc { Get-OpenEDRStatus } `
                -OpenEDRTelemetryFunc { param($m) Get-OpenEDRTelemetry $m } `
                -HostIsolationFunc { param($e) Set-HostIsolation $e $ServerHost $ServerPort } `
                -InstallOpenEDRFunc { Install-OpenEDR } `
                -ScriptPath $PSCommandPath `
                -ThreatHashes $global:ThreatHashes `
                -DLPEnabled $DLPEnabled `
                -DLPBlockTransfer $DLPBlockTransfer

            Send-Msg -Stream $stream -Data $resp
        }

    } catch {
        # Retry connection
    } finally {
        $global:DyingGaspStream = $null
        if ($stream) { try { $stream.Dispose() } catch {} }
        if ($client) { try { $client.Close() } catch {} }
    }

    Start-Sleep -Seconds $ReconnectSecs
}
