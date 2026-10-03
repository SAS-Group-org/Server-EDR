# ============================================================
#  Agent-Core.ps1 - Modular Windows Endpoint Defense Sensor
# ============================================================

param(
    [string]$ConfigPath      = "",
    [string]$ServerHost      = "",
    [int]$ServerPort         = 443,
    [string]$PSK             = "",
    [string]$CertThumbprint  = "",
    [string]$UseTLSStr       = "",
    [int]$ReconnectSecs      = 0,
    [switch]$ValidateConfig,
    [switch]$CheckConnection,
    [switch]$InstallOpenEDR,
    [switch]$InstallDeps,
    [switch]$EnableDebug
)

if ($ServerPort -le 0) {
    $ServerPort = if ($env:EDR_SERVER_PORT) { [int]$env:EDR_SERVER_PORT } else { 443 }
}

$PSScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ModulesDir  = Join-Path $PSScriptDir "Modules"

# Import all subsystem modules
Import-Module (Join-Path $ModulesDir "Common.psm1")   -Force
Import-Module (Join-Path $ModulesDir "FIM.psm1")      -Force
Import-Module (Join-Path $ModulesDir "DLP.psm1")      -Force
Import-Module (Join-Path $ModulesDir "Malware.psm1")  -Force
Import-Module (Join-Path $ModulesDir "OpenEDR.psm1")  -Force
Import-Module (Join-Path $ModulesDir "Executor.psm1") -Force

# Initialize debug logging if requested
if ($EnableDebug) {
    Initialize-EDRDebug -Enable
    Write-DebugLog "DEBUG_MODE" "Debug logging enabled via -EnableDebug switch" -Level "INFO"
}

# 1. Load baseline config from agent_config.json or env vars or defaults
$config = Load-AgentConfig -ConfigPath $ConfigPath

# 2. Command-line parameters take highest precedence
if ($ServerHost) {
    $config.server_host = $ServerHost
    $config.server.host = $ServerHost
}
if ($PSBoundParameters.ContainsKey('ServerPort')) {
    $config.server_port = $ServerPort
    $config.server.port = $ServerPort
}
if ($PSK) {
    $config.psk = $PSK
    $config.auth.psk = $PSK
}
if ($CertThumbprint) {
    $config.cert_thumbprint = $CertThumbprint
    $config.cert_fingerprint = $CertThumbprint
    $config.server.cert_thumbprint = $CertThumbprint
    $config.server.cert_fingerprint = $CertThumbprint
}
if ($UseTLSStr -ne "") {
    $useTlsBool = ($UseTLSStr -notin @("0", "false", "no", "off"))
    $config.use_tls = $useTlsBool
    $config.server.use_tls = $useTlsBool
}
if ($ReconnectSecs -gt 0) {
    $config.reconnect_secs = $ReconnectSecs
    $config.server.reconnect_interval = $ReconnectSecs
}

$ServerHost     = $config.server_host
$ServerPort     = $config.server_port
$PSK            = $config.psk
$CertThumbprint = $config.cert_thumbprint
$UseTLS         = $config.use_tls
$ReconnectSecs  = $config.reconnect_secs

$FIMEnabled         = $config.fim_enabled
$DLPEnabled         = $config.dlp_enabled
$DLPBlockTransfer   = $config.dlp_block_transfer

# 3. Handle explicit CLI action switches
if ($ValidateConfig) {
    $val = Validate-AgentConfig $config
    $statusStr = if ($val.IsValid) { "VALID" } else { "INVALID" }
    Write-Host "[*] Configuration Status: $statusStr ($($val.Summary))"
    Write-Host "    Host: ${ServerHost}:${ServerPort}"
    Write-Host "    PSK:  $(Get-MaskedSecret $PSK)"
    Write-Host "    TLS:  $UseTLS"
    if ($CertThumbprint) {
        Write-Host "    Cert: $CertThumbprint"
    }
    if ($val.IsValid) { exit 0 } else { exit 1 }
}

if ($CheckConnection) {
    Write-Host "[*] Probing server endpoint at ${ServerHost}:${ServerPort}..."
    $res = Test-ServerConnectivity -ServerHost $ServerHost -ServerPort $ServerPort
    Write-Host "[*] Endpoint Probe: $($res.Message)"
    if ($res.Success) { exit 0 } else { exit 1 }
}

# Direct installation flags
if ($InstallOpenEDR -or $InstallDeps) {
    Write-Host "[*] Installing and verifying OpenEDR dependencies..."
    $res = Install-OpenEDR
    Write-Host "[*] Result ($($res.status)): $($res.message)"
    return
}

$QuarantineDir      = Get-QuarantineDir
Ensure-QuarantineDir $QuarantineDir

Register-FIMSelfProtect $PSCommandPath
Register-FIMSelfProtect $QuarantineDir

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
        Write-DebugLog "CONNECT_START" "target=${ServerHost}:${ServerPort}  tls=$UseTLS"
        $client = New-Object System.Net.Sockets.TcpClient
        $connectTask = $client.ConnectAsync($ServerHost, $ServerPort)
        if (-not $connectTask.Wait(15000)) { throw "Connection timeout" }
        Write-DebugLog "TCP_OK" "connected to ${ServerHost}:${ServerPort}"

        $stream = Get-SecureStream -TcpClient $client -ServerHost $ServerHost -CertThumbprint $CertThumbprint -UseTLS $UseTLS

        # HMAC Handshake
        Write-DebugLog "AUTH_WAIT_CHALLENGE" "Waiting for server challenge..."
        $challenge = Recv-Msg -Stream $stream
        if ($null -eq $challenge -or $challenge.type -ne "challenge") {
            Write-DebugLog "AUTH_FAIL" "Expected 'challenge', got '$($challenge.type)'" -Level "ERROR"
            throw "Expected auth challenge"
        }

        $nonceHex = $challenge.nonce
        $hmacStr  = Compute-HMAC -Key $PSK -NonceHex $nonceHex
        Write-DebugLog "AUTH_SEND_HMAC" "nonce=$($nonceHex.Substring(0, [Math]::Min(16, $nonceHex.Length)))...  hmac=$($hmacStr.Substring(0, [Math]::Min(16, $hmacStr.Length)))..."
        Send-Msg -Stream $stream -Data @{ type = "auth"; hmac = $hmacStr }

        Write-DebugLog "AUTH_WAIT_RESPONSE" "Waiting for auth_ok from server..."
        $authResp = Recv-Msg -Stream $stream
        if ($null -eq $authResp -or $authResp.type -ne "auth_ok") {
            Write-DebugLog "AUTH_FAIL" "Server rejected authentication (type=$($authResp.type)). Check PSK matches server." -Level "ERROR"
            throw "Authentication failed"
        }
        Write-DebugLog "AUTH_SUCCESS" "Server accepted authentication"

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
        Write-DebugLog "REGISTER_SEND" "hostname=$($reg.hostname)  ip=$($reg.ip)  os=$($reg.os)"
        Send-Msg -Stream $stream -Data $reg
        $global:DyingGaspStream = $stream
        Write-DebugLog "CONNECTED" "Authenticated and registered as Windows Defense Sensor" -Level "INFO"
        Write-Host "[+] Connected and authenticated as Windows Defense Sensor"

        # Apply NTFS ACL protection
        Protect-AgentFiles @($PSCommandPath, $QuarantineDir)

        $lastFIMCheck      = [datetime]::UtcNow
        $lastDefenderCheck = [datetime]::UtcNow
        $lastUSBCheck      = [datetime]::UtcNow

        $edrInitial = $false
        try { $edrInitial = (Get-Service -Name "edrsvc" -ErrorAction SilentlyContinue).Status -eq "Running" } catch {}

        # -- Non-Blocking Command & Event Loop --
        Write-DebugLog "CMD_LOOP_ENTER" "Waiting for server commands..."
        while ($true) {
            if ($null -eq $client -or -not $client.Connected) {
                Write-DebugLog "DISCONNECT" "TCP client disconnected" -Level "WARNING"
                break
            }

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
        Write-DebugLog "CONNECTION_ERROR" "$($_.Exception.GetType().Name): $($_.Exception.Message)" -Level "ERROR"
    } finally {
        $global:DyingGaspStream = $null
        if ($stream) { try { $stream.Dispose() } catch {} }
        if ($client) { try { $client.Close() } catch {} }
        Write-DebugLog "DISCONNECT" "Cleaned up TCP client and streams"
    }

    Write-DebugLog "RECONNECT_WAIT" "seconds=$ReconnectSecs"
    Write-Host "[*] Reconnecting in $ReconnectSecs seconds..."
    Start-Sleep -Seconds $ReconnectSecs
}
