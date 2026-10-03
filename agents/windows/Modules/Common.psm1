# ============================================================
#  Common.psm1 - Protocol, Cryptography & Shared State
# ============================================================

$global:SendLock = New-Object System.Object
$global:EventQueue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()

function Send-Msg {
    param($Stream, $Data)
    [System.Threading.Monitor]::Enter($global:SendLock)
    try {
        $json  = $Data | ConvertTo-Json -Compress -Depth 10
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $len   = [System.BitConverter]::GetBytes([int32]$bytes.Length)
        $Stream.Write($len,   0, 4)
        $Stream.Write($bytes, 0, $bytes.Length)
        $Stream.Flush()
    } finally {
        [System.Threading.Monitor]::Exit($global:SendLock)
    }
}

function Recv-Msg {
    param($Stream)
    $hdr = New-Object byte[] 4
    $got = 0
    while ($got -lt 4) {
        $n = $Stream.Read($hdr, $got, 4 - $got)
        if ($n -eq 0) { return $null }
        $got += $n
    }
    $len = [System.BitConverter]::ToInt32($hdr, 0)
    if ($len -le 0 -or $len -gt (50 * 1024 * 1024)) { return $null }   # 50 MB cap
    $buf = New-Object byte[] $len
    $got = 0
    while ($got -lt $len) {
        $n = $Stream.Read($buf, $got, $len - $got)
        if ($n -eq 0) { return $null }
        $got += $n
    }
    $json = [System.Text.Encoding]::UTF8.GetString($buf)
    try { return $json | ConvertFrom-Json } catch { return $null }
}

function Send-Event {
    param(
        $Stream,
        [string]$Subsystem,
        [string]$Severity,
        [string]$Title,
        [string]$Details,
        [hashtable]$Extra = @{}
    )
    $evt = @{
        type      = "event"
        subsystem = $Subsystem
        severity  = $Severity
        title     = $Title
        details   = $Details
        timestamp = (Get-Date -Format "o")
        host      = $env:COMPUTERNAME
    }
    foreach ($k in $Extra.Keys) { $evt[$k] = $Extra[$k] }
    if ($Stream) {
        try {
            Send-Msg -Stream $Stream -Data $evt
        } catch {
            $global:EventQueue.Enqueue($evt)
        }
    } else {
        $global:EventQueue.Enqueue($evt)
    }
}

function Send-Telemetry {
    param(
        $Stream,
        [string]$Category,
        [array]$Events
    )
    $msg = @{
        type      = "telemetry"
        category  = $Category
        events    = $Events
        timestamp = (Get-Date -Format "o")
        host      = $env:COMPUTERNAME
    }
    if ($Stream) {
        try {
            Send-Msg -Stream $Stream -Data $msg
        } catch {}
    }
}

function Compute-HMAC {
    param([string]$Key, [string]$NonceHex)
    $keyBytes   = [System.Text.Encoding]::UTF8.GetBytes($Key)
    $nonceBytes = New-Object byte[] ($NonceHex.Length / 2)
    for ($i = 0; $i -lt $NonceHex.Length; $i += 2) {
        $nonceBytes[$i / 2] = [Convert]::ToByte($NonceHex.Substring($i, 2), 16)
    }
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $keyBytes
    $hash = $hmac.ComputeHash($nonceBytes)
    $hmac.Dispose()
    return ($hash | ForEach-Object { $_.ToString("x2") }) -join ""
}

function Get-SecureStream {
    param($TcpClient, [string]$ServerHost, [string]$CertThumbprint, [bool]$UseTLS = $true)

    $rawStream = $TcpClient.GetStream()
    if (-not $UseTLS) { return $rawStream }

    $validationCallback = {
        param($sender, $certificate, $chain, $sslPolicyErrors)
        if ($CertThumbprint -ne "") {
            $actual = $certificate.GetCertHashString("SHA256")
            return ($actual -ieq $CertThumbprint)
        }
        return $true
    }

    $sslStream = New-Object System.Net.Security.SslStream(
        $rawStream, $false, $validationCallback
    )
    try {
        $sslStream.AuthenticateAsClient($ServerHost)
        return $sslStream
    } catch {
        $sslStream.Dispose()
        throw $_
    }
}

function Get-LocalIP {
    try {
        $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
               Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.InterfaceAlias -notmatch "Loopback" } |
               Select-Object -First 1).IPAddress
        if ($ip) { return $ip }
    } catch {}
    try {
        $sock = New-Object System.Net.Sockets.Socket(
            [System.Net.Sockets.AddressFamily]::InterNetwork,
            [System.Net.Sockets.SocketType]::Dgram, 0
        )
        $sock.Connect("8.8.8.8", 65530)
        $ip = $sock.LocalEndPoint.Address.ToString()
        $sock.Close()
        return $ip
    } catch {}
    return "127.0.0.1"
}

function Get-MaskedSecret {
    param([string]$Secret)
    if ([string]::IsNullOrEmpty($Secret) -or $Secret.Length -le 8) {
        return "***"
    }
    return $Secret.Substring(0, 4) + "..." + $Secret.Substring($Secret.Length - 4)
}

function Validate-AgentConfig {
    param($Config)
    $errors = [System.Collections.Generic.List[string]]::new()

    # Extract host
    $hostVal = ""
    if ($Config.server_host) {
        $hostVal = [string]$Config.server_host
    } elseif ($Config.server -and $Config.server.host) {
        $hostVal = [string]$Config.server.host
    }
    if ([string]::IsNullOrWhiteSpace($hostVal)) {
        $errors.Add("server_host must be a non-empty hostname or IP address")
    }

    # Extract port
    $portVal = $null
    if ($Config.server_port) {
        $portVal = $Config.server_port
    } elseif ($Config.server -and $Config.server.port) {
        $portVal = $Config.server.port
    }
    try {
        $portInt = [int]$portVal
        if ($portInt -lt 1 -or $portInt -gt 65535) {
            $errors.Add("server_port must be between 1 and 65535 (got: $portVal)")
        }
    } catch {
        $errors.Add("server_port must be a valid integer (got: $portVal)")
    }

    # Extract cert thumbprint
    $fpVal = ""
    if ($Config.cert_thumbprint) {
        $fpVal = [string]$Config.cert_thumbprint
    } elseif ($Config.cert_fingerprint) {
        $fpVal = [string]$Config.cert_fingerprint
    } elseif ($Config.server -and $Config.server.cert_fingerprint) {
        $fpVal = [string]$Config.server.cert_fingerprint
    }
    if (-not [string]::IsNullOrWhiteSpace($fpVal)) {
        $cleanFp = $fpVal.Replace(":", "").Replace(" ", "")
        if ($cleanFp.Length -ne 64 -or ($cleanFp -notmatch '^[0-9a-fA-F]{64}$')) {
            $errors.Add("cert_thumbprint must be a 64-character SHA-256 hex string")
        }
    }

    # Extract reconnect interval
    $recVal = $null
    if ($Config.reconnect_secs) {
        $recVal = $Config.reconnect_secs
    } elseif ($Config.server -and $Config.server.reconnect_interval) {
        $recVal = $Config.server.reconnect_interval
    }
    if ($null -ne $recVal) {
        try {
            $recInt = [int]$recVal
            if ($recInt -le 0) {
                $errors.Add("reconnect_secs must be greater than 0")
            }
        } catch {
            $errors.Add("reconnect_secs must be an integer")
        }
    }

    $isValid = ($errors.Count -eq 0)
    $summary = if ($isValid) { "Configuration is valid" } else { $errors -join "; " }

    return [PSCustomObject]@{
        IsValid = $isValid
        Errors  = $errors.ToArray()
        Summary = $summary
    }
}

function Load-AgentConfig {
    param(
        [string]$ConfigPath = "",
        [bool]$Validate = $false
    )

    $defaultConfig = @{
        server_host        = "127.0.0.1"
        server_port        = 4444
        psk                = "PASTE_PSK_HERE"
        cert_thumbprint    = ""
        use_tls            = $true
        reconnect_secs     = 10
        max_reconnect_secs = 60
        group_tag          = "default"
        polling_interval   = 10
        fim_enabled        = $true
        dlp_enabled        = $true
        dlp_block_transfer = $false
        log_level          = "INFO"
        source_path        = ""
    }

    # Locate config file
    $targetPath = ""
    if ($ConfigPath -and (Test-Path $ConfigPath)) {
        $targetPath = (Resolve-Path $ConfigPath).Path
    } elseif ($env:EDR_CONFIG_FILE -and (Test-Path $env:EDR_CONFIG_FILE)) {
        $targetPath = (Resolve-Path $env:EDR_CONFIG_FILE).Path
    } elseif ($env:EDR_CONFIG_PATH -and (Test-Path $env:EDR_CONFIG_PATH)) {
        $targetPath = (Resolve-Path $env:EDR_CONFIG_PATH).Path
    } else {
        $searchPaths = @(
            (Join-Path $PSScriptRoot "agent_config.json"),
            (Join-Path (Split-Path -Parent $PSScriptRoot) "agent_config.json"),
            (Join-Path $env:ProgramData "Server-EDR\agent_config.json"),
            (Join-Path $env:TEMP "agent_config.json")
        )
        foreach ($candidate in $searchPaths) {
            if ($candidate -and (Test-Path $candidate)) {
                $targetPath = (Resolve-Path $candidate).Path
                break
            }
        }
    }

    # Load from file if found
    if ($targetPath -and (Test-Path $targetPath)) {
        try {
            $rawJson = Get-Content -Path $targetPath -Raw -Encoding UTF8 -ErrorAction Stop
            $parsed = $rawJson | ConvertFrom-Json -ErrorAction Stop

            # Check nested vs flat
            if ($parsed.server) {
                if ($parsed.server.host) { $defaultConfig["server_host"] = [string]$parsed.server.host }
                if ($parsed.server.port) { $defaultConfig["server_port"] = [int]$parsed.server.port }
                if ($null -ne $parsed.server.use_tls) { $defaultConfig["use_tls"] = [bool]$parsed.server.use_tls }
                if ($parsed.server.cert_fingerprint) { $defaultConfig["cert_thumbprint"] = [string]$parsed.server.cert_fingerprint }
                if ($parsed.server.cert_thumbprint) { $defaultConfig["cert_thumbprint"] = [string]$parsed.server.cert_thumbprint }
                if ($parsed.server.reconnect_interval) { $defaultConfig["reconnect_secs"] = [int]$parsed.server.reconnect_interval }
            }
            if ($parsed.auth) {
                if ($parsed.auth.psk) { $defaultConfig["psk"] = [string]$parsed.auth.psk }
            }
            if ($parsed.agent) {
                if ($parsed.agent.log_level) { $defaultConfig["log_level"] = [string]$parsed.agent.log_level }
                if ($null -ne $parsed.agent.fim_enabled) { $defaultConfig["fim_enabled"] = [bool]$parsed.agent.fim_enabled }
                if ($null -ne $parsed.agent.dlp_enabled) { $defaultConfig["dlp_enabled"] = [bool]$parsed.agent.dlp_enabled }
                if ($null -ne $parsed.agent.dlp_block_transfers) { $defaultConfig["dlp_block_transfer"] = [bool]$parsed.agent.dlp_block_transfers }
                if ($parsed.agent.group_tag) { $defaultConfig["group_tag"] = [string]$parsed.agent.group_tag }
                if ($parsed.agent.polling_interval) { $defaultConfig["polling_interval"] = [int]$parsed.agent.polling_interval }
            }

            # Top-level flat properties
            if ($parsed.server_host) { $defaultConfig["server_host"] = [string]$parsed.server_host }
            if ($parsed.server_port) { $defaultConfig["server_port"] = [int]$parsed.server_port }
            if ($parsed.psk) { $defaultConfig["psk"] = [string]$parsed.psk }
            if ($parsed.cert_thumbprint) { $defaultConfig["cert_thumbprint"] = [string]$parsed.cert_thumbprint }
            if ($parsed.cert_fingerprint) { $defaultConfig["cert_thumbprint"] = [string]$parsed.cert_fingerprint }
            if ($null -ne $parsed.use_tls) { $defaultConfig["use_tls"] = [bool]$parsed.use_tls }
            if ($parsed.reconnect_secs) { $defaultConfig["reconnect_secs"] = [int]$parsed.reconnect_secs }
            if ($parsed.polling_interval) { $defaultConfig["polling_interval"] = [int]$parsed.polling_interval }
            if ($parsed.group_tag) { $defaultConfig["group_tag"] = [string]$parsed.group_tag }
            if ($null -ne $parsed.fim_enabled) { $defaultConfig["fim_enabled"] = [bool]$parsed.fim_enabled }
            if ($null -ne $parsed.dlp_enabled) { $defaultConfig["dlp_enabled"] = [bool]$parsed.dlp_enabled }
            if ($null -ne $parsed.dlp_block_transfer) { $defaultConfig["dlp_block_transfer"] = [bool]$parsed.dlp_block_transfer }
            if ($parsed.log_level) { $defaultConfig["log_level"] = [string]$parsed.log_level }

            $defaultConfig["source_path"] = $targetPath
        } catch {
            Write-Warning "[!] Failed to parse configuration file '$targetPath': $($_.Exception.Message)"
        }
    }

    # Environment variables override (EDR_* and RAT_*)
    $envHost = if ($env:EDR_SERVER_HOST) { $env:EDR_SERVER_HOST } elseif ($env:RAT_SERVER_HOST) { $env:RAT_SERVER_HOST } elseif ($env:RAT_SERVER) { $env:RAT_SERVER } else { $null }
    if ($envHost) { $defaultConfig["server_host"] = $envHost }

    $envPort = if ($env:EDR_SERVER_PORT) { $env:EDR_SERVER_PORT } elseif ($env:RAT_SERVER_PORT) { $env:RAT_SERVER_PORT } elseif ($env:RAT_PORT) { $env:RAT_PORT } else { $null }
    if ($envPort) {
        try { $defaultConfig["server_port"] = [int]$envPort } catch {}
    }

    $envPsk = if ($env:EDR_PSK) { $env:EDR_PSK } elseif ($env:RAT_PSK) { $env:RAT_PSK } else { $null }
    if ($envPsk) { $defaultConfig["psk"] = $envPsk }

    $envCert = if ($env:EDR_CERT_FINGERPRINT) { $env:EDR_CERT_FINGERPRINT } elseif ($env:RAT_CERT_FINGERPRINT) { $env:RAT_CERT_FINGERPRINT } elseif ($env:EDR_CERT_THUMBPRINT) { $env:EDR_CERT_THUMBPRINT } else { $null }
    if ($envCert) { $defaultConfig["cert_thumbprint"] = $envCert }

    $envTls = if ($null -ne $env:EDR_USE_TLS) { $env:EDR_USE_TLS } elseif ($null -ne $env:RAT_USE_TLS) { $env:RAT_USE_TLS } else { $null }
    if ($null -ne $envTls) {
        $defaultConfig["use_tls"] = ($envTls -notin @("0", "false", "no", "off"))
    }

    $envRec = if ($env:EDR_RECONNECT_SECS) { $env:EDR_RECONNECT_SECS } elseif ($env:RAT_RECONNECT_SECS) { $env:RAT_RECONNECT_SECS } else { $null }
    if ($envRec) {
        try { $defaultConfig["reconnect_secs"] = [int]$envRec } catch {}
    }

    $envPoll = if ($env:EDR_POLLING_INTERVAL) { $env:EDR_POLLING_INTERVAL } else { $null }
    if ($envPoll) {
        try { $defaultConfig["polling_interval"] = [int]$envPoll } catch {}
    }

    $envGroup = if ($env:EDR_GROUP_TAG) { $env:EDR_GROUP_TAG } else { $null }
    if ($envGroup) { $defaultConfig["group_tag"] = [string]$envGroup }

    if ($null -ne $env:EDR_FIM_ENABLED) {
        $defaultConfig["fim_enabled"] = ($env:EDR_FIM_ENABLED -notin @("0", "false", "no", "off"))
    }
    if ($null -ne $env:EDR_DLP_ENABLED) {
        $defaultConfig["dlp_enabled"] = ($env:EDR_DLP_ENABLED -notin @("0", "false", "no", "off"))
    }
    if ($null -ne $env:EDR_DLP_BLOCK_TRANSFERS) {
        $defaultConfig["dlp_block_transfer"] = ($env:EDR_DLP_BLOCK_TRANSFERS -in @("1", "true", "yes", "on"))
    }

    # Construct final PSCustomObject with both flat and nested properties
    $resultObj = [PSCustomObject]@{
        server_host        = $defaultConfig["server_host"]
        server_port        = [int]$defaultConfig["server_port"]
        psk                = $defaultConfig["psk"]
        cert_thumbprint    = $defaultConfig["cert_thumbprint"]
        cert_fingerprint   = $defaultConfig["cert_thumbprint"]
        use_tls            = [bool]$defaultConfig["use_tls"]
        reconnect_secs     = [int]$defaultConfig["reconnect_secs"]
        max_reconnect_secs = [int]$defaultConfig["max_reconnect_secs"]
        group_tag          = [string]$defaultConfig["group_tag"]
        polling_interval   = [int]$defaultConfig["polling_interval"]
        fim_enabled        = [bool]$defaultConfig["fim_enabled"]
        dlp_enabled        = [bool]$defaultConfig["dlp_enabled"]
        dlp_block_transfer = [bool]$defaultConfig["dlp_block_transfer"]
        log_level          = $defaultConfig["log_level"]
        source_path        = $defaultConfig["source_path"]
        server             = [PSCustomObject]@{
            host               = $defaultConfig["server_host"]
            port               = [int]$defaultConfig["server_port"]
            use_tls            = [bool]$defaultConfig["use_tls"]
            cert_fingerprint   = $defaultConfig["cert_thumbprint"]
            cert_thumbprint    = $defaultConfig["cert_thumbprint"]
            reconnect_interval = [int]$defaultConfig["reconnect_secs"]
        }
        auth               = [PSCustomObject]@{
            psk                = $defaultConfig["psk"]
        }
        agent              = [PSCustomObject]@{
            log_level          = $defaultConfig["log_level"]
            group_tag          = [string]$defaultConfig["group_tag"]
            polling_interval   = [int]$defaultConfig["polling_interval"]
            fim_enabled        = [bool]$defaultConfig["fim_enabled"]
            dlp_enabled        = [bool]$defaultConfig["dlp_enabled"]
            dlp_block_transfers= [bool]$defaultConfig["dlp_block_transfer"]
        }
    }

    if ($Validate) {
        $val = Validate-AgentConfig $resultObj
        if (-not $val.IsValid) {
            Write-Warning "[!] Configuration validation warnings: $($val.Summary)"
        }
    }

    return $resultObj
}

function Save-AgentConfig {
    param(
        $Config,
        [string]$FilePath
    )
    try {
        $parent = Split-Path -Parent $FilePath
        if ($parent -and (-not (Test-Path $parent))) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }

        # Convert to nested JSON structure
        $outData = [ordered]@{
            server = [ordered]@{
                host               = if ($Config.server_host) { $Config.server_host } elseif ($Config.server.host) { $Config.server.host } else { "127.0.0.1" }
                port               = if ($Config.server_port) { [int]$Config.server_port } elseif ($Config.server.port) { [int]$Config.server.port } else { 4444 }
                use_tls            = if ($null -ne $Config.use_tls) { [bool]$Config.use_tls } elseif ($Config.server -and ($null -ne $Config.server.use_tls)) { [bool]$Config.server.use_tls } else { $true }
                cert_fingerprint   = if ($Config.cert_thumbprint) { $Config.cert_thumbprint } elseif ($Config.cert_fingerprint) { $Config.cert_fingerprint } else { "" }
                reconnect_interval = if ($Config.reconnect_secs) { [int]$Config.reconnect_secs } else { 10 }
            }
            auth = [ordered]@{
                psk                = if ($Config.psk) { $Config.psk } elseif ($Config.auth.psk) { $Config.auth.psk } else { "" }
            }
            agent = [ordered]@{
                log_level          = if ($Config.log_level) { $Config.log_level } else { "INFO" }
                fim_enabled        = if ($null -ne $Config.fim_enabled) { [bool]$Config.fim_enabled } else { $true }
                dlp_enabled        = if ($null -ne $Config.dlp_enabled) { [bool]$Config.dlp_enabled } else { $true }
                dlp_block_transfers= if ($null -ne $Config.dlp_block_transfer) { [bool]$Config.dlp_block_transfer } else { $false }
            }
        }

        $jsonStr = $outData | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText($FilePath, $jsonStr, [System.Text.Encoding]::UTF8)

        # Set restrictive permissions if possible
        try {
            & icacls.exe "`"$FilePath`"" /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" | Out-Null
        } catch {}

        return $true
    } catch {
        Write-Warning "[!] Failed to save configuration to $FilePath : $($_.Exception.Message)"
        return $false
    }
}

function Test-ServerConnectivity {
    param(
        [string]$ServerHost,
        [int]$ServerPort,
        [int]$TimeoutMs = 3000
    )
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($ServerHost, $ServerPort, $null, $null)
        $wh = $iar.AsyncWaitHandle
        $connected = $wh.WaitOne($TimeoutMs, $false)
        if ($connected) {
            $client.EndConnect($iar)
            return [PSCustomObject]@{
                Success = $true
                Message = "Successfully connected to server endpoint at ${ServerHost}:${ServerPort}"
            }
        } else {
            return [PSCustomObject]@{
                Success = $false
                Message = "Connection to ${ServerHost}:${ServerPort} timed out after ${TimeoutMs}ms"
            }
        }
    } catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "Connection to ${ServerHost}:${ServerPort} failed: $($_.Exception.Message)"
        }
    } finally {
        $client.Close()
        $client.Dispose()
    }
}

Export-ModuleMember -Function Send-Msg, Recv-Msg, Send-Event, Send-Telemetry, Compute-HMAC, Get-SecureStream, Get-LocalIP, Get-MaskedSecret, Validate-AgentConfig, Load-AgentConfig, Save-AgentConfig, Test-ServerConnectivity -Variable SendLock, EventQueue
