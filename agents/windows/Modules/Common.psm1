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

Export-ModuleMember -Function Send-Msg, Recv-Msg, Send-Event, Send-Telemetry, Compute-HMAC, Get-SecureStream, Get-LocalIP -Variable SendLock, EventQueue
