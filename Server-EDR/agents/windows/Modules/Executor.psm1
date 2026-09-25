# ============================================================
#  Executor.psm1 - Asynchronous Non-Blocking Command Dispatcher
# ============================================================

$global:ResponseQueue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()

function Invoke-AgentCommand {
    param(
        $Msg,
        [scriptblock]$DlpScanFunc,
        [scriptblock]$MalwareScanFunc,
        [scriptblock]$QuarantineFunc,
        [scriptblock]$QuarantineListFunc,
        [scriptblock]$QuarantineRestoreFunc,
        [scriptblock]$FimInitFunc,
        [scriptblock]$FimCheckFunc,
        [scriptblock]$FimAddPathFunc,
        [scriptblock]$OpenEDRStatusFunc,
        [scriptblock]$OpenEDRTelemetryFunc,
        [scriptblock]$HostIsolationFunc,
        [scriptblock]$InstallOpenEDRFunc,
        [string]$ScriptPath,
        [hashtable]$ThreatHashes,
        [bool]$DLPEnabled = $true,
        [bool]$DLPBlockTransfer = $false
    )

    $cmd = $Msg.command
    $mid = $Msg.id
    $resp = @{ type = "response"; id = $mid; status = "ok"; output = "" }

    try {
        switch ($cmd) {
            "ping" {
                $resp.output = "pong"
            }

            "shell" {
                try {
                    $resp.output = Invoke-Expression ($Msg.args) 2>&1 | Out-String
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "sysinfo" {
                try {
                    $osInfo = $null
                    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
                        try { $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch {}
                    } else {
                        try { $osInfo = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop } catch {}
                    }
                    $up = "N/A"
                    if ($osInfo) {
                        $bootTime = $null
                        if ($osInfo.LastBootUpTime -is [datetime]) {
                            $bootTime = $osInfo.LastBootUpTime
                        } elseif ($osInfo.PSObject.Methods["ConvertToDateTime"]) {
                            $bootTime = $osInfo.ConvertToDateTime($osInfo.LastBootUpTime)
                        }
                        if ($bootTime) {
                            $span = (Get-Date) - $bootTime
                            $up   = "{0}d {1}h {2}m" -f [int]$span.TotalDays, $span.Hours, $span.Minutes
                        }
                    }
                    $ramGB = if ($osInfo -and $osInfo.TotalVisibleMemorySize) {
                        [math]::Round($osInfo.TotalVisibleMemorySize / 1MB, 2)
                    } else { "Unknown" }

                    $csInfo = $null
                    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
                        try { $csInfo = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch {}
                    } else {
                        try { $csInfo = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop } catch {}
                    }
                    $model = if ($csInfo) { "$($csInfo.Manufacturer) $($csInfo.Model)".Trim() } else { "Unknown" }

                    $cpu = "Unknown"
                    try {
                        $cpuObj = if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
                            Get-CimInstance Win32_Processor | Select-Object -First 1
                        } else {
                            Get-WmiObject Win32_Processor | Select-Object -First 1
                        }
                        if ($cpuObj) { $cpu = $cpuObj.Name.Trim() }
                    } catch {}

                    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                                   [Security.Principal.WindowsBuiltInRole]::Administrator)

                    $edrStatus = if ($OpenEDRStatusFunc) { & $OpenEDRStatusFunc } else { @{ service_status = "Unknown" } }

                    $info = [ordered]@{
                        hostname             = $env:COMPUTERNAME
                        username             = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                        os                   = if ($osInfo) { $osInfo.Caption } else { "Windows" }
                        os_version           = if ($osInfo) { $osInfo.Version } else { "Unknown" }
                        arch                 = if ($osInfo) { $osInfo.OSArchitecture } else { $env:PROCESSOR_ARCHITECTURE }
                        cpu                  = $cpu
                        ram_gb               = $ramGB
                        model                = $model
                        uptime               = $up
                        is_admin             = $isAdmin
                        ps_version           = $PSVersionTable.PSVersion.ToString()
                        openedr_installed    = $edrStatus.installed
                        openedr_running      = $edrStatus.running
                        defense_capabilities = @("malware_prevention", "fim", "dlp", "openedr")
                    }
                    $resp.output = ($info | ConvertTo-Json -Compress)
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "ls" {
                try {
                    $targetPath = if ($Msg.args) {
                        $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Msg.args)
                    } else { (Get-Location).Path }

                    if (-not (Test-Path -LiteralPath $targetPath)) {
                        throw "Path does not exist: $targetPath"
                    }
                    $items = Get-ChildItem -LiteralPath $targetPath -Force -ErrorAction Stop |
                        Select-Object Name, Length, LastWriteTime, Mode,
                            @{ N = "IsDirectory"; E = { $_.PSIsContainer } }
                    $resp.output = ($items | ConvertTo-Json -Compress)
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "cd" {
                try {
                    $target = if ($Msg.args) { $Msg.args } else { $env:USERPROFILE }
                    Set-Location -LiteralPath $target -ErrorAction Stop
                    $resp.output = (Get-Location).Path
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "ps" {
                try {
                    $procs = Get-Process -ErrorAction Stop |
                        Select-Object Id, ProcessName,
                            @{ N = "CPU"; E = { if ($_.CPU) { [math]::Round($_.CPU, 2) } else { 0 } } },
                            @{ N = "RAM"; E = { [math]::Round($_.WorkingSet64 / 1MB, 1) } } |
                        Sort-Object ProcessName
                    $resp.output = ($procs | ConvertTo-Json -Compress)
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "kill" {
                try {
                    Stop-Process -Id ([int]$Msg.args) -Force -ErrorAction Stop
                    $resp.output = "Process $($Msg.args) terminated."
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "download" {
                try {
                    $targetPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Msg.args)
                    if ($DLPEnabled -and $DlpScanFunc) {
                        $violations = & $DlpScanFunc $targetPath
                        if ($violations -and $violations.Count -gt 0) {
                            if ($DLPBlockTransfer) {
                                throw "DLP Policy Block: Exfiltration of sensitive file prevented"
                            }
                        }
                    }
                    if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
                        throw "Target path is not a valid file: $targetPath"
                    }
                    $fi = Get-Item -LiteralPath $targetPath
                    if ($fi.Length -gt 36700160) {
                        throw "File size ($([math]::Round($fi.Length / 1MB, 2)) MB) exceeds single-frame transfer limit of 35 MB."
                    }
                    $bytes = [System.IO.File]::ReadAllBytes($targetPath)
                    $resp.output   = [Convert]::ToBase64String($bytes)
                    $resp.filename = [System.IO.Path]::GetFileName($targetPath)
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "upload" {
                try {
                    $destPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Msg.path)
                    $bytes = [Convert]::FromBase64String($Msg.data)
                    # Pre-write malware scan
                    $sha = [System.Security.Cryptography.SHA256]::Create()
                    $hash = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
                    $sha.Dispose()
                    if ($ThreatHashes -and $ThreatHashes.ContainsKey($hash.ToLower())) {
                        $threat = $ThreatHashes[$hash.ToLower()]
                        throw "Malware Block: File signature matches threat $threat"
                    }

                    $parentDir = [System.IO.Path]::GetDirectoryName($destPath)
                    if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
                        [System.IO.Directory]::CreateDirectory($parentDir) | Out-Null
                    }
                    [System.IO.File]::WriteAllBytes($destPath, $bytes)
                    $resp.output = "Uploaded $($bytes.Length) bytes to $destPath"
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "download_chunk" {
                try {
                    $rawPath = if ($Msg.path) { $Msg.path } elseif ($Msg.args) { $Msg.args } else { "" }
                    $targetPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($rawPath)
                    $offset = if ($null -ne $Msg.offset) { [long]$Msg.offset } else { 0L }
                    $chunkSize = if ($Msg.chunk_size) { [int]$Msg.chunk_size } else { 524288 }

                    if ($offset -eq 0 -and $DLPEnabled -and $DlpScanFunc) {
                        $violations = & $DlpScanFunc $targetPath
                        if ($violations -and $violations.Count -gt 0) {
                            if ($DLPBlockTransfer) {
                                throw "DLP Policy Block: Exfiltration of sensitive file prevented"
                            }
                        }
                    }

                    if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
                        throw "Target path is not a valid file: $targetPath"
                    }

                    $fi = Get-Item -LiteralPath $targetPath
                    $totalSize = $fi.Length

                    $fs = [System.IO.File]::Open($targetPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    if ($offset -gt 0) {
                        [void]$fs.Seek($offset, [System.IO.SeekOrigin]::Begin)
                    }
                    $buffer = New-Object byte[] $chunkSize
                    $bytesRead = $fs.Read($buffer, 0, $chunkSize)
                    $fs.Close()
                    $fs.Dispose()

                    $isEof = ($offset + $bytesRead -ge $totalSize)
                    $outBuffer = if ($bytesRead -eq $chunkSize) { $buffer } else {
                        $trimmed = New-Object byte[] $bytesRead
                        [System.Array]::Copy($buffer, $trimmed, $bytesRead)
                        $trimmed
                    }

                    $resp.total_size  = $totalSize
                    $resp.offset      = $offset
                    $resp.chunk_size  = $bytesRead
                    $resp.eof         = $isEof
                    $resp.data        = [Convert]::ToBase64String($outBuffer)
                    $resp.filename    = [System.IO.Path]::GetFileName($targetPath)
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "upload_chunk" {
                try {
                    $rawPath = if ($Msg.path) { $Msg.path } elseif ($Msg.args) { $Msg.args } else { "" }
                    $destPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($rawPath)
                    $offset = if ($null -ne $Msg.offset) { [long]$Msg.offset } else { 0L }
                    $isEof = if ($null -ne $Msg.eof) { [bool]$Msg.eof } else { $false }
                    $bytes = [Convert]::FromBase64String($Msg.data)

                    $parentDir = [System.IO.Path]::GetDirectoryName($destPath)
                    if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
                        [System.IO.Directory]::CreateDirectory($parentDir) | Out-Null
                    }

                    $mode = if ($offset -eq 0) { [System.IO.FileMode]::Create } else { [System.IO.FileMode]::OpenOrCreate }
                    $fs = [System.IO.File]::Open($destPath, $mode, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                    if ($offset -gt 0) {
                        [void]$fs.Seek($offset, [System.IO.SeekOrigin]::Begin)
                    }
                    $fs.Write($bytes, 0, $bytes.Length)
                    $fs.Flush()
                    $fs.Close()
                    $fs.Dispose()

                    if ($isEof) {
                        $sha = [System.Security.Cryptography.SHA256]::Create()
                        $fsCheck = [System.IO.File]::OpenRead($destPath)
                        $hb = $sha.ComputeHash($fsCheck)
                        $fsCheck.Close()
                        $fsCheck.Dispose()
                        $sha.Dispose()
                        $hash = ($hb | ForEach-Object { $_.ToString("x2") }) -join ""

                        if ($ThreatHashes -and $ThreatHashes.ContainsKey($hash.ToLower())) {
                            Remove-Item -LiteralPath $destPath -Force -ErrorAction SilentlyContinue
                            $threat = $ThreatHashes[$hash.ToLower()]
                            throw "Malware Block: File signature matches threat $threat"
                        }
                    }

                    $resp.bytes_written = $bytes.Length
                    $resp.offset        = $offset
                    $resp.eof           = $isEof
                    $resp.output        = "Wrote $($bytes.Length) bytes at offset $offset"
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "malware_scan" {
                try {
                    $target = if ($Msg.args) { $Msg.args } else { (Get-Location).Path }
                    $findings = if ($MalwareScanFunc) { & $MalwareScanFunc $target } else { @() }
                    $resp.output = ($findings | ConvertTo-Json -Compress)
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "quarantine" {
                try {
                    $qRes = if ($QuarantineFunc) { & $QuarantineFunc $Msg.args } else { @{ status = "error"; message = "Unavailable" } }
                    $resp.status = $qRes.status
                    $resp.output = ($qRes | ConvertTo-Json -Compress)
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "quarantine_list" {
                try {
                    $list = if ($QuarantineListFunc) { & $QuarantineListFunc } else { @() }
                    $resp.output = ($list | ConvertTo-Json -Compress)
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "quarantine_restore" {
                try {
                    $rRes = if ($QuarantineRestoreFunc) { & $QuarantineRestoreFunc $Msg.args } else { @{ status = "error"; message = "Unavailable" } }
                    $resp.status = $rRes.status
                    $resp.output = ($rRes | ConvertTo-Json -Compress)
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "fim_init" {
                try {
                    if ($FimInitFunc) { & $FimInitFunc }
                    $resp.output = "FIM baseline initialized."
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "fim_check" {
                try {
                    $changes = if ($FimCheckFunc) { & $FimCheckFunc } else { @() }
                    $resp.output = ($changes | ConvertTo-Json -Compress)
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "fim_add_path" {
                try {
                    if ($FimAddPathFunc) { & $FimAddPathFunc $Msg.args }
                    $resp.output = "Added $($Msg.args) to FIM targets. Baseline re-indexed."
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "dlp_scan" {
                try {
                    $target = $Msg.args
                    $violations = if (Test-Path -LiteralPath $target -PathType Leaf) {
                        & $DlpScanFunc $target
                    } else {
                        Scan-DLPText $target
                    }
                    $resp.output = ($violations | ConvertTo-Json -Compress)
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "openedr_status" {
                try {
                    $st = if ($OpenEDRStatusFunc) { & $OpenEDRStatusFunc } else { @{} }
                    $resp.output = ($st | ConvertTo-Json -Compress)
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "openedr_fetch_telemetry" {
                try {
                    $t = if ($OpenEDRTelemetryFunc) { & $OpenEDRTelemetryFunc 50 } else { @() }
                    $resp.output = ($t | ConvertTo-Json -Compress)
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "isolate_host" {
                try {
                    $enable = ($Msg.args -eq "true" -or $Msg.args -eq "1" -or $Msg.args -eq $true)
                    $isoRes = if ($HostIsolationFunc) { & $HostIsolationFunc $enable } else { @{ status = "error"; message = "Unavailable" } }
                    $resp.status = $isoRes.status
                    $resp.output = $isoRes.message
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "install_openedr" {
                try {
                    $instRes = if ($InstallOpenEDRFunc) { & $InstallOpenEDRFunc } else { @{ status = "error"; message = "Unavailable" } }
                    $resp.status = $instRes.status
                    $resp.output = $instRes.message
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            "attest" {
                try {
                    $nonce = $Msg.args
                    $resolvedScript = if ($ScriptPath) { $ScriptPath } else {
                        if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.ScriptName }
                    }
                    $codeBytes = [System.IO.File]::ReadAllBytes($resolvedScript)
                    $sha = [System.Security.Cryptography.SHA256]::Create()
                    $rawHash = ($sha.ComputeHash($codeBytes) | ForEach-Object { $_.ToString("x2") }) -join ""
                    $sha.Dispose()

                    $hmacAlg = New-Object System.Security.Cryptography.HMACSHA256
                    $hmacAlg.Key = [System.Text.Encoding]::UTF8.GetBytes($nonce)
                    $attestHash = ($hmacAlg.ComputeHash($codeBytes) | ForEach-Object { $_.ToString("x2") }) -join ""
                    $hmacAlg.Dispose()

                    $info = [ordered]@{
                        path        = $resolvedScript
                        raw_sha256  = $rawHash
                        attest_hmac = $attestHash
                        bytes_len   = $codeBytes.Length
                        pid         = $PID
                    }
                    $resp.output = ($info | ConvertTo-Json -Compress)
                } catch {
                    $resp.status = "error"
                    $resp.output = $_.Exception.Message
                }
            }

            default {
                $resp.status = "error"
                $resp.output = "Unknown command: $($Msg.command)"
            }
        }
    } catch {
        $resp.status = "error"
        $resp.output = $_.Exception.Message
    }

    return $resp
}

Export-ModuleMember -Function Invoke-AgentCommand -Variable ResponseQueue
