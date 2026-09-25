# ============================================================
#  DLP.psm1 - Data Loss Prevention & Removable Media Monitoring
# ============================================================

function Test-Luhn {
    param([string]$Number)
    $digits = ($Number -replace '\D', '').ToCharArray() | ForEach-Object { [int]::Parse($_) }
    if ($digits.Length -lt 13 -or $digits.Length -gt 19) { return $false }
    $sum = 0
    [array]::Reverse($digits)
    for ($i = 0; $i -lt $digits.Length; $i++) {
        $d = $digits[$i]
        if ($i % 2 -eq 1) {
            $doubled = $d * 2
            $sum += if ($doubled -gt 9) { $doubled - 9 } else { $doubled }
        } else {
            $sum += $d
        }
    }
    return ($sum % 10 -eq 0)
}

function Scan-DLPText {
    param([string]$Text)
    $findings = @()

    # Credit Card with Luhn validation
    $ccMatches = [regex]::Matches($Text, '\b(?:\d[ -]*?){13,19}\b')
    foreach ($m in $ccMatches) {
        $raw = $m.Value -replace '[ -]', ''
        if (Test-Luhn $raw) {
            $redacted = $raw.Substring(0, 4) + ("*" * ($raw.Length - 8)) + $raw.Substring($raw.Length - 4)
            $findings += @{ rule = "CREDIT_CARD"; severity = "CRITICAL"; preview = $redacted }
        }
    }

    # US SSN
    $ssnMatches = [regex]::Matches($Text, '\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b')
    foreach ($m in $ssnMatches) {
        $raw = $m.Value -replace '[- ]', ''
        $findings += @{ rule = "US_SSN"; severity = "HIGH"; preview = "***-**-" + $raw.Substring($raw.Length - 4) }
    }

    # AWS Key
    $awsMatches = [regex]::Matches($Text, '\b(AKIA[0-9A-Z]{16})\b')
    foreach ($m in $awsMatches) {
        $v = $m.Value
        $findings += @{ rule = "AWS_KEY"; severity = "CRITICAL"; preview = $v.Substring(0, 4) + "..." + $v.Substring($v.Length - 4) }
    }

    # GitHub PAT
    $ghMatches = [regex]::Matches($Text, '\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b')
    foreach ($m in $ghMatches) {
        $v = $m.Value
        $findings += @{ rule = "GITHUB_PAT"; severity = "CRITICAL"; preview = $v.Substring(0, 8) + "..." }
    }

    # Private Keys
    if ($Text -match '-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----') {
        $findings += @{ rule = "PRIVATE_KEY"; severity = "CRITICAL"; preview = "-----BEGIN PRIVATE KEY----- [REDACTED]" }
    }

    # JWT Token
    $jwtMatches = [regex]::Matches($Text, '\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b')
    foreach ($m in $jwtMatches) {
        $v = $m.Value
        $findings += @{ rule = "JWT_TOKEN"; severity = "MEDIUM"; preview = $v.Substring(0, [math]::Min(12, $v.Length)) + "..." }
    }

    return $findings
}

function Scan-DLPFile {
    param([string]$Path, [int]$MaxBytes = 5242880)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        $readLen = [math]::Min($fs.Length, $MaxBytes)
        $buffer = New-Object byte[] $readLen
        $null = $fs.Read($buffer, 0, $readLen)
        $fs.Close()
        $content = [System.Text.Encoding]::UTF8.GetString($buffer)
        return (Scan-DLPText $content)
    } catch { return @() }
}

$global:KnownDrives = @()
function Check-RemovableDrives {
    $current = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 2" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DeviceID)
    $newDrives = @()
    if ($global:KnownDrives.Count -gt 0) {
        foreach ($d in $current) {
            if (-not ($global:KnownDrives -contains $d)) {
                $newDrives += $d
            }
        }
    }
    $global:KnownDrives = $current
    return $newDrives
}

Export-ModuleMember -Function Test-Luhn, Scan-DLPText, Scan-DLPFile, Check-RemovableDrives
