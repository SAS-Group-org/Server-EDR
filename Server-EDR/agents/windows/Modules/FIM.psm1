# ============================================================
#  FIM.psm1 - File Integrity Monitoring & Self-Defense Baseline
# ============================================================

$global:FIMBaseline = @{}
$global:FIMTargets  = @(
    "$env:windir\System32\drivers\etc\hosts",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
$global:FIMSelfProtectPaths = @()

function Get-FileSHA256 {
    param([string]$FilePath)
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return "" }
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $fs  = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $hashBytes = $sha.ComputeHash($fs)
        $fs.Close()
        $sha.Dispose()
        return ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""
    } catch { return "" }
}

function Register-FIMSelfProtect {
    param([string]$Path)
    if ($Path -and -not ($global:FIMSelfProtectPaths -contains $Path)) {
        $global:FIMSelfProtectPaths += $Path
        if (-not ($global:FIMTargets -contains $Path)) {
            $global:FIMTargets += $Path
        }
    }
}

function Init-FIMBaseline {
    $global:FIMBaseline = @{}
    foreach ($target in $global:FIMTargets) {
        if (Test-Path -LiteralPath $target -PathType Leaf) {
            $global:FIMBaseline[$target] = Get-FileSHA256 $target
        } elseif (Test-Path -LiteralPath $target -PathType Container) {
            Get-ChildItem -LiteralPath $target -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $global:FIMBaseline[$_.FullName] = Get-FileSHA256 $_.FullName
            }
        }
    }
}

function Add-FIMTarget {
    param([string]$TargetPath)
    if ($TargetPath -and -not ($global:FIMTargets -contains $TargetPath)) {
        $global:FIMTargets += $TargetPath
        if (Test-Path -LiteralPath $TargetPath -PathType Leaf) {
            $global:FIMBaseline[$TargetPath] = Get-FileSHA256 $TargetPath
        } elseif (Test-Path -LiteralPath $TargetPath -PathType Container) {
            Get-ChildItem -LiteralPath $TargetPath -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $global:FIMBaseline[$_.FullName] = Get-FileSHA256 $_.FullName
            }
        }
    }
}

function Check-FIMIntegrity {
    $changes = @()
    # 1. Check existing baseline for modifications and deletions
    foreach ($path in @($global:FIMBaseline.Keys)) {
        $isSelfProtect = $false
        foreach ($sp in $global:FIMSelfProtectPaths) {
            if ($path -eq $sp -or $path.StartsWith($sp + "\")) { $isSelfProtect = $true; break }
        }
        if (-not (Test-Path -LiteralPath $path)) {
            $entry = @{
                action   = "DELETED"
                path     = $path
                severity = if ($isSelfProtect) { "CRITICAL" } else { "HIGH" }
                details  = if ($isSelfProtect) { "ANTI-TAMPER: Agent-protected file was removed!" } else { "Monitored file was removed" }
                old_hash = $global:FIMBaseline[$path]
                tamper   = $isSelfProtect
            }
            $changes += $entry
            $global:FIMBaseline.Remove($path)
        } else {
            $curHash = Get-FileSHA256 $path
            if ($curHash -ne "" -and $curHash -ne $global:FIMBaseline[$path]) {
                $entry = @{
                    action   = "MODIFIED"
                    path     = $path
                    severity = "CRITICAL"
                    details  = if ($isSelfProtect) { "ANTI-TAMPER: Agent script or vault altered on disk!" } else { "File content altered (SHA-256 mismatch)" }
                    old_hash = $global:FIMBaseline[$path]
                    new_hash = $curHash
                    tamper   = $isSelfProtect
                }
                $changes += $entry
                $global:FIMBaseline[$path] = $curHash
            }
        }
    }

    # 2. Check for newly added files in directory targets
    foreach ($target in $global:FIMTargets) {
        if (Test-Path -LiteralPath $target -PathType Container) {
            Get-ChildItem -LiteralPath $target -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $fpath = $_.FullName
                if (-not $global:FIMBaseline.ContainsKey($fpath)) {
                    $newHash = Get-FileSHA256 $fpath
                    $global:FIMBaseline[$fpath] = $newHash
                    $entry = @{
                        action   = "ADDED"
                        path     = $fpath
                        severity = "MEDIUM"
                        details  = "New file created in monitored directory"
                        new_hash = $newHash
                        tamper   = $false
                    }
                    $changes += $entry
                }
            }
        }
    }
    return $changes
}

Export-ModuleMember -Function Get-FileSHA256, Register-FIMSelfProtect, Init-FIMBaseline, Add-FIMTarget, Check-FIMIntegrity -Variable FIMBaseline, FIMTargets, FIMSelfProtectPaths
