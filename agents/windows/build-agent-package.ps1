# ==============================================================================
# build-agent-package.ps1 - Package Builder for Server-EDR Windows Agent
# ==============================================================================

[CmdletBinding()]
param(
    [string]$Version         = "1.0.0",
    [ValidateSet("Full", "Minimal", "Service")]
    [string]$PackageType     = "Full",
    [string]$OutputDir       = "",
    [string]$ConfigFile      = "",
    [string]$ServerHost      = "",
    [int]$ServerPort         = 0,
    [string]$PSK             = "",
    [string]$CertThumbprint  = "",
    [switch]$NoTLS,
    [switch]$DryRun
)

$PSScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $OutputDir) {
    $OutputDir = Join-Path $PSScriptDir "dist"
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$PackageName = "Server-EDR-Agent-Windows-v${Version}"
$ZipPath     = Join-Path $OutputDir "${PackageName}.zip"

Write-Host "=== Server-EDR Windows Agent Package Builder ==="
Write-Host "[*] Target Version:      $Version"
Write-Host "[*] Package Type:        $PackageType"
Write-Host "[*] Output Path:         $ZipPath"

# Define required file sets
$RequiredModules = @(
    "Common.psm1",
    "FIM.psm1",
    "DLP.psm1",
    "Malware.psm1",
    "OpenEDR.psm1",
    "Executor.psm1"
)

$RequiredServices = @(
    "ServiceWrapper.ps1",
    "Install-Service.ps1",
    "Uninstall-Service.ps1"
)

# Validate source files exist
Write-Host "[*] Verifying component files..."
if ($PackageType -in @("Full", "Minimal")) {
    $corePath = Join-Path $PSScriptDir "Agent-Core.ps1"
    if (-not (Test-Path $corePath)) {
        Write-Error "Required file missing: $corePath"
        exit 1
    }

    $modDir = Join-Path $PSScriptDir "Modules"
    foreach ($m in $RequiredModules) {
        $mp = Join-Path $modDir $m
        if (-not (Test-Path $mp)) {
            Write-Error "Required module missing: $mp"
            exit 1
        }
    }
}

if ($PackageType -in @("Full", "Service")) {
    $svcDir = Join-Path $PSScriptDir "Service"
    foreach ($s in $RequiredServices) {
        $sp = Join-Path $svcDir $s
        if (-not (Test-Path $sp)) {
            Write-Error "Required service script missing: $sp"
            exit 1
        }
    }
}

if ($DryRun) {
    Write-Host "[+] Dry run completed. All source files verified."
    exit 0
}

# Create staging workspace
$tempDir = Join-Path $env:TEMP ("server_edr_pkg_" + [System.Guid]::NewGuid().ToString("N"))
$stagingDir = Join-Path $tempDir $PackageName
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

try {
    # 1. Copy core files
    if ($PackageType -in @("Full", "Minimal")) {
        Copy-Item (Join-Path $PSScriptDir "Agent-Core.ps1") -Destination $stagingDir -Force
        
        $destModDir = Join-Path $stagingDir "Modules"
        New-Item -ItemType Directory -Path $destModDir -Force | Out-Null
        foreach ($m in $RequiredModules) {
            Copy-Item (Join-Path (Join-Path $PSScriptDir "Modules") $m) -Destination $destModDir -Force
        }
    }

    # 2. Copy service files
    if ($PackageType -in @("Full", "Service")) {
        $destSvcDir = Join-Path $stagingDir "Service"
        New-Item -ItemType Directory -Path $destSvcDir -Force | Out-Null
        foreach ($s in $RequiredServices) {
            Copy-Item (Join-Path (Join-Path $PSScriptDir "Service") $s) -Destination $destSvcDir -Force
        }
    }

    # 3. Documentation and templates
    if ($PackageType -eq "Full") {
        $tmplPath = Join-Path $PSScriptDir "agent_config.json.template"
        if (Test-Path $tmplPath) {
            Copy-Item $tmplPath -Destination $stagingDir -Force
        }
        $readmePath = Join-Path $PSScriptDir "README.md"
        if (Test-Path $readmePath) {
            Copy-Item $readmePath -Destination $stagingDir -Force
        }
        $installAgentPath = Join-Path $PSScriptDir "Install-Agent.ps1"
        if (Test-Path $installAgentPath) {
            Copy-Item $installAgentPath -Destination $stagingDir -Force
        }
    }

    # 4. Handle injected configuration
    $injectedConfigObj = $null
    if ($ConfigFile -and (Test-Path $ConfigFile)) {
        Copy-Item $ConfigFile -Destination (Join-Path $stagingDir "agent_config.json") -Force
        Write-Host "[+] Injected configuration from: $ConfigFile"
    } elseif ($ServerHost -or $ServerPort -gt 0 -or $PSK) {
        $injectedConfigObj = [ordered]@{
            server = [ordered]@{
                host               = if ($ServerHost) { $ServerHost } else { "127.0.0.1" }
                port               = if ($ServerPort -gt 0) { $ServerPort } else { 443 }
                use_tls            = (-not $NoTLS)
                cert_fingerprint   = if ($CertThumbprint) { $CertThumbprint } else { "" }
                reconnect_interval = 10
                max_reconnect_delay = 60
            }
            auth = [ordered]@{
                psk = if ($PSK) { $PSK } else { "" }
            }
            agent = [ordered]@{
                log_level           = "INFO"
                fim_enabled         = $true
                dlp_enabled         = $true
                dlp_block_transfers = $false
            }
        }
        $jsonStr = $injectedConfigObj | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText((Join-Path $stagingDir "agent_config.json"), $jsonStr, [System.Text.Encoding]::UTF8)
        Write-Host "[+] Generated and injected dynamic agent_config.json"
    }

    # 5. Compute SHA256 checksums and build MANIFEST.json
    Write-Host "[*] Computing component checksums..."
    $manifest = [ordered]@{}
    $checksumLines = [System.Collections.Generic.List[string]]::new()

    $allFiles = Get-ChildItem -Path $stagingDir -Recurse -File
    foreach ($file in $allFiles) {
        $relPath = $file.FullName.Substring($stagingDir.Length).TrimStart("\", "/").Replace("\", "/")
        $hashObj = Get-FileHash -Path $file.FullName -Algorithm SHA256
        $hashHex = $hashObj.Hash.ToLower()

        $manifest[$relPath] = $hashHex
        $checksumLines.Add("${hashHex}  ${relPath}")
    }

    # Write MANIFEST.json and checksums.sha256 inside archive
    $manifestJson = $manifest | ConvertTo-Json -Depth 3
    [System.IO.File]::WriteAllText((Join-Path $stagingDir "MANIFEST.json"), $manifestJson, [System.Text.Encoding]::UTF8)
    [System.IO.File]::WriteAllLines((Join-Path $stagingDir "checksums.sha256"), $checksumLines.ToArray(), [System.Text.Encoding]::UTF8)

    # Also write checksums alongside output zip
    $outChecksumFile = Join-Path $OutputDir "${PackageName}.sha256"

    # 6. Compress staging folder to ZIP
    if (Test-Path $ZipPath) {
        Remove-Item $ZipPath -Force
    }

    Write-Host "[*] Creating zip archive at $ZipPath..."
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    try {
        [System.IO.Compression.ZipFile]::CreateFromDirectory($tempDir, $ZipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)
    } catch {
        Compress-Archive -Path (Join-Path $tempDir "*") -DestinationPath $ZipPath -Force
    }

    # Compute outer ZIP checksum
    $zipHash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLower()
    "${zipHash}  $(Split-Path -Leaf $ZipPath)" | Set-Content -Path $outChecksumFile -Encoding UTF8

    $zipSize = (Get-Item $ZipPath).Length
    Write-Host "[+] Package created successfully!"
    Write-Host "    Archive:  $ZipPath ($("{0:N0}" -f $zipSize) bytes)"
    Write-Host "    SHA256:   $zipHash"
    Write-Host "    Checksum: $outChecksumFile"

    return $ZipPath
} finally {
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
