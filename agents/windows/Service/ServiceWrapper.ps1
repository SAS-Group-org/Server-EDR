# ============================================================
#  ServiceWrapper.ps1 - Headless Windows Service Runner & Watchdog
# ============================================================

$PSScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$WindowsAgent = Split-Path -Parent $PSScriptDir
$CoreScript   = Join-Path $WindowsAgent "Agent-Core.ps1"
$LogDir       = "$env:ProgramData\Server-EDR"
$LogFile      = Join-Path $LogDir "service.log"

$ConfigPath   = Join-Path $LogDir "agent_config.json"
if (-not (Test-Path $ConfigPath)) {
    if (Test-Path (Join-Path $WindowsAgent "agent_config.json")) {
        $ConfigPath = Join-Path $WindowsAgent "agent_config.json"
    }
}

if (-not (Test-Path $LogDir)) {
    try { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null } catch {}
}

function Log-Service {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] $Message"
    try { Add-Content -Path $LogFile -Value $line } catch {}
    Write-Output $line
}

Log-Service "Server-EDR Service Wrapper starting (PID: $PID)"
Log-Service "Core Script: $CoreScript"
if (Test-Path $ConfigPath) {
    Log-Service "Config File: $ConfigPath"
}

if (-not (Test-Path $CoreScript)) {
    Log-Service "ERROR: Agent-Core.ps1 not found at $CoreScript"
    exit 1
}

$running = $true

# Register shutdown handler
Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action {
    Log-Service "Service Wrapper received shutdown signal. Stopping child process."
} | Out-Null

while ($running) {
    Log-Service "Launching Agent-Core.ps1 process..."
    try {
        $coreArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$CoreScript`""
        if (Test-Path $ConfigPath) {
            $coreArgs += " -ConfigPath `"$ConfigPath`""
        }

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        $psi.Arguments = $coreArgs
        $psi.WorkingDirectory = $WindowsAgent
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true

        $proc = [System.Diagnostics.Process]::Start($psi)
        Log-Service "Agent-Core running with PID $($proc.Id)"

        $proc.WaitForExit()
        $code = $proc.ExitCode
        Log-Service "Agent-Core process exited with code $code"

        if ($code -eq 0) {
            Log-Service "Clean exit requested. Stopping wrapper."
            break
        }
    } catch {
        Log-Service "Exception running Agent-Core: $($_.Exception.Message)"
    }

    Log-Service "Respawning Agent-Core in 3 seconds (Watchdog Recovery)..."
    Start-Sleep -Seconds 3
}
