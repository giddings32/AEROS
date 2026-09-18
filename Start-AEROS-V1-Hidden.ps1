# Start-AEROS-V1-Hidden.ps1
# Put this file in the AEROS V1 application folder.
# Direct Python launcher. No nested cmd.exe server wrapper.

$ErrorActionPreference = "Stop"

$AppDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Port = 8765
$BaseUrl = "http://127.0.0.1:$Port"
$Url = "$BaseUrl/index.html?desktop=1"

$LogDir = Join-Path $env:LOCALAPPDATA "AEROS\logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

$LauncherLog = Join-Path $LogDir "launcher.log"
$ServerOut = Join-Path $LogDir "server.out.log"
$ServerErr = Join-Path $LogDir "server.err.log"

function Write-LauncherLog {
    param([string]$Message)
    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LauncherLog -Value "[$stamp] $Message"
}

function Show-ErrorBox {
    param([string]$Message)
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show($Message, "AEROS V1") | Out-Null
}

function Get-ExpectedBuildIdentity {
    if ($script:ExpectedBuildIdentity) { return $script:ExpectedBuildIdentity }
    $files = @(
        "server.py", "desktop_app.py", "app.js", "index.html",
        "app/core/theme-bootstrap.js", "app/core/application.js",
        "app/styles/themes.css", "app/styles/core.css",
        "app/styles/components.css", "app/styles/features.css", "app/styles/pages.css",
        "templates.js", "notes.js", "highlighters.js",
        "app/features/readiness/readiness.js", "review.js",
        "app/features/workflow/exam-controls.js",
        "app/features/workflow/oscp-workflow.js",
        "app/features/navigator/navigator-core.js",
        "app/features/navigator/oscp-navigator.js",
        "app/features/host-workbench/host-workbench.js",
        "profiles.js",
        "scan-intelligence.js", "app/features/imports/import-lifecycle.js",
        "app/features/imports/autorecon-live-import.js", "app/features/imports/live-import-core.js", "app/features/imports/live-import-browser.js",
        "app/features/imports/recon-import.js", "app/features/recon/recon-projection.js", "app/features/recon/recon-triage.js", "app/features/recon/initial-recon.js",
        "app/features/peas/peas-organizer.js",
        "app/features/artifacts/artifact-identity.js", "nmapimport.js",
        "kernel-exploit-helper.js", "network-context.js", "network-context-ui.js", "reference-note-matcher.js", "asset-groups.js",
        "context-foundation.js", "app/features/access-contexts/access-contexts.js",
        "linux-software-intelligence.js", "methodology-tasks.js", "methodology-ui.js",
        "stage-awareness.js", "app/features/methodology/methodology-contexts.js",
        "host-profile.js", "command-paths.js",
        "app/features/reference-notes/reference-note-renderer.js",
        "app/features/recon/recon-workspace.js", "app/features/exploitation-path/exploitation-path.js", "app/features/recon/web-app-review.js",
        "app/features/access-leads/access-leads.js",
        "app/features/exploit-attempts/exploit-attempts.js",
        "app/features/findings/findings.js",
        "app/features/persistence/persistence.js",
        "app/features/engagements/engagements.js",
        "app/features/evidence/evidence.js", "app/features/reporting/reporting.js",
        "ux-enhancements.js", "app/features/asset-groups/group-manager.js",
        "artifact_identity.py", "engagement_model.py", "engagement_store.py", "legacy_import.py"
    )
    $hash = [System.Security.Cryptography.IncrementalHash]::CreateHash(
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    $zero = [byte[]](0)
    foreach ($relative in $files) {
        $hash.AppendData([System.Text.Encoding]::UTF8.GetBytes($relative))
        $hash.AppendData($zero)
        $path = Join-Path $AppDir $relative
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $hash.AppendData([System.IO.File]::ReadAllBytes($path))
        } else {
            $hash.AppendData([System.Text.Encoding]::UTF8.GetBytes("<missing>"))
        }
        $hash.AppendData($zero)
    }
    $script:ExpectedBuildIdentity = ([System.BitConverter]::ToString($hash.GetHashAndReset())).Replace("-", "").ToLowerInvariant()
    $hash.Dispose()
    return $script:ExpectedBuildIdentity
}

function Get-ExpectedDataRoot {
    $override = if (-not [string]::IsNullOrWhiteSpace($env:AEROS_DATA_DIR)) {
        $env:AEROS_DATA_DIR.Trim()
    } elseif (-not [string]::IsNullOrWhiteSpace($env:OSCP_REPORT_BUILDER_DATA_DIR)) {
        $env:OSCP_REPORT_BUILDER_DATA_DIR.Trim()
    } else {
        ""
    }
    $candidate = if ($override) {
        if ($override -eq "~") {
            $env:USERPROFILE
        } elseif ($override.StartsWith("~\") -or $override.StartsWith("~/")) {
            Join-Path $env:USERPROFILE $override.Substring(2)
        } else {
            $override
        }
    } else {
        Join-Path $env:LOCALAPPDATA "AEROS\data"
    }
    return [System.IO.Path]::GetFullPath($candidate)
}

function Get-ExpectedDataRootFingerprint {
    $normalized = (Get-ExpectedDataRoot).Replace("/", "\").ToLowerInvariant()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-ExpectedDataRootOverride {
    return (
        -not [string]::IsNullOrWhiteSpace($env:AEROS_DATA_DIR) -or
        -not [string]::IsNullOrWhiteSpace($env:OSCP_REPORT_BUILDER_DATA_DIR)
    )
}

function Test-AppServer {
    try {
        $indexUrl = "$BaseUrl/index.html?health=$([guid]::NewGuid().ToString())"
        $page = Invoke-WebRequest -Uri $indexUrl -TimeoutSec 2 -UseBasicParsing -Headers @{ "Cache-Control" = "no-cache" }
        $tokenMatch = [regex]::Match([string]$page.Content, 'window\.__APP_TOKEN__=([^;]+);')
        if (-not $tokenMatch.Success) { return $false }
        $token = $tokenMatch.Groups[1].Value | ConvertFrom-Json
        $health = Invoke-RestMethod -Uri "$BaseUrl/api/health" -TimeoutSec 2 -Headers @{ "X-App-Token" = $token }
        return (
            $health.ok -eq $true -and
            $health.instance.applicationId -eq "aeros-v1" -and
            $health.instance.buildIdentity -ceq (Get-ExpectedBuildIdentity) -and
            $health.instance.dataRootFingerprint -ceq (Get-ExpectedDataRootFingerprint) -and
            $health.instance.dataRootOverride -eq (Get-ExpectedDataRootOverride) -and
            $health.capabilities.reconImport -eq $true -and
            $health.capabilities.commandNotes -eq $true
        )
    } catch {
        return $false
    }
}

function Get-RealPython {
    $python = Get-Command python.exe -All -ErrorAction SilentlyContinue |
        Where-Object { $_.Source -and $_.Source -notlike "*\WindowsApps\python.exe" } |
        Select-Object -First 1

    if ($python) { return $python.Source }

    return $null
}

function Focus-ExistingAppWindow {
    try {
        Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32FocusAerosV1 {
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
}
"@ | Out-Null
    } catch {}

    $browserNames = @("msedge", "chrome", "brave")
    $existing = Get-Process $browserNames -ErrorAction SilentlyContinue |
        Where-Object {
            $_.MainWindowHandle -ne 0 -and
            (
                $_.MainWindowTitle -like "*AEROS V1*" -or
                $_.MainWindowTitle -like "*127.0.0.1:$Port*" -or
                $_.MainWindowTitle -like "*localhost:$Port*"
            )
        } |
        Select-Object -First 1

    if ($existing) {
        [Win32FocusAerosV1]::ShowWindowAsync($existing.MainWindowHandle, 9) | Out-Null
        [Win32FocusAerosV1]::SetForegroundWindow($existing.MainWindowHandle) | Out-Null
        Write-LauncherLog "Focused existing browser window: PID $($existing.Id), title '$($existing.MainWindowTitle)'"
        return $true
    }

    return $false
}

function Open-AppWindow {
    $brave1 = "${env:ProgramFiles}\BraveSoftware\Brave-Browser\Application\brave.exe"
    $brave2 = "${env:LOCALAPPDATA}\BraveSoftware\Brave-Browser\Application\brave.exe"
    $edge1 = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    $edge2 = "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe"
    $chrome1 = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
    $chrome2 = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"

    $browser = @($brave1, $brave2, $edge1, $edge2, $chrome1, $chrome2) |
        Where-Object { Test-Path $_ } |
        Select-Object -First 1

    if ($browser) {
        Write-LauncherLog "Opening browser app window: $browser --app=$Url"
        Start-Process -FilePath $browser -ArgumentList "--app=$Url"
    } else {
        Write-LauncherLog "Opening default browser: $Url"
        Start-Process $Url
    }
}

try {
    Write-LauncherLog "Launcher V1 started. AppDir=$AppDir"

    if ((Test-AppServer) -and (Focus-ExistingAppWindow)) {
        exit 0
    }

    if (-not (Test-Path (Join-Path $AppDir "server.py"))) {
        Write-LauncherLog "ERROR: server.py not found in $AppDir"
        Show-ErrorBox "server.py was not found in:`n$AppDir"
        exit 1
    }

    if (-not (Test-AppServer)) {
        Write-LauncherLog "A matching authenticated AEROS server is not responding. Starting this copy."

        $python = Get-RealPython
        if (-not $python) {
            Write-LauncherLog "ERROR: Real python.exe was not found."
            Show-ErrorBox "A real python.exe was not found.`n`nCheck Python install/PATH."
            exit 1
        }

        Write-LauncherLog "Starting direct hidden Python: $python server.py"

        $proc = Start-Process `
            -FilePath $python `
            -ArgumentList @("server.py") `
            -WorkingDirectory $AppDir `
            -WindowStyle Hidden `
            -RedirectStandardOutput $ServerOut `
            -RedirectStandardError $ServerErr `
            -PassThru

        Write-LauncherLog "Started Python PID $($proc.Id)"

        $started = $false
        for ($i = 0; $i -lt 80; $i++) {
            Start-Sleep -Milliseconds 250

            if (Test-AppServer) {
                $started = $true
                break
            }

            try {
                $proc.Refresh()
                if ($proc.HasExited) {
                    Write-LauncherLog "Python exited early with code $($proc.ExitCode)"
                    break
                }
            } catch {}
        }

        if (-not $started) {
            Write-LauncherLog "ERROR: Server did not respond after direct Python start."
            Show-ErrorBox "The server still did not respond on port $Port.`n`nCheck:`n$LauncherLog`n$ServerOut`n$ServerErr`n`nRun the DEBUG launcher if needed."
            exit 1
        }

        Write-LauncherLog "Server responded successfully."
    }

    if (-not (Focus-ExistingAppWindow)) {
        Open-AppWindow
    }
} catch {
    try { Write-LauncherLog "FATAL: $($_.Exception.Message)" } catch {}
    Show-ErrorBox "Launcher failed:`n$($_.Exception.Message)`n`nCheck:`n$LauncherLog"
    exit 1
}
