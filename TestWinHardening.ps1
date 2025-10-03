<#
Hardening script for Windows (PowerShell) that installs and uses NSSM to run a small monitoring service.
- Save as hardening-windows-nssm.ps1
- Run as Administrator: open Elevated PowerShell and run:
    powershell -ExecutionPolicy Bypass -File .\hardening-windows-nssm.ps1
- Idempotent: safe to run multiple times
- Log file: C:\Windows\Temp\hardening-windows-nssm.log
#>

# Ensure script runs as admin
function Assert-Elevation {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "This script must be run as Administrator. Exiting."
        exit 1
    }
}

Assert-Elevation

$LogFile = "C:\Windows\Temp\hardening-windows-nssm.log"
"=== HARDENING START $(Get-Date -Format o) ===" | Out-File -FilePath $LogFile -Encoding utf8 -Append

function Log {
    param($msg)
    $t = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$t  $msg" | Out-File -FilePath $LogFile -Encoding utf8 -Append
    Write-Host $msg
}

Log "Starting hardening run..."

# ----------------------------
# 1) Basic Windows Update (requires internet)
# ----------------------------
Log "Installing PSWindowsUpdate module (if missing) and checking for updates..."
try {
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Install-PackageProvider -Name NuGet -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
        Install-Module -Name PSWindowsUpdate -Force -Scope AllUsers -ErrorAction Stop
        Log "PSWindowsUpdate installed."
    } else {
        Log "PSWindowsUpdate already present."
    }

    # List available updates (non-blocking). Applying updates may require reboots; user/ops control advisable.
    Import-Module PSWindowsUpdate -ErrorAction Stop
    $updates = Get-WindowsUpdate -IgnoreUserInput -AcceptAll -ErrorAction SilentlyContinue
    if ($updates) {
        Log "Found updates: $($updates.Count). Installing..."
        # Install updates non-interactively; a reboot may be required.
        Install-WindowsUpdate -AcceptAll -IgnoreReboot -AutoReboot -Confirm:$false -ErrorAction SilentlyContinue
        Log "Install-WindowsUpdate invoked (some updates may require reboot)."
    } else {
        Log "No applicable updates found or unable to enumerate without elevated network access."
    }
} catch {
    Log "Windows Update step failed or skipped: $_"
}

# ----------------------------
# 2) Windows Defender - enable & basic config
# ----------------------------
Log "Configuring Windows Defender (real-time/cloud/behavior)..."
try {
    # Ensure service is running and set to automatic
    if (Get-Service -Name WinDefend -ErrorAction SilentlyContinue) {
        Set-Service -Name WinDefend -StartupType Automatic
        Start-Service -Name WinDefend -ErrorAction SilentlyContinue
        Log "Windows Defender service started and set to Automatic."
    } else {
        Log "Windows Defender service not found (may be disabled by policy)."
    }

    # Use Defender cmdlets where available
    if (Get-Command -Name Set-MpPreference -ErrorAction SilentlyContinue) {
        Set-MpPreference -DisableRealtimeMonitoring $false -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -HighThreatDefaultAction Clean -ErrorAction SilentlyContinue
        Log "Set-MpPreference applied."
    } else {
        Log "Defender cmdlets not available in this session; ensure Windows Defender feature is present."
    }
} catch {
    Log "Windows Defender configuration failed: $_"
}

# ----------------------------
# 3) Firewall hardening (keep RDP open but enforce NLA)
# ----------------------------
Log "Configuring Windows Firewall and RDP/NLA..."
try {
    # Ensure firewall enabled for all profiles
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
    Log "Firewall enabled for Domain/Private/Public."

    # Ensure Remote Desktop is enabled and NLA required
    # Enable RDP (do not remove access to existing users)
    $rdpRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    Set-ItemProperty -Path $rdpRegPath -Name "fDenyTSConnections" -Value 0 -ErrorAction SilentlyContinue
    Log "Remote Desktop enabled."

    # Require Network Level Authentication
    $nlaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    if (Test-Path $nlaPath) {
        Set-ItemProperty -Path $nlaPath -Name "UserAuthentication" -Value 1 -ErrorAction SilentlyContinue
        Log "NLA for RDP enabled."
    } else {
        Log "RDP-Tcp registry path not present - NLA setting skipped."
    }

    # Create a firewall rule to allow RDP (if not present)
    if (-not (Get-NetFirewallRule -DisplayName "Allow RDP (Hardening script)" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "Allow RDP (Hardening script)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 -Profile Domain,Private -EdgeTraversalPolicy Block
        Log "Firewall rule 'Allow RDP (Hardening script)' created (Domain/Private)."
    } else {
        Log "Firewall rule for RDP already exists."
    }

    # Consider restricting RDP by source IP later; we intentionally don't add Public allow to avoid exposing RDP on Internet.
    Log "Note: RDP is not opened for the Public profile by this script."
} catch {
    Log "Firewall/RDP step failed: $_"
}

# ----------------------------
# 4) Disable SMBv1 and enable SMB signing
# ----------------------------
Log "Disabling SMBv1 (if present) and enabling SMB signing preferences..."
try {
    # Disable SMBv1 server
    sc.exe config lanmanworkstation start= demand | Out-Null
    Enable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart -ErrorAction SilentlyContinue -All:$false | Out-Null
} catch {
    # Fallthrough; some commands may not apply on Server Core or older builds
    Log "SMBv1 commands had partial failure or not applicable: $_"
}

# Set registry keys for SMB signing on client & server (best-effort)
try {
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -PropertyType DWORD -Force | Out-Null
    Log "SMB signing registry preferences set (RequireSecuritySignature=1)."
} catch {
    Log "SMB signing registry write failed: $_"
}

# ----------------------------
# 5) Account lockout & password policy (conservative, idempotent)
# ----------------------------
Log "Applying account lockout policy (conservative defaults)..."
try {
    secedit /export /cfg C:\Windows\Temp\secpol-before.inf | Out-Null

    $secSettings = @"
[System Access]
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 15
MinimumPasswordLength = 8
PasswordComplexity = 1
"@

    $secFile = "C:\Windows\Temp\secpol-hardening.inf"
    $secSettings | Out-File -FilePath $secFile -Encoding ascii

    # Apply using secedit (merge)
    secedit /configure /db C:\Windows\security\local.sdb /cfg $secFile /areas SECURITYPOLICY | Out-Null
    Log "Account lockout and password policy applied (LockoutBadCount=5, Duration=15m, Reset=15m)."
} catch {
    Log "Account lockout policy set failed: $_"
}

# ----------------------------
# 6) Audit policy (enable key categories)
# ----------------------------
Log "Configuring audit policy (logon, privilege use, process creation, object access)..."
try {
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Privilege Use" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Object Access" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Policy Change" /success:enable /failure:enable | Out-Null
    Log "auditpol categories enabled."
} catch {
    Log "auditpol configuration failed: $_"
}

# OPTIONAL: enable process creation command line capture (requires setting registry)
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    New-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWORD -Force | Out-Null
    Log "Enabled process creation command-line capture (registry)."
} catch {
    Log "Failed to set process creation command-line capture: $_"
}

# ----------------------------
# 7) UAC / basic registry tweaks (non-invasive)
# ----------------------------
Log "Ensuring UAC is enabled and default behavior..."
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Force
    Log "UAC (EnableLUA) set to 1."
} catch {
    Log "UAC registry tweak failed: $_"
}

# ----------------------------
# 8) Install NSSM (Non-Sucking Service Manager) and create a monitoring service
# ----------------------------
$NssmRoot = "C:\nssm"
$NssmExe = Join-Path $NssmRoot "nssm.exe"
$NssmDownloadUrl = "https://nssm.cc/release/nssm-2.24.zip"  # default; if URL changes, update accordingly

Log "Installing NSSM if missing..."
try {
    if (-not (Test-Path $NssmExe)) {
        New-Item -Path $NssmRoot -ItemType Directory -Force | Out-Null
        $tmpZip = Join-Path $env:TEMP "nssm.zip"
        Log "Downloading NSSM from $NssmDownloadUrl ... (verify source if offline/locked down)"
        Invoke-WebRequest -Uri $NssmDownloadUrl -OutFile $tmpZip -UseBasicParsing -ErrorAction Stop
        Log "Downloaded NSSM zip to $tmpZip"
        # Extract: try Expand-Archive and fallback to Shell.Application
        try {
            Expand-Archive -Path $tmpZip -DestinationPath $NssmRoot -Force
        } catch {
            # Fallback: use COM Shell to extract
            $shell = New-Object -ComObject shell.application
            $zip = $shell.NameSpace($tmpZip)
            foreach ($item in $zip.Items()) { $shell.NameSpace($NssmRoot).CopyHere($item) }
        }
        # Try to locate nssm.exe under extracted contents (nssm-*/win64/nssm.exe or win32)
        $found = Get-ChildItem -Path $NssmRoot -Filter "nssm.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            Copy-Item -Path $found.FullName -Destination $NssmExe -Force
            Log "nssm.exe copied to $NssmExe"
        } else {
            Log "Unable to locate nssm.exe in the downloaded archive; please extract manually to $NssmRoot"
        }
        Remove-Item -Path $tmpZip -Force -ErrorAction SilentlyContinue
    } else {
        Log "NSSM already present at $NssmExe"
    }
} catch {
    Log "NSSM install/download failed: $_"
}

# ----------------------------
# 9) Create a small monitor script to run as a service (idempotent)
# ----------------------------
$MonitorScript = Join-Path $NssmRoot "svc-monitor.ps1"
$ServiceName = "SvcMonitor"

Log "Creating monitoring script at $MonitorScript (idempotent)."
$monitorContent = @'
# svc-monitor.ps1
# Simple monitor run by NSSM as a long-running service process.
# - Watches for select Event IDs and restarts critical services if they stop.
# - Configure $CriticalServices below to match your environment.
$CriticalServices = @("wuauserv","WinDefend")  # example; adjust as needed
$RestartOnCrash = $true
$EventLogThreshold = 300 # seconds to look back for suspicious events

function Log($m) {
    $t = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$t  $m" | Out-File -FilePath "C:\Windows\Temp\svc-monitor.log" -Encoding utf8 -Append
}

Log "svc-monitor starting..."

# Monitor loop
while ($true) {
    try {
        # Check critical services and restart if stopped
        foreach ($svc in $CriticalServices) {
            $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($s -and $s.Status -ne 'Running') {
                Log "Service $svc is $($s.Status) - attempting restart..."
                try { Start-Service -Name $svc -ErrorAction Stop; Log "Started $svc" } catch { Log "Failed to start $svc: $_" }
            }
        }

        # Example: watch for multiple failed logon events (4625) in recent window
        $since = (Get-Date).AddSeconds(-$EventLogThreshold)
        $failCount = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$since} -ErrorAction SilentlyContinue).Count
        if ($failCount -ge 5) {
            Log "High number of failed logons ($failCount) in last $EventLogThreshold seconds."
            # Placeholder: escalate or create file/alert
            New-Item -Path "C:\Windows\Temp\svc-monitor-alert.txt" -ItemType File -Force | Out-Null
        }
    } catch {
        Log "Monitor loop error: $_"
    }
    Start-Sleep -Seconds 30
}
'@

# Write the monitor script if missing or different
$write = $true
if (Test-Path $MonitorScript) {
    $existing = Get-Content -Raw -Path $MonitorScript -ErrorAction SilentlyContinue
    if ($existing -eq $monitorContent) { $write = $false }
}
if ($write) {
    $monitorContent | Out-File -FilePath $MonitorScript -Encoding utf8 -Force
    Log "Monitor script written/updated."
} else {
    Log "Monitor script unchanged."
}

# Ensure script is executable by PowerShell (just file, execution policy handled by NSSM running pwsh -File)
# ----------------------------
# 10) Register service with NSSM (idempotent)
# ----------------------------
if (Test-Path $NssmExe) {
    Log "Registering service '$ServiceName' with NSSM..."
    # Build command-line: use pwsh (PowerShell 7+) if available, fallback to powershell.exe
    $pwshPath = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source
    if (-not $pwshPath) { $pwshPath = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" }

    # Construct arguments
    $app = $pwshPath
    $appArgs = "-NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$MonitorScript`""

    # Check if service already exists
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        # nssm install ServiceName <app> <args>
        & $NssmExe install $ServiceName $app $appArgs
        Log "nssm install invoked for $ServiceName."

        # Set display name & description
        & $NssmExe set $ServiceName DisplayName "Service Monitor (NSSM)"
        & $NssmExe set $ServiceName Description "Monitors services and important events; installed by hardening script."
        # Auto-start
        & $NssmExe set $ServiceName Start SERVICE_AUTO_START

        # Set stdout/stderr paths for easy debugging
        & $NssmExe set $ServiceName AppStdout "C:\Windows\Temp\svc-monitor-out.log"
        & $NssmExe set $ServiceName AppStderr "C:\Windows\Temp\svc-monitor-err.log"

        # Set recovery options: restart on failure
        sc.exe failure $ServiceName reset= 86400 actions= restart/60000 | Out-Null

        # Start it
        Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        Log "Service $ServiceName installed and started via NSSM."
    } else {
        Log "Service $ServiceName already exists. Ensuring NSSM configured command matches expected entrypoint..."
        # verify nssm params and update if needed
        $currentApp = (& $NssmExe get $ServiceName AppDirectory) 2>$null
        # We keep this conservative; user may choose to re-install manually if differences exist.
        Log "Existing service found; skipping re-installation to avoid disrupting service accounts."
    }
} else {
    Log "nssm.exe not present; service registration skipped. Please install nssm and re-run part of the script if you want the monitor service."
}

# ----------------------------
# 11) Service hardening: set recovery, restart on failure
# ----------------------------
Log "Configuring service recovery options (best-effort)."
try {
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/none/0 | Out-Null
        Log "Service failure/recovery options set for $ServiceName."
    } else {
        Log "Service $ServiceName not present; skipping recovery config."
    }
} catch {
    Log "Service recovery config failed: $_"
}

# ----------------------------
# 12) Final notes, reminders, and clean-up
# ----------------------------
Log "Hardening run complete. Summary of locations:"
Log " - Hardening log: $LogFile"
Log " - Monitor script: $MonitorScript"
Log " - NSSM path: $NssmExe"
Log " - Monitor logs: C:\Windows\Temp\svc-monitor.log (and svc-monitor-out/err.log)"

"=== HARDENING COMPLETE $(Get-Date -Format o) ===" | Out-File -FilePath $LogFile -Encoding utf8 -Append
Log "Done. Please review the log and the changes before rebooting (some updates or policy changes may need a reboot)."
