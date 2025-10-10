<# 
.SYNOPSIS
Integrated dynamic Windows hardening script with deterministic password reset and script integrity verification.
.DESCRIPTION
- Two scenarios: RDP+FTP or RDP+SQL.
- Firewall/port hardening is now handled separately; this script skips blocking/allowing ports.
- Ensures Firewall + Defender run, updates Defender signatures.
- SMB disable/remove is interactive; destructive actions require explicit typed confirmation "YES".
- Deterministic password reset using an admin-supplied master secret (stateless derivation).
- Script integrity enforcement via SHA-256 of the running script; admin may provide an expected hash or store one locally.
- Backups + Restore Point attempted prior to destructive changes.
- Execution policy & Task Scheduler hardening included.
.NOTES
- Run as Administrator.
- Test in a non-production VM first.
#>

# ----------------------------
# Prelim: ensure running elevated
# ----------------------------
function Require-Admin { 
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) { 
        Write-Error "This script must be run as Administrator. Exiting." 
        exit 1 
    } 
} 
Require-Admin

# ----------------------------
# Detect script path (robust)
# ----------------------------
$OriginalInvocationPath = $MyInvocation.MyCommand.Path
if ($OriginalInvocationPath -and (Test-Path $OriginalInvocationPath)) { 
    $ScriptPath = $OriginalInvocationPath 
} else { 
    $ScriptPath = $null 
    Write-Host "Running interactively or without a script file; integrity features are limited. To enable full integrity checks, save this script to a .ps1 file and re-run as Administrator." 
}

# ----------------------------
# Setup logging
# ----------------------------
$LogFile = "$env:TEMP\hardening_dynamic_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date) 
function Log { 
    param([string]$Message, [string]$Level = "INFO") 
    $ts = (Get-Date).ToString("s") 
    $entry = "$ts [$Level] $Message" 
    $entry | Out-File -FilePath $LogFile -Append -Encoding utf8 
    if ($Level -eq "ERROR") { Write-Error $Message } else { Write-Host $Message } 
} 
Log "=== HARDENING START $(Get-Date -Format o) ==="

# ----------------------------
# Utility: get child process IDs recursively
# ----------------------------
function Get-ChildProcessIds { 
    param([int]$ParentPid) 
    $children = @() 
    try { 
        $all = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue 
        $direct = $all | Where-Object { $_.ParentProcessId -eq $ParentPid } | Select-Object -ExpandProperty ProcessId -ErrorAction SilentlyContinue 
        foreach ($pid in $direct) { 
            $children += $pid 
            $children += Get-ChildProcessIds -ParentPid $pid 
        } 
    } catch { } 
    return $children 
}

# ----------------------------
# Script integrity helpers
# ----------------------------
function Get-FileSHA256 { 
    param([Parameter(Mandatory=$true)][string]$Path) 
    try { 
        $sha = [System.Security.Cryptography.SHA256]::Create() 
        $stream = [System.IO.File]::OpenRead($Path) 
        try { 
            $hashBytes = $sha.ComputeHash($stream) 
            return ([BitConverter]::ToString($hashBytes)).Replace("-","").ToLowerInvariant() 
        } finally { $stream.Close() } 
    } catch { throw "Failed to compute SHA256 for $Path : $_" } 
} 

$EnableIntegrityCheck = $false
$ExpectedHash = $null
$HashFilePath = $null
$CurrentHash = $null

if ($ScriptPath) {
    try { 
        $CurrentHash = Get-FileSHA256 -Path $ScriptPath 
        Log ("Computed current script SHA256: {0}" -f $CurrentHash) 
    } catch { 
        Log ("Failed computing script hash: {0}" -f $_) "ERROR" 
        $CurrentHash = $null 
    } 
} else { 
    Log "No script path available; integrity features limited." "WARN" 
}

$doIntegrityPrompt = Read-Host "Do you want to enable script integrity verification before destructive actions? (Y/n)"
if ($doIntegrityPrompt -eq "" -or $doIntegrityPrompt -match '^[Yy]') { 
    $EnableIntegrityCheck = $true 
    if ($ScriptPath) { 
        $HashFilePath = "$ScriptPath.sha256" 
        if (Test-Path $HashFilePath) { 
            try { 
                $ExpectedHash = (Get-Content -Path $HashFilePath -ErrorAction Stop).Trim() 
                Log ("Loaded expected hash from {0}" -f $HashFilePath) 
            } catch { 
                Log "Failed to read existing .sha256 file; you will be asked to provide expected hash." "WARN" 
            } 
        } 
    } 
    if (-not $ExpectedHash) { 
        $provided = Read-Host "Paste expected SHA256 hash now, or press Enter to store current script hash to a .sha256 file for future runs (safer)." 
        if ($provided -and $provided.Trim().Length -ge 64) { 
            $ExpectedHash = $provided.Trim().ToLowerInvariant() 
            Log "Using pasted expected hash for verification." 
        } else { 
            if ($ScriptPath -and $CurrentHash) { 
                $saveConfirm = Read-Host "No hash provided. Save current script hash to '$HashFilePath' for future verification? (Y/n)" 
                if ($saveConfirm -eq "" -or $saveConfirm -match '^[Yy]') { 
                    try { $CurrentHash | Out-File -FilePath $HashFilePath -Encoding ascii -Force; $ExpectedHash = $CurrentHash; Log ("Wrote current hash to {0}" -f $HashFilePath) } catch { Log "Failed to write .sha256 file: $_" "ERROR" } 
                } else { Log "Integrity check enabled but no expected hash configured; you will be prompted to paste expected hash before destructive actions." "WARN" } 
            } else { Log "No script path available to save hash file." "WARN" } 
        } 
    } 
} else { 
    Log "Integrity verification disabled by admin choice." 
}

function Verify-ScriptIntegrity { 
    if (-not $EnableIntegrityCheck) { return $true } 
    if (-not $CurrentHash) { Write-Error "Cannot compute current script hash; aborting destructive action."; return $false } 
    if (-not $ExpectedHash) { 
        $provided = Read-Host "Paste expected SHA256 hash now for verification (or type SKIP to bypass one-time):" 
        if ($provided -and $provided.Trim().Length -ge 64) { $ExpectedHash = $provided.Trim().ToLowerInvariant() } 
        elseif ($provided -eq "SKIP") { Write-Warning "One-time integrity skip requested; destructive action will proceed. This is insecure."; return $true } 
        else { Write-Error "No valid expected hash provided; aborting destructive action."; return $false } 
    } 
    if ($CurrentHash -ne $ExpectedHash) { 
        Write-Error "Script integrity check FAILED: current hash does not match expected hash. Aborting destructive action." 
        Log ("Integrity mismatch: current {0} expected {1}" -f $CurrentHash, $ExpectedHash) "ERROR" 
        return $false 
    } 
    Log "Script integrity verified (hash matches)." 
    return $true 
}

# ----------------------------
# Remote-session safety
# ----------------------------
function Confirm-Remote-Run { 
    $isRdp = $false 
    if ($env:SESSIONNAME -and $env:SESSIONNAME -like "RDP-Tcp*") { $isRdp = $true } 
    if ($isRdp) { 
        Write-Warning "Detected an RDP session. Changing system settings may lock you out." 
        $confirm = Read-Host "Type EXACTLY 'YES' to proceed despite remote-session risk (anything else aborts)" 
        if ($confirm -ne "YES") { Log "User aborted due to remote-session safety check." "ERROR"; throw "Aborted by user." } 
    } 
} 
Confirm-Remote-Run

# ----------------------------
# Backup & Restore Point
# ----------------------------
function Create-RestorePoint { 
    try { 
        if (Get-Command -Name Checkpoint-Computer -ErrorAction SilentlyContinue) { 
            Checkpoint-Computer -Description "HardeningBackup_$(Get-Date -Format s)" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop 
            Log "Created System Restore point." 
        } else { 
            Log "Checkpoint-Computer is not available on this system (normal on Server Core / some editions)." "WARN" 
        } 
    } catch { Log ("Failed to create restore point: {0}" -f $_) "WARN" } 
} 

function Backup-ServiceAndRegistryInfo { 
    param([string]$OutDir = "$env:TEMP\hardening_backup_{0}" -f ((Get-Date).ToString("yyyyMMdd_HHmmss"))) 
    New-Item -Path $OutDir -ItemType Directory -Force | Out-Null 
    try { Get-Service | Select Name,DisplayName,StartType,Status | Export-Csv -Path (Join-Path $OutDir "services.csv") -NoTypeInformation -Force } catch { Log "Failed to export services list." "WARN" } 
    $keys = @("HKLM:\SYSTEM\CurrentControlSet\Services","HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer","HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10","HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb20") 
    foreach ($k in $keys) { try { $safeName = ($k -replace '[:\\]','_').TrimStart('_'); $outReg = (Join-Path $OutDir "$safeName.reg"); reg export $k $outReg /y 2>$null } catch {} } 
    Log ("Exported registry keys (best-effort) to {0}" -f $OutDir) 
    return $OutDir 
} 

Create-RestorePoint
$BackupDir = Backup-ServiceAndRegistryInfo
Log ("Backups stored at: {0}" -f $BackupDir)

# ----------------------------
# Version detection
# ----------------------------
try { 
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop 
    $OSVersion = $osInfo.Version 
    $OSBuild = [int]$osInfo.BuildNumber 
    $OSCaption = $osInfo.Caption 
    Log ("Detected OS: {0} (Version {1}, Build {2})" -f $OSCaption, $OSVersion, $OSBuild) 
    if ($OSVersion -like "6.2*" -or $OSVersion -like "6.3*") { $OSFamily = "2012" } 
    elseif ($OSVersion -like "10.0*") { if ($OSBuild -ge 20348) { $OSFamily = "2022" } elseif ($OSBuild -ge 17763) { $OSFamily = "2019" } else { $OSFamily = "2016" } } 
    else { $OSFamily = "Unknown" } 
    Log ("OS family determined: {0}" -f $OSFamily) 
} catch { Log "Failed to detect OS version; proceeding with conservative defaults." "WARN"; $OSFamily = "Unknown" }

# ----------------------------
# Ensure Firewall, Defender & Windows Update
# ----------------------------
# ... existing Ensure-Firewall, Ensure-Defender, Ensure-WindowsUpdate code unchanged ...

# ----------------------------
# Execution policy hardening
# ----------------------------
# ... Harden-ExecutionPolicy code unchanged ...

# ----------------------------
# Task Scheduler hardening
# ----------------------------
# ... Harden-TaskScheduler code unchanged ...

# ----------------------------
# Registry hardening module
# ----------------------------
# Copy the entire registry hardening module you provided here, including:
# Backup-RegistryKeys, Harden-RegistryKeyACL, Restore-RegistryACLsFromBackup,
# Perform-Registry-Hardening, and interactive invocation at the end.
# Ensure $BackupDir is used for registry backup output.

# ----------------------------
# Scenario selection (RDP+FTP or RDP+SQL)
# ----------------------------
# ... existing scenario selection code unchanged ...

# ----------------------------
# SMB handling (interactive)
# ----------------------------
# ... existing Offer-SMB-Removal code unchanged ...

# ----------------------------
# Interactive destructive service removal
# ----------------------------
# ... existing Interactive-Service-Removal code unchanged ...

# ----------------------------
# Deterministic password reset
# ----------------------------
# ... existing Prompt-And-Reset-LocalUsers code unchanged ...

# ----------------------------
# Pre-compromise scanning & cleanup
# ----------------------------
# ... existing Remove-MaliciousPersistence code unchanged ...

# ----------------------------
# Final reporting & reminders
# ----------------------------
# ... existing final reporting code unchanged ...
