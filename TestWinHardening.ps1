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
    if ($Level -eq "ERROR") { Write-Error $Message } elseif ($Level -eq "WARN") { Write-Warning $Message } else { Write-Host $Message }
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
    foreach ($k in $keys) {
        try {
            $safeName = ($k -replace '[:\\]','_').TrimStart('_')
            $outReg = (Join-Path $OutDir "$safeName.reg")
            reg export $k $outReg /y 2>$null
        } catch { Log ("Failed to export registry key {0}" -f $k) "WARN" }
    }
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
function Ensure-Firewall {
    try {
        Log "Ensuring Windows Firewall (MpsSvc) is running and set to automatic."
        if (Get-Service -Name MpsSvc -ErrorAction SilentlyContinue) {
            Set-Service -Name MpsSvc -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name MpsSvc -ErrorAction SilentlyContinue
            Log "Windows Firewall service ensured running."
        } else { Log "MpsSvc (Windows Firewall) service not found on this system." "WARN" }
    } catch { Log ("Ensure-Firewall failed: {0}" -f $_) "WARN" }
}
function Ensure-Defender {
    try {
        Log "Ensuring Microsoft Defender service is running and updating signatures (if available)."
        if (Get-Service -Name WinDefend -ErrorAction SilentlyContinue) {
            Set-Service -Name WinDefend -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name WinDefend -ErrorAction SilentlyContinue
            Log "WinDefend service ensured running."
        } else { Log "Windows Defender service not present on this system." "WARN" }
        if (Get-Command -Name Update-MpSignature -ErrorAction SilentlyContinue) {
            Update-MpSignature -ErrorAction SilentlyContinue
            Log "Updated Windows Defender signatures."
        } else {
            Log "Windows Defender PowerShell module not available; skipping signature update." "WARN"
        }
    } catch { Log ("Ensure-Defender failed: {0}" -f $_) "WARN" }
}
function Ensure-WindowsUpdate {
    try {
        Log "Ensuring Windows Update service (wuauserv) is running."
        if (Get-Service -Name wuauserv -ErrorAction SilentlyContinue) {
            Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name wuauserv -ErrorAction SilentlyContinue
            Log "wuauserv ensured running."
        } else { Log "wuauserv not found; skipping." "WARN" }
    } catch { Log ("Ensure-WindowsUpdate failed: {0}" -f $_) "WARN" }
}

Ensure-Firewall
Ensure-Defender
Ensure-WindowsUpdate

# ----------------------------
# Execution policy hardening
# ----------------------------
function Harden-ExecutionPolicy {
    try {
        Log "Hardening Execution Policy to 'AllSigned' (requires that scripts be signed by a trusted publisher)."
        # Make a best-effort change - if running in constrained environment this might fail.
        Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine -Force -ErrorAction Stop
        Log "Execution policy set to AllSigned."
    } catch {
        Log ("Failed to set execution policy to AllSigned: {0}" -f $_) "WARN"
        try {
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction SilentlyContinue
            Log "Fallback: Execution policy set to RemoteSigned."
        } catch { Log "Failed to set any stricter execution policy." "WARN" }
    }
}
Harden-ExecutionPolicy

# ----------------------------
# Task Scheduler hardening
# ----------------------------
function Harden-TaskScheduler {
    try {
        Log "Hardening Task Scheduler folder ACLs (C:\Windows\System32\Tasks)."
        $tasksPath = "$env:windir\System32\Tasks"
        if (Test-Path $tasksPath) {
            # Create backup ACL
            $aclBackup = (Get-Acl -Path $tasksPath).Sddl
            $aclBackup | Out-File -FilePath (Join-Path $BackupDir "TasksFolderAcl.sddl") -Encoding ascii -Force
            # Tighten ACL: remove 'Users' and 'Authenticated Users' entries if present
            $acl = Get-Acl -Path $tasksPath
            $removeTargets = @("BUILTIN\Users","NT AUTHORITY\Authenticated Users","Users")
            foreach ($t in $removeTargets) {
                $acl.Access | Where-Object { $_.IdentityReference -match $t } | ForEach-Object { $acl.RemoveAccessRule($_) }
            }
            # Ensure Administrators and SYSTEM have full control
            $admins = New-Object System.Security.Principal.NTAccount("BUILTIN\Administrators")
            $system = New-Object System.Security.Principal.NTAccount("NT AUTHORITY\SYSTEM")
            $fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
            $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
            $prop = [System.Security.AccessControl.PropagationFlags]::None
            $rule1 = New-Object System.Security.AccessControl.FileSystemAccessRule($admins, $fullControl, $inherit, $prop, "Allow")
            $rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule($system, $fullControl, $inherit, $prop, "Allow")
            $acl.AddAccessRule($rule1)
            $acl.AddAccessRule($rule2)
            Set-Acl -Path $tasksPath -AclObject $acl
            Log "Task Scheduler folder ACLs hardened (best-effort). Backup SDDL saved to $BackupDir\TasksFolderAcl.sddl"
        } else {
            Log "Tasks folder not found; skipping Task Scheduler ACL hardening." "WARN"
        }
    } catch { Log ("Harden-TaskScheduler failed: {0}" -f $_) "WARN" }
}
Harden-TaskScheduler

# ----------------------------
# Registry hardening module
# ----------------------------
function Backup-RegistryKeys {
    param([string[]]$Keys, [string]$OutDir)
    foreach ($k in $Keys) {
        try {
            $safeName = ($k -replace '[:\\]','_').TrimStart('_')
            $outReg = (Join-Path $OutDir "$safeName.reg")
            reg export $k $outReg /y 2>$null
            Log ("Exported registry key {0} to {1}" -f $k, $outReg)
        } catch { Log ("Failed to export {0}" -f $k) "WARN" }
    }
}

function Harden-RegistryKeyACL {
    param([string]$KeyPath)
    try {
        # Use PowerShell provider ACL if possible
        $tempFile = Join-Path $env:TEMP ("regacl_{0}.reg" -f ([Guid]::NewGuid().ToString()))
        # We'll attempt to set permissions using subinacl/icacls won't work for HKLM:\ keys, so use PowerShell's Set-Acl on the provider path.
        $provPath = $KeyPath
        $acl = Get-Acl -Path $provPath -ErrorAction Stop
        # Remove Everyone/Users/Authenticated Users
        $removeIds = @("Everyone", "BUILTIN\Users", "NT AUTHORITY\Authenticated Users")
        foreach ($ace in $acl.Access) {
            foreach ($r in $removeIds) {
                if ($ace.IdentityReference -match $r) {
                    $acl.RemoveAccessRule($ace)
                }
            }
        }
        # Add SYSTEM and Administrators full control
        $admins = New-Object System.Security.Principal.NTAccount("BUILTIN\Administrators")
        $system = New-Object System.Security.Principal.NTAccount("NT AUTHORITY\SYSTEM")
        $fileRuleType = [System.Security.AccessControl.RegistryRights]::FullControl
        $inheritFlags = [System.Security.AccessControl.InheritanceFlags]::None
        $propFlags = [System.Security.AccessControl.PropagationFlags]::None
        $ruleA = New-Object System.Security.AccessControl.RegistryAccessRule($admins, $fileRuleType, $inheritFlags, $propFlags, "Allow")
        $ruleS = New-Object System.Security.AccessControl.RegistryAccessRule($system, $fileRuleType, $inheritFlags, $propFlags, "Allow")
        $acl.SetAccessRule($ruleA)
        $acl.SetAccessRule($ruleS)
        Set-Acl -Path $provPath -AclObject $acl -ErrorAction Stop
        Log ("Hardened ACL for registry key {0}" -f $KeyPath)
        return $true
    } catch {
        Log ("Failed to harden ACL for {0}: {1}" -f $KeyPath, $_) "WARN"
        return $false
    }
}

function Restore-RegistryACLsFromBackup {
    param([string]$BackupSddlFile)
    try {
        if (-not (Test-Path $BackupSddlFile)) { Log "Backup SDDL file not found: $BackupSddlFile" "WARN"; return }
        $sddl = Get-Content -Path $BackupSddlFile -Raw
        # This function is a best-effort placeholder: mapping SDDL back to keys requires knowing which key it came from.
        Log "Restore-RegistryACLsFromBackup is not fully automatic. Please manually review $BackupSddlFile to restore ACLs if necessary." "WARN"
    } catch { Log ("Restore-RegistryACLsFromBackup failed: {0}" -f $_) "WARN" }
}

function Perform-Registry-Hardening {
    param([string[]]$TargetKeys, [string]$OutDir)
    Backup-RegistryKeys -Keys $TargetKeys -OutDir $OutDir
    foreach ($k in $TargetKeys) {
        Try {
            Harden-RegistryKeyACL -KeyPath $k | Out-Null
        } catch { Log ("Error hardening {0}: {1}" -f $k, $_) "WARN" }
    }
    Log "Registry hardening attempts complete (see logs for details)."
}

# Example registry keys to harden (best-effort list)
$regKeysToHarden = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
    "HKLM:\SYSTEM\CurrentControlSet\Services",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
)

Perform-Registry-Hardening -TargetKeys $regKeysToHarden -OutDir $BackupDir

# ----------------------------
# Scenario selection (RDP+FTP or RDP+SQL)
# ----------------------------
function Select-Scenario {
    $choice = Read-Host "Select scenario to apply (1) RDP+FTP, (2) RDP+SQL, or press Enter to skip (1/2/skip)"
    switch ($choice) {
        "1" {
            Log "Scenario selected: RDP + FTP"
            # Ensure RDP enabled: set registry & firewall is left external per design
            try {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -ErrorAction Stop
                Log "Enabled Remote Desktop (fDenyTSConnections=0)"
            } catch { Log ("Failed to enable RDP: {0}" -f $_) "WARN" }
            # Attempt to ensure FTP service presence
            if (Get-Service -Name FTPSVC -ErrorAction SilentlyContinue) {
                Set-Service -Name FTPSVC -StartupType Automatic -ErrorAction SilentlyContinue
                Start-Service -Name FTPSVC -ErrorAction SilentlyContinue
                Log "FTPSVC service started (IIS FTP)."
            } else {
                Log "FTPSVC service not found; IIS FTP not installed or named differently." "WARN"
            }
        }
        "2" {
            Log "Scenario selected: RDP + SQL"
            try {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -ErrorAction Stop
                Log "Enabled Remote Desktop (fDenyTSConnections=0)"
            } catch { Log ("Failed to enable RDP: {0}" -f $_) "WARN" }
            # Try to find common SQL Server service names
            $sqlServices = @("MSSQLSERVER","MSSQL$SQLEXPRESS")
            $found = $false
            foreach ($s in $sqlServices) {
                if (Get-Service -Name $s -ErrorAction SilentlyContinue) {
                    Set-Service -Name $s -StartupType Automatic -ErrorAction SilentlyContinue
                    Start-Service -Name $s -ErrorAction SilentlyContinue
                    Log ("Ensured SQL service {0} is running." -f $s)
                    $found = $true
                }
            }
            if (-not $found) { Log "No common SQL Server service found. If SQL is installed under a different instance name, please start/configure it manually." "WARN" }
        }
        default {
            Log "No scenario chosen; skipping scenario-specific items."
        }
    }
}
Select-Scenario

# ----------------------------
# SMB handling (interactive)
# ----------------------------
function Offer-SMB-Removal {
    Log "Interactive SMB disable/removal offered. This is destructive and may impact file sharing."
    $choice = Read-Host "Do you want to disable/remove SMBv1 and stop SMB Server service? (YES to proceed, anything else to skip)"
    if ($choice -ne "YES") { Log "SMB removal skipped by admin choice."; return }
    if (-not (Verify-ScriptIntegrity)) { throw "Integrity check failed; aborting SMB removal." }
    # Disable SMBv1 feature if present
    try {
        if (Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue) {
            Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue
            Log "Attempted to disable SMB1Protocol feature."
        } else {
            Log "SMB1Protocol feature not present or not queryable."
        }
    } catch { Log ("Failed disabling SMB1Protocol: {0}" -f $_) "WARN" }
    # Stop and disable LanmanServer (Server) service if admin confirms
    $svc = Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
    if ($svc) {
        $confirm2 = Read-Host "Stopping & disabling 'LanmanServer' (Server) will remove file sharing. Type EXACTLY 'YES' to continue:"
        if ($confirm2 -eq "YES") {
            try { Stop-Service -Name LanmanServer -Force -ErrorAction SilentlyContinue; Set-Service -Name LanmanServer -StartupType Disabled -ErrorAction SilentlyContinue; Log "LanmanServer stopped and disabled." } catch { Log ("Failed to disable LanmanServer: {0}" -f $_) "WARN" }
        } else { Log "LanmanServer disable aborted by admin." }
    } else { Log "LanmanServer service not found; SMB server may not be present." }
}
Offer-SMB-Removal

# ----------------------------
# Interactive destructive service removal
# ----------------------------
function Interactive-Service-Removal {
    param([string[]]$ServiceNames)
    if (-not $ServiceNames -or $ServiceNames.Count -eq 0) { return }
    Log "Interactive service removal requested for: $($ServiceNames -join ', ')"
    $consent = Read-Host "Type EXACTLY 'YES' to permanently delete the listed services: $($ServiceNames -join ', ')"
    if ($consent -ne "YES") { Log "Service deletion aborted by admin." ; return }
    if (-not (Verify-ScriptIntegrity)) { throw "Integrity check failed; aborting service deletion." }
    foreach ($s in $ServiceNames) {
        try {
            $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
            if ($svc) {
                Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
                Set-Service -Name $s -StartupType Disabled -ErrorAction SilentlyContinue
            }
            sc.exe delete $s | Out-Null
            Log ("Service '{0}' delete attempted." -f $s)
        } catch { Log ("Failed removing service {0}: {1}" -f $s, $_) "WARN" }
    }
}

# Example: offer to remove FTP service if admin wants (destructive)
$svcToRemove = @()
if (Get-Service -Name FTPSVC -ErrorAction SilentlyContinue) { $svcToRemove += "FTPSVC" }
if ($svcToRemove.Count -gt 0) { Interactive-Service-Removal -ServiceNames $svcToRemove }

# ----------------------------
# Deterministic password reset
# ----------------------------
function ConvertTo-SecureStringFromPlain {
    param([string]$Plain)
    return ConvertTo-SecureString -String $Plain -AsPlainText -Force
}

function Set-LocalUserPassword {
    param(
        [Parameter(Mandatory=$true)][string]$AccountName,
        [Parameter(Mandatory=$true)][securestring]$SecurePwd
    )
    # Try the modern module first
    if (Get-Command -Name Set-LocalUser -ErrorAction SilentlyContinue) {
        try {
            Set-LocalUser -Name $AccountName -Password $SecurePwd -ErrorAction Stop
            return $true
        } catch {
            Log ("Set-LocalUser failed for {0}: {1}" -f $AccountName, $_) "WARN"
        }
    }
    # ADSI fallback
    try {
        $user = [ADSI]"WinNT://./$AccountName,user"
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePwd))
        $user.SetPassword($plain)
        $user.SetInfo()
        return $true
    } catch {
        Log ("ADSI fallback failed to set password for {0}: {1}" -f $AccountName, $_) "WARN"
        return $false
    }
}

function Derive-DeterministicPassword {
    param([string]$MasterSecret, [string]$Username, [string]$Sid, [int]$Length = 20)
    # Use HMAC-SHA256 over master + username + sid -> base64 -> filter to allowed characters
    $enc = [System.Text.Encoding]::UTF8
    $hmac = New-Object System.Security.Cryptography.HMACSHA256 ($enc.GetBytes($MasterSecret))
    $input = $enc.GetBytes("$Username|$Sid")
    $hash = $hmac.ComputeHash($input)
    $b64 = [System.Convert]::ToBase64String($hash)
    # Replace URL-unsafe chars and ensure complexity: include upper, lower, digits, punctuation
    $pw = ($b64 -replace '[+/=]','A')
    # If too short, repeat
    while ($pw.Length -lt $Length) { $pw += $pw }
    $pw = $pw.Substring(0,$Length)
    # Guarantee complexity (ensure at least one digit, one upper, one lower, one special)
    if ($pw -notmatch '\d') { $pw = $pw.Substring(0,$Length-1) + '9' }
    if ($pw -notmatch '[A-Z]') { $pw = 'A' + $pw.Substring(1) }
    if ($pw -notmatch '[a-z]') { $pw = $pw.Substring(0,$Length-1) + 'a' }
    if ($pw -notmatch '[^A-Za-z0-9]') { $pw = $pw.Substring(0,$Length-1) + '!' }
    return $pw
}

function Prompt-And-Reset-LocalUsers {
    Log "Deterministic password reset process starting."
    $master = Read-Host -AsSecureString "Enter master secret (will be used to derive deterministic passwords) - input hidden"
    if (-not $master) { Log "No master secret provided; skipping password reset." ; return }
    $masterPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($master))
    # Collect accounts to reset: members of Administrators group and built-in Administrator
    $targets = @()
    try {
        if (Get-LocalGroupMember -Name "Administrators" -ErrorAction SilentlyContinue) {
            $members = Get-LocalGroupMember -Name "Administrators" -ErrorAction SilentlyContinue | Where-Object { $_.ObjectClass -eq "User" }
            foreach ($m in $members) {
                # Skip domain accounts (only local accounts)
                if ($m.Name -like "*\*") { continue }
                $targets += $m.Name
            }
        } else {
            # ADSI fallback: enumerate local users and check group membership
            $admins = @()
            $group = [ADSI]"WinNT://./Administrators,group"
            $members = $group.psbase.Invoke("Members")
            foreach ($mem in $members) {
                $obj = $mem.GetType().InvokeMember("Name","GetProperty",$null,$mem,$null)
                if ($obj) { $targets += $obj }
            }
        }
    } catch { Log ("Failed to enumerate administrators: {0}" -f $_) "WARN" }
    # Always include Administrator account name if present
    try {
        if (Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue) { $targets += "Administrator" }
    } catch { }
    $targets = $targets | Sort-Object -Unique
    if ($targets.Count -eq 0) { Log "No local administrator accounts discovered to reset." ; return }
    Write-Host "Accounts to reset (local): $($targets -join ', ')"
    $consent = Read-Host "Type EXACTLY 'YES' to proceed with resetting these accounts' passwords deterministically"
    if ($consent -ne "YES") { Log "Password reset aborted by admin." ; return }
    if (-not (Verify-ScriptIntegrity)) { throw "Integrity check failed; aborting password reset." }
    # For each account, derive SID and set password
    foreach ($acct in $targets) {
        try {
            # Retrieve SID
            $sid = $null
            try {
                $lu = Get-LocalUser -Name $acct -ErrorAction Stop
                $sid = $lu.SID.Value
            } catch {
                # ADSI fallback
                try {
                    $adsi = [ADSI]"WinNT://./$acct,user"
                    $sid = $adsi.objectSid | ForEach-Object { $_ } # might be binary
                    if ($sid -is [byte[]]) { $sid = (New-Object System.Security.Principal.SecurityIdentifier($sid,0)).Value }
                } catch { $sid = (New-Object System.Security.Principal.SecurityIdentifier((Get-WmiObject Win32_UserAccount -Filter "Name='$acct' and LocalAccount=True").SID)).Value }
            }
            if (-not $sid) { Log ("Could not determine SID for {0}; skipping" -f $acct) ; continue }
            $derived = Derive-DeterministicPassword -MasterSecret $masterPlain -Username $acct -Sid $sid -Length 20
            $secure = ConvertTo-SecureStringFromPlain -Plain $derived
            $ok = Set-LocalUserPassword -AccountName $acct -SecurePwd $secure
            if ($ok) {
                Log ("Password reset for account {0} (deterministically derived). DO NOT lose the master secret; you can re-derive this password using the same master secret." -f $acct)
                # Save derivation metadata into backup directory (not the password)
                $meta = "Account: $acct`nSID: $sid`nMethod: deterministic-HMAC-SHA256`nLength: 20`nTimestamp: $(Get-Date -Format o)"
                $meta | Out-File -FilePath (Join-Path $BackupDir ("pwdreset_{0}.meta" -f $acct)) -Encoding utf8 -Force
            } else {
                Log ("Failed to set password for {0}" -f $acct) "WARN"
            }
        } catch { Log ("Error resetting password for {0}: {1}" -f $acct, $_) "WARN" }
    }
    # Clear masterPlain from memory
    $masterPlain = $null
    [System.GC]::Collect()
}

Prompt-And-Reset-LocalUsers

# ----------------------------
# Pre-compromise scanning & cleanup
# ----------------------------
function Find-Suspicious-ScheduledTasks {
    $suspicious = @()
    try {
        $tasks = schtasks /Query /FO LIST /V 2>$null
        if ($LASTEXITCODE -ne 0) { Log "Could not query scheduled tasks with schtasks." ; return @() }
        # Parse by blocks separated by blank lines
        $raw = ($tasks -join "`n") -split "(\r?\n){2,}"
        foreach ($block in $raw) {
            if ($block -match "TaskName:\s*(.+)" -and $block -match "Task To Run:\s*(.+)") {
                $name = ($matches[1]).Trim()
                $action = ($block -match "Task To Run:\s*(.+)" | Out-Null)
                # Extract action path manually
                if ($block -match "Task To Run:\s*(.+)") { $action = $matches[1].Trim() } else { $action = "" }
                if ($action -match "(%temp%|AppData|\\Users\\.*\\AppData|\\temp\\|\\downloads\\|\\windows\\temp)" -or $action -match "\.ps1|\.vbs|\.bat") {
                    $suspicious += @{ Name = $name; Action = $action; Block = $block }
                }
            }
        }
    } catch { Log ("Error scanning scheduled tasks: {0}" -f $_) "WARN" }
    return $suspicious
}

function Remove-MaliciousPersistence {
    Log "Scanning for suspicious persistence (scheduled tasks, startup entries)."
    $tasks = Find-Suspicious-ScheduledTasks
    if ($tasks.Count -eq 0) { Log "No obvious suspicious scheduled tasks found (best-effort)." }
    else {
        foreach ($t in $tasks) {
            Write-Host "Suspicious task: $($t.Name) -> $($t.Action)"
        }
        $consent = Read-Host "Type EXACTLY 'YES' to delete these scheduled tasks"
        if ($consent -eq "YES") {
            if (-not (Verify-ScriptIntegrity)) { throw "Integrity check failed; aborting task deletions." }
            foreach ($t in $tasks) {
                try {
                    schtasks /Delete /TN $t.Name /F | Out-Null
                    Log ("Deleted suspicious scheduled task {0}" -f $t.Name)
                } catch { Log ("Failed to delete scheduled task {0}: {1}" -f $t.Name, $_) "WARN" }
            }
        } else { Log "No scheduled tasks were deleted." }
    }

    # Check startup registry and startup folders for suspicious entries
    $startupLocations = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($loc in $startupLocations) {
        try {
            $items = Get-ItemProperty -Path $loc -ErrorAction SilentlyContinue
            if ($items) {
                foreach ($prop in $items.PSObject.Properties) {
                    $val = $prop.Value
                    if ($val -and $val -match "(%temp%|AppData|\\Users\\.*\\AppData|\\temp\\|\\downloads\\|\\windows\\temp)" ) {
                        Log ("Found suspicious startup entry {0} => {1} in {2}" -f $prop.Name, $val, $loc) 
                        $confirm = Read-Host "Delete startup entry $($prop.Name) from $loc? Type YES to delete"
                        if ($confirm -eq "YES") {
                            Remove-ItemProperty -Path $loc -Name $prop.Name -ErrorAction SilentlyContinue
                            Log ("Removed startup entry {0} from {1}" -f $prop.Name, $loc)
                        }
                    }
                }
            }
        } catch { Log ("Failed scanning startup location {0}: {1}" -f $loc, $_) "WARN" }
    }

    # Startup folders
    $folders = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($f in $folders) {
        try {
            if (Test-Path $f) {
                Get-ChildItem -Path $f -File -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($_.FullName -match "(AppData|temp|downloads)" -or $_.Name -match "\.lnk|\.bat|\.cmd|\.ps1") {
                        $confirm = Read-Host "Delete startup file $($_.FullName)? Type YES to delete"
                        if ($confirm -eq "YES") {
                            Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
                            Log ("Deleted startup file {0}" -f $_.FullName)
                        }
                    }
                }
            }
        } catch { Log ("Failed scanning startup folder {0}: {1}" -f $f, $_) "WARN" }
    }
}
Remove-MaliciousPersistence

# ----------------------------
# Final reporting & reminders
# ----------------------------
function Final-Report {
    Log "=== HARDENING COMPLETE ==="
    Log ("Backups were stored at: {0}" -f $BackupDir)
    Log ("Log file: {0}" -f $LogFile)
    Write-Host ""
    Write-Host "Summary / Reminders:"
    Write-Host " - Review the log at $LogFile"
    Write-Host " - Review files in the backup directory: $BackupDir"
    Write-Host " - If deterministic password reset was used, KEEP the master secret secure. It is REQUIRED to re-derive passwords."
    Write-Host " - Some hardening actions might require a restart (e.g., SMB feature removal). Consider scheduling a maintenance window."
    Write-Host ""
}

Final-Report
