# ----------------------------
# Dynamic IP Blocker for Windows (RDP-Safe, All ports except RDP, Popup only)
# ----------------------------

# Run-as-admin check
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# --- Configuration ---
$AllowedIPs = @(
    "192.168.1.10",  # Local network
    "10.0.0.5",      # Trusted admin machine
    "127.0.0.1"      # Localhost
)

$MaxConnections = 10
$RulePrefix = "DynamicBlock"
$BlockDurationMinutes = 15   # Set 0 to disable auto-unblock
$LogFile = "C:\ProgramData\DynamicIPBlocker\blocked.log"
New-Item -Path (Split-Path $LogFile) -ItemType Directory -Force | Out-Null

# Load Windows Forms for popup
Add-Type -AssemblyName System.Windows.Forms

# ----------------------------
# Function: Add firewall rule for blocking IP on all non-RDP ports
function Block-IP {
    param ($IP)

    if ($AllowedIPs -contains $IP) { return }

    # Check for existing rules for this IP
    $existing = Get-NetFirewallRule -DisplayName "$RulePrefix-$IP-*" -ErrorAction SilentlyContinue
    if ($existing) { return }

    $timestamp = (Get-Date).ToString("o")
    
    # Block all ports except 3389 (RDP)
    try {
        New-NetFirewallRule -DisplayName "$RulePrefix-$IP-All" `
                            -Direction Inbound `
                            -RemoteAddress $IP `
                            -Protocol TCP `
                            -Action Block `
                            -Description "Dynamically blocked at $timestamp (RDP-safe, all ports except 3389)" `
                            -ErrorAction Stop

        # Log the block
        Add-Content -Path $LogFile -Value "$(Get-Date -Format o) BLOCKED $IP (all ports except 3389)"

        # Popup alert (no beep)
        $msg = "Blocked IP: $IP`nTime: $timestamp`nAll ports blocked except RDP (3389)"
        [System.Windows.Forms.MessageBox]::Show($msg, "DynamicIPBlocker - IP Blocked", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null

    } catch {
        Add-Content -Path $LogFile -Value "$(Get-Date -Format o) ERROR creating rule for $IP : $_"
    }
}

# ----------------------------
# Function: Cleanup old rules (auto-unblock)
function Cleanup-Rules {
    if ($BlockDurationMinutes -le 0) { return }

    $cutoff = (Get-Date).AddMinutes(-$BlockDurationMinutes)
    $rules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "$RulePrefix-*" -and $_.Description -like "Dynamically blocked at *" }

    foreach ($rule in $rules) {
        $desc = $rule.Description
        if ($desc -match "Dynamically blocked at (.+)$") {
            $tsString = $matches[1]
            try {
                $ts = [datetime]::Parse($tsString)
                if ($ts -lt $cutoff) {
                    # Remove all rules for this IP
                    $parts = $rule.DisplayName -split '-'
                    if ($parts.Length -ge 2) {
                        $ipPart = $parts[1]
                        $toRemove = Get-NetFirewallRule -DisplayName "$RulePrefix-$ipPart-*" -ErrorAction SilentlyContinue
                        if ($toRemove) {
                            foreach ($r in $toRemove) {
                                try {
                                    Remove-NetFirewallRule -Name $r.Name -ErrorAction Stop
                                } catch {
                                    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) ERROR removing rule $($r.DisplayName) : $_"
                                }
                            }
                            Add-Content -Path $LogFile -Value "$(Get-Date -Format o) UNBLOCKED $ipPart after $BlockDurationMinutes minutes"
                        }
                    }
                }
            } catch {}
        }
    }
}

# ----------------------------
# Track connection attempts (snapshot) excluding RDP port
try {
    $connections = Get-NetTCPConnection -State SynReceived -ErrorAction Stop | Where-Object { $_.LocalPort -ne 3389 }
} catch {
    Write-Error "Failed to enumerate TCP connections: $_"
    exit 1
}

# Group by remote IP
$grouped = $connections | Group-Object -Property RemoteAddress

foreach ($group in $grouped) {
    $IP = $group.Name
    if ([string]::IsNullOrWhiteSpace($IP)) { continue }
    if ($IP -eq '::1' -or $IP -eq '127.0.0.1') { continue }

    $Count = $group.Count
    if ($AllowedIPs -contains $IP) { continue }

    if ($Count -gt $MaxConnections) {
        Block-IP $IP
        Write-Host "Blocked $IP for exceeding $MaxConnections connections (RDP-safe)"
    }
}

# Run cleanup
Cleanup-Rules
