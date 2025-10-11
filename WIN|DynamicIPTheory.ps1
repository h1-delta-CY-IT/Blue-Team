# ----------------------------
# Dynamic IP Blocker for Windows

# ----------------------------

# --- Configuration ---
# CHANGE YOUR ALLOWED IP WHITELIST AS NEEDED
$AllowedIPs = @(
    "192.168.1.10",
    "10.0.0.5",
    "127.0.0.1"
)

# Threshold for maximum new connections in the time window
$MaxConnections = 10

# Time window in seconds to count connections
$TimeWindow = 60

# Firewall rule prefix for dynamic blocks
$RulePrefix = "DynamicBlock"

# ----------------------------
# Function: Add firewall rule for blocking IP
function Block-IP {
    param ($IP)
    
    # Check if rule already exists
    $existing = Get-NetFirewallRule -DisplayName "$RulePrefix-$IP" -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-NetFirewallRule -DisplayName "$RulePrefix-$IP" `
                            -Direction Inbound `
                            -RemoteAddress $IP `
                            -Action Block `
                            -Description "Dynamically blocked for exceeding connection threshold"
    }
}

# ----------------------------
# Function: Cleanup old rules (optional)
function Cleanup-Rules {
    $rules = Get-NetFirewallRule | Where-Object {$_.DisplayName -like "$RulePrefix-*"}
    foreach ($rule in $rules) {
        # You could add logic to unblock after X minutes
        # Remove-NetFirewallRule -Name $rule.Name
    }
}

# ----------------------------
# Track connection attempts
# This uses TCP connections in SYN_RECEIVED state (attempting handshake)
$connections = Get-NetTCPConnection -State SynReceived

# Group by remote IP
$grouped = $connections | Group-Object -Property RemoteAddress

foreach ($group in $grouped) {
    $IP = $group.Name
    $Count = $group.Count

    # Skip allowed IPs
    if ($AllowedIPs -contains $IP) { continue }

    # Check threshold
    if ($Count -gt $MaxConnections) {
        Block-IP $IP
        Write-Host "Blocked $IP for exceeding $MaxConnections connections"
    }
}

# Optionally clean up old dynamic rules
Cleanup-Rules
