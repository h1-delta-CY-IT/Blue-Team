# Define allowed ports
$allowedPorts = @(
    3389,  # RDP
    3306   # MySQL
)

# Get all existing inbound firewall rules and remove them
Write-Host "Removing all existing inbound rules..."
Get-NetFirewallRule -Direction Inbound | Remove-NetFirewallRule

# Create a new rule to allow RDP
Write-Host "Creating firewall rule for RDP (3389)..."
New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow

# Create a new rule to allow MySQL
Write-Host "Creating firewall rule for MySQL (3306)..."
New-NetFirewallRule -DisplayName "Allow MySQL" -Direction Inbound -Protocol TCP -LocalPort 3306 -Action Allow

# Block all other inbound traffic
Write-Host "Blocking all other inbound traffic..."
New-NetFirewallRule -DisplayName "Block All Other Inbound" -Direction Inbound -Action Block

Write-Host "Firewall rules updated successfully!"
