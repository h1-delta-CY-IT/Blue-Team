# --- Allow RDP
New-NetFirewallRule -DisplayName "Allow RDP 3389" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow

# --- Allow MySQL
New-NetFirewallRule -DisplayName "Allow MySQL 3306" -Direction Inbound -Protocol TCP -LocalPort 3306 -Action Allow

# --- Block all other inbound traffic
New-NetFirewallRule -DisplayName "Block All Other Inbound" -Direction Inbound -Action Block -Enabled True
