param(
    [string]$AdminUser = 'Administrator'  # local admin username
)

# --- Password pool 
$PasswordPool = @(
    'D31tASFaVPa33W0#d*',
    'B3sTfR1EnD()fD3lt4#',
    'FuC&R3DT3Am#',
    'Tr7T1hF0rSI$E',
)

try {
    # select a random password from pool
    $newPassword = Get-Random -InputObject $PasswordPool

    # convert to secure string
    $securePwd = ConvertTo-SecureString $newPassword -AsPlainText -Force

    # attempt to set local user password
    if (Get-Command -Name Set-LocalUser -ErrorAction SilentlyContinue) {
        # ensure the account exists
        $user = Get-LocalUser -Name $AdminUser -ErrorAction Stop
        Set-LocalUser -Name $AdminUser -Password $securePwd
    } else {
        # fallback to net user
        net user $AdminUser $newPassword | Out-Null
    }

    # Optional: Log successful rotation (no password included)
    Write-EventLog -LogName Application -Source RotateAdminPassword -EntryType Information `
        -EventId 1000 -Message "Rotated password for '$AdminUser' at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" `
        -ErrorAction SilentlyContinue
}
catch {
    $err = $_.Exception.Message
    Write-EventLog -LogName Application -Source RotateAdminPassword -EntryType Error `
        -EventId 1001 -Message "Password rotation failed: $err" `
        -ErrorAction SilentlyContinue
    throw
}
