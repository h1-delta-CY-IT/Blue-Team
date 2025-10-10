# Rotate-AdminPassword-Pool.ps1
param(
    [string]$AdminUser = 'Administrator',                   # local admin username
    [string[]]$Recipients = @('sec-team@example.com'),     # recipients for email
    [string]$From = 'server-alerts@example.com',
    [string]$SmtpServer = 'smtp.example.com',
    [int]$SmtpPort = 587,
    [string]$SmtpUser = 'smtp-user@example.com',
    [string]$SmtpPlainPassword = 'smtp-plaintext-password' # for quick test only; prefer using Export-Clixml
)

# --- Password pool 
$PasswordPool = @(
    'D31tASFaVPa33W0#d*',
    'B3sTfR1EnD()fD3lt4#',
    'FuC&R3DT3Am#',
    'Tr7T1hF0rSI$E',
    'G0O)(LuC4#Bu7',
    'N0tT()dAy1!.&',
    'N1cEtR7)(>:#D#'
)

try {
    # select a random password from pool
    $newPassword = Get-Random -InputObject $PasswordPool

    # convert to secure string
    $securePwd = ConvertTo-SecureString $newPassword -AsPlainText -Force

    # attempt to set local user password (Windows Server 2022)
    if (Get-Command -Name Set-LocalUser -ErrorAction SilentlyContinue) {
        # ensure the account exists
        $user = Get-LocalUser -Name $AdminUser -ErrorAction Stop
        Set-LocalUser -Name $AdminUser -Password $securePwd
    } else {
        # fallback to net user
        net user $AdminUser $newPassword | Out-Null
    }

    # prepare SMTP credential
    $smtpSecurePwd = ConvertTo-SecureString $SmtpPlainPassword -AsPlainText -Force
    $smtpCred = New-Object System.Management.Automation.PSCredential($SmtpUser, $smtpSecurePwd)

    $body = @"
New administrator password for computer: $env:COMPUTERNAME
Account: $AdminUser
Password: $newPassword

Generated at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')
Note: This message contains the plaintext password. Handle securely.
"@

    # send email (requires TLS-capable SMTP)
    Send-MailMessage -From $From -To $Recipients -Subject "New admin password for $env:COMPUTERNAME ($AdminUser)" `
        -Body $body -SmtpServer $SmtpServer -Port $SmtpPort -UseSsl -Credential $smtpCred

    # optional logging
    Write-EventLog -LogName Application -Source RotateAdminPassword -EntryType Information -EventId 1000 -Message "Rotated password for '$AdminUser' and emailed to $($Recipients -join ',')" -ErrorAction SilentlyContinue
}
catch {
    $err = $_.Exception.Message
    Write-EventLog -LogName Application -Source RotateAdminPassword -EntryType Error -EventId 1001 -Message "Password rotation failed: $err" -ErrorAction SilentlyContinue
    throw
}
