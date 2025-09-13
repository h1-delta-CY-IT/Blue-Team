#!/bin/bash
# -----------------------------
# Dynamic Super Hardening Script for Blue Team CTFs
# Author: Adapted from Ardian Peach + enhancements
# Last Updated: 2025-09-12
# Fedora Vers.
# -----------------------------

set -u

# -----------------------------
# CONFIGURATION VARIABLES
# -----------------------------
SECRET_BASE="/var/lib/.hardening"
BACKUP_DIR="$SECRET_BASE/backups"
PASSWORD_FILE="$SECRET_BASE/user_passwords_$(date +%F_%H%M%S).txt"

SCORING_USER="hkeating"
ADMIN_USERS=("ubuntu" "$SCORING_USER")
SCORING_FILES=("/files/Seabiscuit.jpg")

SSH_CONFIG="/etc/ssh/sshd_config"
VSFTPD_CONF="/etc/vsftpd.conf"
VSFTPD_USERLIST="/etc/vsftpd.userlist"

FIREWALL_ALLOW=("Apache Secure" "OpenSSH" "ftp" "http")
FIREWALL_DENY_IN=(4444)
FIREWALL_DENY_OUT=(23 445 3389 31337)

SYSTEM_UID_THRESHOLD=1000
DISABLE_SERVICES=("avahi-daemon" "cups" "rpcbind")
TOOLS=("ranger" "fail2ban" "tmux" "curl" "whowatch" "auditd" "logwatch")

PSPY_URL="https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64"

# -----------------------------
# HELPERS
# -----------------------------
pkg_install() {
    # pkg_install "pkg1" "pkg2"
    if command -v apt >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt update -y >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt install -y "$@" >/dev/null 2>&1 || return 1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y "$@" >/dev/null 2>&1 || return 1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y "$@" >/dev/null 2>&1 || return 1
    else
        return 1
    fi
    return 0
}

safe_chattr_i() {
    for f in "$@"; do
        [[ -e "$f" ]] && command -v chattr >/dev/null 2>&1 && chattr +i "$f" 2>/dev/null || true
    done
}

detect_pam_common() {
    # Debian: /etc/pam.d/common-password
    # RHEL/Fedora: /etc/pam.d/system-auth or /etc/pam.d/password-auth
    if [[ -f /etc/pam.d/common-password ]]; then
        echo "/etc/pam.d/common-password"
    elif [[ -f /etc/pam.d/system-auth ]]; then
        echo "/etc/pam.d/system-auth"
    elif [[ -f /etc/pam.d/password-auth ]]; then
        echo "/etc/pam.d/password-auth"
    else
        echo ""
    fi
}

# -----------------------------
# ROOT CHECK
# -----------------------------
if [[ $EUID -ne 0 ]]; then
    echo "[-] Must be run as root"
    exit 1
fi

# Make secret dirs
mkdir -p "$BACKUP_DIR"
chmod 700 "$SECRET_BASE"
chmod 700 "$BACKUP_DIR"

# Create the password file (so chmod won't fail)
: > "$PASSWORD_FILE"
chmod 600 "$PASSWORD_FILE"

# -----------------------------
# SECTION 1: Root & User Security
# -----------------------------
echo "[*] Locking root account..."
passwd -l root >/dev/null 2>&1 || true

echo "[*] Expiring non-system user passwords..."
awk -F: -v threshold="$SYSTEM_UID_THRESHOLD" '{if ($3 >= threshold && $1 != "nobody") print $1}' /etc/passwd | while read -r user; do
    chage -d 0 "$user" >/dev/null 2>&1 || true
done

echo "[*] Installing PAM cracklib / pwquality and enforcing password policies..."
# Install appropriate PAM quality package
if pkg_install libpam-cracklib 2>/dev/null; then
    :
elif pkg_install libpwquality 2>/dev/null; then
    :
fi

pamfile=$(detect_pam_common)
if [[ -n "$pamfile" ]]; then
    if ! grep -q "pam_cracklib.so" "$pamfile" 2>/dev/null && ! grep -q "pam_pwquality.so" "$pamfile" 2>/dev/null; then
        # append a conservative rule for both variants
        if grep -q "pam_pwquality.so" /usr/lib*/pam_pwquality.so >/dev/null 2>&1 || pkg_install libpwquality >/dev/null 2>&1; then
            echo "password requisite pam_pwquality.so retry=3 minlen=12 difok=3" >> "$pamfile"
        else
            echo "password requisite pam_cracklib.so retry=3 minlen=12 difok=3" >> "$pamfile"
        fi
    fi
else
    echo "[!] PAM configuration file not found; skipping pam rule insertion"
fi

echo "[*] Fixing critical file permissions..."
chmod 644 /etc/passwd 2>/dev/null || true
chmod 600 /etc/shadow /etc/gshadow 2>/dev/null || true
sed -i -e '/nopasswdlogin/d' /etc/group 2>/dev/null || true

# -----------------------------
# SECTION 2: SSH Hardening
# -----------------------------
echo "[*] Configuring SSH hardening..."
[[ -f "$SSH_CONFIG" ]] || touch "$SSH_CONFIG"
grep -q "PermitRootLogin no" "$SSH_CONFIG" 2>/dev/null || echo "PermitRootLogin no" >> "$SSH_CONFIG"
grep -q "PasswordAuthentication no" "$SSH_CONFIG" 2>/dev/null || echo "PasswordAuthentication no" >> "$SSH_CONFIG"
grep -q "PermitEmptyPasswords no" "$SSH_CONFIG" 2>/dev/null || echo "PermitEmptyPasswords no" >> "$SSH_CONFIG"
grep -q "Banner /etc/issue.net" "$SSH_CONFIG" 2>/dev/null || echo "Banner /etc/issue.net" >> "$SSH_CONFIG"
grep -q "MaxAuthTries 3" "$SSH_CONFIG" 2>/dev/null || echo "MaxAuthTries 3" >> "$SSH_CONFIG"
grep -q "AllowUsers" "$SSH_CONFIG" 2>/dev/null || echo "AllowUsers ${ADMIN_USERS[*]}" >> "$SSH_CONFIG"
systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || true

# -----------------------------
# SECTION 3: Firewall / Network
# -----------------------------
echo "[*] Installing basic firewall..."
# Prefer firewalld on RHEL/Fedora; UFW on Debian
if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    # RHEL-style
    pkg_install firewalld || echo "[!] Failed to install firewalld"
    systemctl enable --now firewalld 2>/dev/null || true
    # set default zone to drop
    firewall-cmd --set-default-zone=drop 2>/dev/null || true
    # add denies (firewall-cmd does not have 'deny port' -> we add rich rules to reject)
    for p in "${FIREWALL_DENY_IN[@]}"; do
        firewall-cmd --permanent --add-rich-rule="rule family='ipv4' port port='$p' protocol='tcp' reject" 2>/dev/null || true
    done
    for p in "${FIREWALL_DENY_OUT[@]}"; do
        firewall-cmd --permanent --add-rich-rule="rule family='ipv4' port port='$p' protocol='tcp' reject" 2>/dev/null || true
    done
    # allow known services
    for s in "${FIREWALL_ALLOW[@]}"; do
        # try service name first, else try port name as-is
        firewall-cmd --permanent --add-service="$s" 2>/dev/null || firewall-cmd --permanent --add-port="$s"/tcp 2>/dev/null || true
    done
    firewall-cmd --reload 2>/dev/null || true
else
    # Debian/Ubuntu: install ufw if available
    pkg_install ufw || echo "[!] Failed to install UFW"
    if command -v ufw >/dev/null 2>&1; then
        for port in "${FIREWALL_DENY_IN[@]}"; do ufw deny "$port" >/dev/null 2>&1 || true; done
        for port in "${FIREWALL_DENY_OUT[@]}"; do ufw deny out "$port" >/dev/null 2>&1 || true; done
        for service in "${FIREWALL_ALLOW[@]}"; do ufw allow "$service" >/dev/null 2>&1 || true; done
        ufw --force enable >/dev/null 2>&1 || true
    fi
fi

# -----------------------------
# SECTION 4: Service Hardening
# -----------------------------
echo "[*] Disabling unused/unneeded services..."
for svc in "${DISABLE_SERVICES[@]}"; do
    systemctl disable --now "$svc" >/dev/null 2>&1 || true
done

echo "[*] Securing Apache ownership..."
if [[ -d /etc/apache2 ]]; then
    chown -R root:root /etc/apache2 2>/dev/null || true
fi

# -----------------------------
# SECTION 5: FTP Hardening
# -----------------------------
echo "[*] Installing and configuring vsftpd for scoring user..."
pkg_install vsftpd >/dev/null 2>&1 || true
# ensure config files exist
touch "$VSFTPD_CONF" "$VSFTPD_USERLIST" 2>/dev/null || true
echo "$SCORING_USER" > "$VSFTPD_USERLIST"
{
    echo "userlist_enable=YES"
    echo "userlist_file=$VSFTPD_USERLIST"
    echo "userlist_deny=NO"
    echo "chroot_local_user=NO"
    echo "anonymous_enable=NO"
    echo "local_enable=YES"
    echo "write_enable=YES"
    echo "xferlog_enable=YES"
    echo "ascii_upload_enable=NO"
    echo "ascii_download_enable=NO"
} > "$VSFTPD_CONF"
systemctl restart vsftpd 2>/dev/null || service vsftpd restart 2>/dev/null || true
safe_chattr_i "$VSFTPD_CONF" "$VSFTPD_USERLIST"

# -----------------------------
# SECTION 6: File Backups & Integrity
# -----------------------------
echo "[*] Securing scoring files..."
for file in "${SCORING_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        # copy to a few locations like original script but ensure dirs exist & are root-only
        cp "$file" "$HOME/" 2>/dev/null || true
        mkdir -p /bin /media /var 2>/dev/null || true
        cp "$file" /bin/ 2>/dev/null || true
        cp "$file" /media/ 2>/dev/null || true
        cp "$file" /var/ 2>/dev/null || true
        cp "$file" "$BACKUP_DIR/" 2>/dev/null || true
        safe_chattr_i "$BACKUP_DIR/$(basename "$file")" "/bin/$(basename "$file")" "/var/$(basename "$file")" "$HOME/$(basename "$file")"
    else
        echo "[!] Scoring file not found: $file"
    fi
done

# Protect cron and startup scripts if they exist
safe_chattr_i /etc/crontab /etc/rc.local

# -----------------------------
# SECTION 7: Monitoring & Logging
# -----------------------------
echo "[*] Installing monitoring tools..."
pkg_install "${TOOLS[@]}" >/dev/null 2>&1 || true

# Configure persistent audit rules (preferred)
mkdir -p /etc/audit/rules.d
cat > /etc/audit/rules.d/99-hardening.rules <<'EOL'
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/ssh/sshd_config -p wa -k ssh_changes
-w /etc/vsftpd.conf -p wa -k ftp_changes
EOL
# Load rules (augenrules preferred)
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
elif command -v auditctl >/dev/null 2>&1; then
    # fallback: load rules with auditctl
    while read -r line; do
        auditctl $line >/dev/null 2>&1 || true
    done < <(sed -n 's/^-w //p' /etc/audit/rules.d/99-hardening.rules 2>/dev/null)
fi

echo "[*] Downloading pspy for process monitoring..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$PSPY_URL" -o "$SECRET_BASE/pspy64" 2>/dev/null || true
elif command -v wget >/dev/null 2>&1; then
    wget -q "$PSPY_URL" -O "$SECRET_BASE/pspy64" >/dev/null 2>&1 || true
fi
chmod +x "$SECRET_BASE/pspy64" 2>/dev/null || true
safe_chattr_i "$SECRET_BASE/pspy64"

# -----------------------------
# SECTION 8: System Updates
# -----------------------------
echo "[*] Installing unattended security updates..."
if command -v apt >/dev/null 2>&1; then
    pkg_install unattended-upgrades >/dev/null 2>&1 || true
    # Using dpkg-reconfigure only on Debian if available
    if command -v dpkg-reconfigure >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -plow unattended-upgrades >/dev/null 2>&1 || true
    fi
else
    # RHEL/Fedora: use dnf-automatic / yum-cron
    if pkg_install dnf-automatic >/dev/null 2>&1; then
        systemctl enable --now dnf-automatic.timer >/dev/null 2>&1 || true
    elif pkg_install yum-cron >/dev/null 2>&1; then
        systemctl enable --now yum-cron >/dev/null 2>&1 || true
    fi
fi

# -----------------------------
# SECTION 9: User Cleanup & Verification
# -----------------------------
echo "[*] Resetting local user passwords (stored in secure location)..."
awk -F: -v threshold="$SYSTEM_UID_THRESHOLD" '{if ($3 >= threshold && $1 != "nobody") print $1}' /etc/passwd | while read -r user; do
    # generate non-interactive password and store it securely
    NEW_PASS=$(openssl rand -base64 16 2>/dev/null || head -c 24 /dev/urandom | base64)
    if echo "$user:$NEW_PASS" | chpasswd 2>/dev/null; then
        echo "$user:$NEW_PASS" >> "$PASSWORD_FILE"
    else
        echo "[!] Could not update password for $user" >/dev/null 2>&1
    fi
done
chmod 600 "$PASSWORD_FILE"

# run consistency checks quietly
pwck >/dev/null 2>&1 || true
grpck >/dev/null 2>&1 || true

# ----------
