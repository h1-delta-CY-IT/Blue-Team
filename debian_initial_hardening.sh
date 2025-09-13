#!/bin/bash
# -----------------------------
# Dynamic Super Hardening Script for Blue Team CTFs 
# Author: Adapted from Ardian Peach + enhancements
# Last Updated: 2025-09-12
# Debian Vers.
# -----------------------------

# -----------------------------
# CONFIGURATION VARIABLES
# -----------------------------
SECRET_BASE="/var/lib/.hardening"
mkdir -p "$SECRET_BASE"
chmod 700 "$SECRET_BASE"

BACKUP_DIR="$SECRET_BASE/backups"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

PASSWORD_FILE="$SECRET_BASE/user_passwords_$(date +%F_%H%M%S).txt"
chmod 600 "$PASSWORD_FILE"

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

# -----------------------------
# ROOT CHECK
# -----------------------------
if [[ $EUID -ne 0 ]]; then
    echo "[-] Must be run as root"
    exit 1
fi

# -----------------------------
# SECTION 1: Root & User Security
# -----------------------------
echo "[*] Locking root account..."
passwd -l root

echo "[*] Expiring non-system user passwords..."
awk -F: -v threshold="$SYSTEM_UID_THRESHOLD" '{if ($3 >= threshold && $1 != "nobody") print $1}' /etc/passwd | while read -r user; do
    chage -d 0 "$user"
done

echo "[*] Installing PAM cracklib and enforcing password policies..."
apt update -y && apt install -y libpam-cracklib ufw unattended-upgrades 2>/dev/null
grep -q "pam_cracklib.so" /etc/pam.d/common-password || \
echo "password requisite pam_cracklib.so retry=3 minlen=12 difok=3" >> /etc/pam.d/common-password

echo "[*] Fixing critical file permissions..."
chmod 644 /etc/passwd
chmod 600 /etc/shadow /etc/gshadow
sed -i -e '/nopasswdlogin/d' /etc/group

# -----------------------------
# SECTION 2: SSH Hardening
# -----------------------------
echo "[*] Configuring SSH hardening..."
grep -q "PermitRootLogin no" "$SSH_CONFIG" || echo "PermitRootLogin no" >> "$SSH_CONFIG"
grep -q "PasswordAuthentication no" "$SSH_CONFIG" || echo "PasswordAuthentication no" >> "$SSH_CONFIG"
grep -q "PermitEmptyPasswords no" "$SSH_CONFIG" || echo "PermitEmptyPasswords no" >> "$SSH_CONFIG"
grep -q "Banner /etc/issue.net" "$SSH_CONFIG" || echo "Banner /etc/issue.net" >> "$SSH_CONFIG"
grep -q "MaxAuthTries 3" "$SSH_CONFIG" || echo "MaxAuthTries 3" >> "$SSH_CONFIG"
grep -q "AllowUsers" "$SSH_CONFIG" || echo "AllowUsers ${ADMIN_USERS[*]}" >> "$SSH_CONFIG"
systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null

# -----------------------------
# SECTION 3: Firewall / Network
# -----------------------------
echo "[*] Installing basic firewall..."
apt install -y ufw 2>/dev/null || echo "[!] Failed to install UFW"

echo "[*] Configuring UFW..."
for port in "${FIREWALL_DENY_IN[@]}"; do ufw deny "$port"; done
for port in "${FIREWALL_DENY_OUT[@]}"; do ufw deny out "$port"; done
for service in "${FIREWALL_ALLOW[@]}"; do ufw allow "$service"; done
ufw --force enable

# -----------------------------
# SECTION 4: Service Hardening
# -----------------------------
echo "[*] Disabling unused/unneeded services..."
for svc in "${DISABLE_SERVICES[@]}"; do
    systemctl disable --now "$svc" 2>/dev/null || true
done
echo "[*] Securing Apache ownership..."
chown -R root:root /etc/apache2 2>/dev/null || true

# -----------------------------
# SECTION 5: FTP Hardening
# -----------------------------
echo "[*] Configuring vsftpd for scoring user..."
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
} >> "$VSFTPD_CONF"
systemctl restart vsftpd 2>/dev/null || service vsftpd restart 2>/dev/null
chattr +i "$VSFTPD_CONF" "$VSFTPD_USERLIST"

# -----------------------------
# SECTION 6: File Backups & Integrity
# -----------------------------
echo "[*] Securing scoring files..."
for file in "${SCORING_FILES[@]}"; do
    cp "$file" "$BACKUP_DIR/"
    chattr +i "$BACKUP_DIR/$(basename $file)"
done
chattr +i /etc/crontab /etc/rc.local

# -----------------------------
# SECTION 7: Monitoring & Logging
# -----------------------------
echo "[*] Installing monitoring tools..."
apt install -y "${TOOLS[@]}" 2>/dev/null

echo "[*] Configuring auditd..."
systemctl enable --now auditd
auditctl -w /etc/passwd -p wa -k passwd_changes
auditctl -w /etc/shadow -p wa -k shadow_changes
auditctl -w /etc/ssh/sshd_config -p wa -k ssh_changes
auditctl -w /etc/vsftpd.conf -p wa -k ftp_changes

echo "[*] Downloading pspy for process monitoring..."
wget -q https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 -O "$SECRET_BASE/pspy64"
chmod +x "$SECRET_BASE/pspy64"

# -----------------------------
# SECTION 8: System Updates
# -----------------------------
echo "[*] Installing unattended security updates..."
apt install -y unattended-upgrades 2>/dev/null
dpkg-reconfigure -plow unattended-upgrades

# -----------------------------
# SECTION 9: User Cleanup & Verification
# -----------------------------
echo "[*] Resetting local user passwords (stored in secure location)..."
awk -F: -v threshold="$SYSTEM_UID_THRESHOLD" '{if ($3 >= threshold && $1 != "nobody") print $1}' /etc/passwd | while read -r user; do
    NEW_PASS=$(openssl rand -base64 16)
    echo "$user:$NEW_PASS" | chpasswd
    echo "$user:$NEW_PASS" >> "$PASSWORD_FILE"
done
chmod 600 "$PASSWORD_FILE"

pwck
grpck

# -----------------------------
# SECTION 10: Final Config Protection
# -----------------------------
echo "[*] Locking critical configuration files..."
for file in /etc/passwd /etc/shadow /etc/gshadow /etc/ssh/sshd_config; do
    command -v chattr >/dev/null 2>&1 && chattr +i "$file" 2>/dev/null || true
done

echo "[*] Dynamic Super Hardening Script completed successfully!"
echo "[*] Sensitive data stored in $SECRET_BASE"
