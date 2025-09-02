#!/bin/bash
# Dynamic Super Hardening Script for Blue Team Competitions
# Author: Adapted from Ardian Peach + enhancements
# Last Updated: 2025-09-02

# -----------------------------
# CONFIGURATION VARIABLES
# -----------------------------

# Users
SCORING_USER="hkeating"
ADMIN_USERS=("ubuntu" "$SCORING_USER")

# Backup / scoring files (can be multiple)
SCORING_FILES=("/files/Seabiscuit.jpg")  

# SSH Hardening
SSH_CONFIG="/etc/ssh/sshd_config"

# FTP Config
VSFTPD_CONF="/etc/vsftpd.conf"
VSFTPD_USERLIST="/etc/vsftpd.userlist"

# Firewall
FIREWALL_ALLOW=("Apache Secure" "OpenSSH" "ftp" "http")
FIREWALL_DENY_IN=(4444)
FIREWALL_DENY_OUT=(23 445 3389 31337)

# System users
SYSTEM_UID_THRESHOLD=1000

# Services to disable
DISABLE_SERVICES=("avahi-daemon" "cups" "rpcbind")

# Tools to install
TOOLS=("ranger" "fail2ban" "tmux" "curl" "whowatch" "auditd" "logwatch")

# -----------------------------
# SECTION 1: Root & User Security
# -----------------------------

echo "[*] Locking root account..."
passwd -l root

echo "[*] Expiring non-system user passwords..."
for user in $(awk -F: -v threshold="$SYSTEM_UID_THRESHOLD" '{if ($3 >= threshold && $1 != "nobody") print $1}' /etc/passwd); do
    chage -d 0 "$user"
done

echo "[*] Installing PAM cracklib and enforcing password policies..."
apt install -y libpam-cracklib
grep -q "pam_cracklib.so" /etc/pam.d/common-password || \
    echo "password requisite pam_cracklib.so retry=3 minlen=12 difok=3" >> /etc/pam.d/common-password

echo "[*] Fixing critical file permissions..."
chmod 644 /etc/passwd
chmod 600 /etc/shadow /etc/gshadow

echo "[*] Removing nopasswdlogin group if exists..."
sed -i -e '/nopasswdlogin/d' /etc/group

# -----------------------------
# SECTION 2: SSH Hardening
# -----------------------------

echo "[*] Configuring SSH hardening..."
for admin in "${ADMIN_USERS[@]}"; do
    grep -q "AllowUsers" "$SSH_CONFIG" || echo "AllowUsers ${ADMIN_USERS[*]}" >> "$SSH_CONFIG"
done
grep -q "PermitRootLogin no" "$SSH_CONFIG" || echo "PermitRootLogin no" >> "$SSH_CONFIG"
grep -q "PasswordAuthentication no" "$SSH_CONFIG" || echo "PasswordAuthentication no" >> "$SSH_CONFIG"
grep -q "PermitEmptyPasswords no" "$SSH_CONFIG" || echo "PermitEmptyPasswords no" >> "$SSH_CONFIG"
grep -q "Banner /etc/issue.net" "$SSH_CONFIG" || echo "Banner /etc/issue.net" >> "$SSH_CONFIG"
grep -q "MaxAuthTries 3" "$SSH_CONFIG" || echo "MaxAuthTries 3" >> "$SSH_CONFIG"
service ssh restart

# -----------------------------
# SECTION 3: Firewall / Network
# -----------------------------

echo "[*] Installing and configuring UFW..."
apt install -y ufw

# Deny inbound dangerous ports
for port in "${FIREWALL_DENY_IN[@]}"; do
    ufw deny "$port"
done

# Deny outbound dangerous ports
for port in "${FIREWALL_DENY_OUT[@]}"; do
    ufw deny out "$port"
done

# Allow necessary services
for service in "${FIREWALL_ALLOW[@]}"; do
    ufw allow "$service"
done

ufw enable

# -----------------------------
# SECTION 4: Service Hardening
# -----------------------------
echo "[*] Disabling unused/unneeded services..."
for svc in "${DISABLE_SERVICES[@]}"; do
    systemctl disable --now "$svc"
done

echo "[*] Securing Apache ownership..."
chown -R root:root /etc/apache2

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

service vsftpd restart
chattr +i "$VSFTPD_CONF" "$VSFTPD_USERLIST"

# -----------------------------
# SECTION 6: File Backups & Integrity
# -----------------------------
echo "[*] Securing scoring files..."
for file in "${SCORING_FILES[@]}"; do
    cp "$file" ~
    cp "$file" /bin
    cp "$file" /media
    cp "$file" /var
    chattr +i "$file"
done

# Protect cron and startup scripts
chattr +i /etc/crontab /etc/rc.local

# -----------------------------
# SECTION 7: Monitoring & Logging
# -----------------------------
echo "[*] Installing monitoring tools..."
apt update -y
apt install -y "${TOOLS[@]}"

echo "[*] Configuring auditd..."
systemctl enable --now auditd
auditctl -w /etc/passwd -p wa -k passwd_changes
auditctl -w /etc/shadow -p wa -k shadow_changes
auditctl -w /etc/ssh/sshd_config -p wa -k ssh_changes
auditctl -w /etc/vsftpd.conf -p wa -k ftp_changes

echo "[*] Downloading pspy for process monitoring..."
wget -q https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
chmod +x pspy64

# -----------------------------
# SECTION 8: System Updates
# -----------------------------
echo "[*] Installing unattended security updates..."
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades

# -----------------------------
# SECTION 9: User Cleanup & Verification
# -----------------------------
echo "[*] Resetting local user passwords..."
for user in $(awk -F: -v threshold="$SYSTEM_UID_THRESHOLD" '{if ($3 >= threshold && $1 != "nobody") print $1}' /etc/passwd); do
    (echo "PASSWORD!"; echo "PASSWORD!") | passwd "$user"
done

pwck
grpck

# -----------------------------
# SECTION 10: Final Config Protection
# -----------------------------
echo "[*] Locking critical configuration files..."
chattr +i /etc/passwd /etc/shadow /etc/gshadow /etc/ssh/sshd_config

echo "[*] Dynamic Super Hardening Script completed successfully!"
