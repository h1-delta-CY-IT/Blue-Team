#!/bin/bash
# -----------------------------------------
# Unified Blue Team Hardening & Cleanup Script
# Works on Debian/Ubuntu and Fedora/RHEL
# Author: Adapted from Ardian Peach + ChatGPT enhancements
# Last Updated: 2025-09-13
# -----------------------------------------

set -euo pipefail

# -----------------------------
# Detect distro
# -----------------------------
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO="$ID"
else
    DISTRO="unknown"
fi

echo "[*] Detected OS: $DISTRO"

# -----------------------------
# Setup secure directories
# -----------------------------
SECRET_BASE="/var/lib/.hardening"
mkdir -p "$SECRET_BASE/backups"
chmod 700 "$SECRET_BASE"
PASSWORD_FILE="$SECRET_BASE/user_passwords_$(date +%F_%H%M%S).txt"
: > "$PASSWORD_FILE"
chmod 600 "$PASSWORD_FILE"

WORKDIR="$SECRET_BASE"
mkdir -p "$WORKDIR"/{quarantine,logs}
LOGFILE="$WORKDIR/logs/cleanup_$(date +%F_%T).log"
exec > >(tee -a "$LOGFILE") 2>&1

# -----------------------------
# Configuration variables
# -----------------------------
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
# Helper functions
# -----------------------------
pkg_install() {
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
# Root check
# -----------------------------
if [[ $EUID -ne 0 ]]; then
    echo "[-] Must be run as root"
    exit 1
fi

# -----------------------------
# OS-specific hardening
# -----------------------------
case "$DISTRO" in
    debian|ubuntu)
        echo "[*] Running Debian hardening..."
        apt update -y
        apt upgrade -y
        apt install -y libpam-cracklib ufw unattended-upgrades auditd fail2ban 2>/dev/null || true

        # Root & user security
        passwd -l root
        awk -F: -v threshold="$SYSTEM_UID_THRESHOLD" '{if ($3 >= threshold && $1 != "nobody") print $1}' /etc/passwd | while read -r user; do
            chage -d 0 "$user"
        done
        PAMFILE=$(detect_pam_common)
        if [[ -n "$PAMFILE" ]]; then
            grep -q "pam_cracklib.so" "$PAMFILE" || echo "password requisite pam_cracklib.so retry=3 minlen=12 difok=3" >> "$PAMFILE"
        fi

        # SSH hardening
        grep -q "PermitRootLogin no" "$SSH_CONFIG" || echo "PermitRootLogin no" >> "$SSH_CONFIG"
        grep -q "PasswordAuthentication no" "$SSH_CONFIG" || echo "PasswordAuthentication no" >> "$SSH_CONFIG"
        grep -q "PermitEmptyPasswords no" "$SSH_CONFIG" || echo "PermitEmptyPasswords no" >> "$SSH_CONFIG"
        grep -q "Banner /etc/issue.net" "$SSH_CONFIG" || echo "Banner /etc/issue.net" >> "$SSH_CONFIG"
        grep -q "MaxAuthTries 3" "$SSH_CONFIG" || echo "MaxAuthTries 3" >> "$SSH_CONFIG"
        grep -q "AllowUsers" "$SSH_CONFIG" || echo "AllowUsers ${ADMIN_USERS[*]}" >> "$SSH_CONFIG"
        systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || true

        # Firewall
        for port in "${FIREWALL_DENY_IN[@]}"; do ufw deny "$port"; done
        for port in "${FIREWALL_DENY_OUT[@]}"; do ufw deny out "$port"; done
        for svc in "${FIREWALL_ALLOW[@]}"; do ufw allow "$svc"; done
        ufw --force enable

        # Disable services
        for svc in "${DISABLE_SERVICES[@]}"; do
            systemctl disable --now "$svc" 2>/dev/null || true
        done

        # Secure scoring files
        for file in "${SCORING_FILES[@]}"; do
            cp "$file" "$SECRET_BASE/backups/" 2>/dev/null || true
            safe_chattr_i "$SECRET_BASE/backups/$(basename "$file")"
        done

        # Install monitoring tools
        apt install -y "${TOOLS[@]}" 2>/dev/null || true
        systemctl enable --now auditd

        # Download pspy
        wget -q "$PSPY_URL" -O "$SECRET_BASE/pspy64"
        chmod +x "$SECRET_BASE/pspy64"

        # Unattended upgrades
        dpkg-reconfigure -plow unattended-upgrades 2>/dev/null || true
        ;;

    fedora|rhel|centos)
        echo "[*] Running Fedora/RHEL hardening..."
        dnf update -y
        dnf upgrade -y
        dnf install -y firewalld libpwquality audit fail2ban vsftpd 2>/dev/null || true

        # Root & user security
        passwd -l root
        awk -F: -v threshold="$SYSTEM_UID_THRESHOLD" '{if ($3 >= threshold && $1 != "nobody") print $1}' /etc/passwd | while read -r user; do
            chage -d 0 "$user"
        done
        PAMFILE=$(detect_pam_common)
        if [[ -n "$PAMFILE" ]]; then
            grep -q "pam_pwquality.so" "$PAMFILE" || echo "password requisite pam_pwquality.so retry=3 minlen=12 difok=3" >> "$PAMFILE"
        fi

        # SSH hardening
        grep -q "PermitRootLogin no" "$SSH_CONFIG" || echo "PermitRootLogin no" >> "$SSH_CONFIG"
        grep -q "PasswordAuthentication no" "$SSH_CONFIG" || echo "PasswordAuthentication no" >> "$SSH_CONFIG"
        grep -q "PermitEmptyPasswords no" "$SSH_CONFIG" || echo "PermitEmptyPasswords no" >> "$SSH_CONFIG"
        grep -q "Banner /etc/issue.net" "$SSH_CONFIG" || echo "Banner /etc/issue.net" >> "$SSH_CONFIG"
        grep -q "MaxAuthTries 3" "$SSH_CONFIG" || echo "MaxAuthTries 3" >> "$SSH_CONFIG"
        grep -q "AllowUsers" "$SSH_CONFIG" || echo "AllowUsers ${ADMIN_USERS[*]}" >> "$SSH_CONFIG"
        systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || true

        # Firewall
        systemctl enable --now firewalld
        firewall-cmd --set-default-zone=drop
        for p in "${FIREWALL_DENY_IN[@]}"; do
            firewall-cmd --permanent --add-rich-rule="rule family='ipv4' port port='$p' protocol='tcp' reject"
        done
        for p in "${FIREWALL_DENY_OUT[@]}"; do
            firewall-cmd --permanent --add-rich-rule="rule family='ipv4' port port='$p' protocol='tcp' reject"
        done
        for svc in "${FIREWALL_ALLOW[@]}"; do
            firewall-cmd --permanent --add-service="$svc"
        done
        firewall-cmd --reload

        # Disable services
        for svc in "${DISABLE_SERVICES[@]}"; do
            systemctl disable --now "$svc" 2>/dev/null || true
        done

        # Secure scoring files
        for file in "${SCORING_FILES[@]}"; do
            cp "$file" "$SECRET_BASE/backups/" 2>/dev/null || true
            safe_chattr_i "$SECRET_BASE/backups/$(basename "$file")"
        done

        # Install monitoring tools
        dnf install -y "${TOOLS[@]}" 2>/dev/null || true
        systemctl enable --now auditd

        # Download pspy
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL "$PSPY_URL" -o "$SECRET_BASE/pspy64"
        else
            wget -q "$PSPY_URL" -O "$SECRET_BASE/pspy64"
        fi
        chmod +x "$SECRET_BASE/pspy64"
        ;;

    *)
        echo "[!] Unsupported OS. Only Debian/Ubuntu and Fedora/RHEL are supported."
        exit 1
        ;;
esac

# -----------------------------
# Service hardening (common)
# -----------------------------
SERVICE_HARDEN_SCRIPT="./suspicious_harden.sh"
if [[ -f "$SERVICE_HARDEN_SCRIPT" ]]; then
    echo "[*] Running service hardening script..."
    chmod +x "$SERVICE_HARDEN_SCRIPT"
    "$SERVICE_HARDEN_SCRIPT"
fi

echo "[*] Unified hardening completed successfully."
