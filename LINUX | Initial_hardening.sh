#!/usr/bin/env bash
# Hardening script for AlmaLinux 9 (RHEL-family) and Debian/Ubuntu
# Run as root: sudo bash hardening-linux.sh
# Logs to /var/log/hardening_linux.log

set -euo pipefail
LOG=/var/log/hardening_linux.log
exec > >(tee -a "$LOG") 2>&1

echo "=== START hardening: $(date) ==="

# Detect OS family
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS=$ID
  OS_FAMILY=$ID_LIKE
else
  echo "Cannot detect OS, aborting."
  exit 1
fi

echo "[+] Detected OS: $PRETTY_NAME"

# Define package manager commands
if [[ "$OS" =~ (almalinux|rhel|centos|rocky) || "$OS_FAMILY" =~ rhel ]]; then
  PKG_UPDATE="dnf -y update"
  PKG_INSTALL="dnf -y install"
  FIREWALL_CMD="firewall-cmd"
  USE_FIREWALLD=1
elif [[ "$OS" =~ (debian|ubuntu) || "$OS_FAMILY" =~ debian ]]; then
  PKG_UPDATE="apt-get update -y && apt-get upgrade -y"
  PKG_INSTALL="apt-get install -y"
  FIREWALL_CMD="ufw"
  USE_FIREWALLD=0
else
  echo "Unsupported OS family: $OS $OS_FAMILY"
  exit 1
fi

# 1) Update system
echo "[+] Updating system..."
eval $PKG_UPDATE

# 2) Install baseline packages
echo "[+] Installing packages..."
if [ $USE_FIREWALLD -eq 1 ]; then
  eval $PKG_INSTALL firewalld fail2ban audit policycoreutils-python-utils passwdqc
else
  eval $PKG_INSTALL ufw fail2ban auditd libpam-pwquality
fi

# 3) SELinux (Alma only)
if [ $USE_FIREWALLD -eq 1 ]; then
  echo "[+] Ensuring SELinux enforcing..."
  sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
  setenforce 1 || true
fi

# 4) Firewall configuration
echo "[+] Configuring firewall..."
if [ $USE_FIREWALLD -eq 1 ]; then
  systemctl enable --now firewalld
  $FIREWALL_CMD --set-default-zone=public
  $FIREWALL_CMD --permanent --zone=public --add-service=ssh
  $FIREWALL_CMD --permanent --zone=public --add-service=http
  $FIREWALL_CMD --reload
else
  ufw --force enable
  ufw allow ssh
  ufw allow http
  # optionally allow https if needed
fi

# 5) SSH hardening
echo "[+] Hardening SSH..."
SSH_DROPIN=/etc/ssh/sshd_config.d/00-hardening.conf
mkdir -p /etc/ssh/sshd_config.d
cat > "$SSH_DROPIN" <<'EOF'
PermitRootLogin no
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
AllowTcpForwarding no
AllowUsers jmoney plinktern
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

systemctl reload ssh || systemctl restart sshd

# 6) Fail2ban
echo "[+] Configuring fail2ban..."
JAILCONF=/etc/fail2ban/jail.d/defaults.conf
mkdir -p /etc/fail2ban/jail.d
cat > "$JAILCONF" <<'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
maxretry = 4
bantime = 3600
findtime = 600
EOF
systemctl enable --now fail2ban

# 7) Auditd
echo "[+] Configuring auditd..."
if [ $USE_FIREWALLD -eq 1 ]; then
  systemctl enable --now auditd
else
  systemctl enable --now auditd || true
fi

AUDIT_RULES=/etc/audit/rules.d/hardening.rules
cat > "$AUDIT_RULES" <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/sudoers -p wa -k scope
-w /var/www -p wa -k web-content
EOF

if command -v augenrules >/dev/null; then
  augenrules --load || true
fi

# 8) Sysctl hardening
echo "[+] Applying sysctl hardening..."
SYSCTL_CONF=/etc/sysctl.d/99-hardening.conf
cat > "$SYSCTL_CONF" <<'EOF'
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
kernel.randomize_va_space = 2
EOF
sysctl --system

# 9) File permissions
echo "[+] Fixing world-writable dirs..."
for d in $(df --local -P | awk 'NR>1 {print $6}'); do
  find "$d" -xdev -type d -perm -0002 -print | while read -r wdir; do
    if [[ "$wdir" == /tmp* ]]; then
      chmod 1777 "$wdir" || true
    else
      chmod o-w "$wdir" || true
    fi
  done
done

# 10) Disable uncommon filesystems (Alma only)
if [ $USE_FIREWALLD -eq 1 ]; then
  cat > /etc/modprobe.d/disable-extra-mods.conf <<'EOF'
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF
fi

# 11) Sudoers tweaks
echo "[+] Configuring sudoers..."
if ! grep -q '^%wheel' /etc/sudoers; then
  echo "%wheel ALL=(ALL) ALL" >> /etc/sudoers
fi
if ! grep -q 'timestamp_timeout' /etc/sudoers; then
  echo "Defaults timestamp_timeout=5" >> /etc/sudoers
fi

# 12) Cron permissions
echo "[+] Hardening cron dirs..."
chmod -R go-w /etc/cron.* /var/spool/cron || true
chown root:root /etc/cron.* || true

echo "=== HARDENING COMPLETE $(date) ==="
