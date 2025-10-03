#!/usr/bin/env bash
# Hardening script for AlmaLinux 9 (RHEL9 family)
# - Idempotent: safe to run multiple times
# - Preserves SSH access for users 'jmoney' and 'plinktern' (do NOT change those credentials here)
# Run as root: sudo bash hardening-alma9.sh

set -euo pipefail
LOG=/var/log/hardening_alma9.log
exec > >(tee -a "$LOG") 2>&1

echo "=== START hardening: $(date) ==="

# 1) Basic update + install required packages
echo "[+] Updating system and installing packages..."
dnf -y update
dnf -y install firewalld fail2ban audit policycoreutils-python-utils passwdqc yum-utils

# 2) Ensure SELinux is enforcing (write config + setenforce)
echo "[+] Ensuring SELinux is enforcing..."
if [ -f /etc/selinux/config ]; then
  sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
fi
setenforce 1 || true

# 3) Firewalld: enable, set default zone, allow only necessary services (SSH + HTTP)
echo "[+] Configuring firewalld..."
systemctl enable --now firewalld
# Set default zone to public (conservative) and remove direct rules
firewall-cmd --set-default-zone=public

# Allow essential services required by the competition
# SSH must be reachable for jmoney/plinktern (score checks), HTTP for WooCommerce on storkfront.
firewall-cmd --permanent --zone=public --add-service=ssh
firewall-cmd --permanent --zone=public --add-service=http
# If HTTPS exists in your environment, consider enabling https
# firewall-cmd --permanent --zone=public --add-service=https

# Tighten default inbound policy: drop other incoming
# firewalld default is to reject/allow by zone; ensure no broad open ports:
firewall-cmd --permanent --zone=public --remove-service=mdns || true

firewall-cmd --reload
firewall-cmd --list-all

# 4) SSH hardening - use sshd_config.d to avoid upstream overrides
# We intentionally keep PasswordAuthentication yes because competition may require password logins
# but we severely limit which users may log in.
echo "[+] Hardening SSH (sshd)..."
SSH_DROPIN=/etc/ssh/sshd_config.d/00-hardening.conf
cat > "$SSH_DROPIN" <<'EOF'
# Hardening drop-in for sshd
PermitRootLogin no
# Keep PasswordAuthentication yes for competition scoring users; restrict logins to specific users
# IMPORTANT: do NOT remove jmoney or plinktern here if these accounts are used by score checks.
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
AllowTcpForwarding no
# Restrict SSH to only the accounts necessary for scoring + admin
AllowUsers jmoney plinktern
# Connection limits
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
# Banner (optional)
Banner /etc/issue.net
EOF

# reload sshd
systemctl reload sshd

# 5) Fail2ban: basic protection for ssh
echo "[+] Configuring fail2ban..."
cat > /etc/fail2ban/jail.d/defaults.conf <<'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
maxretry = 4
bantime = 3600
findtime = 600
EOF
systemctl enable --now fail2ban

# 6) Auditd - enable and add core rules
echo "[+] Enabling auditd and core audit rules..."
systemctl enable --now auditd

AUDIT_RULES=/etc/audit/rules.d/hardening.rules
cat > "$AUDIT_RULES" <<'EOF'
# Basic audit rules
-D
-b 8192
# Audit config file changes
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/sudoers -p wa -k scope
# Monitor /var/www (web content)
-w /var/www -p wa -k web-content
# Monitor systemd unit changes
-w /etc/systemd/system -p wa -k systemd
EOF

augenrules --load || true

# 7) Kernel hardening via sysctl (apply runtime + persist)
echo "[+] Applying sysctl hardening..."
SYSCTL_CONF=/etc/sysctl.d/99-hardening.conf
cat > "$SYSCTL_CONF" <<'EOF'
# Network / kernel hardening
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
# Reduce ICMP exposure
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Ignore bogus ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
# Enable ASLR (usually enabled by default)
kernel.randomize_va_space = 2
EOF

sysctl --system

# 8) File permissions & world-writable dir checks (report & fix common issues)
echo "[+] Checking and tightening common world-writable dirs..."
# find world-writable directories (excluding /proc and /sys)
for d in $(df --local -P | awk 'NR>1 {print $6}'); do
  find "$d" -xdev -type d -perm -0002 -print | while read -r wdir; do
    # skip /tmp (we'll set sticky bit)
    if [ "$wdir" = "/tmp" ] || echo "$wdir" | grep -q "^/tmp"; then
      chmod 1777 "$wdir" || true
    else
      echo "Fixing perms for $wdir"
      chmod o-w "$wdir" || true
    fi
  done
done

# 9) Disable unused filesystems (best-effort; do not break system)
echo "[+] Disabling uncommon kernel modules to reduce attack surface..."
cat > /etc/modprobe.d/disable-extra-mods.conf <<'EOF'
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF

# 10) Configure sudo timeout & wheel group only
echo "[+] Tightening sudoers..."
# ensure only wheel can sudo and set timestamp_timeout = 5
if ! grep -q '^%wheel' /etc/sudoers; then
  echo "%wheel ALL=(ALL) ALL" >> /etc/sudoers
fi
if ! grep -q '^Defaults\s\+timestamp_timeout=' /etc/sudoers; then
  echo "Defaults    timestamp_timeout=5" >> /etc/sudoers
fi

# 11) Ensure cron jobs owned by root and no world-writable cron dirs
echo "[+] Verifying cron directories..."
chmod -R go-w /etc/cron.* /var/spool/cron || true
chown root:root /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly || true

# 12) Ensure rsyslog/journald retention sensible (do not logrotate too rarely)
echo "[+] Ensuring journald/rsyslog rotate/retention defaults..."
# Keep default; optionally tune /etc/systemd/journald.conf/max_retention_sec etc.

# 13) Final: restart services to ensure new configs active
echo "[+] Restarting services where necessary..."
systemctl restart sshd || true
systemctl restart firewalld || true
systemctl restart auditd || true
systemctl restart fail2ban || true

echo "=== HARDENING COMPLETE: $(date) ==="
echo "Log written to $LOG"
