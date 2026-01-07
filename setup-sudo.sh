#!/bin/bash
# Setup passwordless sudo for MCP Cybersec Watchdog security audit commands
# This provides ONLY the necessary read-only commands for security auditing

SUDOERS_FILE="/etc/sudoers.d/mcp-security"
USER="${1:-$USER}"

echo "=== MCP Cybersec Watchdog - Sudo Configuration ==="
echo "Setting up passwordless sudo for user: $USER"
echo ""

# Create sudoers file with ALL required commands
sudo tee "$SUDOERS_FILE" > /dev/null <<EOF
# MCP Cybersec Watchdog - Passwordless sudo for security audit commands
# This file grants read-only access to security-related information
# User: $USER

# Firewall analysis
$USER ALL=(ALL) NOPASSWD: /usr/sbin/ufw status
$USER ALL=(ALL) NOPASSWD: /usr/sbin/ufw status verbose
$USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables -L -n
$USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables -L -n -v
$USER ALL=(ALL) NOPASSWD: /usr/bin/firewall-cmd --state
$USER ALL=(ALL) NOPASSWD: /usr/bin/firewall-cmd --list-services

# Fail2ban analysis
$USER ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client status
$USER ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client status *

# Threat analysis (log reading)
$USER ALL=(ALL) NOPASSWD: /usr/bin/cat /var/log/auth.log
$USER ALL=(ALL) NOPASSWD: /usr/bin/cat /var/log/secure
$USER ALL=(ALL) NOPASSWD: /bin/cat /var/log/auth.log
$USER ALL=(ALL) NOPASSWD: /bin/cat /var/log/secure
$USER ALL=(ALL) NOPASSWD: /usr/bin/grep * /var/log/auth.log
$USER ALL=(ALL) NOPASSWD: /usr/bin/grep * /var/log/secure
$USER ALL=(ALL) NOPASSWD: /bin/grep * /var/log/auth.log

# Services and ports analysis
$USER ALL=(ALL) NOPASSWD: /usr/bin/ss -tulpn
$USER ALL=(ALL) NOPASSWD: /usr/sbin/ss -tulpn
$USER ALL=(ALL) NOPASSWD: /usr/bin/netstat -tulpn
$USER ALL=(ALL) NOPASSWD: /bin/netstat -tulpn
$USER ALL=(ALL) NOPASSWD: /usr/bin/lsof -i *

# Security updates check
$USER ALL=(ALL) NOPASSWD: /usr/bin/apt-get update -qq
$USER ALL=(ALL) NOPASSWD: /usr/bin/apt list --upgradable
$USER ALL=(ALL) NOPASSWD: /usr/bin/apt list --installed
$USER ALL=(ALL) NOPASSWD: /usr/bin/yum check-update --security -q
$USER ALL=(ALL) NOPASSWD: /usr/bin/dnf check-update --security -q

# AppArmor/SELinux status
$USER ALL=(ALL) NOPASSWD: /usr/sbin/apparmor_status
$USER ALL=(ALL) NOPASSWD: /usr/sbin/aa-status
$USER ALL=(ALL) NOPASSWD: /usr/sbin/getenforce
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sestatus

# Systemd services analysis
$USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl is-active *
$USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl is-enabled *
$USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *
$USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl list-units --failed *
$USER ALL=(ALL) NOPASSWD: /bin/systemctl is-active *
$USER ALL=(ALL) NOPASSWD: /bin/systemctl is-enabled *

# User and group analysis
$USER ALL=(ALL) NOPASSWD: /usr/bin/getent passwd
$USER ALL=(ALL) NOPASSWD: /usr/bin/getent passwd *
$USER ALL=(ALL) NOPASSWD: /usr/bin/getent group sudo
$USER ALL=(ALL) NOPASSWD: /usr/bin/getent group wheel
$USER ALL=(ALL) NOPASSWD: /usr/bin/getent group *
$USER ALL=(ALL) NOPASSWD: /usr/bin/lastb
$USER ALL=(ALL) NOPASSWD: /usr/bin/last *

# Sudoers audit (read-only)
$USER ALL=(ALL) NOPASSWD: /usr/bin/cat /etc/sudoers
$USER ALL=(ALL) NOPASSWD: /usr/bin/cat /etc/sudoers.d/*
$USER ALL=(ALL) NOPASSWD: /bin/cat /etc/sudoers
$USER ALL=(ALL) NOPASSWD: /bin/cat /etc/sudoers.d/*

# Rootkit detection
$USER ALL=(ALL) NOPASSWD: /usr/bin/which rkhunter
$USER ALL=(ALL) NOPASSWD: /usr/bin/which chkrootkit
$USER ALL=(ALL) NOPASSWD: /usr/bin/ps -eo pid
$USER ALL=(ALL) NOPASSWD: /usr/bin/ps -eo *
$USER ALL=(ALL) NOPASSWD: /bin/ps -eo pid
$USER ALL=(ALL) NOPASSWD: /bin/ps -eo *
$USER ALL=(ALL) NOPASSWD: /usr/bin/rkhunter --check --sk --rwo
$USER ALL=(ALL) NOPASSWD: /usr/bin/chkrootkit
$USER ALL=(ALL) NOPASSWD: /bin/cat /proc/*/cmdline

# Kernel security parameters
$USER ALL=(ALL) NOPASSWD: /usr/sbin/sysctl -n *
$USER ALL=(ALL) NOPASSWD: /sbin/sysctl -n *

# Docker/Container security
$USER ALL=(ALL) NOPASSWD: /usr/bin/docker ps *
$USER ALL=(ALL) NOPASSWD: /usr/bin/docker inspect *
$USER ALL=(ALL) NOPASSWD: /usr/bin/docker images

# Filesystem security checks
$USER ALL=(ALL) NOPASSWD: /usr/bin/find /tmp * -type f *
$USER ALL=(ALL) NOPASSWD: /usr/bin/find /var/tmp * -type f *
$USER ALL=(ALL) NOPASSWD: /usr/bin/find /dev/shm * -type f *
$USER ALL=(ALL) NOPASSWD: /usr/bin/find / -perm -4000 -type f
$USER ALL=(ALL) NOPASSWD: /usr/bin/stat *
$USER ALL=(ALL) NOPASSWD: /usr/bin/ls -la *

# Audit system
$USER ALL=(ALL) NOPASSWD: /usr/bin/cat /etc/audit/auditd.conf
$USER ALL=(ALL) NOPASSWD: /bin/cat /etc/audit/auditd.conf

# SSH configuration audit
$USER ALL=(ALL) NOPASSWD: /usr/bin/cat /etc/ssh/sshd_config
$USER ALL=(ALL) NOPASSWD: /bin/cat /etc/ssh/sshd_config

# PAM configuration audit
$USER ALL=(ALL) NOPASSWD: /usr/bin/cat /etc/pam.d/*
$USER ALL=(ALL) NOPASSWD: /bin/cat /etc/pam.d/*
$USER ALL=(ALL) NOPASSWD: /usr/bin/cat /etc/security/*
$USER ALL=(ALL) NOPASSWD: /bin/cat /etc/security/*

# Disk usage
$USER ALL=(ALL) NOPASSWD: /usr/bin/df -h
$USER ALL=(ALL) NOPASSWD: /bin/df -h
$USER ALL=(ALL) NOPASSWD: /usr/bin/du -sh *
EOF

# Set correct permissions (440 = read-only by root)
sudo chmod 440 "$SUDOERS_FILE"

echo ""
echo "=== Validating sudoers syntax ==="

# Validate sudoers syntax
if sudo visudo -c -f "$SUDOERS_FILE" > /dev/null 2>&1; then
    echo "✓ Passwordless sudo configured successfully"
    echo "✓ File: $SUDOERS_FILE"
    echo "✓ Permissions: 440 (read-only by root)"
    echo ""
    echo "=== Testing sudo access ==="

    # Test a few key commands
    if sudo -n apparmor_status > /dev/null 2>&1 || sudo -n aa-status > /dev/null 2>&1; then
        echo "✓ AppArmor check: OK"
    else
        echo "⚠ AppArmor check: FAILED (may not be installed)"
    fi

    if sudo -n cat /etc/sudoers > /dev/null 2>&1; then
        echo "✓ Sudoers read: OK"
    else
        echo "✗ Sudoers read: FAILED"
    fi

    if sudo -n ps -eo pid > /dev/null 2>&1; then
        echo "✓ Process list: OK"
    else
        echo "✗ Process list: FAILED"
    fi

    echo ""
    echo "=== Configuration complete ==="
    echo "You can now run security audits without entering password."
    echo ""
    echo "Test with:"
    echo "  sudo -n apparmor_status"
    echo "  sudo -n cat /etc/sudoers"

else
    echo "✗ Error: Invalid sudoers configuration"
    echo "✗ Removing invalid file..."
    sudo rm -f "$SUDOERS_FILE"
    exit 1
fi
