"""Mandatory Access Control (AppArmor/SELinux) analysis."""

import re
import os
from ..utils.command import run_command_sudo, run_command


def check_apparmor():
    """Check AppArmor status and profiles."""
    # First try without sudo - check if module is loaded
    result = run_command(["lsmod"], timeout=5)
    apparmor_loaded = False
    if result and result.success:
        apparmor_loaded = "apparmor" in result.stdout.lower()

    # Also check /sys/module/apparmor/parameters/enabled
    if not apparmor_loaded and os.path.exists("/sys/module/apparmor/parameters/enabled"):
        try:
            with open("/sys/module/apparmor/parameters/enabled", "r") as f:
                apparmor_loaded = f.read().strip() == "Y"
        except (OSError, PermissionError):
            pass

    # If AppArmor not loaded at all, return None
    if not apparmor_loaded:
        return None

    # AppArmor is loaded, now try to get detailed status
    # Try with full path first (required by sudo rules)
    result = run_command_sudo(["/usr/sbin/apparmor_status"], timeout=5)
    if not result or not result.success:
        # Fallback to aa-status
        result = run_command_sudo(["/usr/sbin/aa-status"], timeout=5)

    if not result or not result.success:
        # AppArmor exists but we can't read status - needs sudo
        return {
            "type": "apparmor",
            "enabled": True,
            "enforce_count": 0,
            "complain_count": 0,
            "unconfined_count": 0,
            "needs_sudo": True,
        }

    output = result.stdout

    if not output or "do not have enough privilege" in output.lower():
        # AppArmor exists but needs sudo
        return {
            "type": "apparmor",
            "enabled": True,
            "enforce_count": 0,
            "complain_count": 0,
            "unconfined_count": 0,
            "needs_sudo": True,
        }

    # Parse status
    enabled = "apparmor module is loaded" in output.lower()

    # Extract profile counts
    enforce_count = 0
    complain_count = 0
    unconfined_count = 0

    enforce_match = re.search(r"(\d+) profiles are in enforce mode", output)
    if enforce_match:
        enforce_count = int(enforce_match.group(1))

    complain_match = re.search(r"(\d+) profiles are in complain mode", output)
    if complain_match:
        complain_count = int(complain_match.group(1))

    unconfined_match = re.search(r"(\d+) processes are unconfined", output)
    if unconfined_match:
        unconfined_count = int(unconfined_match.group(1))

    return {
        "type": "apparmor",
        "enabled": enabled,
        "enforce_count": enforce_count,
        "complain_count": complain_count,
        "unconfined_count": unconfined_count,
    }


def check_selinux():
    """Check SELinux status and mode."""
    result = run_command_sudo(["/usr/sbin/getenforce"])

    if not result:
        return None

    mode = result.stdout.strip().lower()

    enabled = mode in ("enforcing", "permissive")
    enforcing = mode == "enforcing"

    return {"type": "selinux", "enabled": enabled, "enforcing": enforcing, "mode": mode}


def analyze_mac():
    """Analyze Mandatory Access Control configuration."""
    # Try AppArmor first (common on Debian/Ubuntu)
    apparmor = check_apparmor()
    if apparmor:
        issues = []

        # Check if we need sudo for full analysis
        if apparmor.get("needs_sudo"):
            issues.append(
                {
                    "severity": "info",
                    "message": "AppArmor detected but full status requires sudo access",
                    "recommendation": "Run ./setup-sudo.sh to enable complete AppArmor analysis",
                }
            )
        elif not apparmor["enabled"]:
            issues.append(
                {
                    "severity": "high",
                    "message": "AppArmor is not enabled",
                    "recommendation": "Enable AppArmor for mandatory access control protection",
                }
            )
        elif apparmor["complain_count"] > apparmor["enforce_count"]:
            issues.append(
                {
                    "severity": "medium",
                    "message": f"{apparmor['complain_count']} profiles in complain mode",
                    "recommendation": "Move profiles from complain to enforce mode for better security",
                }
            )

        return {**apparmor, "issues": issues}

    # Try SELinux (common on RHEL/CentOS)
    selinux = check_selinux()
    if selinux:
        issues = []

        if not selinux["enabled"]:
            issues.append(
                {
                    "severity": "high",
                    "message": "SELinux is disabled",
                    "recommendation": "Enable SELinux for mandatory access control protection",
                }
            )
        elif not selinux["enforcing"]:
            issues.append(
                {
                    "severity": "medium",
                    "message": "SELinux is in permissive mode",
                    "recommendation": "Set SELinux to enforcing mode for active protection",
                }
            )

        return {**selinux, "issues": issues}

    # No MAC system detected
    return {
        "type": "none",
        "enabled": False,
        "issues": [
            {
                "severity": "high",
                "message": "No Mandatory Access Control system detected",
                "recommendation": "Install and enable AppArmor or SELinux for enhanced security",
            }
        ],
    }
