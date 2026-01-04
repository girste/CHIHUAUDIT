"""Mandatory Access Control (AppArmor/SELinux) analysis."""

import re
from ..utils.command import run_command_sudo


def check_apparmor():
    """Check AppArmor status and profiles."""
    # apparmor_status requires root to show profile details
    result = run_command_sudo(["apparmor_status"], timeout=5)

    if not result or not result.success:
        return None

    output = result.stdout

    if not output or "do not have enough privilege" in output.lower():
        return None

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
    result = run_command_sudo(["getenforce"])

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

        if not apparmor["enabled"]:
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
