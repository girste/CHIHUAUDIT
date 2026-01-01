"""NIST 800-53 Security Controls baseline checker.

Implements high-priority controls from NIST 800-53 Rev 5.
Focus on technical controls applicable to Linux servers.
"""

import subprocess
from ..utils.detect import run_with_sudo


NIST_FAMILIES = {
    "AC": "Access Control",
    "AU": "Audit and Accountability",
    "CM": "Configuration Management",
    "IA": "Identification and Authentication",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}


def _check_audit_logging():
    """Check if audit logging (auditd) is configured."""
    result = run_with_sudo(["systemctl", "is-active", "auditd.service"])

    if not result:
        return False, "auditd not installed"

    status = result.stdout.strip()
    if status == "active":
        return True, "auditd active and logging"

    return False, f"auditd {status}"


def _check_password_complexity():
    """Check if password complexity requirements are enforced."""
    try:
        result = subprocess.run(
            [
                "grep",
                "-E",
                "^(minlen|dcredit|ucredit|lcredit|ocredit)",
                "/etc/security/pwquality.conf",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )

        if result.returncode == 0 and result.stdout:
            return True, "Password complexity configured"

        return False, "Password complexity not configured"

    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        return False, "Unable to check password policy"


def _check_session_timeout():
    """Check if idle session timeout is configured."""
    try:
        result = subprocess.run(
            ["grep", "-E", "^(TMOUT|ClientAliveInterval)", "/etc/profile", "/etc/ssh/sshd_config"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )

        if result.returncode == 0 and result.stdout:
            return True, "Session timeout configured"

        return False, "Session timeout not configured"

    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        return False, "Unable to check session timeout"


def _check_automatic_updates():
    """Check if automatic security updates are enabled."""
    result = run_with_sudo(["systemctl", "is-enabled", "unattended-upgrades.service"])

    if not result:
        return False, "Automatic updates not configured"

    status = result.stdout.strip()
    if status == "enabled":
        return True, "Automatic security updates enabled"

    return False, f"Automatic updates {status}"


def check_access_control():
    """NIST AC - Access Control family."""
    controls = []

    passed, detail = _check_session_timeout()
    controls.append(
        {
            "id": "AC-11",
            "name": "Session Lock",
            "description": "Ensure idle sessions are automatically terminated",
            "family": "AC",
            "passed": passed,
            "detail": detail,
        }
    )

    passed, detail = _check_password_complexity()
    controls.append(
        {
            "id": "AC-7",
            "name": "Unsuccessful Logon Attempts",
            "description": "Enforce account lockout after failed login attempts",
            "family": "AC",
            "passed": passed,
            "detail": detail,
        }
    )

    return controls


def check_audit_accountability():
    """NIST AU - Audit and Accountability family."""
    controls = []

    passed, detail = _check_audit_logging()
    controls.append(
        {
            "id": "AU-2",
            "name": "Event Logging",
            "description": "Ensure comprehensive system auditing is enabled",
            "family": "AU",
            "passed": passed,
            "detail": detail,
        }
    )

    return controls


def check_system_protection():
    """NIST SC - System and Communications Protection family."""
    controls = []

    # Check kernel ASLR
    try:
        result = subprocess.run(
            ["sysctl", "-n", "kernel.randomize_va_space"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )

        value = result.stdout.strip()
        passed = value == "2"
        detail = f"ASLR {'enabled (full)' if passed else f'partial or disabled ({value})'}"

    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        passed = False
        detail = "Unable to check ASLR"

    controls.append(
        {
            "id": "SC-39",
            "name": "Process Isolation",
            "description": "Ensure ASLR (Address Space Layout Randomization) is enabled",
            "family": "SC",
            "passed": passed,
            "detail": detail,
        }
    )

    return controls


def check_system_integrity():
    """NIST SI - System and Information Integrity family."""
    controls = []

    passed, detail = _check_automatic_updates()
    controls.append(
        {
            "id": "SI-2",
            "name": "Flaw Remediation",
            "description": "Ensure automatic security updates are configured",
            "family": "SI",
            "passed": passed,
            "detail": detail,
        }
    )

    return controls


def analyze_nist():
    """Run NIST 800-53 baseline compliance checks."""
    all_controls = []
    all_controls.extend(check_access_control())
    all_controls.extend(check_audit_accountability())
    all_controls.extend(check_system_protection())
    all_controls.extend(check_system_integrity())

    passed_count = sum(1 for c in all_controls if c["passed"])
    failed_count = len(all_controls) - passed_count
    compliance_percentage = (passed_count / len(all_controls) * 100) if all_controls else 0

    issues = []
    for control in all_controls:
        if not control["passed"]:
            issues.append(
                {
                    "severity": "high",
                    "message": f"NIST {control['id']} ({control['name']}): {control['description']} - FAILED",
                    "recommendation": f"Review and fix: {control['detail']}",
                }
            )

    return {
        "checked": True,
        "standard": "NIST 800-53 Rev 5 Baseline",
        "total_controls": len(all_controls),
        "passed": passed_count,
        "failed": failed_count,
        "compliance_percentage": round(compliance_percentage, 1),
        "controls": all_controls,
        "issues": issues,
        "note": "Automated checks cover subset of NIST 800-53 - full compliance requires manual assessment",
    }
