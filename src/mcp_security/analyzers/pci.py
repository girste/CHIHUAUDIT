"""PCI-DSS (Payment Card Industry Data Security Standard) compliance checker.

Implements technical requirements from PCI-DSS v4.0.
Focus on system hardening and security controls for Linux servers.
"""

from ..utils.detect import run_with_sudo
from ..utils.command import run_command_sudo


PCI_REQUIREMENTS = {
    "2": "Apply Secure Configurations to All System Components",
    "8": "Identify Users and Authenticate Access to System Components",
    "10": "Log and Monitor All Access to System Components and Cardholder Data",
}


def _check_firewall_enabled():
    """PCI Req 1.2.1 - Ensure firewall is enabled."""
    result = run_with_sudo(["ufw", "status"])

    if not result:
        return False, "Firewall not found or not running"

    if "Status: active" in result.stdout:
        return True, "Firewall active"

    return False, "Firewall inactive"


def _check_default_passwords():
    """PCI Req 2.1 - Check for default/vendor-supplied passwords."""
    # This is a simplified check - would need database of default passwords
    weak_users = ["admin", "administrator", "root"]

    result = run_with_sudo(["getent", "passwd"])
    if not result:
        return True, "Unable to enumerate users (assumed compliant)"

    users = [line.split(":")[0] for line in result.stdout.split("\n") if line]
    found_weak = [u for u in weak_users if u in users and u != "root"]

    if found_weak:
        return False, f"Potentially weak usernames found: {', '.join(found_weak)}"

    return True, "No obvious default usernames detected"


def _check_unnecessary_services():
    """PCI Req 2.2.2 - Disable unnecessary services."""
    unnecessary = ["telnet", "ftp", "rsh", "rlogin"]
    running = []

    for service in unnecessary:
        result = run_with_sudo(["systemctl", "is-active", f"{service}.service"])
        if result and result.stdout.strip() == "active":
            running.append(service)

    if running:
        return False, f"Insecure services running: {', '.join(running)}"

    return True, "No insecure services detected"


def _check_password_policy():
    """PCI Req 8.3.6 - Strong password requirements."""
    try:
        result = run_command_sudo(
            ["grep", "-E", "^minlen", "/etc/security/pwquality.conf"],
            timeout=5,
        )

        if result.returncode == 0 and result.stdout:
            # Check if minimum length is at least 12 (PCI-DSS 4.0 requirement)
            for line in result.stdout.split("\n"):
                if "minlen" in line:
                    try:
                        length = int(line.split("=")[1].strip())
                        if length >= 12:
                            return True, f"Password minimum length: {length} chars"
                        return False, f"Password too short: {length} chars (require 12+)"
                    except (ValueError, IndexError):
                        pass

        return False, "Password policy not configured"

    except Exception:
        return False, "Unable to check password policy"


def _check_logging_enabled():
    """PCI Req 10.2 - Audit logging is enabled."""
    critical_logs = ["/var/log/auth.log", "/var/log/syslog"]
    missing = []

    for log_file in critical_logs:
        try:
            result = run_command_sudo(
                ["test", "-f", log_file],
                timeout=5,
            )
            if not result or not result.success:
                missing.append(log_file)
        except Exception:
            missing.append(log_file)

    if missing:
        return False, f"Missing log files: {', '.join(missing)}"

    return True, "Critical log files present"


def _check_time_sync():
    """PCI Req 10.4 - Time synchronization."""
    result = run_with_sudo(["systemctl", "is-active", "systemd-timesyncd.service"])

    if not result:
        # Try chrony
        result = run_with_sudo(["systemctl", "is-active", "chronyd.service"])

    if result and result.stdout.strip() == "active":
        return True, "Time synchronization active"

    return False, "Time synchronization not configured"


def check_requirement_2():
    """PCI Req 2 - Secure Configurations."""
    controls = []

    passed, detail = _check_default_passwords()
    controls.append(
        {
            "id": "2.1",
            "requirement": "2",
            "description": "Change vendor-supplied defaults before installing system",
            "passed": passed,
            "detail": detail,
        }
    )

    passed, detail = _check_unnecessary_services()
    controls.append(
        {
            "id": "2.2.2",
            "requirement": "2",
            "description": "Disable unnecessary services and protocols",
            "passed": passed,
            "detail": detail,
        }
    )

    return controls


def check_requirement_8():
    """PCI Req 8 - Identification and Authentication."""
    controls = []

    passed, detail = _check_password_policy()
    controls.append(
        {
            "id": "8.3.6",
            "requirement": "8",
            "description": "Strong password requirements (12+ characters)",
            "passed": passed,
            "detail": detail,
        }
    )

    return controls


def check_requirement_10():
    """PCI Req 10 - Logging and Monitoring."""
    controls = []

    passed, detail = _check_logging_enabled()
    controls.append(
        {
            "id": "10.2",
            "requirement": "10",
            "description": "Implement audit logging for all system components",
            "passed": passed,
            "detail": detail,
        }
    )

    passed, detail = _check_time_sync()
    controls.append(
        {
            "id": "10.4",
            "requirement": "10",
            "description": "Synchronize all critical system clocks",
            "passed": passed,
            "detail": detail,
        }
    )

    return controls


def analyze_pci():
    """Run PCI-DSS compliance baseline checks."""
    from ..profile_weights import get_pci_control_weight, PROFILES

    all_controls = []
    all_controls.extend(check_requirement_2())
    all_controls.extend(check_requirement_8())
    all_controls.extend(check_requirement_10())

    passed_count = sum(1 for c in all_controls if c["passed"])
    failed_count = len(all_controls) - passed_count
    compliance_percentage = (passed_count / len(all_controls) * 100) if all_controls else 0

    # Calculate profile-weighted scores
    profile_scores = {}
    for profile_name in PROFILES.keys():
        total_weight = 0.0
        achieved_weight = 0.0

        for control in all_controls:
            weight = get_pci_control_weight(control["id"], profile_name)
            total_weight += weight
            if control["passed"]:
                achieved_weight += weight

        profile_scores[profile_name] = round((achieved_weight / total_weight * 100) if total_weight > 0 else 0, 1)

    issues = []
    for control in all_controls:
        if not control["passed"]:
            issues.append(
                {
                    "severity": "critical",
                    "message": f"PCI-DSS Req {control['id']}: {control['description']} - FAILED",
                    "recommendation": f"Review and fix: {control['detail']}",
                }
            )

    return {
        "checked": True,
        "standard": "PCI-DSS v4.0 Baseline",
        "total_controls": len(all_controls),
        "passed": passed_count,
        "failed": failed_count,
        "compliance_percentage": round(compliance_percentage, 1),
        "profile_scores": profile_scores,
        "controls": all_controls,
        "issues": issues,
        "note": "Automated checks cover technical subset - full PCI-DSS compliance requires QSA assessment",
    }
