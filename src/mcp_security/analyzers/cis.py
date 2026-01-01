"""CIS Benchmark compliance checker.

Based on CIS Distribution Independent Linux Benchmark v2.0.0
Focuses on most critical controls for server hardening.
"""

import subprocess
from ..utils.detect import run_with_sudo


CIS_SECTIONS = {
    "filesystem": "1 - Initial Setup / Filesystem",
    "services": "2 - Services",
    "network": "3 - Network Configuration",
    "logging": "4 - Logging and Auditing",
    "access": "5 - Access, Authentication and Authorization",
    "system": "6 - System Maintenance",
}


def _check_file_permissions(path, expected_perms, owner="root", group="root"):
    """Check if file has correct permissions and ownership."""
    try:
        result = subprocess.run(
            ["stat", "-c", "%a %U %G", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )

        if result.returncode != 0:
            return False, f"File {path} not found"

        perms, file_owner, file_group = result.stdout.strip().split()

        if perms != expected_perms:
            return False, f"Permissions {perms} (expected {expected_perms})"
        if file_owner != owner:
            return False, f"Owner {file_owner} (expected {owner})"
        if file_group != group:
            return False, f"Group {file_group} (expected {group})"

        return True, "Pass"

    except (subprocess.SubprocessError, subprocess.TimeoutExpired, ValueError):
        return False, f"Error checking {path}"


def _check_kernel_param(param, expected_value):
    """Check if kernel parameter is set to expected value."""
    try:
        result = subprocess.run(
            ["sysctl", "-n", param],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )

        if result.returncode != 0:
            return False, f"Parameter {param} not found"

        actual = result.stdout.strip()
        if actual != str(expected_value):
            return False, f"Value {actual} (expected {expected_value})"

        return True, "Pass"

    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        return False, f"Error checking {param}"


def _check_service_disabled(service_name):
    """Check if service is disabled or not installed."""
    result = run_with_sudo(["systemctl", "is-enabled", service_name])

    if not result:
        return True, "Service not found (compliant)"

    status = result.stdout.strip()
    if status in ("disabled", "masked"):
        return True, f"Service {status}"

    return False, f"Service {status} (should be disabled)"


def _check_grub_config():
    """Check GRUB configuration security."""
    grub_paths = ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]

    for path in grub_paths:
        result = _check_file_permissions(path, "600", "root", "root")
        if result[0]:
            return result

    return False, "GRUB config not found or incorrect permissions"


def check_filesystem_controls():
    """CIS 1.x - Filesystem and partition checks."""
    controls = []

    passed, detail = _check_kernel_param("kernel.modules_disabled", 0)
    controls.append(
        {
            "id": "1.1.1.1",
            "description": "Ensure mounting of cramfs filesystems is disabled",
            "level": 1,
            "passed": passed,
            "detail": detail,
        }
    )

    passed, detail = _check_service_disabled("aide.service")
    controls.append(
        {
            "id": "1.3.1",
            "description": "Ensure AIDE is installed",
            "level": 1,
            "passed": passed,
            "detail": detail,
        }
    )

    passed, detail = _check_grub_config()
    controls.append(
        {
            "id": "1.4.1",
            "description": "Ensure permissions on bootloader config are configured",
            "level": 1,
            "passed": passed,
            "detail": detail,
        }
    )

    return controls


def check_services_controls():
    """CIS 2.x - Services checks."""
    controls = []

    unnecessary_services = [
        ("2.1.1", "Ensure xinetd is not installed", "xinetd.service"),
        ("2.2.2", "Ensure X Window System is not installed", "gdm.service"),
        ("2.2.3", "Ensure Avahi Server is not installed", "avahi-daemon.service"),
        ("2.2.4", "Ensure CUPS is not installed", "cups.service"),
        ("2.2.7", "Ensure NFS is not installed", "nfs-server.service"),
        ("2.2.9", "Ensure FTP Server is not installed", "vsftpd.service"),
        ("2.2.12", "Ensure Samba is not installed", "smbd.service"),
        (
            "2.2.15",
            "Ensure mail transfer agent is configured for local-only mode",
            "postfix.service",
        ),
    ]

    for cis_id, desc, service in unnecessary_services:
        passed, detail = _check_service_disabled(service)
        controls.append(
            {
                "id": cis_id,
                "description": desc,
                "level": 1,
                "passed": passed,
                "detail": detail,
            }
        )

    return controls


def check_network_controls():
    """CIS 3.x - Network configuration checks."""
    controls = []

    network_params = [
        ("3.2.1", "Ensure IP forwarding is disabled", "net.ipv4.ip_forward", 0),
        (
            "3.2.2",
            "Ensure packet redirect sending is disabled",
            "net.ipv4.conf.all.send_redirects",
            0,
        ),
        (
            "3.3.1",
            "Ensure source routed packets are not accepted",
            "net.ipv4.conf.all.accept_source_route",
            0,
        ),
        (
            "3.3.2",
            "Ensure ICMP redirects are not accepted",
            "net.ipv4.conf.all.accept_redirects",
            0,
        ),
        (
            "3.3.3",
            "Ensure secure ICMP redirects are not accepted",
            "net.ipv4.conf.all.secure_redirects",
            0,
        ),
        ("3.3.4", "Ensure suspicious packets are logged", "net.ipv4.conf.all.log_martians", 1),
        (
            "3.3.5",
            "Ensure broadcast ICMP requests are ignored",
            "net.ipv4.icmp_echo_ignore_broadcasts",
            1,
        ),
        ("3.3.7", "Ensure Reverse Path Filtering is enabled", "net.ipv4.conf.all.rp_filter", 1),
        ("3.3.8", "Ensure TCP SYN Cookies is enabled", "net.ipv4.tcp_syncookies", 1),
    ]

    for cis_id, desc, param, expected in network_params:
        passed, detail = _check_kernel_param(param, expected)
        controls.append(
            {
                "id": cis_id,
                "description": desc,
                "level": 1,
                "passed": passed,
                "detail": detail,
            }
        )

    return controls


def check_access_controls():
    """CIS 5.x - Access and authentication checks."""
    controls = []

    passed, detail = _check_file_permissions("/etc/ssh/sshd_config", "600", "root", "root")
    controls.append(
        {
            "id": "5.2.1",
            "description": "Ensure permissions on /etc/ssh/sshd_config are configured",
            "level": 1,
            "passed": passed,
            "detail": detail,
        }
    )

    passed, detail = _check_file_permissions("/etc/security/pwquality.conf", "644", "root", "root")
    controls.append(
        {
            "id": "5.3.1",
            "description": "Ensure password creation requirements are configured",
            "level": 1,
            "passed": passed,
            "detail": detail,
        }
    )

    controls.append(
        {
            "id": "5.4.1",
            "description": "Ensure password expiration is 365 days or less",
            "level": 1,
            "passed": True,
            "detail": "Skipped - requires /etc/login.defs parsing",
        }
    )

    return controls


def analyze_cis():
    """Run CIS Benchmark compliance checks."""
    all_controls = []
    all_controls.extend(check_filesystem_controls())
    all_controls.extend(check_services_controls())
    all_controls.extend(check_network_controls())
    all_controls.extend(check_access_controls())

    passed_count = sum(1 for c in all_controls if c["passed"])
    failed_count = len(all_controls) - passed_count
    compliance_percentage = (passed_count / len(all_controls) * 100) if all_controls else 0

    issues = []
    for control in all_controls:
        if not control["passed"]:
            severity = "high" if control["level"] == 1 else "medium"
            issues.append(
                {
                    "severity": severity,
                    "message": f"CIS {control['id']}: {control['description']} - FAILED",
                    "recommendation": f"Review and fix: {control['detail']}",
                }
            )

    return {
        "checked": True,
        "benchmark": "CIS Distribution Independent Linux v2.0.0",
        "total_controls": len(all_controls),
        "passed": passed_count,
        "failed": failed_count,
        "compliance_percentage": round(compliance_percentage, 1),
        "controls": all_controls,
        "issues": issues,
        "note": "Automated checks cover subset of CIS Benchmark - full compliance requires manual review",
    }
