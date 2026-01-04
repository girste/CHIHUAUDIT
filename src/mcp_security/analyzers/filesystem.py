"""Filesystem security analyzer.

Scans for world-writable files, SUID/SGID binaries, and suspicious files
that could indicate security issues or privilege escalation risks.
"""

from typing import List, Dict
# Command utilities
from ..utils.command import run_command_sudo

from ..constants import (
    TIMEOUT_SHORT,
    TIMEOUT_MEDIUM,
    TIMEOUT_LONG,
    MAX_WORLD_WRITABLE_FILES,
    MAX_SUID_FILES,
)

EXCLUDED_PATHS = ["/proc", "/sys", "/dev", "/run"]

SUID_WHITELIST = {
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/gpasswd",
    "/usr/bin/newgrp",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/pkexec",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/policykit-1/polkit-agent-helper-1",
}


def _build_exclude_args() -> List[str]:
    """Build find command exclusion arguments."""
    args = []
    for path in EXCLUDED_PATHS:
        args.extend(["-path", path, "-prune", "-o"])
    return args


def _find_world_writable_files() -> List[str]:
    """Find world-writable files (excluding common safe locations)."""
    exclude_args = _build_exclude_args()

    try:
        result = run_command_sudo(
            ["find", "/", *exclude_args, "-type", "f", "-perm", "-002", "-print"],
            timeout=TIMEOUT_LONG,
        )

        if not result or not result.success:
            return []

        files = [
            line.strip()
            for line in result.stdout.split("\n")
            if line.strip() and not line.startswith("/tmp/") and not line.startswith("/var/tmp/")
        ]

        return files[:MAX_WORLD_WRITABLE_FILES]

    except (Exception):
        return []


def _find_suid_files() -> List[Dict[str, str]]:
    """Find SUID and SGID binaries."""
    exclude_args = _build_exclude_args()

    try:
        result = run_command_sudo(
            [
                "find",
                "/",
                *exclude_args,
                "-type",
                "f",
                "(",
                "-perm",
                "-4000",
                "-o",
                "-perm",
                "-2000",
                ")",
                "-print",
            ],
            timeout=TIMEOUT_LONG,
        )

        if not result or not result.success:
            return []

        files = []
        for line in result.stdout.split("\n"):
            if line.strip():
                path = line.strip()
                is_whitelisted = path in SUID_WHITELIST

                files.append(
                    {
                        "path": path,
                        "whitelisted": is_whitelisted,
                    }
                )

        return files[:MAX_SUID_FILES]

    except (Exception):
        return []


def _check_tmp_permissions() -> Dict:
    """Check /tmp directory permissions."""
    try:
        result = run_command_sudo(
            ["stat", "-c", "%a", "/tmp"],
            timeout=TIMEOUT_SHORT,
        )

        if result.returncode == 0:
            perms = result.stdout.strip()
            # /tmp should be 1777 (sticky bit + rwx for all)
            is_secure = perms == "1777"

            return {
                "checked": True,
                "permissions": perms,
                "secure": is_secure,
            }

    except (Exception):
        pass

    return {"checked": False}


def _check_suspicious_files() -> List[str]:
    """Look for suspicious files in common locations."""
    # TODO: Implement pattern-based filtering for more targeted detection
    suspicious_files = []

    for location in ["/tmp", "/var/tmp", "/dev/shm"]:
        try:
            result = run_command_sudo(
                ["find", location, "-type", "f", "-mtime", "-7"],
                timeout=TIMEOUT_MEDIUM,
            )

            if result.returncode == 0:
                files = [f.strip() for f in result.stdout.split("\n") if f.strip()]
                suspicious_files.extend(files[:20])  # Limit per location

        except (Exception):
            continue

    return suspicious_files[:30]  # Global limit


def analyze_filesystem():
    """Analyze filesystem for security issues."""
    issues = []

    # Check world-writable files
    writable_files = _find_world_writable_files()
    writable_count = len(writable_files)

    if writable_count > 0:
        issues.append(
            {
                "severity": "high",
                "message": f"{writable_count} world-writable files found outside /tmp",
                "recommendation": "Review and restrict permissions: chmod o-w <file>",
            }
        )

    # Check SUID/SGID files
    suid_files = _find_suid_files()
    suspicious_suid = [f for f in suid_files if not f["whitelisted"]]
    suid_count = len(suspicious_suid)

    if suid_count > 0:
        issues.append(
            {
                "severity": "medium",
                "message": f"{suid_count} non-standard SUID/SGID binaries found",
                "recommendation": "Review SUID binaries for potential privilege escalation risks",
            }
        )

    # Check /tmp permissions
    tmp_check = _check_tmp_permissions()
    if tmp_check["checked"] and not tmp_check["secure"]:
        issues.append(
            {
                "severity": "medium",
                "message": f"/tmp has insecure permissions: {tmp_check['permissions']} (should be 1777)",
                "recommendation": "Fix /tmp permissions: chmod 1777 /tmp",
            }
        )

    # Check suspicious files
    suspicious = _check_suspicious_files()
    if len(suspicious) > 10:
        issues.append(
            {
                "severity": "low",
                "message": f"{len(suspicious)} recently modified files in /tmp, /var/tmp, /dev/shm",
                "recommendation": "Review temporary files for suspicious activity",
            }
        )

    return {
        "checked": True,
        "world_writable_files": writable_count,
        "world_writable_sample": writable_files[:10],
        "suid_sgid_total": len(suid_files),
        "suid_sgid_suspicious": suid_count,
        "suid_sgid_sample": suspicious_suid[:10],
        "tmp_permissions": tmp_check,
        "suspicious_tmp_files": len(suspicious),
        "issues": issues,
    }
