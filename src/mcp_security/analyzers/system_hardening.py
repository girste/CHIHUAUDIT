"""System hardening checks.

Additional security hardening checks:
- Core dumps disabled
- Development tools in production
- Package repository integrity
- Time synchronization
"""

import os
import subprocess
from ..utils.detect import run_with_sudo
from ..utils.logger import get_logger

logger = get_logger(__name__)


def _check_core_dumps():
    """Check if core dumps are disabled."""
    issues = []

    # Check systemd-coredump
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "systemd-coredump.socket"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )

        if result.returncode == 0:
            status = result.stdout.strip()
            if status == "active":
                issues.append("systemd-coredump.socket is active")

    except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
        logger.debug(f"Error checking systemd-coredump: {e}")

    # Check sysctl fs.suid_dumpable
    try:
        result = subprocess.run(
            ["sysctl", "-n", "fs.suid_dumpable"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )

        if result.returncode == 0:
            value = result.stdout.strip()
            if value != "0":
                issues.append(f"fs.suid_dumpable = {value} (should be 0)")

    except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
        logger.debug(f"Error checking sysctl: {e}")

    # Check /proc/sys/kernel/core_pattern
    try:
        if os.path.exists("/proc/sys/kernel/core_pattern"):
            with open("/proc/sys/kernel/core_pattern", "r") as f:
                pattern = f.read().strip()
                # If core_pattern is not "|/bin/false" or empty, cores might be written
                if pattern and pattern != "|/bin/false":
                    issues.append(f"core_pattern = {pattern} (cores may be written)")

    except (OSError, PermissionError) as e:
        logger.debug(f"Cannot read core_pattern: {e}")

    # Check ulimit
    try:
        result = subprocess.run(
            ["sh", "-c", "ulimit -c"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )

        if result.returncode == 0:
            limit = result.stdout.strip()
            if limit != "0":
                issues.append(f"ulimit core size = {limit} (should be 0)")

    except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
        logger.debug(f"Error checking ulimit: {e}")

    return {
        "disabled": len(issues) == 0,
        "issues": issues,
    }


def _check_dev_tools():
    """Check if development tools are installed (red flag in production)."""
    dev_tools = [
        "gcc",
        "g++",
        "make",
        "cmake",
        "gdb",
        "strace",
        "ltrace",
    ]

    installed_tools = []

    for tool in dev_tools:
        try:
            result = subprocess.run(
                ["which", tool],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                path = result.stdout.strip()
                installed_tools.append({"tool": tool, "path": path})

        except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
            logger.debug(f"Error checking {tool}: {e}")
            continue

    return installed_tools


def _check_package_integrity():
    """Check package manager integrity and GPG verification."""
    result = {
        "apt_gpg_check": None,
        "yum_gpg_check": None,
        "issues": [],
    }

    # Check APT (Debian/Ubuntu)
    if os.path.exists("/etc/apt/apt.conf.d"):
        try:
            # Check if GPG check is enabled
            apt_result = run_with_sudo(
                ["apt-config", "dump"],
                timeout=10,
            )

            if apt_result:
                gpg_check_enabled = True
                for line in apt_result.stdout.split("\n"):
                    if "APT::Get::AllowUnauthenticated" in line:
                        if "true" in line.lower():
                            gpg_check_enabled = False
                            break

                result["apt_gpg_check"] = gpg_check_enabled

                if not gpg_check_enabled:
                    result["issues"].append("APT GPG verification disabled")

        except Exception as e:
            logger.debug(f"Error checking APT config: {e}")

    # Check YUM/DNF (RHEL/CentOS/Fedora)
    yum_conf = "/etc/yum.conf"
    if os.path.exists(yum_conf):
        try:
            with open(yum_conf, "r") as f:
                content = f.read()

                # Check gpgcheck setting
                if "gpgcheck=0" in content:
                    result["yum_gpg_check"] = False
                    result["issues"].append("YUM GPG verification disabled")
                else:
                    result["yum_gpg_check"] = True

        except (OSError, PermissionError) as e:
            logger.debug(f"Cannot read {yum_conf}: {e}")

    return result


def _check_time_sync():
    """Check if time synchronization is configured and working."""
    result = {
        "ntp_installed": False,
        "chrony_installed": False,
        "systemd_timesyncd": False,
        "sync_enabled": False,
        "issues": [],
    }

    # Check systemd-timesyncd (most common)
    try:
        status = subprocess.run(
            ["systemctl", "is-active", "systemd-timesyncd"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )

        if status.returncode == 0 and status.stdout.strip() == "active":
            result["systemd_timesyncd"] = True
            result["sync_enabled"] = True

    except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
        logger.debug(f"Error checking systemd-timesyncd: {e}")

    # Check chronyd
    try:
        status = subprocess.run(
            ["systemctl", "is-active", "chronyd"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )

        if status.returncode == 0 and status.stdout.strip() == "active":
            result["chrony_installed"] = True
            result["sync_enabled"] = True

    except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
        logger.debug(f"Error checking chronyd: {e}")

    # Check ntpd
    try:
        status = subprocess.run(
            ["systemctl", "is-active", "ntpd"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )

        if status.returncode == 0 and status.stdout.strip() == "active":
            result["ntp_installed"] = True
            result["sync_enabled"] = True

    except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
        logger.debug(f"Error checking ntpd: {e}")

    # Check timedatectl
    try:
        tc_result = subprocess.run(
            ["timedatectl", "show"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )

        if tc_result.returncode == 0:
            for line in tc_result.stdout.split("\n"):
                if "NTPSynchronized=yes" in line:
                    result["sync_enabled"] = True
                    break

    except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
        logger.debug(f"Error checking timedatectl: {e}")

    # Issues
    if not result["sync_enabled"]:
        result["issues"].append("Time synchronization not enabled")

    return result


def analyze_system_hardening():
    """Analyze system hardening configuration.

    Returns:
        dict: System hardening analysis results
    """
    result = {
        "checked": True,
        "core_dumps": {},
        "dev_tools_installed": [],
        "package_integrity": {},
        "time_sync": {},
        "issues": [],
    }

    # Check core dumps
    core_dumps = _check_core_dumps()
    result["core_dumps"] = core_dumps

    if not core_dumps["disabled"]:
        result["issues"].append(
            {
                "severity": "medium",
                "message": "Core dumps not fully disabled",
                "recommendation": f"Disable core dumps: {', '.join(core_dumps['issues'][:3])}",
            }
        )

    # Check dev tools
    dev_tools = _check_dev_tools()
    result["dev_tools_installed"] = dev_tools

    if dev_tools:
        tools_list = [t["tool"] for t in dev_tools]
        result["issues"].append(
            {
                "severity": "low",
                "message": f"{len(dev_tools)} development tools installed",
                "recommendation": f"Consider removing in production: {', '.join(tools_list[:5])}",
            }
        )

    # Check package integrity
    pkg_integrity = _check_package_integrity()
    result["package_integrity"] = pkg_integrity

    if pkg_integrity["issues"]:
        result["issues"].append(
            {
                "severity": "critical",
                "message": "Package integrity verification disabled",
                "recommendation": "; ".join(pkg_integrity["issues"]),
            }
        )

    # Check time sync
    time_sync = _check_time_sync()
    result["time_sync"] = time_sync

    if not time_sync["sync_enabled"]:
        result["issues"].append(
            {
                "severity": "medium",
                "message": "Time synchronization not configured",
                "recommendation": "Enable systemd-timesyncd or install chrony/ntp for accurate timekeeping",
            }
        )

    return result
