"""Rootkit and malware detection analyzer.

Checks for common rootkit indicators and suspicious system modifications.
Does not replace dedicated tools like rkhunter/chkrootkit but provides
basic compromise detection.
"""

import os
from pathlib import Path
from ..utils.detect import run_with_sudo
from ..utils.command import run_command_sudo
from ..utils.logger import get_logger

logger = get_logger(__name__)


def _check_rkhunter_installed():
    """Check if rkhunter is installed and available."""
    try:
        result = run_command_sudo(
            ["which", "rkhunter"],
            timeout=5,
        )
        return result.success if result else False
    except Exception:
        return False


def _check_chkrootkit_installed():
    """Check if chkrootkit is installed and available."""
    try:
        result = run_command_sudo(
            ["which", "chkrootkit"],
            timeout=5,
        )
        return result.success if result else False
    except Exception:
        return False


def _check_hidden_processes():
    """Check for hidden processes (basic detection)."""
    try:
        # Compare /proc PIDs with ps output
        proc_pids = set()
        for item in Path("/proc").iterdir():
            if item.is_dir() and item.name.isdigit():
                proc_pids.add(int(item.name))

        # Get PIDs from ps
        result = run_command_sudo(
            ["ps", "-eo", "pid"],
            timeout=10,
        )

        if not result or not result.success:
            return 0, []

        ps_pids = set()
        for line in result.stdout.strip().split("\n")[1:]:  # Skip header
            try:
                ps_pids.add(int(line.strip()))
            except ValueError:
                continue

        # Hidden processes = in /proc but not in ps
        hidden = proc_pids - ps_pids
        # Filter out kernel threads and very short-lived processes
        hidden = {pid for pid in hidden if pid > 1}

        # Filter out kernel threads by checking cmdline
        filtered_hidden = []
        for pid in hidden:
            cmdline_path = Path(f"/proc/{pid}/cmdline")
            try:
                if cmdline_path.exists():
                    cmdline = cmdline_path.read_text()
                    # Kernel threads have empty cmdline
                    if cmdline.strip():
                        # Not a kernel thread - potential hidden process
                        filtered_hidden.append(pid)
            except (OSError, PermissionError):
                # Can't read - might be suspicious, include it
                filtered_hidden.append(pid)

        return len(filtered_hidden), filtered_hidden[:10]  # Sample first 10

    except OSError as e:
        logger.debug(f"Error checking hidden processes: {e}")
        return 0, []


def _check_suspicious_files():
    """Check for suspicious files in common locations."""
    suspicious_locations = [
        "/tmp",
        "/var/tmp",
        "/dev/shm",
    ]

    suspicious_patterns = [
        ".ssh",  # SSH configs in /tmp
        "known_hosts",
        "authorized_keys",
        ".bash_history",
    ]

    findings = []

    for location in suspicious_locations:
        if not os.path.isdir(location):
            continue

        try:
            for root, dirs, files in os.walk(location):
                # Don't recurse too deep (performance)
                depth = root[len(location) :].count(os.sep)
                if depth > 2:
                    continue

                for file in files:
                    for pattern in suspicious_patterns:
                        if pattern in file.lower():
                            filepath = os.path.join(root, file)
                            findings.append(filepath)

                            # Limit findings
                            if len(findings) >= 20:
                                return findings

        except (OSError, PermissionError) as e:
            logger.debug(f"Error scanning {location}: {e}")
            continue

    return findings


def _check_ld_preload_hijacking():
    """Check for LD_PRELOAD hijacking attempts."""
    issues = []

    # Check /etc/ld.so.preload
    if os.path.exists("/etc/ld.so.preload"):
        try:
            with open("/etc/ld.so.preload", "r") as f:
                content = f.read().strip()
                if content:
                    issues.append(f"/etc/ld.so.preload contains: {content}")
        except (OSError, PermissionError) as e:
            logger.debug(f"Cannot read /etc/ld.so.preload: {e}")

    # Check environment variable (current process)
    if os.environ.get("LD_PRELOAD"):
        issues.append(f"LD_PRELOAD set: {os.environ.get('LD_PRELOAD')}")

    return issues


def _check_system_binaries_modified():
    """Check if critical system binaries have been modified recently."""
    critical_binaries = [
        "/bin/ps",
        "/bin/netstat",
        "/bin/ls",
        "/usr/bin/find",
        "/usr/bin/lsof",
        "/sbin/ifconfig",
        "/bin/login",
    ]

    modified = []

    for binary in critical_binaries:
        if not os.path.exists(binary):
            continue

        try:
            stat = os.stat(binary)
            # Check if modified in last 30 days (suspicious)
            import time

            age_days = (time.time() - stat.st_mtime) / 86400
            if age_days < 30:
                modified.append(
                    {
                        "binary": binary,
                        "days_ago": int(age_days),
                    }
                )
        except OSError as e:
            logger.debug(f"Cannot stat {binary}: {e}")
            continue

    return modified


def _run_rkhunter_check():
    """Run rkhunter if available (quick check only)."""
    if not _check_rkhunter_installed():
        return None

    try:
        result = run_with_sudo(
            ["rkhunter", "--check", "--sk", "--rwo"],  # Skip keypress, report warnings
            timeout=60,  # Quick check
        )

        if not result:
            return None

        output = result.stdout
        # Parse warnings
        warnings = []
        for line in output.split("\n"):
            if "Warning:" in line or "warning" in line.lower():
                warnings.append(line.strip())

        return {"warnings": warnings, "total": len(warnings)}

    except Exception as e:
        logger.warning(f"rkhunter check failed: {e}")
        return None


def analyze_rootkit():
    """Analyze system for rootkit indicators.

    Returns:
        dict: Rootkit analysis results
    """
    result = {
        "checked": True,
        "rkhunter_available": False,
        "chkrootkit_available": False,
        "hidden_processes": 0,
        "suspicious_files": [],
        "ld_preload_hijacking": [],
        "modified_binaries": [],
        "rkhunter_warnings": None,
        "issues": [],
    }

    # Check available tools
    result["rkhunter_available"] = _check_rkhunter_installed()
    result["chkrootkit_available"] = _check_chkrootkit_installed()

    # Hidden processes check
    hidden_count, hidden_pids = _check_hidden_processes()
    result["hidden_processes"] = hidden_count
    if hidden_count > 0:
        result["issues"].append(
            {
                "severity": "high",
                "message": f"Found {hidden_count} potentially hidden processes",
                "recommendation": f"Investigate PIDs: {hidden_pids}. May be rootkit or kernel threads.",
            }
        )

    # Suspicious files
    suspicious = _check_suspicious_files()
    result["suspicious_files"] = suspicious
    if suspicious:
        result["issues"].append(
            {
                "severity": "medium",
                "message": f"Found {len(suspicious)} suspicious files in /tmp or /dev/shm",
                "recommendation": f"Review files: {', '.join(suspicious[:5])}{'...' if len(suspicious) > 5 else ''}",
            }
        )

    # LD_PRELOAD hijacking
    ld_issues = _check_ld_preload_hijacking()
    result["ld_preload_hijacking"] = ld_issues
    if ld_issues:
        result["issues"].append(
            {
                "severity": "critical",
                "message": "LD_PRELOAD hijacking detected",
                "recommendation": f"Investigate immediately: {'; '.join(ld_issues)}",
            }
        )

    # Modified binaries
    modified = _check_system_binaries_modified()
    result["modified_binaries"] = modified
    if modified:
        binaries = [m["binary"] for m in modified]
        result["issues"].append(
            {
                "severity": "medium",
                "message": f"{len(modified)} critical system binaries modified recently",
                "recommendation": f"Verify integrity: {', '.join(binaries[:3])}",
            }
        )

    # Run rkhunter if available
    if result["rkhunter_available"]:
        rkhunter_result = _run_rkhunter_check()
        if rkhunter_result and rkhunter_result["total"] > 0:
            result["rkhunter_warnings"] = rkhunter_result
            result["issues"].append(
                {
                    "severity": "high",
                    "message": f"rkhunter found {rkhunter_result['total']} warnings",
                    "recommendation": "Run 'sudo rkhunter --check' for details",
                }
            )

    # Recommendations if no tools installed
    if not result["rkhunter_available"] and not result["chkrootkit_available"]:
        result["issues"].append(
            {
                "severity": "low",
                "message": "No rootkit detection tools installed",
                "recommendation": "Install rkhunter or chkrootkit for comprehensive scanning: apt install rkhunter",
            }
        )

    return result
