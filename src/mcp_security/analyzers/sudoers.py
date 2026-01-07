"""Sudo configuration security analyzer.

Audits /etc/sudoers and /etc/sudoers.d/ for security issues:
- NOPASSWD usage
- Dangerous wildcards
- Command aliases with shell access
- Excessive privileges
"""

import re
from pathlib import Path
from ..utils.detect import run_with_sudo
from ..utils.command import run_command_sudo
from ..utils.logger import get_logger

logger = get_logger(__name__)


def _parse_sudoers_files():
    """Parse sudoers configuration files."""
    sudoers_files = ["/etc/sudoers"]
    sudoers_d = Path("/etc/sudoers.d")

    if sudoers_d.exists():
        try:
            for file in sudoers_d.iterdir():
                if file.is_file() and not file.name.startswith("."):
                    sudoers_files.append(str(file))
        except (OSError, PermissionError) as e:
            logger.debug(f"Cannot list /etc/sudoers.d/: {e}")

    entries = []

    for filepath in sudoers_files:
        try:
            result = run_with_sudo(["cat", filepath], timeout=5)
            if not result:
                logger.debug(f"Cannot read {filepath}")
                continue

            for line_num, line in enumerate(result.stdout.split("\n"), 1):
                # Skip comments and empty lines
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Parse sudoers entry
                # Format: user HOST=(RUNAS) TAGS: commands
                if re.search(r"\bALL\b|\bNOPASSWD\b|%", line):
                    entries.append(
                        {
                            "file": filepath,
                            "line": line_num,
                            "content": line,
                        }
                    )

        except Exception as e:
            logger.warning(f"Error parsing {filepath}: {e}")
            continue

    return entries


def _check_nopasswd_usage(entries):
    """Check for NOPASSWD entries."""
    nopasswd_entries = []

    for entry in entries:
        if "NOPASSWD" in entry["content"]:
            # Extract user/group
            match = re.match(r"^([%\w]+)\s+", entry["content"])
            user = match.group(1) if match else "unknown"

            nopasswd_entries.append(
                {
                    "user": user,
                    "file": entry["file"],
                    "line": entry["line"],
                    "config": entry["content"],
                }
            )

    return nopasswd_entries


def _check_dangerous_wildcards(entries):
    """Check for dangerous wildcard usage in commands."""
    # Standard system users and groups that are expected to have full access
    EXPECTED_FULL_ACCESS = {"root", "%admin", "%sudo", "%wheel"}

    dangerous_patterns = [
        (r"\bALL\s*=.*\bALL\b", "Full root access (user ALL=(ALL) ALL)"),
        (r"/bin/\*", "Wildcard in /bin/* allows arbitrary commands"),
        (r"/usr/bin/\*", "Wildcard in /usr/bin/* allows arbitrary commands"),
        (r"\*/bash", "Wildcard allows shell access"),
        (r"\*/sh", "Wildcard allows shell access"),
        (r"sudoedit\s+/\*", "Wildcard with sudoedit allows file manipulation"),
    ]

    findings = []

    for entry in entries:
        content = entry["content"]

        for pattern, description in dangerous_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                match = re.match(r"^([%\w]+)\s+", content)
                user = match.group(1) if match else "unknown"

                # Skip if this is an expected full access entry for system accounts
                if description == "Full root access (user ALL=(ALL) ALL)" and user in EXPECTED_FULL_ACCESS:
                    continue

                findings.append(
                    {
                        "user": user,
                        "file": entry["file"],
                        "line": entry["line"],
                        "issue": description,
                        "config": content,
                    }
                )
                break  # One issue per entry

    return findings


def _check_shell_access(entries):
    """Check for sudo rules granting shell access."""
    shell_commands = [
        "/bin/bash",
        "/bin/sh",
        "/bin/zsh",
        "/bin/fish",
        "/usr/bin/bash",
        "/usr/bin/sh",
        "bash",
        "sh",
        "zsh",
    ]

    findings = []

    for entry in entries:
        content = entry["content"]

        for shell in shell_commands:
            if shell in content.lower():
                match = re.match(r"^([%\w]+)\s+", content)
                user = match.group(1) if match else "unknown"

                findings.append(
                    {
                        "user": user,
                        "file": entry["file"],
                        "line": entry["line"],
                        "shell": shell,
                        "config": content,
                    }
                )
                break

    return findings


def _get_sudo_users():
    """Get list of users with sudo privileges."""
    sudo_users = []

    # Users in sudo group
    try:
        result = run_command_sudo(
            ["getent", "group", "sudo"],
            timeout=5,
        )

        if result.returncode == 0:
            # Format: sudo:x:27:user1,user2
            parts = result.stdout.strip().split(":")
            if len(parts) >= 4 and parts[3]:
                sudo_users.extend(parts[3].split(","))

    except Exception as e:
        logger.debug(f"Error getting sudo group: {e}")

    # Users in wheel group (RHEL/CentOS)
    try:
        result = run_command_sudo(
            ["getent", "group", "wheel"],
            timeout=5,
        )

        if result.returncode == 0:
            parts = result.stdout.strip().split(":")
            if len(parts) >= 4 and parts[3]:
                for user in parts[3].split(","):
                    if user not in sudo_users:
                        sudo_users.append(user)

    except Exception as e:
        logger.debug(f"Error getting wheel group: {e}")

    return sudo_users


def analyze_sudoers():
    """Analyze sudo configuration for security issues.

    Returns:
        dict: Sudo security analysis results
    """
    result = {
        "checked": True,
        "sudoers_files_parsed": 0,
        "sudo_users": [],
        "nopasswd_entries": [],
        "dangerous_wildcards": [],
        "shell_access_granted": [],
        "total_issues": 0,
        "issues": [],
    }

    # Parse sudoers files
    entries = _parse_sudoers_files()
    result["sudoers_files_parsed"] = len(set(e["file"] for e in entries))

    if result["sudoers_files_parsed"] == 0:
        result["issues"].append(
            {
                "severity": "info",
                "message": "Sudoers audit requires sudo access",
                "recommendation": "Run ./setup-sudo.sh to enable complete sudoers analysis",
            }
        )
        return result

    # Get sudo users
    sudo_users = _get_sudo_users()
    result["sudo_users"] = sudo_users

    # Check NOPASSWD usage
    nopasswd = _check_nopasswd_usage(entries)
    result["nopasswd_entries"] = nopasswd
    if nopasswd:
        users = [e["user"] for e in nopasswd]
        result["issues"].append(
            {
                "severity": "high",
                "message": f"{len(nopasswd)} NOPASSWD sudo entries found",
                "recommendation": f"Review NOPASSWD usage for: {', '.join(users[:5])}. Require password for sudo.",
            }
        )

    # Check dangerous wildcards
    wildcards = _check_dangerous_wildcards(entries)
    result["dangerous_wildcards"] = wildcards
    if wildcards:
        result["issues"].append(
            {
                "severity": "critical",
                "message": f"{len(wildcards)} dangerous wildcard patterns in sudo config",
                "recommendation": "Remove wildcards from sudo rules. Specify exact commands instead.",
            }
        )

    # Check shell access
    shells = _check_shell_access(entries)
    result["shell_access_granted"] = shells
    if shells:
        users = [e["user"] for e in shells]
        result["issues"].append(
            {
                "severity": "high",
                "message": f"{len(shells)} sudo rules grant shell access",
                "recommendation": f"Review shell access for: {', '.join(set(users)[:5])}. Avoid granting sudo shell access.",
            }
        )

    # Excessive sudo users
    if len(sudo_users) > 5:
        result["issues"].append(
            {
                "severity": "medium",
                "message": f"{len(sudo_users)} users have sudo privileges",
                "recommendation": "Review sudo group membership. Follow principle of least privilege.",
            }
        )

    result["total_issues"] = len(nopasswd) + len(wildcards) + len(shells)

    return result
