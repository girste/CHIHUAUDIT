"""User and group security audit analyzer.

Audits system users, groups, password policies, and identifies
potential security issues like users with UID 0, no password, etc.
"""

import subprocess
from typing import List, Dict

SYSTEM_UID_MAX = 999

VALID_SHELLS = {
    "/bin/bash",
    "/bin/sh",
    "/bin/dash",
    "/bin/zsh",
    "/usr/bin/fish",
}

NOLOGIN_SHELLS = {
    "/usr/sbin/nologin",
    "/bin/false",
    "/sbin/nologin",
}

PRIVILEGED_GROUPS = {"root", "sudo", "wheel", "admin", "docker", "adm"}


def _parse_passwd_file() -> List[Dict]:
    """Parse /etc/passwd for user information."""
    try:
        result = subprocess.run(
            ["getent", "passwd"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )

        if result.returncode != 0:
            return []

        users = []
        for line in result.stdout.split("\n"):
            if not line.strip():
                continue

            parts = line.split(":")
            if len(parts) < 7:
                continue

            username = parts[0]
            uid = int(parts[2]) if parts[2].isdigit() else -1
            gid = int(parts[3]) if parts[3].isdigit() else -1
            home = parts[5]
            shell = parts[6]

            users.append(
                {
                    "username": username,
                    "uid": uid,
                    "gid": gid,
                    "home": home,
                    "shell": shell,
                }
            )

        return users

    except (subprocess.SubprocessError, subprocess.TimeoutExpired, ValueError):
        return []


def _check_shadow_file() -> Dict[str, bool]:
    """Check for users without passwords or with weak password hashes."""
    try:
        result = subprocess.run(
            ["sudo", "-n", "getent", "shadow"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )

        if result.returncode != 0:
            return {}

        users_without_password = {}
        for line in result.stdout.split("\n"):
            if not line.strip():
                continue

            parts = line.split(":")
            if len(parts) < 2:
                continue

            username = parts[0]
            password_hash = parts[1]

            # Empty password or disabled account
            if password_hash in ["", "!", "*", "!!"]:
                users_without_password[username] = True

        return users_without_password

    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        return {}


def _get_group_members() -> Dict[str, List[str]]:
    """Get members of privileged groups."""
    try:
        result = subprocess.run(
            ["getent", "group"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )

        if result.returncode != 0:
            return {}

        privileged_members = {}
        for line in result.stdout.split("\n"):
            if not line.strip():
                continue

            parts = line.split(":")
            if len(parts) < 4:
                continue

            group_name = parts[0]
            members = parts[3].split(",") if parts[3] else []

            if group_name in PRIVILEGED_GROUPS and members:
                privileged_members[group_name] = [m for m in members if m]

        return privileged_members

    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        return {}


def _find_uid_zero_users(users: List[Dict]) -> List[str]:
    """Find users with UID 0 (root privileges)."""
    return [u["username"] for u in users if u["uid"] == 0 and u["username"] != "root"]


def _find_users_with_login_shell(users: List[Dict]) -> List[Dict]:
    """Find non-system users with interactive shells."""
    interactive_users = []

    for user in users:
        if user["uid"] >= SYSTEM_UID_MAX and user["shell"] in VALID_SHELLS:
            interactive_users.append(
                {
                    "username": user["username"],
                    "uid": user["uid"],
                    "shell": user["shell"],
                }
            )

    return interactive_users


def _find_suspicious_shells(users: List[Dict]) -> List[Dict]:
    """Find users with unusual or suspicious shells."""
    suspicious = []

    for user in users:
        shell = user["shell"]
        if shell and shell not in VALID_SHELLS and shell not in NOLOGIN_SHELLS:
            suspicious.append(
                {
                    "username": user["username"],
                    "uid": user["uid"],
                    "shell": shell,
                }
            )

    return suspicious


def analyze_users():
    """Audit system users and groups for security issues."""
    users = _parse_passwd_file()

    if not users:
        return {
            "checked": False,
            "message": "Unable to retrieve user information",
            "issues": [],
        }

    # Run checks
    uid_zero_users = _find_uid_zero_users(users)
    interactive_users = _find_users_with_login_shell(users)
    suspicious_shells = _find_suspicious_shells(users)
    users_without_password = _check_shadow_file()
    privileged_groups = _get_group_members()

    # Count totals
    total_users = len(users)
    system_users = len([u for u in users if u["uid"] < SYSTEM_UID_MAX])
    human_users = len([u for u in users if u["uid"] >= SYSTEM_UID_MAX])

    # Generate issues
    issues = []

    if uid_zero_users:
        issues.append(
            {
                "severity": "critical",
                "message": f"{len(uid_zero_users)} non-root users with UID 0: {', '.join(uid_zero_users)}",
                "recommendation": "Remove or change UID of unauthorized root-equivalent accounts",
            }
        )

    # Check for human users with interactive shells but no password
    for user_info in interactive_users:
        username = user_info["username"]
        if username in users_without_password:
            issues.append(
                {
                    "severity": "high",
                    "message": f"User '{username}' has interactive shell but no password set",
                    "recommendation": f"Set a password for '{username}' or disable the account",
                }
            )

    if suspicious_shells:
        shell_list = [f"{u['username']} ({u['shell']})" for u in suspicious_shells[:5]]
        issues.append(
            {
                "severity": "medium",
                "message": f"{len(suspicious_shells)} users with unusual shells",
                "recommendation": f"Review suspicious shells: {', '.join(shell_list)}",
            }
        )

    # Check privileged group membership
    total_privileged = sum(len(members) for members in privileged_groups.values())
    if total_privileged > 10:
        issues.append(
            {
                "severity": "low",
                "message": f"{total_privileged} users in privileged groups (sudo, docker, etc.)",
                "recommendation": "Review privileged group membership and remove unnecessary access",
            }
        )

    return {
        "checked": True,
        "total_users": total_users,
        "system_users": system_users,
        "human_users": human_users,
        "interactive_users": len(interactive_users),
        "uid_zero_users": len(uid_zero_users),
        "uid_zero_list": uid_zero_users,
        "users_without_password": len(users_without_password),
        "suspicious_shells": len(suspicious_shells),
        "privileged_groups": privileged_groups,
        "total_privileged_users": total_privileged,
        "issues": issues,
    }
