"""Permission checking for sudo commands."""

import subprocess
from pathlib import Path


REQUIRED_SUDO_COMMANDS = [
    (["ufw", "status", "verbose"], "Firewall analysis (ufw)"),
    (["fail2ban-client", "status"], "Fail2ban status"),
    (["ss", "-tulpn"], "Network services analysis"),
    (["sysctl", "-n", "kernel.dmesg_restrict"], "Kernel hardening check"),
]


def check_sudo_permissions():
    """
    Check if required sudo commands work without password.
    Returns (ok: bool, missing: list[str])
    """
    missing = []

    for cmd, description in REQUIRED_SUDO_COMMANDS:
        try:
            result = subprocess.run(
                ["sudo", "-n"] + cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            if result.returncode != 0:
                missing.append(description)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            missing.append(description)

    return len(missing) == 0, missing


def get_setup_hint():
    """Get setup instructions for missing sudo permissions."""
    setup_script = Path(__file__).parent.parent.parent.parent / "setup-sudo.sh"

    if setup_script.exists():
        return f"Run: bash {setup_script}"

    return "Configure passwordless sudo for security audit commands in /etc/sudoers.d/"


def check_and_warn():
    """
    Check permissions and print warning if needed.
    Returns True if all permissions OK, False otherwise.
    """
    ok, missing = check_sudo_permissions()

    if not ok:
        print("⚠️  Warning: Some security checks require sudo permissions")
        print("\nMissing permissions for:")
        for item in missing:
            print(f"  - {item}")
        print(f"\n{get_setup_hint()}")
        print("\nContinuing with limited analysis...\n")
        return False

    return True
