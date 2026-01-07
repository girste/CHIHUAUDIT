"""Helper functions for CIS Benchmark checks.

Reusable functions for common security checks across CIS controls.
"""

import os
import re
from ..utils.detect import run_with_sudo
from ..utils.command import run_command
from ..utils.logger import get_logger

logger = get_logger(__name__)


def check_package_installed(package_name):
    """Check if package is installed via dpkg/rpm/apk.

    Args:
        package_name: Name of package to check

    Returns:
        tuple: (bool, str) - (installed, detail_message)
    """
    # Try dpkg (Debian/Ubuntu)
    result = run_command(["dpkg", "-l", package_name], timeout=5)
    if result and result.success:
        # Check if actually installed (not removed)
        for line in result.stdout.split("\n"):
            if line.startswith("ii"):  # installed
                return True, f"Package {package_name} installed"
        return False, f"Package {package_name} not installed"

    # Try rpm (RHEL/CentOS/Fedora)
    result = run_command(["rpm", "-q", package_name], timeout=5)
    if result and result.success:
        return True, f"Package {package_name} installed"

    # Try apk (Alpine)
    result = run_command(["apk", "info", "-e", package_name], timeout=5)
    if result and result.success:
        return True, f"Package {package_name} installed"

    return False, "Cannot determine package status"


def check_service_enabled(service_name):
    """Check if systemd service is enabled.

    Args:
        service_name: Name of systemd service

    Returns:
        tuple: (bool, str) - (enabled, detail_message)
    """
    result = run_with_sudo(["systemctl", "is-enabled", service_name])

    if not result:
        return False, "Service not found"

    status = result.stdout.strip()
    if status == "enabled":
        return True, f"Service {status}"

    return False, f"Service {status} (should be enabled)"


def check_mount_option(mount_point, required_option):
    """Check if filesystem is mounted with specific option.

    Args:
        mount_point: Mount point path (e.g., /tmp, /var)
        required_option: Required mount option (e.g., noexec, nodev, nosuid)

    Returns:
        tuple: (bool, str) - (has_option, detail_message)
    """
    result = run_command(["mount"], timeout=5)
    if not result or not result.success:
        return False, "Cannot read mount info"

    # Parse mount output
    for line in result.stdout.split("\n"):
        if f" on {mount_point} " in line or line.startswith(f"{mount_point} "):
            # Extract options (between parentheses)
            match = re.search(r"\((.*?)\)", line)
            if match:
                options = match.group(1).split(",")
                if required_option in options:
                    return True, f"{mount_point} mounted with {required_option}"
                else:
                    return False, f"{mount_point} missing {required_option}"

    return False, f"{mount_point} not mounted"


def check_config_contains_line(file_path, pattern, regex=False):
    """Check if config file contains specific line or pattern.

    Args:
        file_path: Path to config file
        pattern: String or regex pattern to search
        regex: If True, use regex matching

    Returns:
        tuple: (bool, str) - (found, detail_message)
    """
    try:
        # Try reading with sudo if needed
        result = run_with_sudo(["cat", file_path], timeout=5)

        if not result:
            # Try without sudo
            if not os.path.exists(file_path):
                return False, f"File {file_path} not found"

            with open(file_path, "r") as f:
                content = f.read()
        else:
            content = result.stdout

        # Search for pattern
        for line in content.split("\n"):
            # Skip comments and empty lines
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if regex:
                if re.search(pattern, line):
                    return True, f"Found: {line[:60]}"
            else:
                if pattern in line:
                    return True, f"Found: {line[:60]}"

        return False, f"Pattern not found in {file_path}"

    except (OSError, PermissionError) as e:
        logger.debug(f"Error reading {file_path}: {e}")
        return False, f"Cannot read {file_path}"


def check_config_value(file_path, key, expected_value, separator="="):
    """Check if config file has key=value setting.

    Args:
        file_path: Path to config file
        key: Configuration key to check
        expected_value: Expected value
        separator: Separator between key and value (default: =)

    Returns:
        tuple: (bool, str) - (matches, detail_message)
    """
    try:
        # Try reading with sudo if needed
        result = run_with_sudo(["cat", file_path], timeout=5)

        if not result:
            if not os.path.exists(file_path):
                return False, f"File {file_path} not found"

            with open(file_path, "r") as f:
                content = f.read()
        else:
            content = result.stdout

        # Parse config file
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Check for key=value
            if separator in line:
                parts = line.split(separator, 1)
                if len(parts) == 2:
                    file_key = parts[0].strip()
                    file_value = parts[1].strip()

                    if file_key == key:
                        if file_value == str(expected_value):
                            return True, f"{key}={file_value}"
                        else:
                            return False, f"{key}={file_value} (expected {expected_value})"

        return False, f"{key} not found in {file_path}"

    except (OSError, PermissionError) as e:
        logger.debug(f"Error reading {file_path}: {e}")
        return False, f"Cannot read {file_path}"


def check_modprobe_disabled(module_name):
    """Check if kernel module is disabled via modprobe.

    Args:
        module_name: Kernel module name

    Returns:
        tuple: (bool, str) - (disabled, detail_message)
    """
    # First, check if module is actually loaded in memory
    result = run_command(["lsmod"], timeout=5)
    if result and result.success:
        # Check if module is in lsmod output
        for line in result.stdout.split("\n"):
            # lsmod output: "module_name size used_by"
            if line.split()[0:1] == [module_name]:
                # Module is loaded, must be explicitly disabled
                break
        else:
            # Module not loaded = secure by default
            return True, f"Module {module_name} not loaded"

    # Module is loaded or lsmod check failed, check blacklist
    modprobe_files = [
        f"/etc/modprobe.d/{module_name}.conf",
        "/etc/modprobe.d/blacklist.conf",
        "/etc/modprobe.d/CIS.conf",
    ]

    patterns = [
        f"install {module_name} /bin/true",
        f"install {module_name} /bin/false",
        f"blacklist {module_name}",
    ]

    for filepath in modprobe_files:
        if not os.path.exists(filepath):
            continue

        try:
            with open(filepath, "r") as f:
                content = f.read()

            for pattern in patterns:
                if pattern in content:
                    return True, f"Module {module_name} disabled in {filepath}"

        except (OSError, PermissionError):
            continue

    return False, f"Module {module_name} not disabled"


def check_cron_restriction(cron_file):
    """Check if cron access is restricted via cron.allow/cron.deny.

    Args:
        cron_file: Path to cron.allow or cron.deny

    Returns:
        tuple: (bool, str) - (configured, detail_message)
    """
    if os.path.exists(cron_file):
        # Check permissions
        try:
            stat_result = os.stat(cron_file)
            perms = oct(stat_result.st_mode)[-3:]

            if perms == "600":
                return True, f"{cron_file} exists with correct permissions"
            else:
                return False, f"{cron_file} has permissions {perms} (expected 600)"

        except OSError:
            return False, f"Cannot stat {cron_file}"
    else:
        return False, f"{cron_file} does not exist"


def check_pam_module_enabled(pam_file, module_name):
    """Check if PAM module is enabled in PAM config.

    Args:
        pam_file: Path to PAM config file (e.g., /etc/pam.d/common-password)
        module_name: PAM module to check (e.g., pam_pwquality.so)

    Returns:
        tuple: (bool, str) - (enabled, detail_message)
    """
    if not os.path.exists(pam_file):
        return False, f"PAM file {pam_file} not found"

    # Support both legacy and modern PAM modules
    module_variants = [module_name]
    if "tally" in module_name.lower():
        # pam_tally2.so (legacy) or pam_faillock.so (modern Ubuntu 24.04+)
        module_variants = ["pam_tally2.so", "pam_faillock.so"]

    try:
        with open(pam_file, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue

                # Check if any variant is present
                for variant in module_variants:
                    if variant in line and not line.startswith("#"):
                        return True, f"{variant} enabled"

        # Build error message
        if len(module_variants) > 1:
            return False, f"Neither {' nor '.join(module_variants)} found in {pam_file}"
        else:
            return False, f"{module_name} not found in {pam_file}"

    except (OSError, PermissionError) as e:
        logger.debug(f"Error reading {pam_file}: {e}")
        return False, f"Cannot read {pam_file}"


def check_directory_permissions(directory, expected_perms, owner="root", group="root"):
    """Check directory permissions and ownership.

    Args:
        directory: Path to directory
        expected_perms: Expected permissions (e.g., "755")
        owner: Expected owner (default: root)
        group: Expected group (default: root)

    Returns:
        tuple: (bool, str) - (correct, detail_message)
    """
    if not os.path.isdir(directory):
        return False, f"Directory {directory} not found"

    result = run_command(["stat", "-c", "%a %U %G", directory], timeout=5)
    if not result or not result.success:
        return False, f"Cannot stat {directory}"

    try:
        perms, dir_owner, dir_group = result.stdout.strip().split()

        if perms != expected_perms:
            return False, f"Permissions {perms} (expected {expected_perms})"
        if dir_owner != owner:
            return False, f"Owner {dir_owner} (expected {owner})"
        if dir_group != group:
            return False, f"Group {dir_group} (expected {group})"

        return True, "Pass"

    except ValueError as e:
        logger.debug(f"Error parsing stat output for {directory}: {e}")
        return False, f"Error checking {directory}"


def check_syslog_service():
    """Check if syslog service (rsyslog/syslog-ng) is running.

    Returns:
        tuple: (bool, str) - (running, detail_message)
    """
    syslog_services = ["rsyslog", "syslog-ng"]

    for service in syslog_services:
        result = run_with_sudo(["systemctl", "is-active", service])
        if result and result.stdout.strip() == "active":
            return True, f"{service} is active"

    return False, "No syslog service running"
