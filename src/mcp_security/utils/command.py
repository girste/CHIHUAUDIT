"""Unified command execution utilities."""

import subprocess
from typing import Optional, List, Union
from ..constants import TIMEOUT_SHORT


class CommandResult:
    """Wrapper for subprocess results with convenience methods."""

    def __init__(self, process: subprocess.CompletedProcess):
        self._process = process

    @property
    def stdout(self) -> str:
        """Get stdout as string."""
        return self._process.stdout

    @property
    def stderr(self) -> str:
        """Get stderr as string."""
        return self._process.stderr

    @property
    def returncode(self) -> int:
        """Get return code."""
        return self._process.returncode

    @property
    def success(self) -> bool:
        """Check if command succeeded."""
        return self._process.returncode == 0

    def __bool__(self) -> bool:
        """Result is truthy if command succeeded."""
        return self.success


def run_command(
    cmd: Union[str, List[str]],
    timeout: int = TIMEOUT_SHORT,
    capture_stderr: bool = False,
    check: bool = False,
) -> Optional[CommandResult]:
    """
    Unified command execution with consistent error handling.

    Args:
        cmd: Command to run (string or list)
        timeout: Timeout in seconds
        capture_stderr: Whether to capture stderr (default: discard it)
        check: Whether to raise on non-zero exit

    Returns:
        CommandResult if successful, None if command not found or timeout

    Example:
        result = run_command(["ufw", "status"])
        if result and result.success:
            print(result.stdout)
    """
    # Ensure cmd is list
    if isinstance(cmd, str):
        cmd = cmd.split()

    try:
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE if capture_stderr else subprocess.DEVNULL,
            text=True,
            timeout=timeout,
            check=check,
        )
        return CommandResult(process)

    except FileNotFoundError:
        # Command not found
        return None

    except subprocess.TimeoutExpired:
        # Command timed out
        return None

    except subprocess.CalledProcessError as e:
        # Command failed and check=True
        if check:
            raise
        return CommandResult(e)


def run_command_sudo(
    cmd: Union[str, List[str]],
    timeout: int = TIMEOUT_SHORT,
    capture_stderr: bool = False,
) -> Optional[CommandResult]:
    """
    Run command with automatic sudo fallback.

    Tries command normally first, then with sudo -n if permission denied.

    Args:
        cmd: Command to run
        timeout: Timeout in seconds
        capture_stderr: Whether to capture stderr

    Returns:
        CommandResult if successful, None on failure
    """
    # Ensure cmd is list
    if isinstance(cmd, str):
        cmd = cmd.split()

    # If command is in /usr/sbin or /sbin, likely needs sudo - try directly
    if cmd and (cmd[0].startswith("/usr/sbin/") or cmd[0].startswith("/sbin/")):
        sudo_cmd = ["sudo", "-n"] + cmd
        result = run_command(sudo_cmd, timeout=timeout, capture_stderr=capture_stderr)
        if result and result.success:
            return result
        # If sudo fails, fall through to try without sudo

    # Try without sudo first
    result = run_command(cmd, timeout=timeout, capture_stderr=True)

    if result and result.success:
        return result

    # Check if error is permission-related
    if result is not None and result.stderr:
        stderr_lower = result.stderr.lower()
        permission_keywords = ["permission denied", "you must be root", "you need to be root"]

        if any(keyword in stderr_lower for keyword in permission_keywords):
            # Try with sudo
            sudo_cmd = ["sudo", "-n"] + cmd
            return run_command(sudo_cmd, timeout=timeout, capture_stderr=capture_stderr)

    # If we got here, command failed for other reasons
    return result


def command_exists(cmd: str) -> bool:
    """
    Check if command exists and is executable.

    Args:
        cmd: Command name to check

    Returns:
        True if command exists, False otherwise
    """
    result = run_command(["which", cmd], timeout=1)
    return result and result.success


def is_service_active(service: str) -> bool:
    """
    Check if systemd service is active.

    Args:
        service: Service name

    Returns:
        True if service is active, False otherwise
    """
    result = run_command(["systemctl", "is-active", service], timeout=5)
    return result and result.success
