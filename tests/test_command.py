"""Test command execution utilities."""

import subprocess
from unittest.mock import Mock, patch
from mcp_security.utils.command import run_command_sudo, CommandResult


def test_run_command_sudo_permission_denied():
    """
    REGRESSION TEST for critical bug: run_command_sudo must try sudo
    when receiving permission denied errors.

    Bug: The condition `if result and result.stderr:` was evaluated as False
    when result.success=False (because __bool__ returns self.success),
    preventing the sudo fallback from executing.

    Fix: Changed to `if result is not None and result.stderr:` to properly
    check for result existence regardless of success status.
    """
    # Mock first attempt (without sudo) - permission denied
    mock_denied = Mock(spec=subprocess.CompletedProcess)
    mock_denied.returncode = 1
    mock_denied.stdout = ""
    mock_denied.stderr = "ERROR: You need to be root to run this script\n"

    # Mock second attempt (with sudo) - success
    mock_success = Mock(spec=subprocess.CompletedProcess)
    mock_success.returncode = 0
    mock_success.stdout = "Status: active\n"
    mock_success.stderr = ""

    with patch("mcp_security.utils.command.subprocess.run") as mock_run:
        # First call returns permission denied, second call succeeds
        mock_run.side_effect = [mock_denied, mock_success]

        result = run_command_sudo(["ufw", "status", "verbose"])

    # Verify it tried sudo fallback
    assert mock_run.call_count == 2

    # Verify first call was without sudo
    first_call = mock_run.call_args_list[0]
    assert first_call[0][0] == ["ufw", "status", "verbose"]

    # Verify second call was WITH sudo -n
    second_call = mock_run.call_args_list[1]
    assert second_call[0][0] == ["sudo", "-n", "ufw", "status", "verbose"]

    # Verify final result is the successful one
    assert result is not None
    assert result.success
    assert "Status: active" in result.stdout


def test_run_command_sudo_permission_denied_variant_message():
    """Test run_command_sudo with 'permission denied' variant."""
    mock_denied = Mock(spec=subprocess.CompletedProcess)
    mock_denied.returncode = 1
    mock_denied.stdout = ""
    mock_denied.stderr = "permission denied\n"

    mock_success = Mock(spec=subprocess.CompletedProcess)
    mock_success.returncode = 0
    mock_success.stdout = "success\n"
    mock_success.stderr = ""

    with patch("mcp_security.utils.command.subprocess.run") as mock_run:
        mock_run.side_effect = [mock_denied, mock_success]
        result = run_command_sudo(["test", "command"])

    # Should have tried sudo fallback
    assert mock_run.call_count == 2
    assert result.success


def test_run_command_sudo_you_must_be_root():
    """Test run_command_sudo with 'you must be root' variant."""
    mock_denied = Mock(spec=subprocess.CompletedProcess)
    mock_denied.returncode = 1
    mock_denied.stdout = ""
    mock_denied.stderr = "you must be root\n"

    mock_success = Mock(spec=subprocess.CompletedProcess)
    mock_success.returncode = 0
    mock_success.stdout = "success\n"
    mock_success.stderr = ""

    with patch("mcp_security.utils.command.subprocess.run") as mock_run:
        mock_run.side_effect = [mock_denied, mock_success]
        result = run_command_sudo(["test", "command"])

    # Should have tried sudo fallback
    assert mock_run.call_count == 2
    assert result.success


def test_run_command_sudo_success_without_sudo():
    """Test run_command_sudo when command succeeds without sudo."""
    mock_success = Mock(spec=subprocess.CompletedProcess)
    mock_success.returncode = 0
    mock_success.stdout = "success\n"
    mock_success.stderr = ""

    with patch("mcp_security.utils.command.subprocess.run", return_value=mock_success):
        result = run_command_sudo(["ls"])

    # Should NOT try sudo if command succeeds
    assert result.success
    assert "success" in result.stdout


def test_run_command_sudo_non_permission_error():
    """Test run_command_sudo with non-permission error (should not retry with sudo)."""
    mock_error = Mock(spec=subprocess.CompletedProcess)
    mock_error.returncode = 127
    mock_error.stdout = ""
    mock_error.stderr = "command not found\n"

    with patch("mcp_security.utils.command.subprocess.run", return_value=mock_error) as mock_run:
        result = run_command_sudo(["nonexistent"])

    # Should NOT try sudo for non-permission errors
    assert mock_run.call_count == 1
    assert not result.success


def test_command_result_bool_false_on_failure():
    """
    Test that CommandResult.__bool__ returns False when command fails.
    This is critical for the bug - we need to ensure result existence is
    checked with 'is not None' rather than truthy evaluation.
    """
    mock_process = Mock(spec=subprocess.CompletedProcess)
    mock_process.returncode = 1
    mock_process.stdout = ""
    mock_process.stderr = "error"

    result = CommandResult(mock_process)

    # Verify __bool__ returns False when command fails
    assert result.success is False
    assert bool(result) is False  # This is why 'if result and result.stderr' failed!

    # But result still exists and has stderr
    assert result is not None
    assert result.stderr == "error"
