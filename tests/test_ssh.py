"""Test SSH analyzer."""

import tempfile
from pathlib import Path
from unittest.mock import patch
from mcp_security.analyzers.ssh import parse_sshd_config, analyze_ssh


def test_parse_sshd_config_secure():
    """Test parsing secure SSH configuration."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".conf") as f:
        f.write(
            """# SSH Configuration
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
"""
        )
        config_path = f.name

    try:
        result = parse_sshd_config(config_path)
        assert result["port"] == 2222
        assert result["permit_root_login"] == "no"
        assert result["password_auth"] == "no"
        assert result["pubkey_auth"] == "yes"
    finally:
        Path(config_path).unlink()


def test_parse_sshd_config_insecure():
    """Test parsing insecure SSH configuration."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".conf") as f:
        f.write(
            """Port 22
PermitRootLogin yes
PasswordAuthentication yes
"""
        )
        config_path = f.name

    try:
        result = parse_sshd_config(config_path)
        assert result["port"] == 22
        assert result["permit_root_login"] == "yes"
        assert result["password_auth"] == "yes"
    finally:
        Path(config_path).unlink()


def test_parse_sshd_config_with_comments():
    """Test parsing config with comments."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".conf") as f:
        f.write(
            """# This is a comment
Port 2244
# PermitRootLogin yes (commented out)
PermitRootLogin no
PasswordAuthentication no  # inline comment
"""
        )
        config_path = f.name

    try:
        result = parse_sshd_config(config_path)
        assert result["port"] == 2244
        assert result["permit_root_login"] == "no"
        assert result["password_auth"] == "no"
    finally:
        Path(config_path).unlink()


def test_parse_sshd_config_case_insensitive():
    """Test that parsing is case insensitive."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".conf") as f:
        f.write(
            """PORT 9999
PERMITROOTLOGIN NO
passwordauthentication NO
"""
        )
        config_path = f.name

    try:
        result = parse_sshd_config(config_path)
        assert result["port"] == 9999
        assert result["permit_root_login"] == "no"
        assert result["password_auth"] == "no"
    finally:
        Path(config_path).unlink()


def test_parse_sshd_config_defaults():
    """Test default values when config is empty."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".conf") as f:
        f.write("# Empty config\n")
        config_path = f.name

    try:
        result = parse_sshd_config(config_path)
        assert result["port"] == 22  # Default
        assert result["permit_root_login"] == "unknown"
        assert result["password_auth"] == "unknown"
        assert result["pubkey_auth"] == "unknown"
    finally:
        Path(config_path).unlink()


def test_parse_sshd_config_file_not_found():
    """Test behavior when config file doesn't exist."""
    result = parse_sshd_config("/nonexistent/path/sshd_config")
    assert result["port"] == 22
    assert result["permit_root_login"] == "unknown"


def test_analyze_ssh_with_mock_secure():
    """Test analyze_ssh with mocked secure configuration."""
    mock_config = {
        "port": 2222,
        "permit_root_login": "no",
        "password_auth": "no",
        "pubkey_auth": "yes",
    }

    with patch("mcp_security.analyzers.ssh.parse_sshd_config", return_value=mock_config):
        result = analyze_ssh()

    assert result["port"] == 2222
    assert result["permit_root_login"] == "no"
    assert len(result["issues"]) == 0


def test_analyze_ssh_with_mock_insecure():
    """Test analyze_ssh with mocked insecure configuration."""
    mock_config = {
        "port": 22,
        "permit_root_login": "yes",
        "password_auth": "yes",
        "pubkey_auth": "unknown",
    }

    with patch("mcp_security.analyzers.ssh.parse_sshd_config", return_value=mock_config):
        result = analyze_ssh()

    assert len(result["issues"]) > 0
    severities = [issue["severity"] for issue in result["issues"]]
    assert "high" in severities
