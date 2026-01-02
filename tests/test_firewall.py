"""Test firewall analyzer."""

from unittest.mock import Mock, patch
from mcp_security.analyzers.firewall import (
    analyze_ufw,
    analyze_iptables,
    analyze_firewalld,
    analyze_firewall,
)


def test_analyze_ufw_active():
    """Test UFW analyzer with active firewall."""
    mock_result = Mock()
    mock_result.stdout = """Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
"""
    mock_result.returncode = 0

    with patch("mcp_security.analyzers.firewall.run_with_sudo", return_value=mock_result):
        result = analyze_ufw()

    assert result is not None
    assert result["type"] == "ufw"
    assert result["active"] is True
    assert result["rules_count"] == 3
    assert 22 in result["open_ports"]
    assert 80 in result["open_ports"]
    assert 443 in result["open_ports"]


def test_analyze_ufw_inactive():
    """Test UFW with inactive status."""
    mock_result = Mock()
    mock_result.stdout = "Status: inactive\n"
    mock_result.returncode = 0

    with patch("mcp_security.analyzers.firewall.run_with_sudo", return_value=mock_result):
        result = analyze_ufw()

    assert result is not None
    assert result["active"] is False


def test_analyze_ufw_default_deny():
    """Test UFW with default deny policy."""
    mock_result = Mock()
    mock_result.stdout = """Status: active

Default: deny (incoming), allow (outgoing), deny (routed)
"""
    mock_result.returncode = 0

    with patch("mcp_security.analyzers.firewall.run_with_sudo", return_value=mock_result):
        result = analyze_ufw()

    assert result["default_policy"] == "deny"


def test_analyze_ufw_not_installed():
    """Test UFW when not installed."""
    with patch("mcp_security.analyzers.firewall.run_with_sudo", return_value=None):
        result = analyze_ufw()

    assert result is None


def test_analyze_iptables_active():
    """Test iptables with many rules."""
    mock_result = Mock()
    mock_result.stdout = """Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:http
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:https
DROP       all  --  anywhere             anywhere
DROP       all  --  anywhere             anywhere
DROP       all  --  anywhere             anywhere

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
"""
    mock_result.returncode = 0

    with patch("mcp_security.analyzers.firewall.run_with_sudo", return_value=mock_result):
        result = analyze_iptables()

    assert result is not None
    assert result["type"] == "iptables"
    assert result["active"] is True  # More than 5 rules
    assert result["rules_count"] > 5


def test_analyze_iptables_minimal():
    """Test iptables with minimal rules (inactive)."""
    mock_result = Mock()
    mock_result.stdout = """Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
"""
    mock_result.returncode = 0

    with patch("mcp_security.analyzers.firewall.run_with_sudo", return_value=mock_result):
        result = analyze_iptables()

    assert result is not None
    assert result["active"] is False  # Less than 5 rules


def test_analyze_firewalld_running():
    """Test firewalld when running."""
    mock_state = Mock()
    mock_state.stdout = "running"
    mock_state.returncode = 0

    mock_services = Mock()
    mock_services.stdout = "ssh http https"
    mock_services.returncode = 0

    with patch("mcp_security.analyzers.firewall.run_with_sudo") as mock_sudo:
        mock_sudo.side_effect = [mock_state, mock_services]
        result = analyze_firewalld()

    assert result is not None
    assert result["type"] == "firewalld"
    assert result["active"] is True
    assert result["rules_count"] == 3


def test_analyze_firewalld_not_running():
    """Test firewalld when not running."""
    mock_result = Mock()
    mock_result.stdout = "failed"
    mock_result.returncode = 0

    with patch("mcp_security.analyzers.firewall.run_with_sudo", return_value=mock_result):
        result = analyze_firewalld()

    assert result is None


def test_analyze_firewall_detects_ufw():
    """Test analyze_firewall auto-detects UFW."""
    mock_result = Mock()
    mock_result.stdout = "Status: active"
    mock_result.returncode = 0

    with patch("mcp_security.analyzers.firewall.run_with_sudo", return_value=mock_result):
        result = analyze_firewall()

    assert result["type"] == "ufw"


def test_analyze_firewall_no_firewall():
    """Test when no firewall is detected."""
    with patch("mcp_security.analyzers.firewall.run_with_sudo", return_value=None):
        result = analyze_firewall()

    assert result["type"] == "none"
    assert result["active"] is False
