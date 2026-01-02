"""Test services analyzer."""

from unittest.mock import patch
from mcp_security.analyzers.services import analyze_services


def test_analyze_services_with_risky_exposed():
    """Test detection of exposed risky services."""
    with patch(
        "mcp_security.analyzers.services.parse_listening_ports",
        return_value=[
            {
                "port": 3306,
                "protocol": "tcp",
                "address": "0.0.0.0",
                "exposed": True,
                "process": "mysqld",
            },
            {
                "port": 5432,
                "protocol": "tcp",
                "address": "0.0.0.0",
                "exposed": True,
                "process": "postgres",
            },
        ],
    ):
        with patch("mcp_security.analyzers.services.check_systemd_failed", return_value=[]):
            with patch("mcp_security.analyzers.services.check_critical_services", return_value=[]):
                result = analyze_services()

    assert result["total_services"] == 2
    assert result["exposed_services"] == 2
    assert len(result["by_category"]["risky"]) == 2
    assert len(result["issues"]) >= 2
    assert any(issue["severity"] == "high" for issue in result["issues"])


def test_analyze_services_with_failed_systemd():
    """Test detection of failed systemd units."""
    with patch(
        "mcp_security.analyzers.services.parse_listening_ports",
        return_value=[
            {
                "port": 22,
                "protocol": "tcp",
                "address": "0.0.0.0",
                "exposed": True,
                "process": "sshd",
            },
        ],
    ):
        with patch(
            "mcp_security.analyzers.services.check_systemd_failed",
            return_value=[
                "nginx.service",
                "mysql.service",
            ],
        ):
            with patch("mcp_security.analyzers.services.check_critical_services", return_value=[]):
                result = analyze_services()

    assert result["systemd"]["failed_count"] == 2
    assert len(result["issues"]) >= 1
    assert any("systemd unit" in issue["message"] for issue in result["issues"])


def test_analyze_services_with_critical_down():
    """Test detection of failed critical services."""
    with patch("mcp_security.analyzers.services.parse_listening_ports", return_value=[]):
        with patch("mcp_security.analyzers.services.check_systemd_failed", return_value=[]):
            with patch(
                "mcp_security.analyzers.services.check_critical_services",
                return_value=[
                    {"name": "nginx", "status": "failed", "active": False},
                    {"name": "ssh", "status": "active", "active": True},
                ],
            ):
                result = analyze_services()

    assert result["systemd"]["critical_down"] == 1
    assert len(result["issues"]) >= 1
    assert any("Critical service" in issue["message"] for issue in result["issues"])


def test_analyze_services_many_unknown():
    """Test warning when many unknown services are exposed."""
    unknown_services = [
        {
            "port": 9000 + i,
            "protocol": "tcp",
            "address": "0.0.0.0",
            "exposed": True,
            "process": f"custom{i}",
        }
        for i in range(5)
    ]

    with patch(
        "mcp_security.analyzers.services.parse_listening_ports", return_value=unknown_services
    ):
        with patch("mcp_security.analyzers.services.check_systemd_failed", return_value=[]):
            with patch("mcp_security.analyzers.services.check_critical_services", return_value=[]):
                result = analyze_services()

    assert len(result["by_category"]["unknown"]) == 5
    assert len(result["issues"]) >= 1
    assert any("unknown services" in issue["message"] for issue in result["issues"])


def test_analyze_services_localhost_only():
    """Test services bound only to localhost."""
    with patch(
        "mcp_security.analyzers.services.parse_listening_ports",
        return_value=[
            {
                "port": 22,
                "protocol": "tcp",
                "address": "127.0.0.1",
                "exposed": False,
                "process": "sshd",
            },
            {
                "port": 80,
                "protocol": "tcp",
                "address": "127.0.0.1",
                "exposed": False,
                "process": "nginx",
            },
        ],
    ):
        with patch("mcp_security.analyzers.services.check_systemd_failed", return_value=[]):
            with patch("mcp_security.analyzers.services.check_critical_services", return_value=[]):
                result = analyze_services()

    assert result["total_services"] == 2
    assert result["exposed_services"] == 0
    assert result["internal_only"] == 2


def test_analyze_services_secure_config():
    """Test services with secure configuration."""
    with patch(
        "mcp_security.analyzers.services.parse_listening_ports",
        return_value=[
            {
                "port": 22,
                "protocol": "tcp",
                "address": "0.0.0.0",
                "exposed": True,
                "process": "sshd",
            },
            {
                "port": 443,
                "protocol": "tcp",
                "address": "0.0.0.0",
                "exposed": True,
                "process": "nginx",
            },
        ],
    ):
        with patch("mcp_security.analyzers.services.check_systemd_failed", return_value=[]):
            with patch(
                "mcp_security.analyzers.services.check_critical_services",
                return_value=[
                    {"name": "ssh", "status": "active", "active": True},
                    {"name": "nginx", "status": "active", "active": True},
                ],
            ):
                result = analyze_services()

    assert result["total_services"] == 2
    assert result["exposed_services"] == 2
    assert len(result["by_category"]["safe"]) == 2
    assert result["systemd"]["failed_count"] == 0
    assert result["systemd"]["critical_down"] == 0
