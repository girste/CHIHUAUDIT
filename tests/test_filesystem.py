"""Test filesystem analyzer."""

from unittest.mock import patch
from mcp_security.analyzers.filesystem import analyze_filesystem


def test_analyze_filesystem_secure():
    """Test filesystem analysis with secure configuration."""
    with patch("mcp_security.analyzers.filesystem._find_world_writable_files", return_value=[]):
        with patch(
            "mcp_security.analyzers.filesystem._find_suid_files",
            return_value=[
                {"path": "/usr/bin/sudo", "whitelisted": True},
                {"path": "/usr/bin/passwd", "whitelisted": True},
            ],
        ):
            with patch(
                "mcp_security.analyzers.filesystem._check_tmp_permissions",
                return_value={
                    "checked": True,
                    "permissions": "1777",
                    "secure": True,
                },
            ):
                with patch(
                    "mcp_security.analyzers.filesystem._check_suspicious_files", return_value=[]
                ):
                    result = analyze_filesystem()

    assert result["checked"] is True
    assert result["world_writable_files"] == 0
    assert result["suid_sgid_suspicious"] == 0
    assert len(result["issues"]) == 0


def test_analyze_filesystem_with_world_writable():
    """Test detection of world-writable files."""
    with patch(
        "mcp_security.analyzers.filesystem._find_world_writable_files",
        return_value=[
            "/home/user/bad1.txt",
            "/var/www/bad2.php",
        ],
    ):
        with patch("mcp_security.analyzers.filesystem._find_suid_files", return_value=[]):
            with patch(
                "mcp_security.analyzers.filesystem._check_tmp_permissions",
                return_value={
                    "checked": True,
                    "permissions": "1777",
                    "secure": True,
                },
            ):
                with patch(
                    "mcp_security.analyzers.filesystem._check_suspicious_files", return_value=[]
                ):
                    result = analyze_filesystem()

    assert result["world_writable_files"] == 2
    assert len(result["issues"]) >= 1
    assert any("world-writable" in issue["message"] for issue in result["issues"])


def test_analyze_filesystem_with_suspicious_suid():
    """Test detection of suspicious SUID binaries."""
    with patch("mcp_security.analyzers.filesystem._find_world_writable_files", return_value=[]):
        with patch(
            "mcp_security.analyzers.filesystem._find_suid_files",
            return_value=[
                {"path": "/usr/bin/sudo", "whitelisted": True},
                {"path": "/usr/local/bin/suspicious1", "whitelisted": False},
                {"path": "/opt/app/suspicious2", "whitelisted": False},
            ],
        ):
            with patch(
                "mcp_security.analyzers.filesystem._check_tmp_permissions",
                return_value={
                    "checked": True,
                    "permissions": "1777",
                    "secure": True,
                },
            ):
                with patch(
                    "mcp_security.analyzers.filesystem._check_suspicious_files", return_value=[]
                ):
                    result = analyze_filesystem()

    assert result["suid_sgid_total"] == 3
    assert result["suid_sgid_suspicious"] == 2
    assert len(result["issues"]) >= 1
    assert any("SUID/SGID" in issue["message"] for issue in result["issues"])


def test_analyze_filesystem_insecure_tmp():
    """Test detection of insecure /tmp permissions."""
    with patch("mcp_security.analyzers.filesystem._find_world_writable_files", return_value=[]):
        with patch("mcp_security.analyzers.filesystem._find_suid_files", return_value=[]):
            with patch(
                "mcp_security.analyzers.filesystem._check_tmp_permissions",
                return_value={
                    "checked": True,
                    "permissions": "0777",
                    "secure": False,
                },
            ):
                with patch(
                    "mcp_security.analyzers.filesystem._check_suspicious_files", return_value=[]
                ):
                    result = analyze_filesystem()

    assert result["tmp_permissions"]["secure"] is False
    assert len(result["issues"]) >= 1
    assert any("/tmp" in issue["message"] for issue in result["issues"])


def test_analyze_filesystem_many_suspicious_files():
    """Test detection of many suspicious temporary files."""
    suspicious_files = [f"/tmp/file{i}.tmp" for i in range(15)]

    with patch("mcp_security.analyzers.filesystem._find_world_writable_files", return_value=[]):
        with patch("mcp_security.analyzers.filesystem._find_suid_files", return_value=[]):
            with patch(
                "mcp_security.analyzers.filesystem._check_tmp_permissions",
                return_value={
                    "checked": True,
                    "permissions": "1777",
                    "secure": True,
                },
            ):
                with patch(
                    "mcp_security.analyzers.filesystem._check_suspicious_files",
                    return_value=suspicious_files,
                ):
                    result = analyze_filesystem()

    assert result["suspicious_tmp_files"] == 15
    assert len(result["issues"]) >= 1
    assert any("recently modified files" in issue["message"] for issue in result["issues"])


def test_analyze_filesystem_all_issues():
    """Test filesystem with multiple security issues."""
    with patch(
        "mcp_security.analyzers.filesystem._find_world_writable_files",
        return_value=[
            "/home/user/bad.txt",
        ],
    ):
        with patch(
            "mcp_security.analyzers.filesystem._find_suid_files",
            return_value=[
                {"path": "/suspicious/binary", "whitelisted": False},
            ],
        ):
            with patch(
                "mcp_security.analyzers.filesystem._check_tmp_permissions",
                return_value={
                    "checked": True,
                    "permissions": "0777",
                    "secure": False,
                },
            ):
                with patch(
                    "mcp_security.analyzers.filesystem._check_suspicious_files",
                    return_value=[f"/tmp/file{i}" for i in range(15)],
                ):
                    result = analyze_filesystem()

    assert result["world_writable_files"] > 0
    assert result["suid_sgid_suspicious"] > 0
    assert result["tmp_permissions"]["secure"] is False
    assert result["suspicious_tmp_files"] > 10
    assert len(result["issues"]) >= 3
