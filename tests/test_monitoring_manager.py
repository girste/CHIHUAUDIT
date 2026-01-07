"""Tests for monitoring manager."""

import json
import tempfile
from pathlib import Path

import pytest

from mcp_security.monitoring.manager import MonitoringManager


@pytest.fixture
def temp_log_dir():
    """Create temporary log directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


def test_manager_initialization(temp_log_dir):
    """Test manager initialization."""
    mgr = MonitoringManager(str(temp_log_dir))
    assert mgr.log_dir == temp_log_dir
    assert mgr.pid_file == temp_log_dir / "monitoring.pid"


def test_is_running_no_pid_file(temp_log_dir):
    """Test is_running when no PID file exists."""
    mgr = MonitoringManager(str(temp_log_dir))
    assert mgr.is_running() is False


def test_is_running_invalid_pid(temp_log_dir):
    """Test is_running with invalid PID."""
    mgr = MonitoringManager(str(temp_log_dir))
    temp_log_dir.mkdir(parents=True, exist_ok=True)
    (temp_log_dir / "monitoring.pid").write_text("99999999")

    assert mgr.is_running() is False
    assert not (temp_log_dir / "monitoring.pid").exists()


def test_get_status_no_daemon(temp_log_dir):
    """Test status when daemon is not running."""
    mgr = MonitoringManager(str(temp_log_dir))
    status = mgr.get_status()

    assert status["running"] is False
    assert status["pid"] is None
    assert status["bulletin_count"] == 0
    assert status["anomaly_count"] == 0


def test_get_status_with_bulletins(temp_log_dir):
    """Test status with existing bulletins."""
    temp_log_dir.mkdir(parents=True, exist_ok=True)
    mgr = MonitoringManager(str(temp_log_dir))

    # Create fake bulletins
    (temp_log_dir / "bulletin_20260107_120000.txt").write_text("Bulletin 1")
    (temp_log_dir / "bulletin_20260107_130000.txt").write_text("Bulletin 2")

    # Create fake anomaly
    (temp_log_dir / "anomaly_20260107_120000.json").write_text(
        json.dumps({"anomalies": [{"type": "test"}]})
    )

    status = mgr.get_status()

    assert status["bulletin_count"] == 2
    assert status["anomaly_count"] == 1
    assert status["total_disk_usage_kb"] >= 0


def test_stop_not_running(temp_log_dir):
    """Test stopping when not running."""
    mgr = MonitoringManager(str(temp_log_dir))
    result = mgr.stop()

    assert result["success"] is False
    assert "error" in result


def test_cleanup_no_logs(temp_log_dir):
    """Test cleanup with no logs."""
    mgr = MonitoringManager(str(temp_log_dir))
    result = mgr.cleanup_old_logs()

    assert result["bulletins_removed"] == 0
    assert result["anomalies_removed"] == 0


def test_cleanup_old_logs(temp_log_dir):
    """Test cleanup of old logs."""
    temp_log_dir.mkdir(parents=True, exist_ok=True)
    mgr = MonitoringManager(str(temp_log_dir))

    # Create many bulletins (more than limit)
    import time

    for i in range(60):
        bulletin = temp_log_dir / f"bulletin_{i:05d}.txt"
        bulletin.write_text(f"Bulletin {i}")
        # Small delay to ensure different mtimes
        time.sleep(0.001)

    # Create many anomalies
    for i in range(30):
        anomaly = temp_log_dir / f"anomaly_{i:05d}.json"
        anomaly.write_text(json.dumps({"anomalies": []}))
        time.sleep(0.001)

    result = mgr.cleanup_old_logs(max_bulletins=50, max_anomalies=20)

    # Should keep only most recent 50 bulletins and 20 anomalies
    assert result["bulletins_removed"] == 10
    assert result["anomalies_removed"] == 10
    assert result["bulletins_remaining"] == 50
    assert result["anomalies_remaining"] == 20

    # Verify files were actually deleted
    remaining_bulletins = list(temp_log_dir.glob("bulletin_*.txt"))
    remaining_anomalies = list(temp_log_dir.glob("anomaly_*.json"))
    assert len(remaining_bulletins) == 50
    assert len(remaining_anomalies) == 20
