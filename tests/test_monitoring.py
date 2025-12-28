"""Test monitoring functionality."""

import tempfile
from pathlib import Path

from mcp_security.monitoring.baseline import BaselineManager
from mcp_security.monitoring.anomaly import AnomalyDetector
from mcp_security.monitoring.bulletin import BulletinGenerator
from mcp_security.monitoring.daemon import SecurityMonitor


def test_baseline_save_and_load():
    """Test baseline creation and loading."""
    with tempfile.TemporaryDirectory() as tmpdir:
        baseline_path = Path(tmpdir) / "baseline.json"
        mgr = BaselineManager(str(baseline_path))

        # Mock report
        mock_report = {
            "firewall": {"active": True, "rules_count": 5, "open_ports": [22, 80, 443]},
            "ssh": {"port": 22, "permit_root_login": "no", "password_auth": "no"},
        }

        # Save baseline
        assert mgr.save(mock_report)
        assert baseline_path.exists()

        # Load baseline
        loaded = mgr.load()
        assert loaded is not None
        assert "snapshot" in loaded
        assert "timestamp" in loaded


def test_anomaly_detection_firewall_disabled():
    """Test detection of firewall being disabled."""
    detector = AnomalyDetector()

    baseline = {"firewall": {"active": True, "rules_count": 5, "open_ports": [22, 80]}}

    current = {"firewall": {"active": False, "rules_count": 0, "open_ports": []}}

    anomalies = detector.detect(baseline, current)

    assert len(anomalies) > 0
    assert any(a["category"] == "firewall" for a in anomalies)
    assert any(a["severity"] == "critical" for a in anomalies)


def test_anomaly_detection_new_port():
    """Test detection of new open port."""
    detector = AnomalyDetector()

    baseline = {"firewall": {"active": True, "rules_count": 2, "open_ports": [22, 80]}}

    current = {"firewall": {"active": True, "rules_count": 3, "open_ports": [22, 80, 3306]}}

    anomalies = detector.detect(baseline, current)

    assert len(anomalies) > 0
    port_anomaly = [a for a in anomalies if "3306" in str(a["message"])]
    assert len(port_anomaly) > 0


def test_anomaly_detection_ssh_root_enabled():
    """Test detection of SSH root login being enabled."""
    detector = AnomalyDetector()

    baseline = {"ssh": {"port": 22, "permit_root_login": "no", "password_auth": "no"}}

    current = {"ssh": {"port": 22, "permit_root_login": "yes", "password_auth": "no"}}

    anomalies = detector.detect(baseline, current)

    assert len(anomalies) > 0
    assert any(a["severity"] == "critical" for a in anomalies)


def test_bulletin_generation():
    """Test bulletin generation."""
    gen = BulletinGenerator()

    mock_report = {
        "analysis": {
            "overall_status": "GOOD",
            "score": {
                "critical_issues": 0,
                "high_priority_issues": 0,
                "good_practices_followed": 5,
            },
        },
        "firewall": {"active": True, "type": "ufw", "rules_count": 5, "open_ports": [22, 80]},
        "ssh": {"port": 22, "permit_root_login": "no", "password_auth": "no"},
    }

    bulletin = gen.generate(mock_report, [], baseline_age_hours=24)

    assert "MCP CYBERSEC WATCHDOG" in bulletin
    assert "No anomalies detected" in bulletin
    assert "Firewall: ACTIVE" in bulletin


def test_bulletin_with_anomalies():
    """Test bulletin generation with anomalies."""
    gen = BulletinGenerator()

    mock_report = {
        "analysis": {
            "overall_status": "CRITICAL",
            "score": {
                "critical_issues": 1,
                "high_priority_issues": 0,
                "good_practices_followed": 3,
            },
        },
        "firewall": {"active": False, "type": "ufw", "rules_count": 0, "open_ports": []},
    }

    anomalies = [
        {"severity": "critical", "category": "firewall", "message": "Firewall was disabled"}
    ]

    bulletin = gen.generate(mock_report, anomalies)

    assert "CRITICAL" in bulletin
    assert "Firewall was disabled" in bulletin


def test_monitor_run_once():
    """Test single monitoring run."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_dir = Path(tmpdir) / "logs"
        baseline_path = Path(tmpdir) / "baseline.json"

        monitor = SecurityMonitor(
            interval_seconds=60,
            log_dir=str(log_dir),
            baseline_path=str(baseline_path),
            verbose=False,
        )

        # First run - should create baseline
        result = monitor.run_once()
        assert result["status"] == "baseline_created"
        assert baseline_path.exists()

        # Second run - should detect no anomalies (same state)
        result = monitor.run_once()
        assert result["status"] == "completed"
        assert len(result["anomalies"]) == 0
