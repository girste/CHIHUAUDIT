"""Monitoring daemon management."""

import os
import signal
import subprocess
import time
from pathlib import Path


class MonitoringManager:
    """Manages monitoring daemon lifecycle."""

    def __init__(self, log_dir="/var/log/mcp-watchdog"):
        self.log_dir = Path(log_dir)
        self.pid_file = self.log_dir / "monitoring.pid"

    def is_running(self):
        """Check if monitoring daemon is running."""
        if not self.pid_file.exists():
            return False

        try:
            with open(self.pid_file) as f:
                pid = int(f.read().strip())

            # Check if process exists
            os.kill(pid, 0)
            return True
        except (ValueError, ProcessLookupError, PermissionError):
            # PID file exists but process doesn't
            self.pid_file.unlink(missing_ok=True)
            return False

    def get_status(self):
        """Get detailed monitoring status."""
        running = self.is_running()
        pid = None

        if running and self.pid_file.exists():
            with open(self.pid_file) as f:
                pid = int(f.read().strip())

        # Count log files
        bulletins = list(self.log_dir.glob("bulletin_*.txt")) if self.log_dir.exists() else []
        anomalies = list(self.log_dir.glob("anomaly_*.json")) if self.log_dir.exists() else []
        baseline_exists = (self.log_dir.parent / "baseline.json").exists() or (
            self.log_dir / "baseline.json"
        ).exists()

        return {
            "running": running,
            "pid": pid,
            "log_dir": str(self.log_dir),
            "baseline_exists": baseline_exists,
            "bulletin_count": len(bulletins),
            "anomaly_count": len(anomalies),
            "total_disk_usage_kb": sum(f.stat().st_size for f in bulletins + anomalies) // 1024,
        }

    def start(self, interval_seconds=3600):
        """Start monitoring daemon in background."""
        if self.is_running():
            return {"success": False, "error": "Monitoring is already running"}

        # Ensure log directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Get mcp-watchdog executable path
        import sys

        watchdog_path = Path(sys.executable).parent / "mcp-watchdog"
        if not watchdog_path.exists():
            return {"success": False, "error": f"mcp-watchdog not found at {watchdog_path}"}

        # Start daemon in background
        try:
            process = subprocess.Popen(
                [
                    str(watchdog_path),
                    "monitor",
                    "--interval",
                    str(interval_seconds),
                    "--log-dir",
                    str(self.log_dir),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )

            # Give it a moment to start
            time.sleep(1)

            # Check if still running
            if process.poll() is not None:
                return {
                    "success": False,
                    "error": "Daemon process terminated immediately after start. Check permissions and log directory.",
                }

            # Save PID
            with open(self.pid_file, "w") as f:
                f.write(str(process.pid))

            return {
                "success": True,
                "pid": process.pid,
                "interval_seconds": interval_seconds,
                "log_dir": str(self.log_dir),
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def stop(self):
        """Stop monitoring daemon."""
        if not self.is_running():
            return {"success": False, "error": "Monitoring is not running"}

        try:
            with open(self.pid_file) as f:
                pid = int(f.read().strip())

            # Send SIGTERM for graceful shutdown
            os.kill(pid, signal.SIGTERM)

            # Wait up to 5 seconds for process to stop
            for _ in range(50):
                try:
                    os.kill(pid, 0)
                    time.sleep(0.1)
                except ProcessLookupError:
                    break

            # Remove PID file
            self.pid_file.unlink(missing_ok=True)

            return {"success": True, "message": "Monitoring stopped"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def cleanup_old_logs(self, max_bulletins=50, max_anomalies=20):
        """Remove old log files to prevent disk fill."""
        if not self.log_dir.exists():
            return {"bulletins_removed": 0, "anomalies_removed": 0}

        # Get all bulletins sorted by modification time (oldest first)
        bulletins = sorted(self.log_dir.glob("bulletin_*.txt"), key=lambda p: p.stat().st_mtime)

        # Get all anomalies sorted by modification time (oldest first)
        anomalies = sorted(self.log_dir.glob("anomaly_*.json"), key=lambda p: p.stat().st_mtime)

        bulletins_removed = 0
        anomalies_removed = 0

        # Remove old bulletins
        if len(bulletins) > max_bulletins:
            for bulletin in bulletins[:-max_bulletins]:
                bulletin.unlink()
                bulletins_removed += 1

        # Remove old anomalies
        if len(anomalies) > max_anomalies:
            for anomaly in anomalies[:-max_anomalies]:
                anomaly.unlink()
                anomalies_removed += 1

        return {
            "bulletins_removed": bulletins_removed,
            "anomalies_removed": anomalies_removed,
            "bulletins_remaining": len(bulletins) - bulletins_removed,
            "anomalies_remaining": len(anomalies) - anomalies_removed,
        }
