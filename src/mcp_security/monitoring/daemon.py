"""Security monitoring daemon."""

import time
import signal
from datetime import datetime, timezone
from pathlib import Path

from ..audit import run_audit
from .baseline import BaselineManager
from .anomaly import AnomalyDetector
from .bulletin import BulletinGenerator


class SecurityMonitor:
    """
    Continuous security monitoring daemon.

    Behavior:
    - First run: creates baseline
    - Periodic check (default: every hour)
    - Detect anomalies vs baseline
    - Generate bulletins (text file)
    - Anomalies trigger AI analysis via MCP (if configured)
    """

    def __init__(
        self,
        interval_seconds=3600,
        log_dir="/var/log/mcp-watchdog",
        baseline_path=None,
        verbose=False,
    ):
        self.interval = interval_seconds
        self.log_dir = Path(log_dir)
        self.verbose = verbose
        self.running = False

        # Create log directory
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Default baseline_path to log_dir/baseline.json if not specified
        if baseline_path is None:
            baseline_path = self.log_dir / "baseline.json"

        # Initialize components
        self.baseline_mgr = BaselineManager(baseline_path)
        self.anomaly_detector = AnomalyDetector()
        self.bulletin_gen = BulletinGenerator()

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)

    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signals gracefully."""
        self._log("Received shutdown signal, stopping...")
        self.running = False

    def _log(self, message):
        """Print log message if verbose."""
        if self.verbose:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] {message}", flush=True)

    def _write_bulletin(self, bulletin_text):
        """Write bulletin to log file."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        bulletin_file = self.log_dir / f"bulletin_{timestamp}.txt"

        try:
            with open(bulletin_file, "w") as f:
                f.write(bulletin_text)
            self._log(f"Bulletin written to {bulletin_file}")
            return bulletin_file
        except IOError as e:
            self._log(f"Failed to write bulletin: {e}")
            return None

    def _write_anomaly_report(self, anomalies, current_report):
        """Write detailed anomaly report for AI analysis."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        anomaly_file = self.log_dir / f"anomaly_{timestamp}.json"

        import json

        try:
            with open(anomaly_file, "w") as f:
                json.dump(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "anomalies": anomalies,
                        "full_report": current_report,
                    },
                    f,
                    indent=2,
                )
            self._log(f"Anomaly report written to {anomaly_file}")
            return anomaly_file
        except IOError as e:
            self._log(f"Failed to write anomaly report: {e}")
            return None

    def run_once(self):
        """Run a single monitoring check."""
        self._log("Running security audit...")

        # Run full audit (mask_data=True for privacy)
        current_report = run_audit(mask_data=True, verbose=False)

        # Load baseline
        baseline = self.baseline_mgr.get_baseline()

        if baseline is None:
            # First run - create baseline
            self._log("No baseline found, creating initial baseline...")
            self.baseline_mgr.save(current_report)
            self._log("Baseline created. Monitoring will start on next check.")
            return {
                "status": "baseline_created",
                "anomalies": [],
                "bulletin_file": None,
            }

        # Extract comparable snapshots
        baseline_snapshot = baseline["snapshot"]
        current_snapshot = self.baseline_mgr._extract_comparable_data(current_report)

        # Detect anomalies
        self._log("Checking for anomalies...")
        anomalies = self.anomaly_detector.detect(baseline_snapshot, current_snapshot)

        # Calculate baseline age
        baseline_time = datetime.fromisoformat(baseline["timestamp"].replace("Z", "+00:00"))
        baseline_age = datetime.now(timezone.utc) - baseline_time
        baseline_age_hours = baseline_age.total_seconds() / 3600

        # Generate bulletin
        bulletin = self.bulletin_gen.generate(current_report, anomalies, baseline_age_hours)

        # Print bulletin to stdout
        print("\n" + bulletin + "\n")

        # Write bulletin to file
        bulletin_file = self._write_bulletin(bulletin)

        # If anomalies detected, write detailed report for AI
        anomaly_file = None
        if anomalies:
            self._log(f"Detected {len(anomalies)} anomalies")
            anomaly_file = self._write_anomaly_report(anomalies, current_report)

            # Critical or high severity = recommend AI analysis
            if self.anomaly_detector.has_critical():
                self._log("⚠️  CRITICAL anomalies detected - AI analysis recommended")
                print("\n⚠️  CRITICAL ANOMALY DETECTED")
                print(f"Run AI analysis: Use MCP tool 'analyze_anomaly' with file {anomaly_file}")
            elif self.anomaly_detector.has_high():
                self._log("⚠️  High severity anomalies detected - AI analysis recommended")
                print("\n⚠️  HIGH SEVERITY ANOMALY DETECTED")
                print(f"Run AI analysis: Use MCP tool 'analyze_anomaly' with file {anomaly_file}")
        else:
            self._log("No anomalies detected - system stable")

        return {
            "status": "completed",
            "anomalies": anomalies,
            "bulletin_file": str(bulletin_file) if bulletin_file else None,
            "anomaly_file": str(anomaly_file) if anomaly_file else None,
        }

    def run(self):
        """Run continuous monitoring loop."""
        self._log(f"Starting security monitoring (interval: {self.interval}s)")
        self._log(f"Logs: {self.log_dir}")
        self._log(f"Baseline: {self.baseline_mgr.baseline_path}")

        self.running = True
        check_count = 0

        try:
            while self.running:
                check_count += 1
                self._log(f"--- Check #{check_count} ---")

                try:
                    result = self.run_once()
                    self._log(f"Check completed: {result['status']}")

                    # Auto-cleanup every 10 checks to prevent disk fill
                    if check_count % 10 == 0:
                        self._log("Running automatic log cleanup...")
                        from .manager import MonitoringManager

                        manager = MonitoringManager(str(self.log_dir))
                        cleanup_result = manager.cleanup_old_logs()
                        if (
                            cleanup_result["bulletins_removed"] > 0
                            or cleanup_result["anomalies_removed"] > 0
                        ):
                            self._log(
                                f"Cleaned up {cleanup_result['bulletins_removed']} bulletins, "
                                f"{cleanup_result['anomalies_removed']} anomalies"
                            )

                except Exception as e:
                    self._log(f"Error during check: {e}")
                    import traceback

                    traceback.print_exc()

                # Wait for next interval
                if self.running:
                    self._log(f"Sleeping for {self.interval} seconds...")
                    time.sleep(self.interval)

        except KeyboardInterrupt:
            self._log("Interrupted by user")

        self._log("Monitoring stopped")

    def reset_baseline(self):
        """Force reset baseline on next check."""
        if self.baseline_mgr.baseline_path.exists():
            self.baseline_mgr.baseline_path.unlink()
            self._log("Baseline reset - will be recreated on next check")
