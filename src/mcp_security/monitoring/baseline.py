"""Baseline management for security monitoring."""

import json
from datetime import datetime, timezone
from pathlib import Path


class BaselineManager:
    """Manages security baseline snapshots."""

    def __init__(self, baseline_path="/var/lib/mcp-watchdog/baseline.json"):
        self.baseline_path = Path(baseline_path)
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self.baseline = None

    def load(self):
        """Load existing baseline from disk."""
        if not self.baseline_path.exists():
            return None

        try:
            with open(self.baseline_path) as f:
                self.baseline = json.load(f)
            return self.baseline
        except (json.JSONDecodeError, IOError):
            return None

    def save(self, audit_report):
        """Save audit report as new baseline."""
        baseline = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "snapshot": self._extract_comparable_data(audit_report),
        }

        try:
            with open(self.baseline_path, "w") as f:
                json.dump(baseline, f, indent=2)
            self.baseline = baseline
            return True
        except IOError:
            return False

    def _extract_comparable_data(self, report):
        """Extract data points we want to monitor for changes."""
        comparable = {}

        # Firewall state
        if report.get("firewall"):
            fw = report["firewall"]
            comparable["firewall"] = {
                "active": fw.get("active"),
                "rules_count": fw.get("rules_count"),
                "open_ports": sorted(fw.get("open_ports", [])),
            }

        # SSH config
        if report.get("ssh"):
            ssh = report["ssh"]
            comparable["ssh"] = {
                "port": ssh.get("port"),
                "permit_root_login": ssh.get("permit_root_login"),
                "password_auth": ssh.get("password_auth"),
            }

        # Network services
        if report.get("services"):
            svc = report["services"]
            comparable["services"] = {
                "exposed_count": svc.get("exposed_services"),
                "listening_ports": sorted(svc.get("listening_ports", [])),
            }

        # Fail2ban
        if report.get("fail2ban"):
            f2b = report["fail2ban"]
            comparable["fail2ban"] = {
                "active": f2b.get("active"),
                "total_banned": f2b.get("total_banned"),
            }

        # Threat level (simplified for comparison)
        if report.get("threats"):
            threats = report["threats"]
            comparable["threats"] = {
                "total_attempts": threats.get("total_attempts"),
                "unique_ips": threats.get("unique_ips"),
            }

        # Docker containers
        if report.get("docker") and report["docker"].get("installed"):
            docker = report["docker"]
            comparable["docker"] = {
                "running_containers": docker.get("running_containers"),
                "privileged_count": len(docker.get("privileged_containers", [])),
            }

        # Updates pending
        if report.get("updates"):
            upd = report["updates"]
            comparable["updates"] = {"security_updates": upd.get("security_updates", 0)}

        return comparable

    def get_baseline(self):
        """Get current baseline (load if not in memory)."""
        if self.baseline is None:
            self.load()
        return self.baseline
