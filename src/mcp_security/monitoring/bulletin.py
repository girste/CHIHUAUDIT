"""Security bulletin generation."""

from datetime import datetime, timezone


class BulletinGenerator:
    """Generates human-readable security bulletins."""

    def generate(self, current_report, anomalies, baseline_age_hours=None):
        """
        Generate security bulletin.

        Args:
            current_report: Latest audit report
            anomalies: List of detected anomalies
            baseline_age_hours: How old is the baseline (for context)

        Returns:
            String bulletin
        """
        lines = []
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Header
        lines.append("=" * 70)
        lines.append("MCP CYBERSEC WATCHDOG - Security Bulletin")
        lines.append(f"Generated: {timestamp}")
        lines.append("=" * 70)
        lines.append("")

        # Overall status
        status = self._get_status(current_report, anomalies)
        lines.append(f"Status: {status}")

        if baseline_age_hours:
            lines.append(f"Monitoring since: {baseline_age_hours:.1f} hours ago")

        lines.append("")

        # Anomalies section (if any)
        if anomalies:
            lines.append("ANOMALIES DETECTED:")
            lines.append("-" * 70)

            critical = [a for a in anomalies if a["severity"] == "critical"]
            high = [a for a in anomalies if a["severity"] == "high"]
            medium = [a for a in anomalies if a["severity"] == "medium"]
            low = [a for a in anomalies if a["severity"] == "low"]

            if critical:
                lines.append("\n[CRITICAL]")
                for a in critical:
                    lines.append(f"  ! {a['category'].upper()}: {a['message']}")

            if high:
                lines.append("\n[HIGH]")
                for a in high:
                    lines.append(f"  * {a['category'].upper()}: {a['message']}")

            if medium:
                lines.append("\n[MEDIUM]")
                for a in medium:
                    lines.append(f"  - {a['category']}: {a['message']}")

            if low:
                lines.append("\n[LOW]")
                for a in low:
                    lines.append(f"  · {a['category']}: {a['message']}")

            lines.append("")
        else:
            lines.append("No anomalies detected - all systems nominal")
            lines.append("")

        # Quick stats
        lines.append("CURRENT STATE:")
        lines.append("-" * 70)

        analysis = current_report.get("analysis", {})
        score = analysis.get("score", {})

        if analysis.get("overall_status"):
            lines.append(f"Overall: {analysis['overall_status']}")

        lines.append(
            f"Issues: {score.get('critical_issues', 0)} critical, "
            f"{score.get('high_priority_issues', 0)} high priority"
        )
        lines.append(f"Good practices: {score.get('good_practices_followed', 0)}")

        # Firewall
        if current_report.get("firewall"):
            fw = current_report["firewall"]
            status_str = "ACTIVE" if fw.get("active") else "INACTIVE"
            lines.append(
                f"Firewall: {status_str} ({fw.get('type', 'unknown')}) - "
                f"{fw.get('rules_count', 0)} rules, {len(fw.get('open_ports', []))} open ports"
            )

        # SSH
        if current_report.get("ssh"):
            ssh = current_report["ssh"]
            lines.append(
                f"SSH: Port {ssh.get('port')} - "
                f"Root={ssh.get('permit_root_login')}, "
                f"Password={ssh.get('password_auth')}"
            )

        # Threats
        if current_report.get("threats"):
            threats = current_report["threats"]
            lines.append(
                f"Threats: {threats.get('total_attempts', 0)} failed login attempts "
                f"from {threats.get('unique_ips', 0)} IPs "
                f"({threats.get('period_days', 7)} days)"
            )

        # Fail2ban
        if current_report.get("fail2ban"):
            f2b = current_report["fail2ban"]
            if f2b.get("active"):
                lines.append(f"Fail2ban: ACTIVE - {f2b.get('total_banned', 0)} IPs banned")
            else:
                lines.append("Fail2ban: INACTIVE")

        # Docker
        if current_report.get("docker") and current_report["docker"].get("installed"):
            docker = current_report["docker"]
            lines.append(f"Docker: {docker.get('running_containers', 0)} containers running")

        lines.append("")
        lines.append("=" * 70)

        return "\n".join(lines)

    def _get_status(self, report, anomalies):
        """Determine overall status string."""
        if not anomalies:
            analysis = report.get("analysis", {})
            overall = analysis.get("overall_status", "UNKNOWN")
            if overall == "GOOD":
                return "✓ ALL OK"
            elif overall == "FAIR":
                return "✓ OK (minor warnings)"
            else:
                return f"⚠ {overall}"

        # Has anomalies
        critical = any(a["severity"] == "critical" for a in anomalies)
        high = any(a["severity"] == "high" for a in anomalies)

        if critical:
            return "✗ CRITICAL ANOMALY DETECTED"
        elif high:
            return "⚠ HIGH SEVERITY ANOMALY DETECTED"
        else:
            return "⚠ ANOMALIES DETECTED"
