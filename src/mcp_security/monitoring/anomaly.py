"""Anomaly detection for security monitoring."""


class AnomalyDetector:
    """Detects security-relevant changes between baseline and current state."""

    SEVERITY_CRITICAL = "critical"
    SEVERITY_HIGH = "high"
    SEVERITY_MEDIUM = "medium"
    SEVERITY_LOW = "low"

    def __init__(self):
        self.anomalies = []

    def detect(self, baseline_snapshot, current_snapshot):
        """
        Compare baseline vs current and detect anomalies.
        Returns list of anomalies with severity.
        """
        self.anomalies = []

        if not baseline_snapshot or not current_snapshot:
            return []

        self._check_firewall(baseline_snapshot.get("firewall"), current_snapshot.get("firewall"))
        self._check_ssh(baseline_snapshot.get("ssh"), current_snapshot.get("ssh"))
        self._check_services(baseline_snapshot.get("services"), current_snapshot.get("services"))
        self._check_fail2ban(baseline_snapshot.get("fail2ban"), current_snapshot.get("fail2ban"))
        self._check_threats(baseline_snapshot.get("threats"), current_snapshot.get("threats"))
        self._check_docker(baseline_snapshot.get("docker"), current_snapshot.get("docker"))
        self._check_updates(baseline_snapshot.get("updates"), current_snapshot.get("updates"))

        return self.anomalies

    def _add_anomaly(self, severity, category, message, details=None):
        """Add anomaly to list."""
        self.anomalies.append(
            {
                "severity": severity,
                "category": category,
                "message": message,
                "details": details or {},
            }
        )

    def _check_firewall(self, baseline, current):
        """Check firewall changes."""
        if not baseline or not current:
            return

        # Firewall disabled
        if baseline.get("active") and not current.get("active"):
            self._add_anomaly(self.SEVERITY_CRITICAL, "firewall", "Firewall was disabled")

        # New open ports
        baseline_ports = set(baseline.get("open_ports", []))
        current_ports = set(current.get("open_ports", []))
        new_ports = current_ports - baseline_ports

        if new_ports:
            self._add_anomaly(
                self.SEVERITY_HIGH,
                "firewall",
                f"New ports opened: {sorted(new_ports)}",
                {"ports": sorted(new_ports)},
            )

        # Rules count changed significantly
        baseline_rules = baseline.get("rules_count", 0)
        current_rules = current.get("rules_count", 0)
        if abs(current_rules - baseline_rules) > 5:
            self._add_anomaly(
                self.SEVERITY_MEDIUM,
                "firewall",
                f"Firewall rules changed: {baseline_rules} → {current_rules}",
            )

    def _check_ssh(self, baseline, current):
        """Check SSH configuration changes."""
        if not baseline or not current:
            return

        # Port changed
        if baseline.get("port") != current.get("port"):
            self._add_anomaly(
                self.SEVERITY_MEDIUM,
                "ssh",
                f"SSH port changed: {baseline.get('port')} → {current.get('port')}",
            )

        # Root login enabled
        if baseline.get("permit_root_login") == "no" and current.get("permit_root_login") != "no":
            self._add_anomaly(self.SEVERITY_CRITICAL, "ssh", "Root login was enabled in SSH config")

        # Password auth enabled
        if baseline.get("password_auth") == "no" and current.get("password_auth") == "yes":
            self._add_anomaly(
                self.SEVERITY_HIGH, "ssh", "Password authentication was enabled in SSH"
            )

    def _check_services(self, baseline, current):
        """Check network services changes."""
        if not baseline or not current:
            return

        # New listening ports
        baseline_ports = set(baseline.get("listening_ports", []))
        current_ports = set(current.get("listening_ports", []))
        new_ports = current_ports - baseline_ports

        if new_ports:
            self._add_anomaly(
                self.SEVERITY_MEDIUM,
                "services",
                f"New services listening: ports {sorted(new_ports)}",
                {"ports": sorted(new_ports)},
            )

        # Large increase in exposed services
        baseline_count = baseline.get("exposed_count", 0)
        current_count = current.get("exposed_count", 0)
        if current_count > baseline_count + 3:
            self._add_anomaly(
                self.SEVERITY_MEDIUM,
                "services",
                f"Exposed services increased: {baseline_count} → {current_count}",
            )

    def _check_fail2ban(self, baseline, current):
        """Check fail2ban status changes."""
        if not baseline or not current:
            return

        # Fail2ban disabled
        if baseline.get("active") and not current.get("active"):
            self._add_anomaly(self.SEVERITY_HIGH, "fail2ban", "Fail2ban was disabled or stopped")

    def _check_threats(self, baseline, current):
        """Check threat pattern changes."""
        if not baseline or not current:
            return

        baseline_attempts = baseline.get("total_attempts", 0)
        current_attempts = current.get("total_attempts", 0)

        # Significant increase in attack attempts (>200% increase)
        if baseline_attempts > 0 and current_attempts > baseline_attempts * 3:
            self._add_anomaly(
                self.SEVERITY_HIGH,
                "threats",
                f"Attack volume spike: {baseline_attempts} → {current_attempts} attempts",
                {"baseline": baseline_attempts, "current": current_attempts},
            )

        # New unique attacker IPs (>50% increase)
        baseline_ips = baseline.get("unique_ips", 0)
        current_ips = current.get("unique_ips", 0)
        if baseline_ips > 0 and current_ips > baseline_ips * 1.5:
            self._add_anomaly(
                self.SEVERITY_MEDIUM,
                "threats",
                f"New attacker IPs detected: {baseline_ips} → {current_ips}",
            )

    def _check_docker(self, baseline, current):
        """Check Docker security changes."""
        if not baseline or not current:
            return

        # New privileged containers
        baseline_priv = baseline.get("privileged_count", 0)
        current_priv = current.get("privileged_count", 0)
        if current_priv > baseline_priv:
            self._add_anomaly(
                self.SEVERITY_HIGH,
                "docker",
                f"New privileged container(s) detected: {current_priv - baseline_priv}",
            )

        # Container count spike
        baseline_containers = baseline.get("running_containers", 0)
        current_containers = current.get("running_containers", 0)
        if current_containers > baseline_containers + 5:
            self._add_anomaly(
                self.SEVERITY_LOW,
                "docker",
                f"Many new containers started: {baseline_containers} → {current_containers}",
            )

    def _check_updates(self, baseline, current):
        """Check security updates status."""
        if not baseline or not current:
            return

        baseline_updates = baseline.get("security_updates", 0)
        current_updates = current.get("security_updates", 0)

        # Critical updates appeared
        if current_updates > 10 and current_updates > baseline_updates:
            self._add_anomaly(
                self.SEVERITY_HIGH,
                "updates",
                f"{current_updates} critical security updates now available",
            )

    def has_critical(self):
        """Check if any critical anomalies detected."""
        return any(a["severity"] == self.SEVERITY_CRITICAL for a in self.anomalies)

    def has_high(self):
        """Check if any high severity anomalies detected."""
        return any(
            a["severity"] in [self.SEVERITY_CRITICAL, self.SEVERITY_HIGH] for a in self.anomalies
        )
