"""Firewall analysis module."""

import re
from ..utils.detect import run_with_sudo


def analyze_ufw():
    """Analyze UFW firewall configuration."""
    result = run_with_sudo(["ufw", "status", "verbose"])

    if result:

        output = result.stdout

        active = "Status: active" in output
        default_policy = "deny" if "deny (incoming)" in output.lower() else "allow"

        # Count rules (lines with "ALLOW" or "DENY")
        rules = [line for line in output.split("\n") if "ALLOW" in line or "DENY" in line]
        rules_count = len(rules)

        # Extract open ports
        open_ports = []
        for line in rules:
            if "ALLOW" in line:
                match = re.search(r"(\d+)(?:/tcp)?", line)
                if match:
                    open_ports.append(int(match.group(1)))

        return {
            "type": "ufw",
            "active": active,
            "default_policy": default_policy,
            "rules_count": rules_count,
            "open_ports": sorted(set(open_ports)),
        }

    return None


def analyze_iptables():
    """Analyze iptables configuration."""
    result = run_with_sudo(["iptables", "-L", "-n"])

    if result:

        output = result.stdout

        # Check if there are any rules
        lines = output.split("\n")
        rules_count = len(
            [
                line
                for line in lines
                if line.strip() and not line.startswith("Chain") and not line.startswith("target")
            ]
        )

        # Simple heuristic: if many rules, likely active
        active = rules_count > 5

        return {
            "type": "iptables",
            "active": active,
            "default_policy": "unknown",
            "rules_count": rules_count,
            "open_ports": [],
        }

    return None


def analyze_firewalld():
    """Analyze firewalld configuration."""
    result = run_with_sudo(["firewall-cmd", "--state"])

    if not result:
        return None

    active = "running" in result.stdout.lower()

    if not active:
        return None

    # Get list of services
    services_result = run_with_sudo(["firewall-cmd", "--list-services"])
    services = services_result.stdout.strip().split() if services_result else []

    return {
        "type": "firewalld",
        "active": active,
        "default_policy": "deny",
        "rules_count": len(services),
        "open_ports": [],
    }


def analyze_firewall():
    """Analyze system firewall (auto-detect type)."""
    analyzers = [analyze_ufw, analyze_firewalld, analyze_iptables]

    for analyzer in analyzers:
        result = analyzer()
        if result:
            return result

    return {
        "type": "none",
        "active": False,
        "default_policy": "unknown",
        "rules_count": 0,
        "open_ports": [],
    }
