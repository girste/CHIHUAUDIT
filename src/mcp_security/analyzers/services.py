"""Network services and open ports analysis."""

import re
from ..utils.detect import run_with_sudo

CRITICAL_SERVICES = [
    "ssh",
    "sshd",
    "caddy",
    "nginx",
    "apache2",
    "docker",
    "mysql",
    "mariadb",
    "postgresql",
    "redis",
    "fail2ban",
    "ufw",
    "firewalld",
]

UNKNOWN_SERVICES_THRESHOLD = 3


def parse_listening_ports():
    """Parse listening ports and services using ss command."""
    result = run_with_sudo(["ss", "-tulpn"])

    if not result:
        return []

    services = []

    for line in result.stdout.split("\n"):
        # Skip header and empty lines
        if not line or line.startswith("Netid") or line.startswith("State"):
            continue

        # Parse ss output: protocol state recv-q send-q local_address:port peer_address:port process
        parts = line.split()
        if len(parts) < 5:
            continue

        protocol = parts[0]  # tcp or udp
        local_addr = parts[4]  # address:port

        # Extract port
        port_match = re.search(r":(\d+)$", local_addr)
        if not port_match:
            continue

        port = int(port_match.group(1))

        # Extract bind address
        addr = local_addr.rsplit(":", 1)[0]
        # Handle IPv6 addresses in brackets
        addr = addr.strip("[]")
        # Remove interface suffix (e.g., %lo, %eth0)
        base_addr = addr.split("%")[0]

        # Determine if exposed to external network
        is_external = base_addr not in ("127.0.0.1", "::1", "127.0.0.53", "127.0.0.54", "localhost")

        # Extract process info if available
        process = None
        if len(parts) >= 7:
            process_info = parts[6]
            # Extract process name from users:(("name",pid=123,fd=4))
            proc_match = re.search(r'\(\("([^"]+)"', process_info)
            if proc_match:
                process = proc_match.group(1)

        services.append(
            {
                "port": port,
                "protocol": protocol,
                "address": addr,
                "exposed": is_external,
                "process": process,
            }
        )

    return services


def categorize_services(services):
    """Categorize services by risk level."""
    # Well-known safe services
    safe_services = {
        22: "ssh",
        80: "http",
        443: "https",
    }

    # Potentially risky services
    risky_ports = {
        3306: "mysql",
        5432: "postgresql",
        6379: "redis",
        27017: "mongodb",
        9200: "elasticsearch",
    }

    categorized = {"safe": [], "risky": [], "unknown": []}

    for service in services:
        port = service["port"]

        if port in safe_services:
            categorized["safe"].append({**service, "name": safe_services[port]})
        elif port in risky_ports:
            categorized["risky"].append({**service, "name": risky_ports[port]})
        else:
            categorized["unknown"].append({**service, "name": "unknown"})

    return categorized


def check_systemd_failed():
    """Check for failed systemd units."""
    result = run_with_sudo(["systemctl", "list-units", "--failed", "--no-pager", "--plain"])

    if not result:
        return []

    failed_units = []
    for line in result.stdout.split("\n"):
        line = line.strip()
        if not line or "UNIT" in line or "0 loaded units listed" in line:
            continue

        parts = line.split()
        if len(parts) >= 1:
            unit = parts[0]
            failed_units.append(unit)

    return failed_units


def check_critical_services():
    """Check status of critical system services."""
    services_status = []
    installed_states = {"active", "failed", "degraded", "activating"}

    for service in CRITICAL_SERVICES:
        result = run_with_sudo(["systemctl", "is-active", f"{service}.service"])
        if not result:
            continue

        status = result.stdout.strip()
        if status in installed_states:
            services_status.append(
                {"name": service, "status": status, "active": status == "active"}
            )

    return services_status


def analyze_services():
    """Analyze network services, open ports, and systemd service health."""
    services = parse_listening_ports()
    categorized = (
        categorize_services(services) if services else {"safe": [], "risky": [], "unknown": []}
    )

    exposed_count = sum(1 for s in services if s["exposed"]) if services else 0
    network_data = {
        "total_services": len(services),
        "exposed_services": exposed_count,
        "internal_only": len(services) - exposed_count,
        "by_category": categorized,
    }

    failed_units = check_systemd_failed()
    critical_services = check_critical_services()

    issues = []

    for service in categorized.get("risky", []):
        if service["exposed"]:
            issues.append(
                {
                    "severity": "high",
                    "message": f"Database service {service['name']} exposed on port {service['port']}",
                    "recommendation": f"Bind {service['name']} to localhost only or use firewall to restrict access",
                }
            )

    exposed_unknown = [s for s in categorized.get("unknown", []) if s["exposed"]]
    if len(exposed_unknown) > UNKNOWN_SERVICES_THRESHOLD:
        issues.append(
            {
                "severity": "medium",
                "message": f"{len(exposed_unknown)} unknown services exposed to network",
                "recommendation": "Review and identify all exposed services, close unnecessary ports",
            }
        )

    if failed_units:
        issues.append(
            {
                "severity": "high",
                "message": f"{len(failed_units)} systemd unit(s) in failed state",
                "recommendation": f"Check and fix failed units: {', '.join(failed_units[:3])}",
            }
        )

    failed_critical = [s for s in critical_services if s["status"] in ("failed", "degraded")]
    for svc in failed_critical:
        issues.append(
            {
                "severity": "critical",
                "message": f"Critical service {svc['name']} is {svc['status']}",
                "recommendation": f"Restart/fix {svc['name']} immediately: sudo systemctl restart {svc['name']}",
            }
        )

    return {
        **network_data,
        "systemd": {
            "failed_units": failed_units,
            "failed_count": len(failed_units),
            "critical_services": critical_services,
            "critical_down": len(failed_critical),
        },
        "issues": issues,
    }
