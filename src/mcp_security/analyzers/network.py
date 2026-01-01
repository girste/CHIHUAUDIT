"""Network connections security analyzer.

Analyzes active network connections, listening services, and detects
suspicious network activity or unexpected connections.
"""

import subprocess
import re
from typing import List, Dict

KNOWN_SAFE_PROCESSES = {
    "sshd",
    "systemd",
    "caddy",
    "nginx",
    "apache2",
    "mysqld",
    "postgres",
    "redis-server",
    "docker",
    "containerd",
    "chronyd",
    "systemd-resolved",
}

SUSPICIOUS_PORTS = {
    4444: "Metasploit default",
    5555: "Android Debug Bridge",
    6666: "Common backdoor",
    6667: "IRC",
    31337: "Elite backdoor",
}

PRIVATE_IP_RANGES = [
    "127.",
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
]


def _is_private_ip(ip: str) -> bool:
    """Check if IP is in private range."""
    return any(ip.startswith(prefix) for prefix in PRIVATE_IP_RANGES)


def _parse_ss_output() -> List[Dict]:
    """Parse ss command output to get active connections."""
    try:
        result = subprocess.run(
            ["ss", "-tunap"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return []

        connections = []
        for line in result.stdout.split("\n")[1:]:  # Skip header
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) < 5:
                continue

            state = parts[0]
            local_addr = parts[4]
            remote_addr = parts[5] if len(parts) > 5 else "N/A"

            # Extract process info if available
            process_info = ""
            for part in parts:
                if "users:((" in part:
                    match = re.search(r'users:\(\("([^"]+)"', part)
                    if match:
                        process_info = match.group(1)

            # Parse addresses
            local_ip, local_port = _parse_address(local_addr)
            remote_ip, remote_port = _parse_address(remote_addr)

            connections.append(
                {
                    "state": state,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "process": process_info,
                }
            )

        return connections

    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        return []


def _parse_address(addr: str) -> tuple:
    """Parse IP:port from address string."""
    if ":" not in addr or addr == "*:*":
        return ("*", "*")

    try:
        # Handle IPv6 format [::]:port
        if addr.startswith("["):
            match = re.match(r"\[([^\]]+)\]:(\d+)", addr)
            if match:
                return (match.group(1), match.group(2))

        # Handle IPv4 format ip:port
        parts = addr.rsplit(":", 1)
        return (parts[0], parts[1])

    except (ValueError, IndexError):
        return ("*", "*")


def _analyze_listening_services(connections: List[Dict]) -> Dict:
    """Analyze services listening on network ports."""
    listening = [c for c in connections if c["state"] == "LISTEN"]

    services = {}
    for conn in listening:
        port = conn["local_port"]
        if port == "*":
            continue

        process = conn["process"] or "unknown"

        if port not in services:
            services[port] = {
                "port": port,
                "processes": set(),
                "local_ip": conn["local_ip"],
            }

        services[port]["processes"].add(process)

    # Convert sets to lists for JSON serialization
    for service in services.values():
        service["processes"] = list(service["processes"])

    return services


def _detect_suspicious_connections(connections: List[Dict]) -> List[Dict]:
    """Detect potentially suspicious network connections."""
    suspicious = []

    for conn in connections:
        if conn["state"] != "ESTAB":
            continue

        remote_ip = conn["remote_ip"]
        remote_port = conn["remote_port"]
        process = conn["process"]

        # Skip private IPs
        if _is_private_ip(remote_ip):
            continue

        # Check for suspicious ports
        try:
            port_num = int(remote_port)
            if port_num in SUSPICIOUS_PORTS:
                suspicious.append(
                    {
                        "reason": f"Connection to suspicious port {port_num} ({SUSPICIOUS_PORTS[port_num]})",
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "process": process,
                        "severity": "high",
                    }
                )
                continue
        except ValueError:
            pass

        # Check for unknown processes with external connections
        if process and process not in KNOWN_SAFE_PROCESSES:
            # Only flag if connecting to non-standard ports
            try:
                port_num = int(remote_port)
                if port_num not in [80, 443, 53, 123]:
                    suspicious.append(
                        {
                            "reason": f"Unknown process '{process}' with external connection",
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "process": process,
                            "severity": "medium",
                        }
                    )
            except ValueError:
                pass

    return suspicious


def analyze_network():
    """Analyze active network connections for security issues."""
    connections = _parse_ss_output()

    if not connections:
        return {
            "checked": False,
            "message": "Unable to retrieve network connections",
            "issues": [],
        }

    services = _analyze_listening_services(connections)
    suspicious = _detect_suspicious_connections(connections)

    # Count connection states
    established = len([c for c in connections if c["state"] == "ESTAB"])
    listening = len([c for c in connections if c["state"] == "LISTEN"])

    # Generate issues
    issues = []

    for susp in suspicious:
        issues.append(
            {
                "severity": susp["severity"],
                "message": f"{susp['reason']}: {susp['remote_ip']}:{susp['remote_port']}",
                "recommendation": f"Investigate process '{susp['process']}' and connection legitimacy",
            }
        )

    # Check for too many listening services
    if len(services) > 20:
        issues.append(
            {
                "severity": "low",
                "message": f"{len(services)} services listening on network ports",
                "recommendation": "Review listening services and disable unnecessary ones",
            }
        )

    return {
        "checked": True,
        "total_connections": len(connections),
        "established_connections": established,
        "listening_services": listening,
        "listening_ports": list(services.keys())[:20],
        "suspicious_connections": len(suspicious),
        "suspicious_sample": suspicious[:5],
        "issues": issues,
    }
