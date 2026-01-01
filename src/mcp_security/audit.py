"""Main security audit orchestrator."""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from .analyzers.firewall import analyze_firewall
from .analyzers.ssh import analyze_ssh
from .analyzers.threats import analyze_threats
from .analyzers.fail2ban import analyze_fail2ban
from .analyzers.services import analyze_services
from .analyzers.docker_sec import analyze_docker
from .analyzers.updates import analyze_updates
from .analyzers.mac import analyze_mac
from .analyzers.kernel import analyze_kernel
from .analyzers.ssl import analyze_ssl
from .analyzers.disk import analyze_disk
from .analyzers.cve import analyze_cve
from .analyzers.cis import analyze_cis
from .analyzers.containers import analyze_containers
from .analyzers.nist import analyze_nist
from .analyzers.pci import analyze_pci
from .analyzers.webheaders import analyze_webheaders
from .analyzers.filesystem import analyze_filesystem
from .analyzers.network import analyze_network
from .analyzers.users import analyze_users
from .utils.detect import get_os_info, get_auth_log_path
from .utils.privacy import mask_ip, get_masked_hostname
from .utils.config import load_config
from .constants import MAX_KERNEL_ISSUES_REPORT


# Helper functions for reducing code repetition
def _collect_issues_from_analyzer(
    analyzer_result: Optional[Dict[str, Any]],
) -> List[Dict[str, str]]:
    """Extract issues list from analyzer result if present."""
    if not analyzer_result:
        return []
    return analyzer_result.get("issues", [])


def _evaluate_condition(analyzer: Optional[Dict[str, Any]], condition: Dict[str, Any]) -> bool:
    """Evaluate a condition against analyzer data."""
    if not analyzer:
        return False

    field = condition.get("field")
    operator = condition.get("op")
    value = condition.get("value")

    # Handle nested fields (e.g., "systemd.critical_down")
    data = analyzer
    for key in field.split("."):
        data = data.get(key, {}) if isinstance(data, dict) else data

    # Evaluate based on operator
    if operator == ">":
        return data > value if isinstance(data, (int, float)) else False
    elif operator == ">=":
        return data >= value if isinstance(data, (int, float)) else False
    elif operator == "<":
        return data < value if isinstance(data, (int, float)) else False
    elif operator == "<=":
        return data <= value if isinstance(data, (int, float)) else False
    elif operator == "==":
        return data == value
    elif operator == "!=":
        return data != value
    elif operator == "in":
        return value in data if isinstance(data, (list, str)) else False

    return False


def _format_message(template: str, analyzer: Optional[Dict[str, Any]]) -> str:
    """Format message template with analyzer data."""
    if not analyzer or not template:
        return template

    # Simple template variable replacement {field}
    import re

    def replace_var(match):
        field = match.group(1)
        data = analyzer
        for key in field.split("."):
            data = data.get(key) if isinstance(data, dict) else data
        return str(data) if data is not None else ""

    return re.sub(r"\{([^}]+)\}", replace_var, template)


def _add_issues_to_recommendations(
    recommendations: List[Dict[str, Any]], issues: List[Dict[str, str]]
) -> None:
    """Add analyzer issues to recommendations list."""
    for issue in issues:
        recommendations.append(
            {
                "priority": issue["severity"],
                "title": issue["message"],
                "description": issue["recommendation"],
                "command": None,
            }
        )


def _add_issues_to_recommendations_prioritized(
    recommendations: List[Dict[str, Any]],
    issues: List[Dict[str, str]],
    insert_at_front: bool = False,
) -> None:
    """Add analyzer issues to recommendations list, optionally at front for high priority."""
    for issue in issues:
        rec = {
            "priority": issue["severity"],
            "title": issue["message"],
            "description": issue["recommendation"],
            "command": None,
        }
        if insert_at_front:
            recommendations.insert(0, rec)
        else:
            recommendations.append(rec)


def run_audit(mask_data=None, verbose=False):
    """Run complete security audit and return structured report."""
    config = load_config()
    checks = config["checks"]

    if mask_data is None:
        mask_data = config["mask_data"]

    def log(msg):
        if verbose:
            print(f"  {msg}", flush=True)

    os_info = get_os_info()
    hostname = get_masked_hostname() if mask_data else os_info.get("hostname", "unknown")

    firewall = None
    if checks.get("firewall", True):
        log("Analyzing firewall...")
        firewall = analyze_firewall()

    ssh = None
    if checks.get("ssh", True):
        log("Analyzing SSH configuration...")
        ssh = analyze_ssh()

    threats = None
    if checks.get("threats", True):
        log("Analyzing threat patterns...")
        log_path = get_auth_log_path()
        days = config.get("threat_analysis_days", 7)
        threats = analyze_threats(log_path, days=days)

        if mask_data and threats and threats["top_attackers"]:
            for attacker in threats["top_attackers"]:
                attacker["ip"] = mask_ip(attacker["ip"])

    fail2ban = None
    if checks.get("fail2ban", True):
        log("Checking fail2ban status...")
        fail2ban = analyze_fail2ban()

    services = None
    if checks.get("services", True):
        log("Analyzing network services...")
        services = analyze_services()

    docker = None
    if checks.get("docker", True):
        log("Checking Docker security...")
        docker = analyze_docker()

    updates = None
    if checks.get("updates", True):
        log("Checking for security updates...")
        updates = analyze_updates()

    mac = None
    if checks.get("mac", True):
        log("Checking MAC (AppArmor/SELinux)...")
        mac = analyze_mac()

    kernel = None
    if checks.get("kernel", True):
        log("Analyzing kernel hardening...")
        kernel = analyze_kernel()

    ssl = None
    if checks.get("ssl", True):
        log("Checking SSL certificates...")
        ssl = analyze_ssl()

    disk = None
    if checks.get("disk", True):
        log("Analyzing disk usage...")
        disk = analyze_disk()

    cve = None
    if checks.get("cve", True):
        log("Scanning for known CVE vulnerabilities...")
        cve = analyze_cve()

    cis = None
    if checks.get("cis", True):
        log("Running CIS Benchmark compliance checks...")
        cis = analyze_cis()

    containers = None
    if checks.get("containers", True):
        log("Scanning container images for vulnerabilities...")
        containers = analyze_containers()

    nist = None
    if checks.get("nist", True):
        log("Running NIST 800-53 compliance checks...")
        nist = analyze_nist()

    pci = None
    if checks.get("pci", True):
        log("Running PCI-DSS compliance checks...")
        pci = analyze_pci()

    webheaders = None
    if checks.get("webheaders", True):
        log("Analyzing web server security headers...")
        webheaders = analyze_webheaders()

    filesystem = None
    if checks.get("filesystem", True):
        log("Scanning filesystem for security issues...")
        filesystem = analyze_filesystem()

    network = None
    if checks.get("network", True):
        log("Analyzing active network connections...")
        network = analyze_network()

    users = None
    if checks.get("users", True):
        log("Auditing system users and groups...")
        users = analyze_users()

    # Generate recommendations
    recommendations = generate_recommendations(
        firewall,
        ssh,
        fail2ban,
        threats,
        services,
        docker,
        updates,
        mac,
        kernel,
        ssl,
        disk,
        cve,
        cis,
        containers,
        nist,
        pci,
        webheaders,
        filesystem,
        network,
        users,
    )

    # Generate security analysis summary
    analysis = generate_security_analysis(
        firewall,
        ssh,
        fail2ban,
        threats,
        services,
        docker,
        updates,
        mac,
        kernel,
        ssl,
        disk,
        cve,
        cis,
        containers,
        nist,
        pci,
        webheaders,
        filesystem,
        network,
        users,
        recommendations,
    )

    # Build report
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "hostname": hostname,
        "os": f"{os_info['system']} ({os_info['distro']})",
        "kernel": os_info["kernel"],
        "analysis": analysis,
        "firewall": firewall,
        "ssh": ssh,
        "threats": threats,
        "fail2ban": fail2ban,
        "services": services,
        "docker": docker,
        "updates": updates,
        "mac": mac,
        "kernel_hardening": kernel,
        "ssl_certificates": ssl,
        "disk_usage": disk,
        "cve_vulnerabilities": cve,
        "cis_benchmark": cis,
        "container_security": containers,
        "nist_800_53": nist,
        "pci_dss": pci,
        "web_security_headers": webheaders,
        "filesystem_security": filesystem,
        "network_connections": network,
        "user_audit": users,
        "recommendations": recommendations,
    }

    return report


def generate_security_analysis(
    firewall,
    ssh,
    fail2ban,
    threats,
    services,
    docker,
    updates,
    mac,
    kernel,
    ssl,
    disk,
    cve,
    cis,
    containers,
    nist,
    pci,
    webheaders,
    filesystem,
    network,
    users,
    recommendations,
):
    """Generate human-readable security analysis summary using rule-based evaluation."""
    issues = []
    warnings = []
    good_practices = []
    suspicious = []

    # Data-driven analysis rules configuration
    # Each rule: (analyzer_data, conditions, message, category)
    analysis_rules = [
        # Firewall
        (
            firewall,
            {"field": "active", "op": "==", "value": False},
            "No active firewall detected - server is completely exposed",
            "issues",
        ),
        (
            firewall,
            {"field": "default_policy", "op": "==", "value": "deny"},
            "Firewall follows best practice with default deny policy",
            "good",
        ),
        (
            firewall,
            [
                {"field": "active", "op": "==", "value": True},
                {"field": "default_policy", "op": "!=", "value": "deny"},
            ],
            "Firewall default policy is not restrictive enough",
            "warnings",
        ),
        # SSH
        (
            ssh,
            {"field": "permit_root_login", "op": "==", "value": "no"},
            "Root login via SSH is properly disabled",
            "good",
        ),
        (
            ssh,
            {"field": "permit_root_login", "op": "!=", "value": "no"},
            "Root login is enabled - major security risk",
            "issues",
        ),
        (
            ssh,
            {"field": "password_auth", "op": "==", "value": "no"},
            "Password authentication disabled, key-based auth only",
            "good",
        ),
        (
            ssh,
            {"field": "password_auth", "op": "==", "value": "yes"},
            "Password authentication enabled - brute force attacks possible",
            "warnings",
        ),
        (
            ssh,
            {"field": "port", "op": "!=", "value": 22},
            "SSH running on non-standard port {port} reduces automated attacks",
            "good",
        ),
        # Threats
        (
            threats,
            {"field": "total_attempts", "op": ">", "value": 100},
            "High number of failed login attempts ({total_attempts}) detected",
            "warnings",
        ),
        (
            threats,
            {"field": "total_attempts", "op": ">", "value": 1000},
            "Unusually high attack volume: {total_attempts} attempts in {period_days} days",
            "suspicious",
        ),
        # Services
        (
            services,
            {"field": "exposed_services", "op": ">", "value": 10},
            "{exposed_services} services exposed to internet - large attack surface",
            "warnings",
        ),
        (
            services,
            {"field": "systemd.critical_down", "op": ">", "value": 0},
            "{systemd.critical_down} critical service(s) are down or degraded",
            "issues",
        ),
        (
            services,
            {"field": "systemd.failed_count", "op": ">", "value": 0},
            "{systemd.failed_count} systemd unit(s) in failed state",
            "warnings",
        ),
        # Docker
        (
            docker,
            [
                {"field": "installed", "op": "==", "value": True},
                {"field": "running_containers", "op": ">", "value": 0},
                {"field": "rootless", "op": "==", "value": True},
            ],
            "Docker running in rootless mode for better isolation",
            "good",
        ),
        (
            docker,
            [
                {"field": "installed", "op": "==", "value": True},
                {"field": "running_containers", "op": ">", "value": 0},
                {"field": "rootless", "op": "==", "value": False},
            ],
            "Docker running as root - consider rootless mode for production",
            "warnings",
        ),
        # Updates
        (
            updates,
            {"field": "security_updates", "op": ">", "value": 10},
            "{security_updates} critical security updates pending - apply immediately",
            "issues",
        ),
        (
            updates,
            [
                {"field": "security_updates", "op": ">", "value": 0},
                {"field": "security_updates", "op": "<=", "value": 10},
            ],
            "{security_updates} security updates available",
            "warnings",
        ),
        (
            updates,
            {"field": "security_updates", "op": "==", "value": 0},
            "System is up to date with security patches",
            "good",
        ),
        # MAC
        (
            mac,
            {"field": "enabled", "op": "==", "value": True},
            "Mandatory Access Control ({type}) is enabled and active",
            "good",
        ),
        (
            mac,
            {"field": "enabled", "op": "==", "value": False},
            "No MAC system (AppArmor/SELinux) detected - missing additional security layer",
            "warnings",
        ),
        # Kernel
        (
            kernel,
            {"field": "hardening_percentage", "op": ">=", "value": 80},
            "Excellent kernel hardening ({hardening_percentage}%)",
            "good",
        ),
        (
            kernel,
            [
                {"field": "hardening_percentage", "op": ">=", "value": 60},
                {"field": "hardening_percentage", "op": "<", "value": 80},
            ],
            "Moderate kernel hardening ({hardening_percentage}%) - room for improvement",
            "warnings",
        ),
        (
            kernel,
            {"field": "hardening_percentage", "op": "<", "value": 60},
            "Poor kernel hardening ({hardening_percentage}%) - critical parameters not configured",
            "issues",
        ),
        # Fail2ban
        (
            fail2ban,
            [
                {"field": "installed", "op": "==", "value": True},
                {"field": "active", "op": "==", "value": True},
            ],
            "Fail2ban active for automated intrusion prevention",
            "good",
        ),
        # SSL
        (
            ssl,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "expired", "op": ">", "value": 0},
            ],
            "{expired} SSL certificate(s) have EXPIRED - critical issue",
            "issues",
        ),
        (
            ssl,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "expiring_soon_30days", "op": ">", "value": 0},
            ],
            "{expiring_soon_30days} SSL certificate(s) expiring in less than 30 days",
            "warnings",
        ),
        (
            ssl,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "total_certificates", "op": ">", "value": 0},
                {"field": "expired", "op": "==", "value": 0},
                {"field": "expiring_soon_30days", "op": "==", "value": 0},
            ],
            "All {total_certificates} SSL certificates are valid and not expiring soon",
            "good",
        ),
        # Disk
        (
            disk,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "critical_count", "op": ">", "value": 0},
            ],
            "{critical_count} filesystem(s) critically low on space (>90% full)",
            "issues",
        ),
        (
            disk,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "warning_count", "op": ">", "value": 0},
                {"field": "critical_count", "op": "==", "value": 0},
            ],
            "{warning_count} filesystem(s) running low on space (>70% full)",
            "warnings",
        ),
        (
            disk,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "critical_count", "op": "==", "value": 0},
                {"field": "warning_count", "op": "==", "value": 0},
            ],
            "All filesystems have adequate free space",
            "good",
        ),
        # CVE
        (
            cve,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "critical_vulnerabilities", "op": ">", "value": 0},
            ],
            "{critical_vulnerabilities} CRITICAL CVE vulnerabilities detected - patch immediately",
            "issues",
        ),
        (
            cve,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "high_vulnerabilities", "op": ">", "value": 0},
            ],
            "{high_vulnerabilities} high-severity CVE vulnerabilities found",
            "warnings",
        ),
        (
            cve,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "vulnerabilities_found", "op": ">", "value": 0},
            ],
            "{vulnerabilities_found} known vulnerabilities detected",
            "warnings",
        ),
        # CIS
        (
            cis,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "compliance_percentage", "op": ">=", "value": 90},
            ],
            "Excellent CIS Benchmark compliance ({compliance_percentage}%)",
            "good",
        ),
        (
            cis,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "compliance_percentage", "op": ">=", "value": 70},
                {"field": "compliance_percentage", "op": "<", "value": 90},
            ],
            "Moderate CIS compliance ({compliance_percentage}%) - {failed} controls failing",
            "warnings",
        ),
        (
            cis,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "compliance_percentage", "op": "<", "value": 70},
            ],
            "Poor CIS compliance ({compliance_percentage}%) - {failed} controls failing",
            "issues",
        ),
        # Containers
        (
            containers,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "critical_vulnerabilities", "op": ">", "value": 0},
            ],
            "{critical_vulnerabilities} CRITICAL vulnerabilities in container images",
            "issues",
        ),
        (
            containers,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "high_vulnerabilities", "op": ">", "value": 0},
            ],
            "{high_vulnerabilities} HIGH vulnerabilities in container images",
            "warnings",
        ),
        # NIST
        (
            nist,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "compliance_percentage", "op": ">=", "value": 80},
            ],
            "Good NIST 800-53 compliance ({compliance_percentage}%)",
            "good",
        ),
        (
            nist,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "failed", "op": ">", "value": 0},
            ],
            "NIST 800-53: {failed} controls failing",
            "warnings",
        ),
        # PCI
        (
            pci,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "compliance_percentage", "op": "<", "value": 100},
            ],
            "PCI-DSS compliance at {compliance_percentage}% - {failed} controls failing",
            "issues",
        ),
        (
            pci,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "compliance_percentage", "op": "==", "value": 100},
            ],
            "Full PCI-DSS technical baseline compliance",
            "good",
        ),
        # Web Headers
        (
            webheaders,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "total_missing_high", "op": ">", "value": 0},
            ],
            "{total_missing_high} critical security headers missing from web server",
            "issues",
        ),
        (
            webheaders,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "total_missing_medium", "op": ">", "value": 0},
            ],
            "{total_missing_medium} security headers missing - consider adding",
            "warnings",
        ),
        # Filesystem
        (
            filesystem,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "world_writable_files", "op": ">", "value": 0},
            ],
            "{world_writable_files} world-writable files found - permission issue",
            "issues",
        ),
        (
            filesystem,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "suid_sgid_suspicious", "op": ">", "value": 5},
            ],
            "{suid_sgid_suspicious} non-standard SUID binaries - potential risk",
            "warnings",
        ),
        # Network
        (
            network,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "suspicious_connections", "op": ">", "value": 0},
            ],
            "{suspicious_connections} suspicious network connections detected",
            "suspicious",
        ),
        (
            network,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "listening_services", "op": ">", "value": 20},
            ],
            "{listening_services} services listening - large attack surface",
            "warnings",
        ),
        # Users
        (
            users,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "uid_zero_users", "op": ">", "value": 0},
            ],
            "{uid_zero_users} unauthorized users with root privileges (UID 0)",
            "issues",
        ),
        (
            users,
            [
                {"field": "checked", "op": "==", "value": True},
                {"field": "users_without_password", "op": ">", "value": 0},
            ],
            "{users_without_password} user accounts without password set",
            "warnings",
        ),
    ]

    # Process rules
    for rule in analysis_rules:
        analyzer_data, conditions, message, category = rule

        # Handle both single condition dict and list of conditions (AND logic)
        condition_list = conditions if isinstance(conditions, list) else [conditions]

        # Evaluate all conditions (AND logic)
        if all(_evaluate_condition(analyzer_data, cond) for cond in condition_list):
            formatted_msg = _format_message(message, analyzer_data)

            if category == "issues":
                issues.append(formatted_msg)
            elif category == "warnings":
                warnings.append(formatted_msg)
            elif category == "good":
                good_practices.append(formatted_msg)
            elif category == "suspicious":
                suspicious.append(formatted_msg)

    # Overall assessment
    critical_count = len([r for r in recommendations if r["priority"] == "critical"])
    high_count = len([r for r in recommendations if r["priority"] == "high"])

    if critical_count > 0:
        overall_status = "CRITICAL"
        overall_summary = (
            f"Server has {critical_count} critical security issues requiring immediate attention."
        )
    elif high_count > 3:
        overall_status = "POOR"
        overall_summary = (
            f"Server has {high_count} high-priority security issues that should be addressed soon."
        )
    elif len(issues) > 0:
        overall_status = "NEEDS_IMPROVEMENT"
        overall_summary = (
            "Server has security issues that should be fixed to improve security posture."
        )
    elif len(warnings) > 3:
        overall_status = "FAIR"
        overall_summary = "Server security is acceptable but several improvements recommended."
    else:
        overall_status = "GOOD"
        overall_summary = (
            "Server follows security best practices with only minor improvements needed."
        )

    return {
        "overall_status": overall_status,
        "summary": overall_summary,
        "issues": issues,
        "warnings": warnings,
        "good_practices": good_practices,
        "suspicious_activity": suspicious,
        "score": {
            "critical_issues": critical_count,
            "high_priority_issues": high_count,
            "good_practices_followed": len(good_practices),
            "warnings": len(warnings),
        },
    }


def generate_recommendations(
    firewall,
    ssh,
    fail2ban,
    threats,
    services,
    docker,
    updates,
    mac,
    kernel,
    ssl,
    disk,
    cve,
    cis,
    containers,
    nist,
    pci,
    webheaders,
    filesystem,
    network,
    users,
):
    """Generate prioritized security recommendations."""
    recommendations = []

    # Handle firewall-specific recommendations
    if firewall:
        if not firewall["active"]:
            recommendations.append(
                {
                    "priority": "critical",
                    "title": "Enable firewall",
                    "description": "No active firewall detected. Install and enable ufw or firewalld.",
                    "command": "sudo ufw enable",
                }
            )
        elif firewall["default_policy"] != "deny":
            recommendations.append(
                {
                    "priority": "high",
                    "title": "Set restrictive firewall policy",
                    "description": "Default policy should deny incoming connections.",
                    "command": "sudo ufw default deny incoming",
                }
            )

    # Handle fail2ban/threats-specific recommendations
    if fail2ban and threats:
        if not fail2ban["installed"] and threats["total_attempts"] > 50:
            recommendations.append(
                {
                    "priority": "medium",
                    "title": "Install fail2ban",
                    "description": f"Detected {threats['total_attempts']} failed login attempts. Fail2ban can auto-ban attackers.",
                    "command": "sudo apt install fail2ban",
                }
            )

    if threats and threats["total_attempts"] > 1000:
        recommendations.append(
            {
                "priority": "medium",
                "title": "High number of attack attempts",
                "description": f"{threats['total_attempts']} failed logins in {threats['period_days']} days. Consider stricter policies.",
                "command": None,
            }
        )

    # High-priority issues that should appear first (CVE, containers, PCI, users)
    high_priority_analyzers = [cve, containers, pci, users]
    for analyzer in high_priority_analyzers:
        issues = _collect_issues_from_analyzer(analyzer)
        _add_issues_to_recommendations_prioritized(recommendations, issues, insert_at_front=True)

    # Standard analyzers - append in order
    standard_analyzers = [
        ssh,
        services,
        docker,
        updates,
        mac,
        ssl,
        disk,
        cis,
        nist,
        webheaders,
        filesystem,
        network,
    ]
    for analyzer in standard_analyzers:
        issues = _collect_issues_from_analyzer(analyzer)
        _add_issues_to_recommendations(recommendations, issues)

    # Kernel needs special handling (sort by severity, limit to top issues)
    if kernel:
        kernel_issues = sorted(
            kernel.get("issues", []),
            key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4),
        )
        _add_issues_to_recommendations(recommendations, kernel_issues[:MAX_KERNEL_ISSUES_REPORT])

    return recommendations
