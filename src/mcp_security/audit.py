"""Main security audit orchestrator."""

from datetime import datetime, timezone

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
    """Generate human-readable security analysis summary."""
    issues = []
    warnings = []
    good_practices = []
    suspicious = []

    if firewall:
        if not firewall["active"]:
            issues.append("No active firewall detected - server is completely exposed")
        elif firewall["default_policy"] == "deny":
            good_practices.append("Firewall follows best practice with default deny policy")
        else:
            warnings.append("Firewall default policy is not restrictive enough")

    if ssh:
        if ssh["permit_root_login"] == "no":
            good_practices.append("Root login via SSH is properly disabled")
        else:
            issues.append("Root login is enabled - major security risk")

        if ssh["password_auth"] == "no":
            good_practices.append("Password authentication disabled, key-based auth only")
        elif ssh["password_auth"] == "yes":
            warnings.append("Password authentication enabled - brute force attacks possible")

        if ssh["port"] != 22:
            good_practices.append(
                f"SSH running on non-standard port {ssh['port']} reduces automated attacks"
            )

    if threats:
        if threats["total_attempts"] > 100:
            warnings.append(
                f"High number of failed login attempts ({threats['total_attempts']}) detected"
            )
        if threats["total_attempts"] > 1000:
            suspicious.append(
                f"Unusually high attack volume: {threats['total_attempts']} attempts in {threats['period_days']} days"
            )
        if "ssh_brute_force" in threats.get("patterns", []):
            suspicious.append("SSH brute force attack pattern detected")
        if "distributed_attack" in threats.get("patterns", []):
            suspicious.append("Distributed attack from multiple IPs detected")

    if services:
        if services["exposed_services"] > 10:
            warnings.append(
                f"{services['exposed_services']} services exposed to internet - large attack surface"
            )
        if len(services["by_category"]["risky"]) > 0:
            issues.append(
                f"Database or sensitive services exposed: {', '.join([s['name'] for s in services['by_category']['risky']])}"
            )

    if docker:
        if docker["installed"] and docker["running_containers"] > 0:
            if docker["rootless"]:
                good_practices.append("Docker running in rootless mode for better isolation")
            else:
                warnings.append("Docker running as root - consider rootless mode for production")

            if docker["privileged_containers"]:
                issues.append(
                    f"Privileged containers detected: {', '.join(docker['privileged_containers'])} - security risk"
                )

    if updates:
        if updates["security_updates"] > 10:
            issues.append(
                f"{updates['security_updates']} critical security updates pending - apply immediately"
            )
        elif updates["security_updates"] > 0:
            warnings.append(f"{updates['security_updates']} security updates available")
        else:
            good_practices.append("System is up to date with security patches")

    if mac:
        if mac["enabled"]:
            good_practices.append(f"Mandatory Access Control ({mac['type']}) is enabled and active")
        else:
            warnings.append(
                "No MAC system (AppArmor/SELinux) detected - missing additional security layer"
            )

    if kernel:
        if kernel["hardening_percentage"] >= 80:
            good_practices.append(f"Excellent kernel hardening ({kernel['hardening_percentage']}%)")
        elif kernel["hardening_percentage"] >= 60:
            warnings.append(
                f"Moderate kernel hardening ({kernel['hardening_percentage']}%) - room for improvement"
            )
        else:
            issues.append(
                f"Poor kernel hardening ({kernel['hardening_percentage']}%) - critical parameters not configured"
            )

    if fail2ban:
        if fail2ban["installed"] and fail2ban["active"]:
            good_practices.append("Fail2ban active for automated intrusion prevention")
        elif not fail2ban["installed"] and threats and threats["total_attempts"] > 50:
            warnings.append("Fail2ban not installed despite active attacks")

    if ssl:
        if ssl["checked"]:
            if ssl["expired"] > 0:
                issues.append(f"{ssl['expired']} SSL certificate(s) have EXPIRED - critical issue")
            elif ssl["expiring_soon_30days"] > 0:
                warnings.append(
                    f"{ssl['expiring_soon_30days']} SSL certificate(s) expiring in less than 30 days"
                )
            elif ssl["total_certificates"] > 0:
                good_practices.append(
                    f"All {ssl['total_certificates']} SSL certificates are valid and not expiring soon"
                )

    if disk:
        if disk["checked"]:
            if disk["critical_count"] > 0:
                issues.append(
                    f"{disk['critical_count']} filesystem(s) critically low on space (>90% full)"
                )
            elif disk["warning_count"] > 0:
                warnings.append(
                    f"{disk['warning_count']} filesystem(s) running low on space (>70% full)"
                )
            else:
                good_practices.append("All filesystems have adequate free space")

    if cve:
        if cve["checked"]:
            if cve["critical_vulnerabilities"] > 0:
                issues.append(
                    f"{cve['critical_vulnerabilities']} CRITICAL CVE vulnerabilities detected - patch immediately"
                )
            elif cve["high_vulnerabilities"] > 0:
                warnings.append(
                    f"{cve['high_vulnerabilities']} high-severity CVE vulnerabilities found"
                )
            elif cve["vulnerabilities_found"] > 0:
                warnings.append(f"{cve['vulnerabilities_found']} known vulnerabilities detected")

    if services:
        if services.get("systemd", {}).get("critical_down", 0) > 0:
            issues.append(
                f"{services['systemd']['critical_down']} critical service(s) are down or degraded"
            )
        elif services.get("systemd", {}).get("failed_count", 0) > 0:
            warnings.append(
                f"{services['systemd']['failed_count']} systemd unit(s) in failed state"
            )

    if cis:
        if cis["checked"]:
            if cis["compliance_percentage"] >= 90:
                good_practices.append(
                    f"Excellent CIS Benchmark compliance ({cis['compliance_percentage']}%)"
                )
            elif cis["compliance_percentage"] >= 70:
                warnings.append(
                    f"Moderate CIS compliance ({cis['compliance_percentage']}%) - {cis['failed']} controls failing"
                )
            else:
                issues.append(
                    f"Poor CIS compliance ({cis['compliance_percentage']}%) - {cis['failed']} controls failing"
                )

    if containers:
        if containers["checked"]:
            if containers["critical_vulnerabilities"] > 0:
                issues.append(
                    f"{containers['critical_vulnerabilities']} CRITICAL vulnerabilities in container images"
                )
            elif containers["high_vulnerabilities"] > 0:
                warnings.append(
                    f"{containers['high_vulnerabilities']} HIGH vulnerabilities in container images"
                )

    if nist:
        if nist["checked"] and nist["compliance_percentage"] >= 80:
            good_practices.append(f"Good NIST 800-53 compliance ({nist['compliance_percentage']}%)")
        elif nist["checked"] and nist["failed"] > 0:
            warnings.append(f"NIST 800-53: {nist['failed']} controls failing")

    if pci:
        if pci["checked"] and pci["compliance_percentage"] < 100:
            issues.append(
                f"PCI-DSS compliance at {pci['compliance_percentage']}% - {pci['failed']} controls failing"
            )
        elif pci["checked"]:
            good_practices.append("Full PCI-DSS technical baseline compliance")

    if webheaders:
        if webheaders["checked"]:
            if webheaders["total_missing_high"] > 0:
                issues.append(
                    f"{webheaders['total_missing_high']} critical security headers missing from web server"
                )
            elif webheaders["total_missing_medium"] > 0:
                warnings.append(
                    f"{webheaders['total_missing_medium']} security headers missing - consider adding"
                )

    if filesystem:
        if filesystem["checked"]:
            if filesystem["world_writable_files"] > 0:
                issues.append(
                    f"{filesystem['world_writable_files']} world-writable files found - permission issue"
                )
            if filesystem["suid_sgid_suspicious"] > 5:
                warnings.append(
                    f"{filesystem['suid_sgid_suspicious']} non-standard SUID binaries - potential risk"
                )

    if network:
        if network["checked"]:
            if network["suspicious_connections"] > 0:
                suspicious.append(
                    f"{network['suspicious_connections']} suspicious network connections detected"
                )
            if network["listening_services"] > 20:
                warnings.append(
                    f"{network['listening_services']} services listening - large attack surface"
                )

    if users:
        if users["checked"]:
            if users["uid_zero_users"] > 0:
                issues.append(
                    f"{users['uid_zero_users']} unauthorized users with root privileges (UID 0)"
                )
            if users["users_without_password"] > 0:
                warnings.append(
                    f"{users['users_without_password']} user accounts without password set"
                )

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

    if ssh:
        for issue in ssh.get("issues", []):
            recommendations.append(
                {
                    "priority": issue["severity"],
                    "title": issue["message"],
                    "description": issue["recommendation"],
                    "command": None,
                }
            )

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

    if threats:
        if threats["total_attempts"] > 1000:
            recommendations.append(
                {
                    "priority": "medium",
                    "title": "High number of attack attempts",
                    "description": f"{threats['total_attempts']} failed logins in {threats['period_days']} days. Consider stricter policies.",
                    "command": None,
                }
            )

    if services:
        for issue in services.get("issues", []):
            recommendations.append(
                {
                    "priority": issue["severity"],
                    "title": issue["message"],
                    "description": issue["recommendation"],
                    "command": None,
                }
            )

    if docker:
        for issue in docker.get("issues", []):
            recommendations.append(
                {
                    "priority": issue["severity"],
                    "title": issue["message"],
                    "description": issue["recommendation"],
                    "command": None,
                }
            )

    if updates:
        for issue in updates.get("issues", []):
            recommendations.append(
                {
                    "priority": issue["severity"],
                    "title": issue["message"],
                    "description": issue["recommendation"],
                    "command": None,
                }
            )

    if mac:
        for issue in mac.get("issues", []):
            recommendations.append(
                {
                    "priority": issue["severity"],
                    "title": issue["message"],
                    "description": issue["recommendation"],
                    "command": None,
                }
            )

    if kernel:
        kernel_issues = sorted(
            kernel.get("issues", []),
            key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4),
        )
        for issue in kernel_issues[:3]:
            recommendations.append(
                {
                    "priority": issue["severity"],
                    "title": issue["message"],
                    "description": issue["recommendation"],
                    "command": None,
                }
            )

    if ssl:
        for issue in ssl.get("issues", []):
            recommendations.append(
                {
                    "priority": issue["severity"],
                    "title": issue["message"],
                    "description": issue["recommendation"],
                    "command": None,
                }
            )

    if disk:
        for issue in disk.get("issues", []):
            recommendations.append(
                {
                    "priority": issue["severity"],
                    "title": issue["message"],
                    "description": issue["recommendation"],
                    "command": None,
                }
            )

    if cve:
        for issue in cve.get("issues", []):
            recommendations.insert(
                0,
                {
                    "priority": issue["severity"],
                    "title": issue["message"],
                    "description": issue["recommendation"],
                    "command": None,
                },
            )

    if cis:
        for issue in cis.get("issues", []):
            recommendations.append(
                {
                    "priority": issue["severity"],
                    "title": issue["message"],
                    "description": issue["recommendation"],
                    "command": None,
                }
            )

    if containers:
        for issue in containers.get("issues", []):
            recommendations.insert(
                0,
                {
                    "priority": issue["severity"],
                    "title": issue["message"],
                    "description": issue["recommendation"],
                    "command": None,
                },
            )

    if nist:
        for issue in nist.get("issues", []):
            recommendations.append(
                {
                    "priority": issue["severity"],
                    "title": issue["message"],
                    "description": issue["recommendation"],
                    "command": None,
                }
            )

    if pci:
        for issue in pci.get("issues", []):
            recommendations.insert(
                0,
                {
                    "priority": issue["severity"],
                    "title": issue["message"],
                    "description": issue["recommendation"],
                    "command": None,
                },
            )

    if webheaders:
        for issue in webheaders.get("issues", []):
            recommendations.append(
                {
                    "priority": issue["severity"],
                    "title": issue["message"],
                    "description": issue["recommendation"],
                    "command": None,
                }
            )

    if filesystem:
        for issue in filesystem.get("issues", []):
            recommendations.append(
                {
                    "priority": issue["severity"],
                    "title": issue["message"],
                    "description": issue["recommendation"],
                    "command": None,
                }
            )

    if network:
        for issue in network.get("issues", []):
            recommendations.append(
                {
                    "priority": issue["severity"],
                    "title": issue["message"],
                    "description": issue["recommendation"],
                    "command": None,
                }
            )

    if users:
        for issue in users.get("issues", []):
            recommendations.insert(
                0,
                {
                    "priority": issue["severity"],
                    "title": issue["message"],
                    "description": issue["recommendation"],
                    "command": None,
                },
            )

    return recommendations
