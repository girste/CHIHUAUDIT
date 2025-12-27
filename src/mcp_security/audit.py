"""Main security audit orchestrator."""

from datetime import datetime

from .analyzers.firewall import analyze_firewall
from .analyzers.ssh import analyze_ssh
from .analyzers.threats import analyze_threats
from .analyzers.fail2ban import analyze_fail2ban
from .analyzers.services import analyze_services
from .analyzers.docker_sec import analyze_docker
from .analyzers.updates import analyze_updates
from .analyzers.mac import analyze_mac
from .analyzers.kernel import analyze_kernel
from .utils.detect import get_os_info, get_auth_log_path
from .utils.privacy import mask_ip, get_masked_hostname


def run_audit(mask_data=True):
    """Run complete security audit and return structured report."""

    # System info
    os_info = get_os_info()
    hostname = get_masked_hostname() if mask_data else os_info.get("hostname", "unknown")

    # Firewall analysis
    firewall = analyze_firewall()

    # SSH analysis
    ssh = analyze_ssh()

    # Threat analysis
    log_path = get_auth_log_path()
    threats = analyze_threats(log_path, days=7)

    # Mask IPs if privacy enabled
    if mask_data and threats["top_attackers"]:
        for attacker in threats["top_attackers"]:
            attacker["ip"] = mask_ip(attacker["ip"])

    # Fail2ban analysis
    fail2ban = analyze_fail2ban()

    # Services and open ports analysis
    services = analyze_services()

    # Docker security analysis
    docker = analyze_docker()

    # Security updates check
    updates = analyze_updates()

    # Mandatory Access Control (AppArmor/SELinux)
    mac = analyze_mac()

    # Kernel hardening
    kernel = analyze_kernel()

    # Generate recommendations
    recommendations = generate_recommendations(
        firewall, ssh, fail2ban, threats, services, docker, updates, mac, kernel
    )

    # Generate security analysis summary
    analysis = generate_security_analysis(
        firewall, ssh, fail2ban, threats, services, docker, updates, mac, kernel, recommendations
    )

    # Build report
    report = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
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
        "recommendations": recommendations,
    }

    return report


def generate_security_analysis(firewall, ssh, fail2ban, threats, services, docker, updates, mac, kernel, recommendations):
    """Generate human-readable security analysis summary."""
    issues = []
    warnings = []
    good_practices = []
    suspicious = []

    # Firewall analysis
    if not firewall["active"]:
        issues.append("No active firewall detected - server is completely exposed")
    elif firewall["default_policy"] == "deny":
        good_practices.append("Firewall follows best practice with default deny policy")
    else:
        warnings.append("Firewall default policy is not restrictive enough")

    # SSH analysis
    if ssh["permit_root_login"] == "no":
        good_practices.append("Root login via SSH is properly disabled")
    else:
        issues.append("Root login is enabled - major security risk")

    if ssh["password_auth"] == "no":
        good_practices.append("Password authentication disabled, key-based auth only")
    elif ssh["password_auth"] == "yes":
        warnings.append("Password authentication enabled - brute force attacks possible")

    if ssh["port"] != 22:
        good_practices.append(f"SSH running on non-standard port {ssh['port']} reduces automated attacks")

    # Threat analysis
    if threats["total_attempts"] > 100:
        warnings.append(f"High number of failed login attempts ({threats['total_attempts']}) detected")
    if threats["total_attempts"] > 1000:
        suspicious.append(f"Unusually high attack volume: {threats['total_attempts']} attempts in {threats['period_days']} days")
    if "ssh_brute_force" in threats.get("patterns", []):
        suspicious.append("SSH brute force attack pattern detected")
    if "distributed_attack" in threats.get("patterns", []):
        suspicious.append("Distributed attack from multiple IPs detected")

    # Services analysis
    if services["exposed_services"] > 10:
        warnings.append(f"{services['exposed_services']} services exposed to internet - large attack surface")
    if len(services["by_category"]["risky"]) > 0:
        issues.append(f"Database or sensitive services exposed: {', '.join([s['name'] for s in services['by_category']['risky']])}")

    # Docker analysis
    if docker["installed"] and docker["running_containers"] > 0:
        if docker["rootless"]:
            good_practices.append("Docker running in rootless mode for better isolation")
        else:
            warnings.append("Docker running as root - consider rootless mode for production")

        if docker["privileged_containers"]:
            issues.append(f"Privileged containers detected: {', '.join(docker['privileged_containers'])} - security risk")

    # Updates analysis
    if updates["security_updates"] > 10:
        issues.append(f"{updates['security_updates']} critical security updates pending - apply immediately")
    elif updates["security_updates"] > 0:
        warnings.append(f"{updates['security_updates']} security updates available")
    else:
        good_practices.append("System is up to date with security patches")

    # MAC analysis
    if mac["enabled"]:
        good_practices.append(f"Mandatory Access Control ({mac['type']}) is enabled and active")
    else:
        warnings.append("No MAC system (AppArmor/SELinux) detected - missing additional security layer")

    # Kernel hardening
    if kernel["hardening_percentage"] >= 80:
        good_practices.append(f"Excellent kernel hardening ({kernel['hardening_percentage']}%)")
    elif kernel["hardening_percentage"] >= 60:
        warnings.append(f"Moderate kernel hardening ({kernel['hardening_percentage']}%) - room for improvement")
    else:
        issues.append(f"Poor kernel hardening ({kernel['hardening_percentage']}%) - critical parameters not configured")

    # Fail2ban
    if fail2ban["installed"] and fail2ban["active"]:
        good_practices.append("Fail2ban active for automated intrusion prevention")
    elif not fail2ban["installed"] and threats["total_attempts"] > 50:
        warnings.append("Fail2ban not installed despite active attacks")

    # Overall assessment
    critical_count = len([r for r in recommendations if r["priority"] == "critical"])
    high_count = len([r for r in recommendations if r["priority"] == "high"])

    if critical_count > 0:
        overall_status = "CRITICAL"
        overall_summary = f"Server has {critical_count} critical security issues requiring immediate attention."
    elif high_count > 3:
        overall_status = "POOR"
        overall_summary = f"Server has {high_count} high-priority security issues that should be addressed soon."
    elif len(issues) > 0:
        overall_status = "NEEDS_IMPROVEMENT"
        overall_summary = "Server has security issues that should be fixed to improve security posture."
    elif len(warnings) > 3:
        overall_status = "FAIR"
        overall_summary = "Server security is acceptable but several improvements recommended."
    else:
        overall_status = "GOOD"
        overall_summary = "Server follows security best practices with only minor improvements needed."

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
            "warnings": len(warnings)
        }
    }


def generate_recommendations(firewall, ssh, fail2ban, threats, services, docker, updates, mac, kernel):
    """Generate prioritized security recommendations."""
    recommendations = []

    # Firewall recommendations
    if not firewall["active"]:
        recommendations.append({
            "priority": "critical",
            "title": "Enable firewall",
            "description": "No active firewall detected. Install and enable ufw or firewalld.",
            "command": "sudo ufw enable"
        })
    elif firewall["default_policy"] != "deny":
        recommendations.append({
            "priority": "high",
            "title": "Set restrictive firewall policy",
            "description": "Default policy should deny incoming connections.",
            "command": "sudo ufw default deny incoming"
        })

    # SSH recommendations
    for issue in ssh.get("issues", []):
        priority = issue["severity"]
        recommendations.append({
            "priority": priority,
            "title": issue["message"],
            "description": issue["recommendation"],
            "command": None
        })

    # Fail2ban recommendations
    if not fail2ban["installed"] and threats["total_attempts"] > 50:
        recommendations.append({
            "priority": "medium",
            "title": "Install fail2ban",
            "description": f"Detected {threats['total_attempts']} failed login attempts. Fail2ban can auto-ban attackers.",
            "command": "sudo apt install fail2ban"
        })

    # Threat-based recommendations
    if threats["total_attempts"] > 1000:
        recommendations.append({
            "priority": "medium",
            "title": "High number of attack attempts",
            "description": f"{threats['total_attempts']} failed logins in {threats['period_days']} days. Consider stricter policies.",
            "command": None
        })

    # Services recommendations
    for issue in services.get("issues", []):
        recommendations.append({
            "priority": issue["severity"],
            "title": issue["message"],
            "description": issue["recommendation"],
            "command": None
        })

    # Docker recommendations
    for issue in docker.get("issues", []):
        recommendations.append({
            "priority": issue["severity"],
            "title": issue["message"],
            "description": issue["recommendation"],
            "command": None
        })

    # Updates recommendations
    for issue in updates.get("issues", []):
        recommendations.append({
            "priority": issue["severity"],
            "title": issue["message"],
            "description": issue["recommendation"],
            "command": None
        })

    # MAC (AppArmor/SELinux) recommendations
    for issue in mac.get("issues", []):
        recommendations.append({
            "priority": issue["severity"],
            "title": issue["message"],
            "description": issue["recommendation"],
            "command": None
        })

    # Kernel hardening recommendations (limit to top 3 most severe)
    kernel_issues = sorted(kernel.get("issues", []), key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4))
    for issue in kernel_issues[:3]:
        recommendations.append({
            "priority": issue["severity"],
            "title": issue["message"],
            "description": issue["recommendation"],
            "command": None
        })

    return recommendations
