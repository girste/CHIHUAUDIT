"""Main security audit orchestrator."""

import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Callable

from .utils.detect import get_os_info
from .utils.privacy import mask_ip, get_masked_hostname
from .utils.config import load_config
from .utils.analyzer_registry import get_all_analyzers
from .utils.rules_loader import load_analysis_rules
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


def _run_analyzer_with_timeout(
    analyzer_func: Callable,
    analyzer_name: str,
    timeout: int,
    log_func: Callable,
    **kwargs,
) -> Optional[Dict[str, Any]]:
    """
    Execute analyzer with timeout and error handling.

    Returns analyzer result dict or None on failure/timeout.
    Logs progress and errors via log_func.
    """
    try:
        log_func(f"Analyzing {analyzer_name}...")
        result = analyzer_func(**kwargs)
        return result
    except FuturesTimeoutError:
        log_func(f"WARNING: {analyzer_name} analyzer timed out after {timeout}s")
        return None
    except Exception as e:
        log_func(f"WARNING: {analyzer_name} analyzer failed: {str(e)[:100]}")
        return None


def _get_analyzer_registry(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Build registry of all security analyzers with metadata.

    Uses centralized analyzer_registry module for cleaner management.

    Returns list of dicts with:
    - name: analyzer identifier
    - func: analyzer function
    - enabled: whether analyzer is enabled in config
    - kwargs: optional kwargs for analyzer
    """
    analyzers = get_all_analyzers(config)

    # Convert AnalyzerMetadata to legacy dict format for backward compatibility
    return [
        {
            "name": a.name,
            "func": a.func,
            "enabled": True,  # Already filtered by get_all_analyzers
            "kwargs": a.kwargs,
        }
        for a in analyzers
    ]


def calculate_profile_scores(cis, nist, pci):
    """
    Calculate aggregate security scores for each profile level.

    Combines weighted scores from CIS, NIST, and PCI-DSS compliance frameworks.

    Returns dict with profile names as keys and aggregate scores as values.
    """
    from .profile_weights import PROFILES, get_profile_recommendation

    profile_scores = {}

    # Extract profile scores from each framework
    cis_profiles = cis.get("profile_scores", {}) if cis else {}
    nist_profiles = nist.get("profile_scores", {}) if nist else {}
    pci_profiles = pci.get("profile_scores", {}) if pci else {}

    # Calculate weighted average for each profile
    # CIS: 60%, NIST: 25%, PCI: 15% (CIS has most controls)
    for profile_name in PROFILES.keys():
        cis_score = cis_profiles.get(profile_name, 0)
        nist_score = nist_profiles.get(profile_name, 0)
        pci_score = pci_profiles.get(profile_name, 0)

        # Weighted average
        aggregate_score = (cis_score * 0.6) + (nist_score * 0.25) + (pci_score * 0.15)
        profile_scores[profile_name] = round(aggregate_score, 1)

    # Determine recommended profile
    recommended_profile = get_profile_recommendation(profile_scores)

    return {
        "profile_scores": profile_scores,
        "recommended_profile": recommended_profile,
        "profile_details": PROFILES,
        "framework_breakdown": {
            "cis": cis_profiles,
            "nist": nist_profiles,
            "pci": pci_profiles,
        }
    }


def run_audit(mask_data=None, verbose=False):
    """
    Run complete security audit and return structured report.

    Executes 20+ security analyzers in parallel using ThreadPoolExecutor.
    Performance: ~300-500% faster than sequential execution (1-6s vs 5-30s).
    """
    config = load_config()

    if mask_data is None:
        mask_data = config["mask_data"]

    def log(msg):
        if verbose:
            print(f"  {msg}", flush=True)

    os_info = get_os_info()
    hostname = get_masked_hostname() if mask_data else os_info.get("hostname", "unknown")

    # Build analyzer registry with metadata
    registry = _get_analyzer_registry(config)
    enabled_analyzers = [a for a in registry if a["enabled"]]

    # Determine optimal worker count (CPU count * 2 for I/O-bound tasks)
    max_workers = min(len(enabled_analyzers), (os.cpu_count() or 4) * 2)
    analyzer_timeout = config.get("analyzer_timeout", 10)  # seconds

    # Execute all analyzers in parallel with timeout and error handling
    results_map = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all enabled analyzers
        futures = {
            executor.submit(
                _run_analyzer_with_timeout,
                analyzer_func=analyzer["func"],
                analyzer_name=analyzer["name"],
                timeout=analyzer_timeout,
                log_func=log,
                **analyzer["kwargs"],
            ): analyzer["name"]
            for analyzer in enabled_analyzers
        }

        # Collect results as they complete
        for future in futures:
            analyzer_name = futures[future]
            try:
                result = future.result(timeout=analyzer_timeout)
                results_map[analyzer_name] = result
            except FuturesTimeoutError:
                log(f"WARNING: {analyzer_name} exceeded timeout ({analyzer_timeout}s)")
                results_map[analyzer_name] = None
            except Exception as e:
                log(f"WARNING: {analyzer_name} failed: {str(e)[:100]}")
                results_map[analyzer_name] = None

    # Extract results from map (maintains backward compatibility)
    firewall = results_map.get("firewall")
    ssh = results_map.get("ssh")
    threats = results_map.get("threats")
    fail2ban = results_map.get("fail2ban")
    services = results_map.get("services")
    docker = results_map.get("docker")
    updates = results_map.get("updates")
    mac = results_map.get("mac")
    kernel = results_map.get("kernel")
    ssl = results_map.get("ssl")
    disk = results_map.get("disk")
    cve = results_map.get("cve")
    cis = results_map.get("cis")
    containers = results_map.get("containers")
    nist = results_map.get("nist")
    pci = results_map.get("pci")
    webheaders = results_map.get("webheaders")
    filesystem = results_map.get("filesystem")
    network = results_map.get("network")
    users = results_map.get("users")
    rootkit = results_map.get("rootkit")
    sudoers = results_map.get("sudoers")
    system_hardening = results_map.get("system_hardening")

    # Apply privacy masking to threat analysis results
    if mask_data and threats and threats.get("top_attackers"):
        for attacker in threats["top_attackers"]:
            attacker["ip"] = mask_ip(attacker["ip"])

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
        rootkit,
        sudoers,
        system_hardening,
    )

    # Calculate multi-level profile scores
    profile_analysis = calculate_profile_scores(cis, nist, pci)

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
        rootkit,
        sudoers,
        system_hardening,
        recommendations,
        profile_analysis,
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
        "rootkit_detection": rootkit,
        "sudoers_audit": sudoers,
        "system_hardening": system_hardening,
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
    rootkit,
    sudoers,
    system_hardening,
    recommendations,
    profile_analysis=None,
):
    """Generate human-readable security analysis summary using rule-based evaluation."""
    issues = []
    warnings = []
    good_practices = []
    suspicious = []

    # Load analysis rules from YAML configuration
    rules_by_analyzer = load_analysis_rules()

    # Build analyzer data map for easy lookup
    analyzer_data_map = {
        "firewall": firewall,
        "ssh": ssh,
        "threats": threats,
        "services": services,
        "docker": docker,
        "updates": updates,
        "mac": mac,
        "kernel": kernel,
        "fail2ban": fail2ban,
        "ssl": ssl,
        "disk": disk,
        "cve": cve,
        "cis": cis,
        "nist": nist,
        "pci": pci,
        "containers": containers,
        "rootkit": rootkit,
        "users": users,
    }

    # Convert YAML rules to legacy format for processing
    analysis_rules = []
    for analyzer_name, rules in rules_by_analyzer.items():
        analyzer_data = analyzer_data_map.get(analyzer_name)
        if analyzer_data is None:
            continue

        for rule in rules:
            conditions = rule["conditions"]
            message = rule["message"]
            category = rule["category"]
            analysis_rules.append((analyzer_data, conditions, message, category))

    # Fallback: if no rules loaded, use empty list (system will still work with recommendations)
    if not analysis_rules:
        import warnings

        warnings.warn("No analysis rules loaded - analysis summary will be limited")

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

    result = {
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

    # Add multi-level profile analysis if available
    if profile_analysis:
        result["profile_analysis"] = profile_analysis

    return result


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
    rootkit,
    sudoers,
    system_hardening,
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
        rootkit,
        sudoers,
        system_hardening,
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
