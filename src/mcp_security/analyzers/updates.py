"""Security updates analysis."""

from ..utils.detect import run_with_sudo, get_distro


def check_apt_updates():
    """Check for available security updates on Debian/Ubuntu."""
    # Update package cache (non-invasive, just downloads metadata)
    run_with_sudo(["apt-get", "update", "-qq"])

    # Get upgradable packages
    result = run_with_sudo(["apt", "list", "--upgradable"])

    if not result:
        return None

    total_updates = 0
    security_updates = 0
    packages = []

    for line in result.stdout.split("\n"):
        if not line or line.startswith("Listing"):
            continue

        # Parse line: package/suite version arch [upgradable from: old_version]
        if "[upgradable" in line.lower():
            total_updates += 1

            # Check if it's a security update
            if "-security" in line or "security" in line.lower():
                security_updates += 1

                # Extract package name
                parts = line.split("/")
                if parts:
                    package_name = parts[0]
                    packages.append(package_name)

    return {
        "total_updates": total_updates,
        "security_updates": security_updates,
        "security_packages": packages[:10],  # Limit to first 10
    }


def check_yum_updates():
    """Check for available security updates on RHEL/CentOS."""
    result = run_with_sudo(["yum", "check-update", "--security", "-q"])

    if not result:
        return None

    # yum returns 100 if updates are available, 0 if none
    # Count lines that look like package updates
    updates = []
    for line in result.stdout.split("\n"):
        if line and not line.startswith("Security:") and "." in line:
            parts = line.split()
            if len(parts) >= 2:
                updates.append(parts[0])

    return {
        "total_updates": len(updates),
        "security_updates": len(updates),
        "security_packages": updates[:10],
    }


def analyze_updates():
    """Analyze available security updates."""
    distro = get_distro()

    if distro in ("debian", "arch"):
        updates_info = check_apt_updates()
    elif distro == "rhel":
        updates_info = check_yum_updates()
    else:
        updates_info = None

    if not updates_info:
        return {
            "available": False,
            "total_updates": 0,
            "security_updates": 0,
            "security_packages": [],
            "issues": [],
        }

    issues = []

    # Critical: many security updates
    if updates_info["security_updates"] > 10:
        issues.append(
            {
                "severity": "critical",
                "message": f"{updates_info['security_updates']} security updates available",
                "recommendation": "Apply security updates immediately with 'apt upgrade' or 'yum update'",
            }
        )
    elif updates_info["security_updates"] > 0:
        issues.append(
            {
                "severity": "high",
                "message": f"{updates_info['security_updates']} security updates available",
                "recommendation": "Apply security updates soon with 'apt upgrade' or 'yum update'",
            }
        )

    # Warning: many total updates
    if updates_info["total_updates"] > 50:
        issues.append(
            {
                "severity": "medium",
                "message": f"{updates_info['total_updates']} total updates available",
                "recommendation": "System may be outdated. Review and apply updates regularly.",
            }
        )

    return {
        "available": True,
        "total_updates": updates_info["total_updates"],
        "security_updates": updates_info["security_updates"],
        "security_packages": updates_info["security_packages"],
        "issues": issues,
    }
