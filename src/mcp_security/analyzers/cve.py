"""CVE and vulnerability scanning module."""

import re
from typing import Optional
from ..utils.command import run_command

CRITICAL_PACKAGES = [
    "openssl",
    "libssl3",
    "libssl1.1",
    "openssh-server",
    "openssh-client",
    "sudo",
    "glibc",
    "libc6",
    "systemd",
    "docker.io",
    "containerd",
]

KNOWN_VULNERABILITIES = [
    {
        "packages": ["openssl", "libssl3", "libssl1.1"],
        "max_version": (1, 0, 1, "g"),
        "cve": "CVE-2014-0160",
        "name": "Heartbleed",
        "severity": "critical",
        "description": "OpenSSL Heartbleed vulnerability - allows reading memory",
    },
    {
        "packages": ["sudo"],
        "max_version": (1, 9, 5),
        "cve": "CVE-2021-3156",
        "name": "Baron Samedit",
        "severity": "critical",
        "description": "Heap-based buffer overflow in sudo - local privilege escalation",
    },
]

KERNEL_VULNERABILITIES = [
    {
        "max_version": (4, 8, 3),
        "cve": "CVE-2016-5195",
        "name": "Dirty COW",
        "severity": "critical",
        "description": "Linux kernel race condition - privilege escalation",
    },
]


def _parse_version(version_str):
    """Parse version string into comparable tuple."""
    match = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?([a-z])?", version_str)
    if not match:
        return None

    major, minor, patch, letter = match.groups()
    return (int(major), int(minor), int(patch) if patch else 0, letter if letter else "")


def _is_vulnerable(current_version, max_safe_version):
    """Check if current version is below max safe version."""
    if not current_version:
        return False

    for i, (curr, max_safe) in enumerate(zip(current_version, max_safe_version)):
        if i < len(max_safe_version):
            if curr < max_safe:
                return True
            if curr > max_safe:
                return False

    return False


def get_package_version(package_name: str) -> Optional[str]:
    """Get installed version of a package."""
    result = run_command(["dpkg-query", "-W", "-f=${Version}", package_name], timeout=5)
    return result.stdout.strip() if result and result.success else None


def get_kernel_version() -> Optional[str]:
    """Get current kernel version."""
    result = run_command(["uname", "-r"], timeout=5)
    return result.stdout.strip() if result and result.success else None


def check_critical_packages():
    """Check versions of critical security-sensitive packages."""
    installed = []
    for package in CRITICAL_PACKAGES:
        version = get_package_version(package)
        if version:
            installed.append({"package": package, "version": version})

    return installed


def check_package_vulnerabilities(packages):
    """Check installed packages against known vulnerabilities."""
    vulnerabilities = []

    for pkg in packages:
        pkg_name = pkg["package"]
        pkg_version_str = pkg["version"]
        pkg_version = _parse_version(pkg_version_str)

        if not pkg_version:
            continue

        for vuln in KNOWN_VULNERABILITIES:
            if pkg_name in vuln["packages"] and _is_vulnerable(pkg_version, vuln["max_version"]):
                vulnerabilities.append(
                    {
                        "package": pkg_name,
                        "version": pkg_version_str,
                        "cve": vuln["cve"],
                        "name": vuln["name"],
                        "severity": vuln["severity"],
                        "description": vuln["description"],
                    }
                )

    return vulnerabilities


def check_kernel_vulnerabilities(kernel_version_str):
    """Check kernel version against known vulnerabilities."""
    if not kernel_version_str:
        return []

    kernel_version = _parse_version(kernel_version_str)
    if not kernel_version:
        return []

    vulnerabilities = []
    for vuln in KERNEL_VULNERABILITIES:
        if _is_vulnerable(kernel_version, vuln["max_version"]):
            vulnerabilities.append(
                {
                    "package": "kernel",
                    "version": kernel_version_str,
                    "cve": vuln["cve"],
                    "name": vuln["name"],
                    "severity": vuln["severity"],
                    "description": vuln["description"],
                }
            )

    return vulnerabilities


def analyze_cve():
    """Analyze system for known CVE vulnerabilities."""
    packages = check_critical_packages()
    kernel_version = get_kernel_version()

    vulnerabilities = []
    vulnerabilities.extend(check_package_vulnerabilities(packages))
    vulnerabilities.extend(check_kernel_vulnerabilities(kernel_version))

    issues = [
        {
            "severity": vuln["severity"],
            "message": f"{vuln['name']} ({vuln['cve']}) detected in {vuln['package']} {vuln['version']}",
            "recommendation": f"Update {vuln['package']} immediately: sudo apt update && sudo apt upgrade {vuln['package']}",
        }
        for vuln in vulnerabilities
    ]

    return {
        "checked": True,
        "critical_packages_checked": len(packages),
        "kernel_version": kernel_version,
        "vulnerabilities_found": len(vulnerabilities),
        "critical_vulnerabilities": sum(1 for v in vulnerabilities if v["severity"] == "critical"),
        "high_vulnerabilities": sum(1 for v in vulnerabilities if v["severity"] == "high"),
        "packages": packages,
        "vulnerabilities": vulnerabilities,
        "issues": issues,
        "note": "Basic CVE check - for comprehensive scanning use dedicated tools like trivy, grype, or OpenVAS",
    }
