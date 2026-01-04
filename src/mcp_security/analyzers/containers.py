"""Docker container image vulnerability scanning module."""

import json
from ..utils.command import run_command

CRITICAL_CVE_SCORE = 9.0
HIGH_CVE_SCORE = 7.0


def _run_docker_command(args, timeout=30):
    """Execute docker command safely."""
    result = run_command(["docker"] + args, timeout=timeout, capture_stderr=True)
    return result if result and result.success else None


def get_running_images():
    """Get list of currently running container images."""
    result = _run_docker_command(["ps", "--format", "{{.Image}}"])
    if not result:
        return []

    images = set()
    for line in result.stdout.strip().split("\n"):
        if line:
            images.add(line)

    return list(images)


def get_all_images():
    """Get list of all local Docker images."""
    result = _run_docker_command(["images", "--format", "{{.Repository}}:{{.Tag}}"])
    if not result:
        return []

    images = []
    for line in result.stdout.strip().split("\n"):
        if line and line != "<none>:<none>":
            images.append(line)

    return images


def inspect_image(image_name):
    """Get detailed image information."""
    result = _run_docker_command(["inspect", image_name])
    if not result:
        return None

    try:
        data = json.loads(result.stdout)
        if data and len(data) > 0:
            return data[0]
    except json.JSONDecodeError:
        pass

    return None


def scan_image_with_trivy(image_name):
    """Scan image for vulnerabilities using trivy if available."""
    result = run_command(
        ["trivy", "image", "--format", "json", "--quiet", image_name],
        timeout=120,
    )

    if result and result.success:
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            pass

    return None


def analyze_image_metadata(image_data):
    """Analyze image metadata for security issues."""
    issues = []

    config = image_data.get("Config", {})

    # Check if running as root
    user = config.get("User", "")
    if not user or user == "0" or user == "root":
        issues.append(
            {
                "severity": "medium",
                "type": "privilege",
                "message": "Container runs as root user",
                "recommendation": "Use USER directive in Dockerfile to run as non-root",
            }
        )

    # Check for exposed sensitive ports
    exposed_ports = config.get("ExposedPorts", {})
    sensitive_ports = {"22/tcp", "3306/tcp", "5432/tcp", "6379/tcp", "27017/tcp"}

    for port in exposed_ports.keys():
        if port in sensitive_ports:
            issues.append(
                {
                    "severity": "high",
                    "type": "exposure",
                    "message": f"Sensitive port {port} is exposed",
                    "recommendation": f"Avoid exposing {port} unless absolutely necessary",
                }
            )

    return issues


def analyze_containers():
    """Analyze Docker containers and images for vulnerabilities."""
    # Check if Docker is available
    result = _run_docker_command(["--version"])
    if not result:
        return {
            "checked": False,
            "message": "Docker not available or not running",
            "images": [],
            "issues": [],
        }

    running_images = get_running_images()
    all_images = get_all_images()

    scanned_images = []
    total_vulns = 0
    critical_vulns = 0
    high_vulns = 0
    issues = []

    # Check if trivy is available
    trivy_check = run_command(["which", "trivy"], timeout=5)
    trivy_available = trivy_check and trivy_check.success

    for image in running_images[:5]:  # Limit to 5 images for performance
        image_info = {
            "name": image,
            "running": True,
            "vulnerabilities": [],
            "metadata_issues": [],
        }

        # Scan with trivy if available
        if trivy_available:
            scan_result = scan_image_with_trivy(image)
            if scan_result and "Results" in scan_result:
                for result in scan_result.get("Results", []):
                    vulns = result.get("Vulnerabilities", [])
                    for vuln in vulns:
                        severity = vuln.get("Severity", "").upper()
                        if severity in ("CRITICAL", "HIGH"):
                            image_info["vulnerabilities"].append(
                                {
                                    "cve": vuln.get("VulnerabilityID", "N/A"),
                                    "severity": severity.lower(),
                                    "package": vuln.get("PkgName", "N/A"),
                                    "installed_version": vuln.get("InstalledVersion", "N/A"),
                                    "fixed_version": vuln.get("FixedVersion", "N/A"),
                                }
                            )
                            total_vulns += 1
                            if severity == "CRITICAL":
                                critical_vulns += 1
                            elif severity == "HIGH":
                                high_vulns += 1

        # Analyze metadata
        inspect_data = inspect_image(image)
        if inspect_data:
            metadata_issues = analyze_image_metadata(inspect_data)
            image_info["metadata_issues"] = metadata_issues

            for issue in metadata_issues:
                issues.append(
                    {
                        "severity": issue["severity"],
                        "message": f"{image}: {issue['message']}",
                        "recommendation": issue["recommendation"],
                    }
                )

        scanned_images.append(image_info)

    # Generate overall issues
    if critical_vulns > 0:
        issues.insert(
            0,
            {
                "severity": "critical",
                "message": f"{critical_vulns} CRITICAL vulnerabilities found in container images",
                "recommendation": "Update base images and rebuild containers immediately",
            },
        )
    elif high_vulns > 0:
        issues.insert(
            0,
            {
                "severity": "high",
                "message": f"{high_vulns} HIGH vulnerabilities found in container images",
                "recommendation": "Update base images and rebuild containers soon",
            },
        )

    return {
        "checked": True,
        "trivy_available": trivy_available,
        "total_images": len(all_images),
        "running_images": len(running_images),
        "scanned_images": len(scanned_images),
        "total_vulnerabilities": total_vulns,
        "critical_vulnerabilities": critical_vulns,
        "high_vulnerabilities": high_vulns,
        "images": scanned_images,
        "issues": issues,
        "note": (
            "Install trivy for comprehensive vulnerability scanning: apt install trivy"
            if not trivy_available
            else None
        ),
    }
