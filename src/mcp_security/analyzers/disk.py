"""Disk usage analysis module."""

import subprocess

DISK_USAGE_CRITICAL = 90
DISK_USAGE_HIGH = 80
DISK_USAGE_MEDIUM = 70

EXCLUDED_FSTYPES = {"tmpfs", "devtmpfs", "squashfs", "overlay"}
EXCLUDED_PATH_PATTERNS = {"/docker/", "/snap/"}


def _should_skip_filesystem(fstype, source):
    """Determine if filesystem should be excluded from monitoring."""
    if fstype in EXCLUDED_FSTYPES:
        return True

    return any(pattern in source for pattern in EXCLUDED_PATH_PATTERNS)


def _assess_disk_usage(usage_percent, mount_point):
    """Determine severity and recommendation for disk usage."""
    thresholds = [
        (
            DISK_USAGE_CRITICAL,
            "critical",
            "critically low space",
            f"Free up space on {mount_point} immediately. Check logs, temp files, and unused data.",
        ),
        (
            DISK_USAGE_HIGH,
            "high",
            "running low on space",
            f"Plan to free up space on {mount_point} soon to prevent disk full errors.",
        ),
        (
            DISK_USAGE_MEDIUM,
            "medium",
            None,
            f"Monitor disk usage on {mount_point} and clean up if needed.",
        ),
    ]

    for threshold, severity, status, recommendation in thresholds:
        if usage_percent >= threshold:
            message = f"Disk {mount_point} is {usage_percent}% full"
            if status:
                message += f" - {status}"
            return severity, message, recommendation

    return None, None, None


def get_disk_usage():
    """Get disk usage for all mounted filesystems."""
    try:
        result = subprocess.run(
            ["df", "-h", "--output=source,fstype,size,used,avail,pcent,target"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return []

        lines = result.stdout.strip().split("\n")
        if len(lines) < 2:
            return []

        filesystems = []
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 7:
                continue

            source, fstype, size, used, avail, percent, target = parts
            percent = percent.rstrip("%")

            if _should_skip_filesystem(fstype, source):
                continue

            try:
                usage_percent = int(percent)
            except ValueError:
                continue

            filesystems.append(
                {
                    "device": source,
                    "mount": target,
                    "size": size,
                    "used": used,
                    "available": avail,
                    "usage_percent": usage_percent,
                    "fstype": fstype,
                }
            )

        return filesystems

    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        return []


def analyze_disk():
    """Analyze disk usage and identify potential issues."""
    filesystems = get_disk_usage()

    if not filesystems:
        return {
            "checked": False,
            "message": "Unable to retrieve disk usage information",
            "filesystems": [],
            "issues": [],
        }

    issues = []
    critical_count = 0
    warning_count = 0

    for fs in filesystems:
        severity, message, recommendation = _assess_disk_usage(fs["usage_percent"], fs["mount"])

        if severity:
            issues.append(
                {
                    "severity": severity,
                    "message": message,
                    "recommendation": recommendation,
                }
            )

            if severity == "critical":
                critical_count += 1
            elif severity in ("high", "medium"):
                warning_count += 1

    return {
        "checked": True,
        "total_filesystems": len(filesystems),
        "critical_count": critical_count,
        "warning_count": warning_count,
        "filesystems": filesystems,
        "issues": issues,
    }
