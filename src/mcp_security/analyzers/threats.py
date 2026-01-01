"""Threat analysis from system logs."""

import re
from collections import Counter
from ..utils.detect import run_with_sudo
from ..utils.logger import get_logger

logger = get_logger(__name__)


def parse_failed_ssh_attempts(log_path, days=7):
    """Parse failed SSH login attempts from auth log."""
    if not log_path:
        return []

    attempts = []

    # Pattern: "Failed password for ... from IP"
    pattern = re.compile(r"Failed password for .* from ([\d.]+)")

    # Try reading file directly first
    try:
        with open(log_path) as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    ip = match.group(1)
                    attempts.append(ip)
        return attempts

    except PermissionError:
        logger.debug(f"Permission denied reading {log_path}, trying with sudo")
        # Try with sudo
        result = run_with_sudo(["cat", log_path])
        if result:
            for line in result.stdout.split("\n"):
                match = pattern.search(line)
                if match:
                    ip = match.group(1)
                    attempts.append(ip)
        else:
            logger.debug(f"Cannot read {log_path} even with sudo")

    except FileNotFoundError:
        logger.debug(f"Auth log not found at {log_path}")

    return attempts


def analyze_threats(log_path, days=7):
    """Analyze security threats from logs."""
    failed_attempts = parse_failed_ssh_attempts(log_path, days)

    if not failed_attempts:
        return {
            "period_days": days,
            "total_attempts": 0,
            "unique_ips": 0,
            "top_attackers": [],
            "patterns": [],
        }

    ip_counter = Counter(failed_attempts)
    total = len(failed_attempts)
    unique = len(ip_counter)

    # Top 10 attackers
    top_attackers = [{"ip": ip, "attempts": count} for ip, count in ip_counter.most_common(10)]

    # Detect patterns
    patterns = []
    if total > 100:
        patterns.append("ssh_brute_force")
    if unique > 50:
        patterns.append("distributed_attack")

    return {
        "period_days": days,
        "total_attempts": total,
        "unique_ips": unique,
        "top_attackers": top_attackers,
        "patterns": patterns,
    }
