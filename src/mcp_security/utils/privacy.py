"""Privacy utilities for sanitizing sensitive data."""

import socket
from .logger import get_logger

logger = get_logger(__name__)


def mask_ip(ip):
    """Mask IP address for privacy (keep first two octets)."""
    if not ip or ip == "unknown":
        return ip

    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.***.***"

    # IPv6 - keep first block
    if ":" in ip:
        parts = ip.split(":")
        return f"{parts[0]}:***"

    return "***"


def mask_hostname(hostname):
    """Mask hostname for privacy."""
    if not hostname or len(hostname) < 4:
        return "srv-****"

    return f"srv-{hostname[:2]}**"


def get_masked_hostname():
    """Get current hostname, masked."""
    try:
        hostname = socket.gethostname()
        return mask_hostname(hostname)
    except OSError as e:
        logger.debug(f"Cannot get hostname: {e}, using fallback")
        return "srv-****"
    except Exception as e:
        logger.warning(f"Unexpected error getting hostname: {e}")
        return "srv-****"
