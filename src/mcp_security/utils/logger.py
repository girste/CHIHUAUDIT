"""Lightweight structured logging for security audit."""

import logging
import sys


def setup_logger(name: str, level: str = "WARNING") -> logging.Logger:
    """
    Setup logger with smart defaults.

    Args:
        name: Logger name (typically __name__)
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Returns:
        Configured logger instance

    Usage:
        logger = setup_logger(__name__)
        logger.debug("File not found, using defaults")
        logger.warning("Command timed out, retrying")
        logger.error("Unexpected error", exc_info=True)
    """
    logger = logging.getLogger(name)

    # Avoid duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    # Parse level from string or env
    log_level = getattr(logging, level.upper(), logging.WARNING)
    logger.setLevel(log_level)

    # Console handler with clean format
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(log_level)

    # Format: [WARNING] mcp_security.analyzers.firewall: UFW command failed
    formatter = logging.Formatter(fmt="[%(levelname)s] %(name)s: %(message)s")
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get or create logger with smart defaults.

    Convenience wrapper around setup_logger with auto-detection
    of log level from environment (MCP_SECURITY_LOG_LEVEL).
    """
    import os

    level = os.getenv("MCP_SECURITY_LOG_LEVEL", "WARNING")
    return setup_logger(name, level)
