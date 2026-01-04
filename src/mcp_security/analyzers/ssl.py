"""SSL/TLS certificate analysis module."""

import re
import subprocess
from datetime import datetime
from ..utils.logger import get_logger
from ..utils.command import run_command

logger = get_logger(__name__)

CERT_EXPIRY_CRITICAL_DAYS = 7
CERT_EXPIRY_WARNING_DAYS = 30
OPENSSL_TIMEOUT_SECONDS = 5


def _parse_cert_field(output, field_prefix):
    """Extract field value from openssl output."""
    for line in output.split("\n"):
        if line.startswith(field_prefix):
            return line[len(field_prefix) :].strip()
    return None


def _parse_x509_date(date_str):
    """Parse X.509 date format to datetime object."""
    formats = [
        "%b %d %H:%M:%S %Y %Z",
        "%b %d %H:%M:%S %Y",
    ]

    for fmt in formats:
        try:
            clean_date = date_str.replace(" GMT", "") if fmt == "%b %d %H:%M:%S %Y" else date_str
            return datetime.strptime(clean_date, fmt)
        except ValueError:
            continue

    return None


def get_certificate_info(domain, port=443):
    """Get SSL certificate information for a domain using openssl."""
    try:
        # Get certificate from server
        result = run_command(
            ["openssl", "s_client", "-connect", f"{domain}:{port}", "-servername", domain],
            timeout=OPENSSL_TIMEOUT_SECONDS,
        )

        if not result or not result.success:
            return None

        # Parse certificate details (requires piping, so use subprocess directly)
        cert_result = subprocess.run(
            ["openssl", "x509", "-noout", "-dates", "-subject", "-issuer"],
            input=result.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=OPENSSL_TIMEOUT_SECONDS,
        )

        if cert_result.returncode != 0:
            return None

        not_after = _parse_cert_field(cert_result.stdout, "notAfter=")
        if not not_after:
            return None

        expiry_date = _parse_x509_date(not_after)
        if not expiry_date:
            return None

        days_remaining = (expiry_date - datetime.now()).days

        subject = _parse_cert_field(cert_result.stdout, "subject=")
        cn_match = re.search(r"CN\s*=\s*([^,]+)", subject) if subject else None
        cn = cn_match.group(1).strip() if cn_match else domain

        issuer = _parse_cert_field(cert_result.stdout, "issuer=")
        issuer_match = re.search(r"O\s*=\s*([^,]+)", issuer) if issuer else None
        issuer_org = issuer_match.group(1).strip() if issuer_match else "Unknown"

        return {
            "domain": domain,
            "common_name": cn,
            "issuer": issuer_org,
            "expiry_date": not_after,
            "days_remaining": days_remaining,
            "valid": days_remaining > 0,
        }

    except subprocess.TimeoutExpired:
        logger.debug(f"SSL certificate check timed out for {domain}")
        return None
    except subprocess.SubprocessError as e:
        logger.debug(f"Cannot retrieve SSL certificate for {domain}: {e}")
        return None


def _discover_domains_from_configs():
    """Auto-discover domains from common web server configs."""
    domains = set()

    configs = [
        ("/etc/caddy/Caddyfile", r"^([\w\-\.]+\.[\w\-\.]+)\s"),
        ("/etc/nginx/sites-enabled/*", r"server_name\s+([\w\-\.]+\.[\w\-\.]+)"),
        ("/etc/apache2/sites-enabled/*.conf", r"ServerName\s+([\w\-\.]+\.[\w\-\.]+)"),
    ]

    for config_path, pattern in configs:
        try:
            with open(config_path) as f:
                content = f.read()
                matches = re.findall(pattern, content, re.MULTILINE)
                for domain in matches:
                    if domain and not domain.startswith("*") and "." in domain:
                        domains.add(domain.replace("www.", ""))
        except (FileNotFoundError, IOError):
            continue

    return list(domains)


def _assess_certificate_expiry(days_remaining):
    """Determine severity and messaging for certificate expiry."""
    if days_remaining <= 0:
        return "critical", "has EXPIRED", "immediately"
    elif days_remaining < CERT_EXPIRY_CRITICAL_DAYS:
        return "critical", f"expires in {days_remaining} days", "urgently"
    elif days_remaining < CERT_EXPIRY_WARNING_DAYS:
        return "high", f"expires in {days_remaining} days", None

    return None, None, None


def analyze_ssl(domains=None):
    """Analyze SSL certificates for configured domains."""
    if domains is None:
        domains = _discover_domains_from_configs()

    if not domains:
        return {
            "checked": False,
            "message": "No domains configured for SSL check",
            "certificates": [],
            "issues": [],
        }

    certificates = []
    issues = []

    for domain in domains:
        cert_info = get_certificate_info(domain)
        if not cert_info:
            continue

        certificates.append(cert_info)

        severity, status, urgency = _assess_certificate_expiry(cert_info["days_remaining"])
        if severity:
            recommendation = (
                f"Renew certificate {urgency} for {domain}"
                if urgency
                else f"Plan certificate renewal for {domain}"
            )
            issues.append(
                {
                    "severity": severity,
                    "message": f"SSL certificate for {domain} {status}",
                    "recommendation": recommendation,
                }
            )

    return {
        "checked": True,
        "total_certificates": len(certificates),
        "expired": sum(1 for c in certificates if not c["valid"]),
        "expiring_soon_30days": sum(
            1 for c in certificates if c["valid"] and c["days_remaining"] < CERT_EXPIRY_WARNING_DAYS
        ),
        "certificates": certificates,
        "issues": issues,
    }
