"""Web server security headers analyzer.

Checks HTTP security headers for web servers running on the system.
Detects nginx, Apache, Caddy and analyzes their security headers.
Intelligently extracts real domains from config files and tests them.
"""

import subprocess
import re
from typing import Optional, Dict, List
from pathlib import Path

SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS",
        "severity": "high",
        "description": "Enforces HTTPS connections",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "medium",
        "description": "Prevents clickjacking attacks",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "medium",
        "description": "Prevents MIME-sniffing attacks",
    },
    "content-security-policy": {
        "name": "CSP",
        "severity": "high",
        "description": "Mitigates XSS and injection attacks",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": "low",
        "description": "Legacy XSS protection",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "low",
        "description": "Controls referrer information",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "low",
        "description": "Controls browser features",
    },
}


def _extract_domains_from_caddyfile(caddyfile_path: str = "/etc/caddy/Caddyfile") -> List[str]:
    """Extract real domain names from Caddyfile."""
    domains = []

    try:
        if not Path(caddyfile_path).exists():
            return []

        with open(caddyfile_path, "r") as f:
            content = f.read()

        # Match domain blocks: "domain.com" or "domain.com subdomain.domain.com"
        # Ignore wildcards (*.domain.com), localhost, IP addresses
        for line in content.split("\n"):
            line = line.strip()

            # Skip comments, empty lines, config lines
            if not line or line.startswith("#") or line.startswith("{") or line.startswith("}"):
                continue

            # Match lines that look like domain blocks
            # Format: "domain.com www.domain.com {" or just "domain.com {"
            domain_pattern = r"^([a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:\s+[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})*)\s*\{"
            match = re.match(domain_pattern, line)

            if match:
                # Extract all domains from this line
                domain_list = match.group(1).split()
                for domain in domain_list:
                    # Skip wildcards and ensure it's a valid domain
                    if not domain.startswith("*") and "." in domain:
                        domains.append(domain)

        # Deduplicate and return primary domains (prefer non-www)
        unique_domains = []
        seen = set()

        for domain in domains:
            # Normalize: prefer example.com over www.example.com
            normalized = domain.replace("www.", "")
            if normalized not in seen:
                seen.add(normalized)
                # Use the non-www version
                unique_domains.append(domain if not domain.startswith("www.") else normalized)

        return unique_domains[:5]  # Limit to 5 domains for performance

    except Exception:
        return []


def _extract_domains_from_nginx() -> List[str]:
    """Extract domains from nginx config (basic implementation)."""
    domains = []

    try:
        # Common nginx config locations
        for config_path in ["/etc/nginx/sites-enabled", "/etc/nginx/conf.d"]:
            if not Path(config_path).exists():
                continue

            for conf_file in Path(config_path).glob("*.conf"):
                with open(conf_file, "r") as f:
                    content = f.read()

                # Match server_name directives
                for match in re.finditer(r"server_name\s+([^;]+);", content):
                    server_names = match.group(1).split()
                    for name in server_names:
                        if not name.startswith("*") and "." in name and name != "_":
                            domains.append(name.replace("www.", ""))

        return list(set(domains))[:5]

    except Exception:
        return []


def _get_real_domains(web_servers: List[str]) -> List[str]:
    """Extract real domain names from web server configs."""
    domains = []

    if "caddy" in web_servers:
        domains.extend(_extract_domains_from_caddyfile())

    if "nginx" in web_servers:
        domains.extend(_extract_domains_from_nginx())

    return list(set(domains))


def _get_listening_ports():
    """Get HTTP/HTTPS ports that are listening."""
    try:
        result = subprocess.run(
            ["ss", "-tlnp"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )

        if result.returncode != 0:
            return []

        ports = []
        for line in result.stdout.split("\n"):
            # Look for :80 or :443 or other common web ports
            if ":80 " in line or ":443 " in line or ":8080 " in line or ":8443 " in line:
                match = re.search(r":(\d+)\s", line)
                if match:
                    ports.append(int(match.group(1)))

        return list(set(ports))

    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        return []


def _check_headers_for_url(url: str) -> Optional[Dict[str, str]]:
    """Fetch HTTP headers for a given URL using curl.

    Follows redirects and returns headers from the final destination.
    Returns None if the URL only redirects without serving content.
    """
    try:
        # Follow redirects (-L) to get the final response
        result = subprocess.run(
            ["curl", "-I", "-s", "-L", "-m", "10", url],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=15,
        )

        if result.returncode != 0:
            return None

        # Parse headers from the LAST response (after redirects)
        # Split by blank lines to get each response in redirect chain
        responses = result.stdout.split("\r\n\r\n")

        # Get the last non-empty response
        final_response = None
        for response in reversed(responses):
            if response.strip():
                final_response = response
                break

        if not final_response:
            return None

        headers = {}
        status_code = None

        for line in final_response.split("\n"):
            if line.startswith("HTTP/"):
                # Extract status code
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        status_code = int(parts[1])
                    except ValueError:
                        pass
            elif ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()

        # Add status code to headers for analysis
        if status_code:
            headers["_status_code"] = status_code

        return headers

    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        return None


def _analyze_headers(headers: Dict[str, str]) -> Dict:
    """Analyze security headers and return findings."""
    present = []
    missing = []

    for header_key, header_info in SECURITY_HEADERS.items():
        if header_key in headers:
            present.append(
                {
                    "header": header_info["name"],
                    "value": headers[header_key][:100],  # Truncate long values
                }
            )
        else:
            missing.append(
                {
                    "header": header_info["name"],
                    "severity": header_info["severity"],
                    "description": header_info["description"],
                }
            )

    return {"present": present, "missing": missing}


def _detect_web_server():
    """Detect which web server is running."""
    servers = []

    # Check for common web servers
    for service in ["nginx", "apache2", "httpd", "caddy"]:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", f"{service}.service"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )

            if result.returncode == 0 and result.stdout.strip() == "active":
                servers.append(service)

        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            continue

    return servers


def analyze_webheaders():
    """Analyze web server security headers.

    Intelligently extracts real domains from web server configs and tests them.
    Falls back to localhost testing if no domains found.
    """
    web_servers = _detect_web_server()

    if not web_servers:
        return {
            "checked": False,
            "message": "No web server detected (nginx/apache/caddy)",
            "servers": [],
            "issues": [],
        }

    listening_ports = _get_listening_ports()

    if not listening_ports:
        return {
            "checked": False,
            "message": "Web servers running but no HTTP/HTTPS ports detected",
            "servers": web_servers,
            "issues": [],
        }

    # Try to extract real domains from config files
    real_domains = _get_real_domains(web_servers)

    tested_urls = []
    issues = []
    total_missing_high = 0
    total_missing_medium = 0
    test_mode = "real_domains" if real_domains else "localhost"

    if real_domains:
        # Test real domains via HTTPS
        for domain in real_domains[:3]:  # Limit to 3 domains for performance
            url = f"https://{domain}"

            headers = _check_headers_for_url(url)
            if headers:
                # Remove internal status code from headers before analysis
                status_code = headers.pop("_status_code", 200)

                analysis = _analyze_headers(headers)

                tested_urls.append(
                    {
                        "url": url,
                        "status_code": status_code,
                        "present_headers": len(analysis["present"]),
                        "missing_headers": len(analysis["missing"]),
                        "headers": analysis["present"],
                    }
                )

                # Only report issues for successful responses (200-299)
                if 200 <= status_code < 300:
                    # Generate issues for missing headers
                    for missing in analysis["missing"]:
                        if missing["severity"] in ["high", "critical"]:
                            total_missing_high += 1
                            issues.append(
                                {
                                    "severity": "high",
                                    "message": f"{domain}: Missing {missing['header']} header",
                                    "recommendation": f"Add {missing['header']} header: {missing['description']}",
                                }
                            )
                        elif missing["severity"] == "medium":
                            total_missing_medium += 1

    else:
        # Fallback: Test localhost on detected ports
        for port in listening_ports[:3]:  # Limit to 3 ports for performance
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://localhost:{port}"

            headers = _check_headers_for_url(url)
            if headers:
                status_code = headers.pop("_status_code", 200)
                analysis = _analyze_headers(headers)

                tested_urls.append(
                    {
                        "url": url,
                        "status_code": status_code,
                        "present_headers": len(analysis["present"]),
                        "missing_headers": len(analysis["missing"]),
                        "headers": analysis["present"],
                    }
                )

                # Only report issues for successful responses
                if 200 <= status_code < 300:
                    for missing in analysis["missing"]:
                        if missing["severity"] in ["high", "critical"]:
                            total_missing_high += 1
                            issues.append(
                                {
                                    "severity": "high",
                                    "message": f"{url}: Missing {missing['header']} header",
                                    "recommendation": f"Add {missing['header']} header: {missing['description']}",
                                }
                            )
                        elif missing["severity"] == "medium":
                            total_missing_medium += 1

        # Add warning about localhost testing
        if not tested_urls or all(url["status_code"] >= 300 for url in tested_urls):
            issues.append(
                {
                    "severity": "info",
                    "message": "Could not extract real domains from config - tested localhost only",
                    "recommendation": "Headers checked on localhost. Real domains may have different configurations.",
                }
            )

    # Summary issue (only if real issues found on successful responses)
    if total_missing_high > 0:
        issues.insert(
            0,
            {
                "severity": "high",
                "message": f"{total_missing_high} critical security headers missing",
                "recommendation": "Configure security headers in web server config",
            },
        )
    elif total_missing_medium > 0:
        issues.insert(
            0,
            {
                "severity": "medium",
                "message": f"{total_missing_medium} recommended security headers missing",
                "recommendation": "Consider adding additional security headers for defense in depth",
            },
        )

    return {
        "checked": True,
        "web_servers": web_servers,
        "listening_ports": listening_ports,
        "test_mode": test_mode,
        "domains_found": real_domains if real_domains else [],
        "tested_urls": tested_urls,
        "total_missing_high": total_missing_high,
        "total_missing_medium": total_missing_medium,
        "issues": issues,
    }
