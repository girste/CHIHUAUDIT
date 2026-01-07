"""
Profile-based security control weights for multi-level scoring.

Defines importance weights (0.0-1.0) for each security control across different profiles:
- personal: Home/personal VPS, single user, development/hobby projects
- business: Small business, e-commerce, multiple users, some sensitive data
- corporate: Enterprise, regulated industries, compliance requirements
- military: High-security, classified data, military/government/critical infrastructure
"""

# Profile definitions
PROFILES = {
    "personal": {
        "name": "Personal/Home",
        "description": "Personal VPS, blog, hobby projects",
    },
    "business": {
        "name": "Business/SME",
        "description": "Small business, e-commerce, customer data",
    },
    "corporate": {
        "name": "Corporate/Enterprise",
        "description": "Large enterprise, compliance requirements",
    },
    "military": {
        "name": "High-Security/Military",
        "description": "Military, government, classified data",
    },
}

# Category weights: How important is each category for each profile
CATEGORY_WEIGHTS = {
    "firewall": {
        "personal": 1.0,  # Essential for all
        "business": 1.0,
        "corporate": 1.0,
        "military": 1.0,
    },
    "ssh": {
        "personal": 1.0,  # Essential for all
        "business": 1.0,
        "corporate": 1.0,
        "military": 1.0,
    },
    "fail2ban": {
        "personal": 0.8,  # Important but not critical
        "business": 0.9,
        "corporate": 1.0,
        "military": 1.0,
    },
    "docker": {
        "personal": 0.7,  # Docker security less critical for personal
        "business": 0.9,  # More important for business
        "corporate": 1.0,
        "military": 1.0,
    },
    "updates": {
        "personal": 0.9,  # Important for all
        "business": 0.95,
        "corporate": 1.0,
        "military": 1.0,
    },
    "filesystem_partitions": {
        "personal": 0.1,  # Not practical on VPS
        "business": 0.3,  # Nice to have
        "corporate": 0.8,  # Recommended
        "military": 1.0,  # Required
    },
    "module_blacklisting": {
        "personal": 0.2,  # Not loaded = not a problem
        "business": 0.4,
        "corporate": 0.7,
        "military": 1.0,
    },
    "file_integrity": {  # AIDE
        "personal": 0.0,  # Not needed
        "business": 0.4,
        "corporate": 0.9,
        "military": 1.0,
    },
    "rootkit_detection": {
        "personal": 0.3,  # Nice to have
        "business": 0.6,
        "corporate": 0.9,
        "military": 1.0,
    },
    "audit_logging": {
        "personal": 0.4,  # Basic logging is enough
        "business": 0.7,
        "corporate": 1.0,
        "military": 1.0,
    },
    "network_hardening": {
        "personal": 0.5,  # Some settings needed for Docker
        "business": 0.7,
        "corporate": 0.9,
        "military": 1.0,
    },
    "session_timeout": {
        "personal": 0.2,  # Not critical for personal use
        "business": 0.5,
        "corporate": 0.8,
        "military": 1.0,
    },
    "password_policy": {
        "personal": 0.6,  # Basic security
        "business": 0.8,
        "corporate": 1.0,
        "military": 1.0,
    },
}

# Specific CIS control weights
# Maps CIS control ID patterns to category weights
CIS_CONTROL_CATEGORIES = {
    # Filesystem modules (cramfs, freevxfs, jffs2, hfs, hfsplus, udf)
    "1.1.1.": "module_blacklisting",

    # Partition mounting (/tmp, /var, /var/tmp, /var/log, /home)
    "1.1.2.": "filesystem_partitions",
    "1.1.3.": "filesystem_partitions",
    "1.1.4.": "filesystem_partitions",
    "1.1.5.": "filesystem_partitions",
    "1.1.6.": "filesystem_partitions",

    # /dev/shm hardening
    "1.1.7.": "filesystem_partitions",

    # AIDE
    "1.3.1": "file_integrity",

    # Bootloader
    "1.4.": "password_policy",

    # Services (xinetd, inetd, X11, Avahi, CUPS, DHCP, LDAP, NFS, DNS, FTP, HTTP, etc.)
    "2.1.": "updates",  # Remove unnecessary services
    "2.2.": "updates",
    "2.3.": "updates",

    # Network configuration
    "3.1.": "network_hardening",  # IPv6
    "3.2.": "network_hardening",  # IP forwarding
    "3.3.": "network_hardening",  # Network parameters
    "3.4.": "module_blacklisting",  # Uncommon protocols (DCCP, SCTP, RDS, TIPC)

    # Logging and auditing
    "4.1.": "audit_logging",
    "4.2.": "audit_logging",
    "4.3": "audit_logging",
    "4.4.": "audit_logging",

    # Access control
    "5.1.": "password_policy",  # Cron
    "5.2.": "ssh",  # SSH
    "5.3.": "password_policy",  # PAM
    "5.4.": "password_policy",  # User accounts
}

# NIST 800-53 control weights
NIST_CONTROL_WEIGHTS = {
    "AC-11": {  # Session Lock
        "personal": 0.2,
        "business": 0.5,
        "corporate": 0.8,
        "military": 1.0,
    },
    "AC-7": {  # Unsuccessful Logon Attempts
        "personal": 0.8,
        "business": 0.9,
        "corporate": 1.0,
        "military": 1.0,
    },
    "AU-2": {  # Event Logging
        "personal": 0.6,
        "business": 0.8,
        "corporate": 1.0,
        "military": 1.0,
    },
    "SC-39": {  # Process Isolation (ASLR)
        "personal": 0.9,
        "business": 1.0,
        "corporate": 1.0,
        "military": 1.0,
    },
    "SI-2": {  # Flaw Remediation (Updates)
        "personal": 0.9,
        "business": 0.95,
        "corporate": 1.0,
        "military": 1.0,
    },
}

# PCI-DSS control weights
PCI_CONTROL_WEIGHTS = {
    "2.1": {  # Change vendor defaults
        "personal": 0.7,
        "business": 0.9,
        "corporate": 1.0,
        "military": 1.0,
    },
    "2.2.2": {  # Disable unnecessary services
        "personal": 0.7,
        "business": 0.9,
        "corporate": 1.0,
        "military": 1.0,
    },
    "8.3.6": {  # Strong passwords
        "personal": 0.8,
        "business": 1.0,
        "corporate": 1.0,
        "military": 1.0,
    },
    "10.2": {  # Audit logging
        "personal": 0.5,
        "business": 0.8,
        "corporate": 1.0,
        "military": 1.0,
    },
    "10.4": {  # Time synchronization
        "personal": 0.6,
        "business": 0.8,
        "corporate": 1.0,
        "military": 1.0,
    },
}


def get_cis_control_weight(control_id, profile):
    """
    Get weight for a specific CIS control based on profile.

    Args:
        control_id: CIS control ID (e.g., "1.1.2.1", "3.2.1")
        profile: Profile name ("personal", "business", "corporate", "military")

    Returns:
        float: Weight between 0.0 and 1.0
    """
    # Find matching category by prefix
    for prefix, category in CIS_CONTROL_CATEGORIES.items():
        if control_id.startswith(prefix):
            return CATEGORY_WEIGHTS[category][profile]

    # Default: medium importance
    return 0.7


def get_nist_control_weight(control_id, profile):
    """Get weight for a specific NIST 800-53 control based on profile."""
    return NIST_CONTROL_WEIGHTS.get(control_id, {}).get(profile, 0.7)


def get_pci_control_weight(control_id, profile):
    """Get weight for a specific PCI-DSS control based on profile."""
    return PCI_CONTROL_WEIGHTS.get(control_id, {}).get(profile, 0.7)


def get_category_weight(category, profile):
    """Get weight for an entire category based on profile."""
    return CATEGORY_WEIGHTS.get(category, {}).get(profile, 0.7)


def calculate_weighted_score(total_controls, passed_controls, weights):
    """
    Calculate weighted compliance score.

    Args:
        total_controls: Total number of controls
        passed_controls: Number of passed controls
        weights: List of weights (0.0-1.0) for each control

    Returns:
        float: Weighted score percentage (0-100)
    """
    if not weights or total_controls == 0:
        return 0.0

    # Calculate weighted score
    max_possible_score = sum(weights)
    actual_score = sum(weights[i] if i < passed_controls else 0 for i in range(total_controls))

    if max_possible_score == 0:
        return 0.0

    return (actual_score / max_possible_score) * 100


def get_profile_recommendation(scores):
    """
    Recommend appropriate profile based on scores.

    Args:
        scores: Dict with profile names as keys and scores as values

    Returns:
        str: Recommended profile name
    """
    # A profile is suitable if score >= 80%
    suitable_profiles = [profile for profile, score in scores.items() if score >= 80]

    if not suitable_profiles:
        return "personal"  # Default to most permissive

    # Return highest suitable profile
    profile_order = ["personal", "business", "corporate", "military"]
    for profile in reversed(profile_order):
        if profile in suitable_profiles:
            return profile

    return "personal"
