# Network Security Scan

> **Note:** All data shown below is fictional and for demonstration purposes only.

Network configuration and exposed services analysis.

```bash
# Via MCP tool
scan_network_security

# Or directly
sudo ./bin/chihuaudit audit --scan=network
```

## Output Example

```
═══════════════════════════════════════════════════════════════
  NETWORK SECURITY SCAN
═══════════════════════════════════════════════════════════════

───────────────────────────────────────────────────────────────
  🌐 LISTENING SERVICES
───────────────────────────────────────────────────────────────

  ✅ tcp/22 (SSH)            127.0.0.1:22 (sshd)
     Status: Secure - localhost only
  
  ⚠️  tcp/3306 (MySQL)       0.0.0.0:3306 (mysqld)
     Status: WARNING - Exposed to internet
     Recommendation: Bind to 127.0.0.1
  
  ✅ tcp/80 (HTTP)           0.0.0.0:80 (nginx)
     Status: Public web server (expected)
  
  ✅ tcp/443 (HTTPS)         0.0.0.0:443 (nginx)
     Status: Public web server (expected)
  
  ⚠️  tcp/6379 (Redis)       127.0.0.1:6379 (redis-server)
     Status: Secure but no authentication configured

───────────────────────────────────────────────────────────────
  🔥 FIREWALL STATUS
───────────────────────────────────────────────────────────────

  Status: ✅ Active (UFW)
  Default: deny (incoming), allow (outgoing)
  
  Rules (18 total):
    22/tcp      ALLOW       Anywhere
    80/tcp      ALLOW       Anywhere
    443/tcp     ALLOW       Anywhere
    3306/tcp    DENY        Anywhere  # MySQL blocked at firewall
    ... (14 more rules)

───────────────────────────────────────────────────────────────
  🛡️  KERNEL NETWORK HARDENING
───────────────────────────────────────────────────────────────

  ✅ net.ipv4.conf.all.rp_filter = 1 (Reverse path filtering)
  ✅ net.ipv4.conf.all.accept_source_route = 0 (Block source routing)
  ✅ net.ipv4.icmp_echo_ignore_broadcasts = 1 (Ignore ICMP broadcasts)
  ✅ net.ipv4.tcp_syncookies = 1 (SYN flood protection)
  ❌ net.ipv4.conf.all.log_martians = 0 (Martian packet logging disabled)

───────────────────────────────────────────────────────────────
  💡 RECOMMENDATIONS
───────────────────────────────────────────────────────────────

  1. Restrict MySQL to localhost: bind-address = 127.0.0.1
  2. Enable Redis authentication (requirepass)
  3. Enable martian packet logging for intrusion detection

═══════════════════════════════════════════════════════════════
```
