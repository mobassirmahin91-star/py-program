import socket  # https://docs.python.org/3/library/socket.html
import sys
from datetime import datetime
import threading  # https://docs.python.org/3/library/threading.html
from queue import Queue  # https://docs.python.org/3/library/queue.html
# Port information database
# Reference:https://www.portcheckers.com/port-number-assignment#google_vignette
# Security guidelines: https://owasp.org/
PORT_INFO = {
    21: {"service": "FTP", "risk": "HIGH", "tip": "FTP transmits credentials in plaintext. Use SFTP or FTPS instead."},
    # https://datatracker.ietf.org/doc/html/rfc959
    22: {"service": "SSH", "risk": "MEDIUM", "tip": "Ensure strong passwords, disable root login, and use key-based authentication."},
    # https://datatracker.ietf.org/doc/html/rfc4253
    23: {"service": "Telnet", "risk": "CRITICAL", "tip": "Telnet is unencrypted! Replace with SSH immediately."},
    # https://datatracker.ietf.org/doc/html/rfc854
    25: {"service": "SMTP", "risk": "MEDIUM", "tip": "Ensure proper authentication and use TLS/SSL encryption."},
    # https://datatracker.ietf.org/doc/html/rfc5321
    53: {"service": "DNS", "risk": "LOW", "tip": "Ensure DNS server is properly configured to prevent DNS amplification attacks."},
    # https://datatracker.ietf.org/doc/html/rfc1035
    80: {"service": "HTTP", "risk": "MEDIUM", "tip": "HTTP is unencrypted. Use HTTPS (port 443) for sensitive data."},
    # https://datatracker.ietf.org/doc/html/rfc2616
    110: {"service": "POP3", "risk": "MEDIUM", "tip": "POP3 can transmit passwords in plaintext. Use POP3S (995) instead."},
    # https://datatracker.ietf.org/doc/html/rfc1939
    143: {"service": "IMAP", "risk": "MEDIUM", "tip": "Use IMAPS (993) for encrypted email access."},
    # https://datatracker.ietf.org/doc/html/rfc3501
    443: {"service": "HTTPS", "risk": "LOW", "tip": "Ensure valid SSL/TLS certificates and disable weak cipher suites."},
    # https://datatracker.ietf.org/doc/html/rfc2818
    # https://ssl-config.mozilla.org/
    445: {"service": "SMB", "risk": "HIGH", "tip": "SMB has known vulnerabilities. Keep patched and restrict access."},
    # https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144
    3306: {"service": "MySQL", "risk": "HIGH", "tip": "Never expose database to internet. Use firewall rules and strong passwords."},
    # https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html
    3389: {"service": "RDP", "risk": "HIGH", "tip": "RDP is frequently targeted. Use VPN, strong passwords, and enable NLA."},
    # https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0708
    5432: {"service": "PostgreSQL", "risk": "HIGH", "tip": "Database should not be internet-facing. Use authentication and SSL."},
    # https://www.postgresql.org/docs/current/security.html
    5900: {"service": "VNC", "risk": "HIGH", "tip": "VNC can be insecure. Use strong passwords and SSH tunneling."},
    6379: {"service": "Redis", "risk": "HIGH", "tip": "Redis has no default authentication. Configure requirepass and bind to localhost."},
    # https://redis.io/docs/management/security/
    8080: {"service": "HTTP-Proxy", "risk": "MEDIUM", "tip": "Alternative HTTP port. Ensure proper authentication if public-facing."},
    27017: {"service": "MongoDB", "risk": "HIGH", "tip": "Enable authentication and don't expose to internet without proper security."}
    # https://www.mongodb.com/docs/manual/security/
}
