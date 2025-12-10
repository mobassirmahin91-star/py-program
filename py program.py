import socket
import sys
from datetime import datetime
import threading
from queue import Queue
import json
import csv
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext

# References:
# Tkinter documentation: https://docs.python.org/3/library/tkinter.html
# Socket programming: https://docs.python.org/3/library/socket.html
# Threading: https://docs.python.org/3/library/threading.html
# IANA Port Numbers: https://www.iana.org/assignments/service-names-port-numbers
# TCP Protocol: https://datatracker.ietf.org/doc/html/rfc793

# Port information database with security risk assessments
# https://datatracker.ietf.org/doc/html/rfc959
PORT_INFO = {
    21: {"service": "FTP", "risk": "HIGH", "tip": "FTP transmits credentials in plaintext. Use SFTP or FTPS instead."},

    22: {"service": "SSH", "risk": "MEDIUM", "tip": "Ensure strong passwords, disable root login, and use key-based authentication."},
    
    23: {"service": "Telnet", "risk": "CRITICAL", "tip": "Telnet is unencrypted! Replace with SSH immediately."},
    
    25: {"service": "SMTP", "risk": "MEDIUM", "tip": "Ensure proper authentication and use TLS/SSL encryption."},
    
    53: {"service": "DNS", "risk": "LOW", "tip": "Ensure DNS server is properly configured to prevent DNS amplification attacks."},
   
    80: {"service": "HTTP", "risk": "MEDIUM", "tip": "HTTP is unencrypted. Use HTTPS (port 443) for sensitive data."},
    
    110: {"service": "POP3", "risk": "MEDIUM", "tip": "POP3 can transmit passwords in plaintext. Use POP3S (995) instead."},
    
    143: {"service": "IMAP", "risk": "MEDIUM", "tip": "Use IMAPS (993) for encrypted email access."},
    
    443: {"service": "HTTPS", "risk": "LOW", "tip": "Ensure valid SSL/TLS certificates and disable weak cipher suites."},
    
    445: {"service": "SMB", "risk": "HIGH", "tip": "SMB has known vulnerabilities. Keep patched and restrict access."},
    
    3306: {"service": "MySQL", "risk": "HIGH", "tip": "Never expose database to internet. Use firewall rules and strong passwords."},
    
    3389: {"service": "RDP", "risk": "HIGH", "tip": "RDP is frequently targeted. Use VPN, strong passwords, and enable NLA."},
    
    5432: {"service": "PostgreSQL", "risk": "HIGH", "tip": "Database should not be internet-facing. Use authentication and SSL."},
    
    5900: {"service": "VNC", "risk": "HIGH", "tip": "VNC can be insecure. Use strong passwords and SSH tunneling."},
    6379: {"service": "Redis", "risk": "HIGH", "tip": "Redis has no default authentication. Configure requirepass and bind to localhost."},
    
    8080: {"service": "HTTP-Proxy", "risk": "MEDIUM", "tip": "Alternative HTTP port. Ensure proper authentication if public-facing."},
    27017: {"service": "MongoDB", "risk": "HIGH", "tip": "Enable authentication and don't expose to internet without proper security."}
    
}

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]


class PortScannerGUI:
    """Main GUI class for the Port Scanner application"""
    
    def __init__(self, root):
        """
        Initialize the GUI application
        Sets up window, styling, colors, and creates all widgets
        https://docs.python.org/3/library/tkinter.html#tkinter.Tk
        """
        self.root = root
        self.root.title("Port Scanner & Vulnerability Checker v2.0")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)
        
        # Apply ttk styling theme
        # https://docs.python.org/3/library/tkinter.ttk.html#ttk-styling
        self.style = ttk.Style()
        self.style.theme_use('clam')