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

         # Color palette (Catppuccin Mocha inspired)
        # https://github.com/catppuccin/catppuccin
        self.colors = {
            'bg': '#1e1e2e',
            'fg': '#cdd6f4',
            'accent': '#89b4fa',
            'critical': '#f38ba8',
            'high': '#fab387',
            'medium': '#f9e2af',
            'low': '#a6e3a1',
            'button': '#89b4fa',
            'entry_bg': '#313244',
            'text_bg': '#181825'
        }
        
        self.root.configure(bg=self.colors['bg'])
        
        # Initialize scanner state variables
        self.scan_results = []
        self.is_scanning = False
        self.target_ip = None
        
        self.create_widgets()
    def create_widgets(self):
        """
        Create and layout all GUI widgets
        Builds header, left panel (controls), and right panel (results)
        https://docs.python.org/3/library/tkinter.html#tkinter.Frame
        """
        
        # Header section
        header_frame = tk.Frame(self.root, bg=self.colors['accent'], height=80)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame,
            text="🔒 PORT SCANNER & VULNERABILITY CHECKER",
            font=("Helvetica", 20, "bold"),
            bg=self.colors['accent'],
            fg='#1e1e2e'
        )
        title_label.pack(pady=20)
        
        # Main container
        main_container = tk.Frame(self.root, bg=self.colors['bg'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        # Left panel (controls)
        left_panel = tk.Frame(main_container, bg=self.colors['bg'], width=350)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)

         # Target input section
        # https://docs.python.org/3/library/tkinter.html#tkinter.LabelFrame
        target_frame = tk.LabelFrame(
            left_panel,
            text="  Target Configuration  ",
            font=("Helvetica", 12, "bold"),
            bg=self.colors['bg'],
            fg=self.colors['accent'],
            bd=2,
            relief=tk.GROOVE
        )
        target_frame.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(
            target_frame,
            text="Target IP/Domain:",
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            font=("Helvetica", 10)
        ).pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        # Entry widget for target input
        # https://docs.python.org/3/library/tkinter.html#tkinter.Entry
        self.target_entry = tk.Entry(
            target_frame,
            font=("Helvetica", 11),
            bg=self.colors['entry_bg'],
            fg=self.colors['fg'],
            insertbackground=self.colors['fg'],
            relief=tk.FLAT,
            bd=5
        )
        self.target_entry.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.target_entry.insert(0, "scanme.nmap.org")  # Safe default target
        
        # Scan type selection
        tk.Label(
            target_frame,
            text="Scan Type:",
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            font=("Helvetica", 10)
        ).pack(anchor=tk.W, padx=10, pady=(5, 5))

         # Radio buttons for scan type
        # https://docs.python.org/3/library/tkinter.html#tkinter.Radiobutton
        self.scan_type = tk.StringVar(value="quick")
        
        quick_radio = tk.Radiobutton(
            target_frame,
            text="Quick Scan (Common Ports)",
            variable=self.scan_type,
            value="quick",
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            selectcolor=self.colors['entry_bg'],
            activebackground=self.colors['bg'],
            activeforeground=self.colors['accent'],
            font=("Helvetica", 9)
        )
        quick_radio.pack(anchor=tk.W, padx=20, pady=2)
        
        custom_radio = tk.Radiobutton(
            target_frame,
            text="Custom Range",
            variable=self.scan_type,
            value="custom",
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            selectcolor=self.colors['entry_bg'],
            activebackground=self.colors['bg'],
            activeforeground=self.colors['accent'],
            font=("Helvetica", 9),
            command=self.toggle_custom_ports
        )
        custom_radio.pack(anchor=tk.W, padx=20, pady=2)
        
        #  Custom port range inputs
        self.port_range_frame = tk.Frame(target_frame, bg=self.colors['bg'])
        self.port_range_frame.pack(fill=tk.X, padx=10, pady=(5, 10))
        
        port_container = tk.Frame(self.port_range_frame, bg=self.colors['bg'])
        port_container.pack()
        
        tk.Label(
            port_container,
            text="From:",
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            font=("Helvetica", 9)
        ).grid(row=0, column=0, padx=5)
        
        self.port_start = tk.Entry(
            port_container,
            width=8,
            font=("Helvetica", 10),
            bg=self.colors['entry_bg'],
            fg=self.colors['fg'],
            insertbackground=self.colors['fg'],
            relief=tk.FLAT,
            bd=3,
            state=tk.DISABLED
        )
        self.port_start.grid(row=0, column=1, padx=5)
        self.port_start.insert(0, "1")
        
        tk.Label(
            port_container,
            text="To:",
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            font=("Helvetica", 9)
        ).grid(row=0, column=2, padx=5)
        
        self.port_end = tk.Entry(
            port_container,
            width=8,
            font=("Helvetica", 10),
            bg=self.colors['entry_bg'],
            fg=self.colors['fg'],
            insertbackground=self.colors['fg'],
            relief=tk.FLAT,
            bd=3,
            state=tk.DISABLED
        )
        self.port_end.grid(row=0, column=3, padx=5)
        self.port_end.insert(0, "1000")

         # Start scan button
        # https://docs.python.org/3/library/tkinter.html#tkinter.Button
        self.scan_button = tk.Button(
            left_panel,
            text="🚀 START SCAN",
            command=self.start_scan,
            font=("Helvetica", 12, "bold"),
            bg=self.colors['button'],
            fg='#1e1e2e',
            activebackground='#74c7ec',
            activeforeground='#1e1e2e',
            relief=tk.FLAT,
            bd=0,
            padx=20,
            pady=12,
            cursor="hand2"
        )
        self.scan_button.pack(fill=tk.X, pady=(0, 15))
        
        # Progress section
        progress_frame = tk.LabelFrame(
            left_panel,
            text="  Scan Progress  ",
            font=("Helvetica", 12, "bold"),
            bg=self.colors['bg'],
            fg=self.colors['accent'],
            bd=2,
            relief=tk.GROOVE
        )
        progress_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Progress bar widget
        # https://docs.python.org/3/library/tkinter.ttk.html#progressbar
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            mode='indeterminate',
            length=300
        )
        self.progress_bar.pack(padx=10, pady=10)
        
        self.status_label = tk.Label(
            progress_frame,
            text="Ready to scan",
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            font=("Helvetica", 9)
        )
        self.status_label.pack(pady=(0, 10))

         # Statistics section
        stats_frame = tk.LabelFrame(
            left_panel,
            text="  Statistics  ",
            font=("Helvetica", 12, "bold"),
            bg=self.colors['bg'],
            fg=self.colors['accent'],
            bd=2,
            relief=tk.GROOVE
        )
        stats_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Text widget for statistics display
        # https://docs.python.org/3/library/tkinter.html#tkinter.Text
        self.stats_text = tk.Text(
            stats_frame,
            height=8,
            bg=self.colors['text_bg'],
            fg=self.colors['fg'],
            font=("Courier", 9),
            relief=tk.FLAT,
            bd=5,
            state=tk.DISABLED
        )
        self.stats_text.pack(padx=10, pady=10, fill=tk.BOTH)

        # Action buttons (Export and Clear)
        action_frame = tk.Frame(left_panel, bg=self.colors['bg'])
        action_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.export_button = tk.Button(
            action_frame,
            text="💾 Export",
            command=self.show_export_menu,
            font=("Helvetica", 10, "bold"),
            bg=self.colors['low'],
            fg='#1e1e2e',
            activebackground='#94e2d5',
            relief=tk.FLAT,
            bd=0,
            padx=10,
            pady=8,
            cursor="hand2",
            state=tk.DISABLED
        )
        self.export_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        
        self.clear_button = tk.Button(
            action_frame,
            text="🗑️ Clear",
            command=self.clear_results,
            font=("Helvetica", 10, "bold"),
            bg=self.colors['high'],
            fg='#1e1e2e',
            activebackground='#f5a97f',
            relief=tk.FLAT,
            bd=0,
            padx=10,
            pady=8,
            cursor="hand2"
        )
        self.clear_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(5, 0))
        
        # Right panel (results)
        right_panel = tk.Frame(main_container, bg=self.colors['bg'])
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
         # Search and sort bar
        search_frame = tk.Frame(right_panel, bg=self.colors['bg'])
        search_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(
            search_frame,
            text="🔍",
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            font=("Helvetica", 14)
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        # Search entry with real-time filtering
        self.search_entry = tk.Entry(
            search_frame,
            font=("Helvetica", 11),
            bg=self.colors['entry_bg'],
            fg=self.colors['fg'],
            insertbackground=self.colors['fg'],
            relief=tk.FLAT,
            bd=5
        )
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.search_entry.bind('<KeyRelease>', lambda e: self.search_results())
        
        tk.Label(
            search_frame,
            text="Sort:",
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            font=("Helvetica", 10)
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        # Sort dropdown (Combobox)
        # https://docs.python.org/3/library/tkinter.ttk.html#combobox
        self.sort_var = tk.StringVar(value="port")
        sort_combo = ttk.Combobox(
            search_frame,
            textvariable=self.sort_var,
            values=["port", "service", "risk"],
            state="readonly",
            width=10,
            font=("Helvetica", 10)
        )
        sort_combo.pack(side=tk.LEFT)
        sort_combo.bind('<<ComboboxSelected>>', lambda e: self.sort_results())
         
        