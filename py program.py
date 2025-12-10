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
         # Results table (Treeview)
        # https://docs.python.org/3/library/tkinter.ttk.html#treeview
        results_frame = tk.Frame(right_panel, bg=self.colors['bg'])
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        tree_scroll = tk.Scrollbar(results_frame)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.results_tree = ttk.Treeview(
            results_frame,
            columns=("Port", "Service", "Risk", "Recommendation"),
            show="headings",
            yscrollcommand=tree_scroll.set,
            height=20
        )
        
        tree_scroll.config(command=self.results_tree.yview)
        
        # Define column headings and widths
        self.results_tree.heading("Port", text="Port", anchor=tk.W)
        self.results_tree.heading("Service", text="Service", anchor=tk.W)
        self.results_tree.heading("Risk", text="Risk Level", anchor=tk.CENTER)
        self.results_tree.heading("Recommendation", text="Security Recommendation", anchor=tk.W)
        
        self.results_tree.column("Port", width=80, anchor=tk.W)
        self.results_tree.column("Service", width=120, anchor=tk.W)
        self.results_tree.column("Risk", width=100, anchor=tk.CENTER)
        self.results_tree.column("Recommendation", width=400, anchor=tk.W)
        
        # Configure treeview styling
        self.style.configure(
            "Treeview",
            background=self.colors['text_bg'],
            foreground=self.colors['fg'],
            fieldbackground=self.colors['text_bg'],
            borderwidth=0,
            font=("Helvetica", 10)
        )
        self.style.configure("Treeview.Heading", font=("Helvetica", 11, "bold"))
        self.style.map('Treeview', background=[('selected', self.colors['accent'])])
        
        # Color tags for risk levels
        self.results_tree.tag_configure('CRITICAL', background='#3d1e1e', foreground=self.colors['critical'])
        self.results_tree.tag_configure('HIGH', background='#3d2e1e', foreground=self.colors['high'])
        self.results_tree.tag_configure('MEDIUM', background='#3d3a1e', foreground=self.colors['medium'])
        self.results_tree.tag_configure('LOW', background='#1e3d1e', foreground=self.colors['low'])
        
        self.results_tree.pack(fill=tk.BOTH, expand=True)
    
    def toggle_custom_ports(self):
        """
        Enable/disable custom port range input fields based on scan type selection
        Called when user switches between Quick Scan and Custom Range
        """
        if self.scan_type.get() == "custom":
            self.port_start.config(state=tk.NORMAL)
            self.port_end.config(state=tk.NORMAL)
        else:
            self.port_start.config(state=tk.DISABLED)
            self.port_end.config(state=tk.DISABLED)
    
    def start_scan(self):
        """
        Initiate port scanning process
        Validates input, shows authorization warning, clears old results,
        and starts scan in separate thread to prevent UI freezing
        https://docs.python.org/3/library/threading.html
        """
        if self.is_scanning:
            messagebox.showwarning("Scan in Progress", "A scan is already running!")
            return
        
        target = self.target_entry.get().strip()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or domain!")
            return
        
        # Authorization warning (legal compliance)
        # https://www.law.cornell.edu/uscode/text/18/1030
        response = messagebox.askyesno(
            "⚠️ Authorization Required",
            "Do you have authorization to scan this target?\n\n"
            "Unauthorized port scanning may be illegal in your jurisdiction.\n"
            "Only scan systems you own or have explicit permission to test."
        )
        
        if not response:
            return
        
        # Determine ports to scan
        if self.scan_type.get() == "quick":
            ports = COMMON_PORTS
        else:
            try:
                start = int(self.port_start.get())
                end = int(self.port_end.get())
                if start >= end or start < 1 or end > 65535:
                    raise ValueError
                ports = list(range(start, end + 1))
            except ValueError:
                messagebox.showerror("Error", "Invalid port range! Using common ports.")
                ports = COMMON_PORTS
        
        # Clear previous results
        self.scan_results = []
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Update UI to scanning state
        self.is_scanning = True
        self.scan_button.config(state=tk.DISABLED, text="⏳ SCANNING...")
        self.export_button.config(state=tk.DISABLED)
        self.progress_bar.start(10)
        self.status_label.config(text=f"Scanning {target}...")
        
        # Start scan in daemon thread
        scan_thread = threading.Thread(target=self.run_scan, args=(target, ports))
        scan_thread.daemon = True
        scan_thread.start()
    
    def run_scan(self, target, ports):
        """
        Execute port scanning logic (runs in separate thread)
        Resolves hostname, attempts TCP connections to each port,
        records open ports, and updates GUI with results
        https://docs.python.org/3/library/socket.html
        https://datatracker.ietf.org/doc/html/rfc793
        """
        # Resolve hostname to IP
        try:
            self.target_ip = socket.gethostbyname(target)
            self.update_status(f"Resolved {target} to {self.target_ip}")
        except socket.gaierror:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Cannot resolve hostname: {target}"))
            self.scan_complete()
            return
        
        start_time = datetime.now()
        open_ports = []

         # Scan each port
        for port in ports:
            if not self.is_scanning:
                break
            
            try:
                # Create TCP socket (AF_INET=IPv4, SOCK_STREAM=TCP)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                
                # Attempt connection (returns 0 if open)
                result = sock.connect_ex((self.target_ip, port))
                
                if result == 0:
                    # Port is open - gather info
                    service = PORT_INFO.get(port, {}).get("service", "Unknown")
                    risk = PORT_INFO.get(port, {}).get("risk", "UNKNOWN")
                    tip = PORT_INFO.get(port, {}).get("tip", "No specific recommendation")
                    
                    open_ports.append(port)
                    result_data = {
                        "port": port,
                        "service": service,
                        "risk": risk,
                        "tip": tip
                    }
                    
                    self.scan_results.append(result_data)
                    self.root.after(0, lambda r=result_data: self.add_result_to_tree(r))
                    self.update_status(f"Found open port: {port} ({service})")
                
                sock.close()
            except Exception as e:
                pass
        
        # Calculate scan duration
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        self.update_statistics(len(ports), len(open_ports), duration)
        self.scan_complete()
    
    def add_result_to_tree(self, result):
        """
        Add single scan result to results table
        Inserts row with color coding based on risk level
        """
        self.results_tree.insert(
            "",
            tk.END,
            values=(result['port'], result['service'], result['risk'], result['tip']),
            tags=(result['risk'],)
        )
    
    def update_status(self, message):
        """
        Update status label (thread-safe using root.after)
        https://docs.python.org/3/library/tkinter.html#tkinter.Misc.after
        """
        self.root.after(0, lambda: self.status_label.config(text=message))
    
    def update_statistics(self, total_ports, open_ports, duration):
        """
        Update statistics display with scan results
        Shows target, ports scanned, open ports, duration, and timestamp
        """
        def update():
            self.stats_text.config(state=tk.NORMAL)
            self.stats_text.delete(1.0, tk.END)
            
            stats = f"""
Target: {self.target_ip}
Ports Scanned: {total_ports}
Open Ports: {open_ports}
Duration: {duration:.2f}s
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """
            
            self.stats_text.insert(1.0, stats.strip())
            self.stats_text.config(state=tk.DISABLED)
        
        self.root.after(0, update)
    
    def scan_complete(self):
        """
        Handle scan completion
        Resets UI state and enables export if results exist
        """
        self.root.after(0, self._scan_complete_ui)
    
    def _scan_complete_ui(self):
        """
        Update UI elements after scan completion (runs on main thread)
        """
        self.is_scanning = False
        self.scan_button.config(state=tk.NORMAL, text="🚀 START SCAN")
        self.progress_bar.stop()
        self.status_label.config(text="Scan complete!")
        
        if self.scan_results:
            self.export_button.config(state=tk.NORMAL)
    
    def search_results(self):
        """
        Filter results table based on search query
        Real-time search triggered by KeyRelease event
        """
        search_term = self.search_entry.get().lower()
    
        
         
        