#!/usr/bin/env python3
"""Network Topology Scanner GUI A simple GUI wrapper for the network topology scanner"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from tkinter import ttk, filedialog, messagebox
import tkinter.ttk as ttk
import threading
import subprocess
import ipaddress
import socket
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import matplotlib.pyplot as plt
import networkx as nx
from collections import defaultdict
import json
import csv
import os
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Topology Scanner")
        self.root.geometry("800x700")
        
        # Scanner attributes
        self.discovered_hosts = {}
        self.network_graph = nx.Graph()
        self.scanning = False
        
        self.port_connections = {}  # Will store port-to-port connections
        self.service_map = {}       # Will map ports to service names
        
        self.init_service_mapping()
        
        self.setup_gui()
        
        self.initialize_port_connection_system()
    
    def setup_gui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Scan Configuration", padding="5")
        input_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        input_frame.columnconfigure(1, weight=1)
        
        ttk.Label(input_frame, text="Network Range:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.network_entry = ttk.Entry(input_frame, width=20)
        self.network_entry.insert(0, "192.168.1.0/24")
        self.network_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Label(input_frame, text="Timeout (s):").grid(row=0, column=2, sticky=tk.W, padx=(10, 5))
        self.timeout_var = tk.StringVar(value="1")
        timeout_spin = ttk.Spinbox(input_frame, from_=1, to=5, width=5, textvariable=self.timeout_var)
        timeout_spin.grid(row=0, column=3, sticky=tk.W)
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.export_button = ttk.Button(button_frame, text="Export Results", command=self.export_results, state=tk.DISABLED)
        self.export_button.pack(side=tk.LEFT, padx=(0, 5))
        #print("Methods available:", dir(self))  # Temporary debug line
        
        self.view_map_button = ttk.Button(button_frame, text="View Topology", command=self.show_topology, state=tk.DISABLED)
        self.view_map_button.pack(side=tk.LEFT)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Status label
        self.status_var = tk.StringVar(value="Ready to scan")
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))
        
        # Results notebook
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        main_frame.rowconfigure(4, weight=1)
        
        # Summary tab
        summary_frame = ttk.Frame(notebook)
        notebook.add(summary_frame, text="Summary")
        
        self.summary_text = scrolledtext.ScrolledText(summary_frame, wrap=tk.WORD, height=15)
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Detailed results tab
        details_frame = ttk.Frame(notebook)
        notebook.add(details_frame, text="Detailed Results")
        
        # Treeview for detailed results
        columns = ('IP', 'Hostname', 'Device Type', 'Open Ports')
        self.tree = ttk.Treeview(details_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120)
        
        tree_scroll = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0), pady=5)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
    def build_network_graph(self):
        """Build network graph from discovered hosts"""
        # Clear existing graph
        self.network_graph.clear()
    
        # Add all discovered hosts as nodes with their attributes
        for ip, host_info in self.discovered_hosts.items():
            self.network_graph.add_node(ip, **host_info)
    
        # Build topology using your existing logic
        self.build_topology()
    
    def ping_host(self, ip):
        """Ping a single host to check if it's alive - Windows/Linux compatible"""
        try:
            import platform
            timeout_val = int(self.timeout_var.get())
            
            # Different ping commands for different OS
            if platform.system().lower() == "windows":
                # Windows ping: -n count, -w timeout_in_ms
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', str(timeout_val * 1000), str(ip)], 
                    capture_output=True, 
                    text=True,
                    timeout=timeout_val + 2
                )
            else:
                # Linux/Mac ping: -c count, -W timeout_in_seconds
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', str(timeout_val), str(ip)], 
                    capture_output=True, 
                    text=True,
                    timeout=timeout_val + 2
                )
            
            return str(ip) if result.returncode == 0 else None
        except Exception as e:
            # Fallback: try TCP connection to common ports
            return self.tcp_ping(ip)
    
    def tcp_ping(self, ip):
        """Alternative host detection using TCP connection attempts"""
        common_ports = [80, 443, 22, 21, 23, 25, 53, 135, 139, 445]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((str(ip), port))
                sock.close()
                if result == 0:
                    return str(ip)
            except:
                continue
        return None
    
    def get_hostname(self, ip):
        """Try to resolve hostname for an IP with better error handling"""
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
            return hostname
        except:
            # Try NetBIOS name resolution (Windows)
            try:
                import platform
                if platform.system().lower() == "windows":
                    result = subprocess.run(['nbtstat', '-A', str(ip)], 
                                          capture_output=True, text=True, timeout=3)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if '<00>' in line and 'UNIQUE' in line:
                                name = line.split()[0].strip()
                                if name != str(ip):
                                    return name
            except:
                pass
            return f"host-{str(ip).split('.')[-1]}"
    
    def scan_port(self, ip, port):
        """Check if a specific port is open with shorter timeout"""
        if not self.scanning:
            return None
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)  # Shorter timeout
            result = sock.connect_ex((str(ip), port))
            sock.close()
            return port if result == 0 else None
        except:
            return None
    
    def scan_host_ports(self, ip):
        """Scan common ports on a host"""
        if not self.scanning:
            return []
            
        common_ports = [22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 3389, 5900, 8080, 161]
        open_ports = []
        
        # Use a smaller thread pool and shorter timeout for port scanning
        with ThreadPoolExecutor(max_workers=10) as executor:
            if not self.scanning:
                return []
                
            future_to_port = {}
            for port in common_ports:
                if not self.scanning:
                    break
                future_to_port[executor.submit(self.scan_port, ip, port)] = port
            
            # Check results with timeout
            for future in future_to_port:
                if not self.scanning:
                    # Cancel remaining futures
                    for f in future_to_port:
                        f.cancel()
                    break
                try:
                    result = future.result(timeout=2)  # 2 second timeout per port
                    if result:
                        open_ports.append(result)
                except:
                    continue  # Timeout or error, skip this port
        
        return open_ports
    
    
    def get_mac_address(self, ip):
        """Get MAC address and vendor info for an IP with enhanced detection"""
        mac_info = {'mac': None, 'vendor': None}
    
        # Try multiple methods to get MAC address
        mac_addr = None
    
        # Method 1: Try ARP table first
        mac_addr = self._get_mac_from_arp(ip)
    
        # Method 2: If ARP fails, try ping then ARP (populates ARP table)
        if not mac_addr:
            mac_addr = self._ping_and_get_mac(ip)
    
        # Method 3: Try parsing /proc/net/arp on Linux
        if not mac_addr and hasattr(self, '_get_mac_from_proc'):
            mac_addr = self._get_mac_from_proc(ip)
    
        if mac_addr:
            mac_info['mac'] = mac_addr
            mac_info['vendor'] = self.lookup_mac_vendor(mac_addr)
    
        return mac_info

    def _get_mac_from_arp(self, ip):
        """Get MAC from ARP table"""
        try:
            import platform
            if platform.system().lower() == "windows":
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=3)
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=3)
        
            if result.returncode == 0:
                import re
                mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', result.stdout)
                if mac_match:
                    return mac_match.group(0).replace('-', ':').lower()
        except Exception:
            pass
        return None

    def _ping_and_get_mac(self, ip):
        """Ping device to populate ARP table, then get MAC"""
        try:
            import platform
            # Send a ping to populate ARP table
            if platform.system().lower() == "windows":
                ping_result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                        capture_output=True, text=True, timeout=2)
            else:
                ping_result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                        capture_output=True, text=True, timeout=2)
        
            # Now try ARP again
            if ping_result.returncode == 0:
                return self._get_mac_from_arp(ip)
        except Exception:
            pass
        return None

    def _get_mac_from_proc(self, ip):
        """Get MAC from /proc/net/arp on Linux systems"""
        try:
            with open('/proc/net/arp', 'r') as f:
                for line in f:
                    fields = line.split()
                    if len(fields) >= 4 and fields[0] == ip:
                        mac = fields[3]
                        if mac != '00:00:00:00:00:00':
                            return mac.lower()
        except Exception:
            pass
        return None

    def lookup_mac_vendor(self, mac_addr):
        """Enhanced MAC vendor lookup with larger OUI database"""
        if not mac_addr:
            return None
    
        # Expanded vendor database with more OUIs
        vendor_map = {
            # Apple - Much more comprehensive
            '00:03:93': 'Apple', '00:05:02': 'Apple', '00:0a:27': 'Apple',
            '00:0a:95': 'Apple', '00:0d:93': 'Apple', '00:11:24': 'Apple',
            '00:14:51': 'Apple', '00:16:cb': 'Apple', '00:17:f2': 'Apple',
            '00:19:e3': 'Apple', '00:1b:63': 'Apple', '00:1c:b3': 'Apple',
            '00:1e:c2': 'Apple', '00:1f:5b': 'Apple', '00:1f:f3': 'Apple',
            '00:21:e9': 'Apple', '00:22:41': 'Apple', '00:23:12': 'Apple',
            '00:23:32': 'Apple', '00:23:6c': 'Apple', '00:23:df': 'Apple',
            '00:24:36': 'Apple', '00:25:00': 'Apple', '00:25:4b': 'Apple',
            '00:25:bc': 'Apple', '00:26:08': 'Apple', '00:26:4a': 'Apple',
            '00:26:b0': 'Apple', '00:26:bb': 'Apple', '04:0c:ce': 'Apple',
            '04:69:f8': 'Apple', '28:cf:e9': 'Apple', '3c:07:54': 'Apple',
            '40:6c:8f': 'Apple', '58:55:ca': 'Apple', '5c:95:ae': 'Apple',
            '68:ab:bc': 'Apple', '70:73:cb': 'Apple', '78:4f:43': 'Apple',
            '80:e6:50': 'Apple', '88:63:df': 'Apple', '90:84:0d': 'Apple',
            '98:03:d8': 'Apple', 'a4:83:e7': 'Apple', 'b8:17:c2': 'Apple',
            'bc:52:b7': 'Apple', 'd0:23:db': 'Apple', 'd4:9a:20': 'Apple',
            'e0:ac:cb': 'Apple', 'f0:db:e2': 'Apple', 'f4:5c:89': 'Apple',
            
             # Samsung
            '00:04:20': 'Samsung', '00:07:ab': 'Samsung', '00:0d:e5': 'Samsung',
            '00:12:fb': 'Samsung', '00:15:99': 'Samsung', '00:16:6b': 'Samsung',
            '00:17:d5': 'Samsung', '00:1a:8a': 'Samsung', '00:1b:98': 'Samsung',
            '00:1c:43': 'Samsung', '00:1d:25': 'Samsung', '00:1e:7d': 'Samsung',
            '00:1f:cc': 'Samsung', '00:21:19': 'Samsung', '00:21:d1': 'Samsung',
            '00:23:39': 'Samsung', '00:26:37': 'Samsung', '34:ce:00': 'Samsung',
            '40:b0:34': 'Samsung', '44:4e:6d': 'Samsung', '5c:0a:5b': 'Samsung',
            '78:1f:db': 'Samsung', '8c:77:12': 'Samsung', 'a0:0b:ba': 'Samsung',
            'cc:03:fa': 'Samsung', 'ec:1f:72': 'Samsung', 'f4:7b:5e': 'Samsung',
        
            # TP-Link
            '00:14:6c': 'Tp-Link', '00:23:cd': 'Tp-Link', '00:27:19': 'Tp-Link',
            '50:c7:bf': 'Tp-Link', 'f4:f2:6d': 'Tp-Link', '18:d6:c7': 'Tp-Link',
            '1c:61:b4': 'Tp-Link', '54:a0:50': 'Tp-Link', '98:de:d0': 'Tp-Link',
            'b0:48:7a': 'Tp-Link', 'c4:6e:1f': 'Tp-Link', 'ec:08:6b': 'Tp-Link',
        
            # Netgear
            '00:09:5b': 'Netgear', '00:0f:b5': 'Netgear', '00:14:6c': 'Netgear',
            '00:18:4d': 'Netgear', '00:1b:2f': 'Netgear', '00:1e:2a': 'Netgear',
            '00:22:3f': 'Netgear', '00:24:b2': 'Netgear', '00:26:f2': 'Netgear',
            '20:e5:2a': 'Netgear', '28:c6:8e': 'Netgear', '30:46:9a': 'Netgear',
            '44:94:fc': 'Netgear', '84:1b:5e': 'Netgear', 'a0:04:60': 'Netgear',
        
            # Cisco
            '00:01:42': 'Cisco', '00:01:43': 'Cisco', '00:01:63': 'Cisco',
            '00:01:64': 'Cisco', '00:01:96': 'Cisco', '00:01:97': 'Cisco',
            '00:01:c7': 'Cisco', '00:01:c9': 'Cisco', '00:02:16': 'Cisco',
            '00:02:17': 'Cisco', '00:02:4a': 'Cisco', '00:02:4b': 'Cisco',
            '00:02:ba': 'Cisco', '00:02:fc': 'Cisco', '00:02:fd': 'Cisco',
            '00:03:31': 'Cisco', '00:03:32': 'Cisco', '00:03:6b': 'Cisco',
            '00:03:6c': 'Cisco', '00:03:a0': 'Cisco', '00:03:e3': 'Cisco',
            '00:03:fd': 'Cisco', '00:03:fe': 'Cisco', '00:04:27': 'Cisco',
            '00:04:28': 'Cisco', '00:04:4d': 'Cisco', '00:04:6d': 'Cisco',
            '00:04:9a': 'Cisco', '00:04:c0': 'Cisco', '00:04:c1': 'Cisco',
            '00:04:dd': 'Cisco', '00:05:00': 'Cisco', '00:05:01': 'Cisco',
            '00:05:31': 'Cisco', '00:05:32': 'Cisco', '00:05:5e': 'Cisco',
            '00:05:73': 'Cisco', '00:05:74': 'Cisco', '00:05:dc': 'Cisco',
            '00:05:dd': 'Cisco', '00:06:28': 'Cisco', '00:06:2a': 'Cisco',
            '00:06:52': 'Cisco', '00:06:53': 'Cisco', '00:06:c1': 'Cisco',
            '00:06:d6': 'Cisco', '00:06:d7': 'Cisco', '00:07:0d': 'Cisco',
            '00:07:0e': 'Cisco', '00:07:4f': 'Cisco', '00:07:50': 'Cisco',
            '00:07:84': 'Cisco', '00:07:85': 'Cisco', '00:07:b3': 'Cisco',
            '00:07:b4': 'Cisco', '00:07:eb': 'Cisco', '00:07:ec': 'Cisco',
            '00:08:20': 'Cisco', '00:08:21': 'Cisco', '00:08:2f': 'Cisco',
            '00:08:30': 'Cisco', '00:08:31': 'Cisco', '00:08:7c': 'Cisco',
            '00:08:a3': 'Cisco', '00:08:c2': 'Cisco', '00:08:e2': 'Cisco',
            '00:08:e3': 'Cisco', '00:09:11': 'Cisco', '00:09:12': 'Cisco',
            '00:09:43': 'Cisco', '00:09:44': 'Cisco', '00:09:7b': 'Cisco',
            '00:09:b6': 'Cisco', '00:09:b7': 'Cisco', '00:09:e8': 'Cisco',
            '00:09:e9': 'Cisco', '00:0a:41': 'Cisco', '00:0a:42': 'Cisco',
            '00:0a:8a': 'Cisco', '00:0a:8b': 'Cisco', '00:0a:b7': 'Cisco',
            '00:0a:b8': 'Cisco', '00:0a:f3': 'Cisco', '00:0a:f4': 'Cisco',
            '00:0b:45': 'Cisco', '00:0b:46': 'Cisco', '00:0b:5f': 'Cisco',
            '00:0b:60': 'Cisco', '00:0b:85': 'Cisco', '00:0b:be': 'Cisco',
            '00:0b:bf': 'Cisco', '00:0b:fc': 'Cisco', '00:0b:fd': 'Cisco',
            '00:0c:30': 'Cisco', '00:0c:31': 'Cisco', '00:0c:41': 'Cisco',
            '00:0c:85': 'Cisco', '00:0c:86': 'Cisco', '00:0c:ce': 'Cisco',
            '00:0c:cf': 'Cisco', '00:0d:28': 'Cisco', '00:0d:29': 'Cisco',
            '00:0d:65': 'Cisco', '00:0d:66': 'Cisco', '00:0d:bc': 'Cisco',
            '00:0d:bd': 'Cisco', '00:0d:ed': 'Cisco', '00:0d:ee': 'Cisco',
            '00:0e:08': 'Cisco', '00:0e:38': 'Cisco', '00:0e:39': 'Cisco',
            '00:0e:83': 'Cisco', '00:0e:84': 'Cisco', '00:0e:d6': 'Cisco',
            '00:0e:d7': 'Cisco', '00:0f:23': 'Cisco', '00:0f:24': 'Cisco',
            '00:0f:34': 'Cisco', '00:0f:35': 'Cisco', '00:0f:66': 'Cisco',
            '00:0f:8f': 'Cisco', '00:0f:90': 'Cisco', '00:0f:f7': 'Cisco',
            '00:0f:f8': 'Cisco', '00:10:07': 'Cisco', '00:10:11': 'Cisco',
            '00:10:29': 'Cisco', '00:10:2f': 'Cisco', '00:10:54': 'Cisco',
            '00:10:79': 'Cisco', '00:10:a6': 'Cisco', '00:10:f6': 'Cisco',
            '00:11:20': 'Cisco', '00:11:21': 'Cisco', '00:11:5c': 'Cisco',
            '00:11:5d': 'Cisco', '00:11:92': 'Cisco', '00:11:93': 'Cisco',
            '00:11:bb': 'Cisco', '00:11:bc': 'Cisco', '00:12:00': 'Cisco',
            '00:12:01': 'Cisco', '00:12:17': 'Cisco', '00:12:43': 'Cisco',
            '00:12:44': 'Cisco', '00:12:7f': 'Cisco', '00:12:80': 'Cisco',
            '00:12:d9': 'Cisco', '00:12:da': 'Cisco', '00:13:19': 'Cisco',
            '00:13:1a': 'Cisco', '00:13:5f': 'Cisco', '00:13:60': 'Cisco',
            '00:13:7f': 'Cisco', '00:13:80': 'Cisco', '00:13:c3': 'Cisco',
            '00:13:c4': 'Cisco', '00:14:1b': 'Cisco', '00:14:1c': 'Cisco',
            '00:14:69': 'Cisco', '00:14:6a': 'Cisco', '00:14:a8': 'Cisco',
            '00:14:a9': 'Cisco', '00:14:bf': 'Cisco', '00:14:f1': 'Cisco',
            '00:14:f2': 'Cisco', '00:15:2b': 'Cisco', '00:15:62': 'Cisco',
            '00:15:63': 'Cisco', '00:15:c6': 'Cisco', '00:15:c7': 'Cisco',
            '00:15:f9': 'Cisco', '00:15:fa': 'Cisco', '00:16:46': 'Cisco',
            '00:16:47': 'Cisco', '00:16:9c': 'Cisco', '00:16:9d': 'Cisco',
            '00:16:c7': 'Cisco', '00:16:c8': 'Cisco', '00:17:0e': 'Cisco',
            '00:17:0f': 'Cisco', '00:17:33': 'Cisco', '00:17:34': 'Cisco',
            '00:17:59': 'Cisco', '00:17:5a': 'Cisco', '00:17:94': 'Cisco',
            '00:17:95': 'Cisco', '00:17:df': 'Cisco', '00:17:e0': 'Cisco',
            '00:18:18': 'Cisco', '00:18:19': 'Cisco', '00:18:39': 'Cisco',
            '00:18:68': 'Cisco', '00:18:73': 'Cisco', '00:18:74': 'Cisco',
            '00:18:b9': 'Cisco', '00:18:ba': 'Cisco', '00:18:f8': 'Cisco',
            '00:19:06': 'Cisco', '00:19:07': 'Cisco', '00:19:2f': 'Cisco',
            '00:19:30': 'Cisco', '00:19:47': 'Cisco', '00:19:55': 'Cisco',
            '00:19:56': 'Cisco', '00:19:a9': 'Cisco', '00:19:aa': 'Cisco',
            '00:19:e7': 'Cisco', '00:19:e8': 'Cisco', '00:1a:2f': 'Cisco',
            '00:1a:30': 'Cisco', '00:1a:6c': 'Cisco', '00:1a:6d': 'Cisco',
            '00:1a:a1': 'Cisco', '00:1a:a2': 'Cisco', '00:1a:e2': 'Cisco',
            '00:1a:e3': 'Cisco', '00:1b:0c': 'Cisco', '00:1b:0d': 'Cisco',
            '00:1b:2a': 'Cisco', '00:1b:2b': 'Cisco', '00:1b:53': 'Cisco',
            '00:1b:54': 'Cisco', '00:1b:67': 'Cisco', '00:1b:68': 'Cisco',
            '00:1b:8f': 'Cisco', '00:1b:90': 'Cisco', '00:1b:d4': 'Cisco',
            '00:1b:d5': 'Cisco', '00:1c:0e': 'Cisco', '00:1c:0f': 'Cisco',
            '00:1c:57': 'Cisco', '00:1c:58': 'Cisco', '00:1c:b0': 'Cisco',
            '00:1c:b1': 'Cisco', '00:1c:f6': 'Cisco', '00:1c:f9': 'Cisco',
            '00:1d:45': 'Cisco', '00:1d:46': 'Cisco', '00:1d:70': 'Cisco',
            '00:1d:71': 'Cisco', '00:1d:a1': 'Cisco', '00:1d:a2': 'Cisco',
            '00:1d:e5': 'Cisco', '00:1d:e6': 'Cisco', '00:1e:13': 'Cisco',
            '00:1e:14': 'Cisco', '00:1e:49': 'Cisco', '00:1e:4a': 'Cisco',
            '00:1e:79': 'Cisco', '00:1e:7a': 'Cisco', '00:1e:bd': 'Cisco',
            '00:1e:be': 'Cisco', '00:1e:f6': 'Cisco', '00:1e:f7': 'Cisco',
            '00:1f:26': 'Cisco', '00:1f:27': 'Cisco', '00:1f:6c': 'Cisco',
            '00:1f:6d': 'Cisco', '00:1f:9e': 'Cisco', '00:1f:9f': 'Cisco',
            '00:1f:ca': 'Cisco', '00:1f:cb': 'Cisco', '00:21:1b': 'Cisco',
            '00:21:1c': 'Cisco', '00:21:29': 'Cisco', '00:21:55': 'Cisco',
            '00:21:56': 'Cisco', '00:21:a0': 'Cisco', '00:21:a1': 'Cisco',
            '00:21:d7': 'Cisco', '00:21:d8': 'Cisco', '00:22:0c': 'Cisco',
            '00:22:55': 'Cisco', '00:22:56': 'Cisco', '00:22:90': 'Cisco',
            '00:22:91': 'Cisco', '00:22:bd': 'Cisco', '00:22:be': 'Cisco',
            '00:23:04': 'Cisco', '00:23:05': 'Cisco', '00:23:33': 'Cisco',
            '00:23:34': 'Cisco', '00:23:5d': 'Cisco', '00:23:5e': 'Cisco',
            '00:23:ab': 'Cisco', '00:23:ac': 'Cisco', '00:23:be': 'Cisco',
            '00:23:ea': 'Cisco', '00:23:eb': 'Cisco', '00:24:13': 'Cisco',
            '00:24:14': 'Cisco', '00:24:50': 'Cisco', '00:24:51': 'Cisco',
            '00:24:97': 'Cisco', '00:24:98': 'Cisco', '00:24:c3': 'Cisco',
            '00:24:c4': 'Cisco', '00:24:f7': 'Cisco', '00:24:f9': 'Cisco',
            '00:25:2e': 'Cisco', '00:25:45': 'Cisco', '00:25:46': 'Cisco',
            '00:25:83': 'Cisco', '00:25:84': 'Cisco', '00:25:b4': 'Cisco',
            '00:25:b5': 'Cisco', '00:26:0a': 'Cisco', '00:26:0b': 'Cisco',
            '00:26:51': 'Cisco', '00:26:52': 'Cisco', '00:26:98': 'Cisco',
            '00:26:99': 'Cisco', '00:26:ca': 'Cisco', '00:26:cb': 'Cisco',
            '00:30:19': 'Cisco', '00:30:24': 'Cisco', '00:30:40': 'Cisco',
            '00:30:71': 'Cisco', '00:30:78': 'Cisco', '00:30:7b': 'Cisco',
            '00:30:80': 'Cisco', '00:30:85': 'Cisco', '00:30:94': 'Cisco',
            '00:30:96': 'Cisco', '00:30:a3': 'Cisco', '00:30:b6': 'Cisco',
            '00:30:f2': 'Cisco', '00:40:96': 'Cisco', '00:50:0f': 'Cisco',
            '00:50:14': 'Cisco', '00:50:53': 'Cisco', '00:50:54': 'Cisco',
            '00:50:73': 'Cisco', '00:50:80': 'Cisco', '00:50:a2': 'Cisco',
            '00:50:bd': 'Cisco', '00:50:d1': 'Cisco', '00:50:e2': 'Cisco',
            '00:50:f0': 'Cisco', '00:60:09': 'Cisco', '00:60:2f': 'Cisco',
            '00:60:47': 'Cisco', '00:60:5c': 'Cisco', '00:60:70': 'Cisco',
            '00:60:83': 'Cisco', '00:90:0c': 'Cisco', '00:90:21': 'Cisco',
            '00:90:2b': 'Cisco', '00:90:86': 'Cisco', '00:90:92': 'Cisco',
            '00:90:a6': 'Cisco', '00:90:ab': 'Cisco', '00:90:b1': 'Cisco',
            '00:90:bf': 'Cisco', '00:90:d9': 'Cisco', '00:90:f2': 'Cisco',
            '00:a0:c9': 'Cisco', '00:b0:64': 'Cisco', '00:d0:06': 'Cisco',
            '00:d0:79': 'Cisco', '00:d0:97': 'Cisco', '00:d0:ba': 'Cisco',
            '00:d0:bb': 'Cisco', '00:d0:bc': 'Cisco', '00:d0:c0': 'Cisco',
            '00:d0:d3': 'Cisco', '00:e0:1e': 'Cisco', '00:e0:34': 'Cisco',
            '00:e0:4f': 'Cisco', '00:e0:8f': 'Cisco', '00:e0:a3': 'Cisco',
            '00:e0:b0': 'Cisco', '00:e0:f7': 'Cisco', '00:e0:f9': 'Cisco',
            '00:e0:fe': 'Cisco',
        
            # Asus
            '00:0c:6e': 'Asus', '00:0e:a6': 'Asus', '00:11:2f': 'Asus',
            '00:13:d4': 'Asus', '00:15:f2': 'Asus', '00:17:31': 'Asus',
            '00:18:f3': 'Asus', '00:1a:92': 'Asus', '00:1b:fc': 'Asus',
            '00:1d:60': 'Asus', '00:1e:8c': 'Asus', '00:1f:c6': 'Asus',
            '00:22:15': 'Asus', '00:23:54': 'Asus', '00:24:8c': 'Asus',
            '00:25:22': 'Asus', '00:26:18': 'Asus', '04:d9:f5': 'Asus',
            '08:60:6e': 'Asus', '10:c3:7b': 'Asus', '14:dd:a9': 'Asus',
            '1c:87:2c': 'Asus', '20:cf:30': 'Asus', '2c:56:dc': 'Asus',
            '30:85:a9': 'Asus', '38:2c:4a': 'Asus', '40:16:7e': 'Asus',
            '50:46:5d': 'Asus', '54:04:a6': 'Asus', '60:45:cb': 'Asus',
            '70:4d:7b': 'Asus', '74:d0:2b': 'Asus', '78:24:af': 'Asus',
            '88:d7:f6': 'Asus', '9c:5c:8e': 'Asus', 'ac:22:0b': 'Asus',
            'b0:6e:bf': 'Asus', 'bc:ee:7b': 'Asus', 'c8:60:00': 'Asus',
            'd0:17:c2': 'Asus', 'e0:3f:49': 'Asus', 'f4:6d:04': 'Asus',
        
            # Linksys
            '00:06:25': 'Linksys', '00:0c:41': 'Linksys', '00:0f:66': 'Linksys',
            '00:12:17': 'Linksys', '00:13:10': 'Linksys', '00:14:bf': 'Linksys',
            '00:16:b6': 'Linksys', '00:18:39': 'Linksys', '00:18:f8': 'Linksys',
            '00:1a:70': 'Linksys', '00:1c:10': 'Linksys', '00:1d:7e': 'Linksys',
            '00:1e:e5': 'Linksys', '00:20:a6': 'Linksys', '00:21:29': 'Linksys',
            '00:22:6b': 'Linksys', '00:23:69': 'Linksys', '00:25:9c': 'Linksys',
            '48:f8:b3': 'Linksys', '58:6d:8f': 'Linksys', '60:38:e0': 'Linksys',
            '94:10:3e': 'Linksys', 'c0:c1:c0': 'Linksys', 'e4:f4:c6': 'Linksys',
        
            # D-Link
            '00:05:5d': 'D-Link', '00:0d:88': 'D-Link', '00:0f:3d': 'D-Link',
            '00:11:95': 'D-Link', '00:13:46': 'D-Link', '00:15:e9': 'D-Link',
            '00:17:9a': 'D-Link', '00:19:5b': 'D-Link', '00:1b:11': 'D-Link',
            '00:1c:f0': 'D-Link', '00:1e:58': 'D-Link', '00:1f:1f': 'D-Link',
            '00:21:91': 'D-Link', '00:22:b0': 'D-Link', '00:24:01': 'D-Link',
            '00:26:5a': 'D-Link', '14:d6:4d': 'D-Link', '1c:7e:e5': 'D-Link',
            '28:10:7b': 'D-Link', '34:08:04': 'D-Link', '5c:d9:98': 'D-Link',
            '90:94:e4': 'D-Link', 'c8:d3:a3': 'D-Link', 'cc:b2:55': 'D-Link',
        
            # Ubiquiti
            '00:15:6d': 'Ubiquiti', '04:18:d6': 'Ubiquiti', '04:a1:51': 'Ubiquiti',
            '18:e8:29': 'Ubiquiti', '24:5a:4c': 'Ubiquiti', '24:a4:3c': 'Ubiquiti',
            '44:d9:e7': 'Ubiquiti', '68:72:51': 'Ubiquiti', '68:d7:9a': 'Ubiquiti',
            '70:a7:41': 'Ubiquiti', '78:45:c4': 'Ubiquiti', '78:8a:20': 'Ubiquiti',
            '80:2a:a8': 'Ubiquiti', 'b4:fb:e4': 'Ubiquiti', 'dc:9f:db': 'Ubiquiti',
            'e0:63:da': 'Ubiquiti', 'f0:9f:c2': 'Ubiquiti', 'fc:ec:da': 'Ubiquiti',
        
            # Microsoft
            '00:03:ff': 'Microsoft', '00:0d:3a': 'Microsoft', '00:12:5a': 'Microsoft',
            '00:15:5d': 'Microsoft', '00:17:fa': 'Microsoft', '00:1d:d8': 'Microsoft',
            '00:21:d8': 'Microsoft', '00:22:48': 'Microsoft', '00:24:be': 'Microsoft',
            '00:26:2d': 'Microsoft', '00:50:f2': 'Microsoft', '18:60:24': 'Microsoft',
            '28:18:78': 'Microsoft', '30:59:b7': 'Microsoft', '40:5b:d8': 'Microsoft',
            '64:00:6a': 'Microsoft', '7c:1e:52': 'Microsoft', '98:5f:d3': 'Microsoft',
            'a0:99:9b': 'Microsoft', 'ac:22:05': 'Microsoft', 'e0:cb:ee': 'Microsoft',
        
            # Intel
            '00:02:b3': 'Intel', '00:03:47': 'Intel', '00:07:e9': 'Intel',
            '00:0c:f1': 'Intel', '00:0e:0c': 'Intel', '00:0e:35': 'Intel',
            '00:13:02': 'Intel', '00:13:ce': 'Intel', '00:15:00': 'Intel',
            '00:16:76': 'Intel', '00:16:ea': 'Intel', '00:18:de': 'Intel',
            '00:19:d1': 'Intel', '00:1b:21': 'Intel', '00:1c:23': 'Intel',
            '00:1d:e0': 'Intel', '00:1e:64': 'Intel', '00:1f:3a': 'Intel',
            '00:21:5c': 'Intel', '00:22:fa': 'Intel', '00:24:d7': 'Intel',
            '00:26:c6': 'Intel', '00:27:0e': 'Intel', '0c:8d:db': 'Intel',
            '18:3d:a2': 'Intel', '34:02:86': 'Intel', '3c:a9:f4': 'Intel',
            '40:74:e0': 'Intel', '44:85:00': 'Intel', '4c:80:93': 'Intel',
            '68:05:ca': 'Intel', '74:e5:43': 'Intel', '78:92:9c': 'Intel',
            '7c:7a:91': 'Intel', '84:3a:4b': 'Intel', '94:c6:91': 'Intel',
            'a0:a8:cd': 'Intel', 'a4:4e:31': 'Intel', 'ac:2b:6e': 'Intel',
            'b4:b6:76': 'Intel', 'c8:d9:d2': 'Intel', 'd0:50:99': 'Intel',
            'e0:94:67': 'Intel', 'f4:ee:08': 'Intel',
        
            # VMware
            '00:0c:29': 'VMware', '00:1c:14': 'VMware', '00:50:56': 'VMware',
            '00:05:69': 'VMware',
        
            # VirtualBox
            '08:00:27': 'VirtualBox',
        
            # Parallels
            '00:1c:42': 'Parallels',
        
            # Xen
            '00:16:3e': 'Xen',
        
            # Huawei
            '00:0f:e2': 'Huawei', '00:18:82': 'Huawei', '00:1c:c0': 'Huawei',
            '00:1e:10': 'Huawei', '00:25:68': 'Huawei', '18:cf:5e': 'Huawei',
            '1c:61:b4': 'Huawei', '28:6e:d4': 'Huawei', '34:6b:d3': 'Huawei',
            '40:4e:36': 'Huawei', '4c:54:99': 'Huawei', '58:2c:80': 'Huawei',
            '60:de:44': 'Huawei', '68:bd:ab': 'Huawei', '6c:92:bf': 'Huawei',
            '70:7b:e8': 'Huawei', '74:a7:22': 'Huawei', '78:d7:52': 'Huawei',
            '88:41:fc': 'Huawei', '8c:34:fd': 'Huawei', '94:e9:79': 'Huawei',
            'a8:4c:a6': 'Huawei', 'ac:e2:d3': 'Huawei', 'b0:ec:71': 'Huawei',
            'c8:94:02': 'Huawei', 'd4:6e:0e': 'Huawei', 'dc:d9:16': 'Huawei',
            'e8:cd:2d': 'Huawei', 'f0:79:59': 'Huawei', 'f8:a4:5f': 'Huawei',
        
            # Xiaomi
            '14:f6:5a': 'Xiaomi', '34:ce:00': 'Xiaomi', '50:8f:4c': 'Xiaomi',
            '64:09:80': 'Xiaomi', '78:11:dc': 'Xiaomi', '8c:be:be': 'Xiaomi',
            '98:fa:9b': 'Xiaomi', 'a0:86:c6': 'Xiaomi', 'f8:8f:ca': 'Xiaomi',
        
            # Google
            '18:b4:30': 'Google', '50:f5:da': 'Google', '6c:ad:f8': 'Google',
            '84:f5:a6': 'Google', 'da:a1:19': 'Google', 'f4:f5:e8': 'Google',
        
            # Amazon
            '00:fc:8b': 'Amazon', '44:65:0d': 'Amazon', '50:dc:e7': 'Amazon',
            '74:c2:46': 'Amazon', '84:d6:d0': 'Amazon', 'ac:63:be': 'Amazon',
            'f0:d2:f1': 'Amazon',
        
            # LG
            '00:1c:62': 'LG', '00:1d:25': 'LG', '34:e2:fd': 'LG',
            '64:bc:0c': 'LG', '68:b5:99': 'LG', 'a0:07:98': 'LG',
        
            # Sony
            '00:01:48': 'Sony', '00:04:1f': 'Sony', '00:0a:d9': 'Sony',
            '00:13:a9': 'Sony', '00:16:fe': 'Sony', '00:19:c1': 'Sony',
            '00:1a:80': 'Sony', '00:1d:ba': 'Sony', '00:1f:e4': 'Sony',
            '00:23:06': 'Sony', '30:f9:ed': 'Sony', '54:84:1b': 'Sony',
            'ac:9b:0a': 'Sony',
        
            # Panasonic
            '00:80:f0': 'Panasonic', '04:20:9a': 'Panasonic', '08:76:ff': 'Panasonic',
            '0c:ee:e6': 'Panasonic', '10:4f:a8': 'Panasonic', '10:bf:48': 'Panasonic',
        
            # Nintendo
            '00:09:bf': 'Nintendo', '00:16:56': 'Nintendo', '00:17:ab': 'Nintendo',
            '00:19:1d': 'Nintendo', '00:1a:e9': 'Nintendo', '00:1b:7a': 'Nintendo',
            '00:1c:be': 'Nintendo', '00:1d:bc': 'Nintendo', '00:1e:35': 'Nintendo',
            '00:1f:32': 'Nintendo', '00:21:bd': 'Nintendo', '00:22:aa': 'Nintendo',
            '00:23:31': 'Nintendo', '00:24:44': 'Nintendo', '00:24:f3': 'Nintendo',
            '00:25:a0': 'Nintendo', '00:26:59': 'Nintendo', '18:2a:7b': 'Nintendo',
            '2c:10:c1': 'Nintendo', '34:af:2c': 'Nintendo', '40:f4:07': 'Nintendo',
            '58:bd:a3': 'Nintendo', '78:a2:a0': 'Nintendo', '98:b6:e9': 'Nintendo',
            'a4:c0:e1': 'Nintendo', 'b8:ae:ed': 'Nintendo', 'cc:fb:65': 'Nintendo',
            'd8:6b:f7': 'Nintendo', 'dc:68:eb': 'Nintendo', 'e0:e7:51': 'Nintendo',
        
            # Roku
            '00:0d:4b': 'Roku', 'b0:ee:e4': 'Roku', 'd0:4f:7e': 'Roku',
        
            # Ring (Amazon)
            '74:c2:46': 'Ring/Amazon', '84:d6:d0': 'Ring/Amazon',
        
            # Nest (Google)
            '18:b4:30': 'Nest/Google', '64:16:66': 'Nest/Google',
        
            # Philips
            '00:04:79': 'Philips', '00:12:3f': 'Philips', '00:17:88': 'Philips',
            '00:20:df': 'Philips',
        
            # Common IoT/Security Camera vendors
            '00:01:42': 'Hikvision', '28:57:be': 'Hikvision', '44:19:b6': 'Hikvision',
            '4c:bd:8f': 'Hikvision', '68:3e:34': 'Hikvision', 'bc:ad:28': 'Hikvision',
            '00:12:ac': 'Dahua', '08:57:00': 'Dahua', '54:c4:15': 'Dahua',
        
            # HP
            '00:01:e6': 'HP', '00:01:e7': 'HP', '00:02:a5': 'HP',
            '00:04:ea': 'HP', '00:08:02': 'HP', '00:0b:cd': 'HP',
            '00:0d:9d': 'HP', '00:0f:20': 'HP', '00:0f:61': 'HP',
            '00:10:83': 'HP', '00:11:0a': 'HP', '00:11:85': 'HP',
            '00:12:79': 'HP', '00:13:21': 'HP', '00:14:38': 'HP',
            '00:14:c2': 'HP', '00:15:60': 'HP', '00:16:35': 'HP',
            '00:16:b9': 'HP', '00:17:08': 'HP', '00:17:a4': 'HP',
            '00:18:71': 'HP', '00:18:fe': 'HP', '00:19:bb': 'HP',
            '00:1a:4b': 'HP', '00:1b:78': 'HP', '00:1c:c4': 'HP',
            '00:1d:09': 'HP', '00:1e:0b': 'HP', '00:1f:29': 'HP',
            '00:21:5a': 'HP', '00:22:64': 'HP', '00:23:7d': 'HP',
            '00:24:81': 'HP', '00:25:b3': 'HP', '00:26:55': 'HP',
            '00:30:c1': 'HP', '08:00:09': 'HP', '1c:98:ec': 'HP',
            '2c:41:38': 'HP', '2c:59:e5': 'HP', '34:64:a9': 'HP',
            '3c:4a:92': 'HP', '40:a8:f0': 'HP', '44:31:92': 'HP',
            '64:51:06': 'HP', '70:5a:0f': 'HP', '94:57:a5': 'HP',
            '9c:8e:99': 'HP', 'a4:5d:36': 'HP', 'b4:99:ba': 'HP',
            'c8:cb:b8': 'HP', 'd0:7e:28': 'HP', 'd4:85:64': 'HP',
            'f4:ce:46': 'HP',
        
             # Canon
            '00:00:48': 'Canon', '00:a0:91': 'Canon', '04:f7:e4': 'Canon',
            '34:2e:b6': 'Canon', '9c:04:eb': 'Canon', 'c4:73:1e': 'Canon',
        }
    
        oui = mac_addr[:8].lower()
        vendor = vendor_map.get(oui)
    
        # If not found in our database, try to use an online API (optional enhancement)
        if vendor is None:
            vendor = self._lookup_vendor_online(oui)
    
        return vendor if vendor else 'Unknown Vendor'

    def _lookup_vendor_online(self, oui):
        """Try to lookup vendor from online API as fallback"""
        try:
            import requests
            # Use macvendors.com API (free, no key needed)
            response = requests.get(f"https://api.macvendors.com/{oui}", timeout=2)
            if response.status_code == 200:
                vendor = response.text.strip()
                if vendor and vendor != "Not Found":
                    return vendor
        except:
            pass
    
        try:
            # Alternative: Use IEEE OUI database API
            response = requests.get(f"https://www.macvendorlookup.com/api/v2/{oui}", timeout=2)
            if response.status_code == 200:
                data = response.json()
                if data and len(data) > 0:
                    return data[0].get('company', None)
        except:
            pass
    
        return None

    # Additional helper method to force ARP population for entire subnet  (might need to put back from the tab move)
    def populate_arp_table(self, network):
        """Send pings to all IPs in subnet to populate ARP table before scanning"""
        try:
            import ipaddress
            import threading
            import time
        
            net = ipaddress.IPv4Network(network, strict=False)
        
            def ping_ip(ip):
                try:
                    import platform
                    if platform.system().lower() == "windows":
                        subprocess.run(['ping', '-n', '1', '-w', '500', str(ip)], 
                                    capture_output=True, timeout=1)
                    else:
                        subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], 
                                    capture_output=True, timeout=1)
                except:
                    pass
        
            # Ping up to 50 IPs concurrently to populate ARP table
            threads = []
            for ip in list(net.hosts())[:50]:  # Limit to first 50 hosts
                t = threading.Thread(target=ping_ip, args=(ip,))
                t.start()
                threads.append(t)
        
            # Wait for all pings to complete (max 3 seconds)
            start_time = time.time()
            for t in threads:
                remaining_time = max(0, 3 - (time.time() - start_time))
                t.join(timeout=remaining_time)
            
        except Exception:
            pass
    
    def get_default_gateway(self):
        """Get the default gateway IP"""
        try:
            import platform
            if platform.system().lower() == "windows":
                result = subprocess.run(['route', 'print', '0.0.0.0'], capture_output=True, text=True, timeout=5)
                import re
                gateway_match = re.search(r'0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
                if gateway_match:
                    return gateway_match.group(1)
            else:
                result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True, timeout=5)
                import re
                gateway_match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if gateway_match:
                    return gateway_match.group(1)
        except:
            pass
        return None
   
    def identify_device_type(self, ip, open_ports, additional_info=None):
        """Enhanced device type identification with proper gateway prioritization"""
        if additional_info is None:
            additional_info = {}
    
        # Fix: Safely handle hostname and mac_vendor values
        hostname = (additional_info.get('hostname', '') or '').lower()
        mac_vendor = (additional_info.get('mac_vendor', '') or '').lower()
    
        # PRIORITY 1: Gateway Detection (highest priority)
        # Check if this is identified as the default gateway
        if additional_info.get('is_gateway'):
            return "Gateway (.1/.254)"
    
        # Check for common gateway IP patterns (.1 or .254)
        ip_parts = ip.split('.')
        if len(ip_parts) == 4:
            last_octet = ip_parts[3]
        
            # Pre-define validation variables
            has_router_ports = any(p in open_ports for p in [22, 23, 53, 80, 443, 161, 8080])
            router_vendors = ['netgear', 'linksys', 'asus', 'tp-link', 'ubiquiti', 'cisco', 'juniper', 'd-link']
            has_router_vendor = any(vendor in mac_vendor for vendor in router_vendors)
            router_keywords = ['router', 'gateway', 'rt-', 'gw-', 'ubnt', 'ubiquiti', 'netgear', 'linksys', 'asus', 'tp-link']
            has_router_hostname = any(keyword in hostname for keyword in router_keywords)
        
            if last_octet in ['1', '254']:
                # If it's on .1/.254 AND has router characteristics, it's definitely a gateway
                if has_router_ports or has_router_vendor or has_router_hostname:
                    return "Gateway (.1/.254)"
                # Even without clear router signs, .1/.254 are likely gateways
                elif last_octet == '1':  # .1 is almost always a gateway
                    return "Gateway (.1/.254)"
    
        # PRIORITY 2: Network Infrastructure (routers, switches, APs that aren't gateways)
        # SNMP usually indicates managed network equipment
        if 161 in open_ports:
            if any(p in open_ports for p in [22, 23, 80, 443]):
                return "Router/Switch"
    
        # Hostname-based network device identification
        switch_keywords = ['switch', 'sw-', 'cisco', 'juniper', 'HP']
        ap_keywords = ['ap-', 'wifi', 'wireless', 'wap', 'access-point', 'unifi']
    
        if any(keyword in hostname for keyword in switch_keywords):
            return "Switch"
        if any(keyword in hostname for keyword in ap_keywords):
            return "Access Point"
    
        # Router that's not a gateway (secondary routers, etc.)
        router_keywords = ['router', 'rt-', 'ubnt', 'ubiquiti', 'netgear', 'linksys', 'asus', 'tp-link']
        if any(keyword in hostname for keyword in router_keywords):
            return "Router/Network Device"
    
        # PRIORITY 3: Specialized Devices
        # Security cameras and surveillance
        camera_keywords = ['camera', 'cam-', 'ipcam', 'dvr', 'nvr', 'hikvision', 'dahua', 'axis']
        camera_vendors = ['hikvision', 'dahua', 'axis', 'panasonic', 'sony']
    
        if (any(keyword in hostname for keyword in camera_keywords) or 
            any(vendor in mac_vendor for vendor in camera_vendors)):
            return "IP Camera/CCTV"
    
        # PRIORITY 4: Host Type Detection
        # Windows hosts
        if 445 in open_ports or 3389 in open_ports:
            return "Windows Host"
    
        # Linux/Unix hosts (SSH but not web server)
        if 22 in open_ports and 80 not in open_ports and 443 not in open_ports:
            return "Linux Host"
    
        # Web servers
        if 80 in open_ports or 443 in open_ports:
            return "Server/Web Device"
    
        # PRIORITY 5: Mobile and Consumer Devices
        mobile_keywords = ['android', 'iphone', 'ipad', 'samsung', 'phone', 'mobile']
        mobile_vendors = ['apple', 'samsung', 'huawei', 'xiaomi', 'oneplus', 'lg electronics', 'google']
    
        if (any(keyword in hostname for keyword in mobile_keywords) or 
            any(vendor in mac_vendor for vendor in mobile_vendors)):
            return "Mobile Device"
    
        # PRIORITY 6: MAC vendor-based fallback
        if mac_vendor:
            router_vendors = ['netgear', 'linksys', 'asus', 'tp-link', 'ubiquiti', 'cisco', 'juniper', 'd-link']
            if any(vendor in mac_vendor for vendor in router_vendors):
                return "Router/Network Device"
    
        # PRIORITY 7: Final fallbacks
        if open_ports:
            return "Network Device"
        else:
            return "Host (Filtered/Mobile)"
    
    def get_arp_hosts(self, network):
        """Get hosts from ARP table - useful for WiFi networks"""
        arp_hosts = []
        try:
            import platform
            if platform.system().lower() == "windows":
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    # Extract IP addresses from ARP output
                    import re
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip_str = ip_match.group(1)
                        try:
                            ip_obj = ipaddress.IPv4Address(ip_str)
                            if ip_obj in network:
                                arp_hosts.append(ip_str)
                        except:
                            continue
        except Exception as e:
            print(f"ARP scan failed: {e}")
        
        return arp_hosts
    
    def tcp_sweep(self, host_list):
        """TCP-based host discovery for hosts that don't respond to ping"""
        tcp_alive = []
        common_ports = [80, 443, 22, 135, 445]
        
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = []
            for host in host_list:
                for port in common_ports:
                    if not self.scanning:
                        break
                    futures.append(executor.submit(self.tcp_connect_test, host, port))
            
            for future in futures:
                if not self.scanning:
                    break
                result = future.result()
                if result and result not in tcp_alive:
                    tcp_alive.append(result)
        
        return tcp_alive

    
    def tcp_connect_test(self, ip, port):
        """Test TCP connection to a specific IP:port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((str(ip), port))
            sock.close()
            return str(ip) if result == 0 else None
        except:
            return None
    
    def scan_network(self, network):
        """Enhanced network scan with proper gateway identification"""
        print(f"Scanning network: {network}")
    
        # Get default gateway first
        default_gateway = self.get_default_gateway()
        print(f"Default gateway detected: {default_gateway}")
        
        # Clear previous results
        self.discovered_hosts.clear()
        self.network_graph.clear()
        
        # Multi-method host discovery
        alive_hosts = []
        hosts_list = list(network.hosts())
        
        # Method 1: Ping sweep
        self.root.after(0, lambda: self.status_var.set("Starting ping sweep..."))
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {executor.submit(self.ping_host, ip): ip for ip in hosts_list}
            
            completed = 0
            for future in future_to_ip:
                if not self.scanning:
                    break
                
                result = future.result()
                if result and result not in alive_hosts:
                    alive_hosts.append(result)
                
                completed += 1
                if completed % 20 == 0:
                    self.root.after(0, lambda c=completed, t=len(hosts_list), a=len(alive_hosts): 
                                  self.status_var.set(f"Ping sweep: {c}/{t} ({a} alive)"))
        
        # Method 2: ARP table scan (Windows/local network)
        if self.scanning:
            self.root.after(0, lambda: self.status_var.set("Checking ARP table..."))
            arp_hosts = self.get_arp_hosts(network)
            for host in arp_hosts:
                if host not in alive_hosts:
                    alive_hosts.append(host)
        
        # Method 3: TCP port scan on remaining IPs (for stubborn hosts)
        if self.scanning and len(alive_hosts) < 5:  # Only if we found very few hosts
            self.root.after(0, lambda: self.status_var.set("Performing TCP discovery..."))
            remaining_hosts = [str(ip) for ip in hosts_list if str(ip) not in alive_hosts]
            tcp_found = self.tcp_sweep(remaining_hosts[:50])  # Limit to first 50
            alive_hosts.extend(tcp_found)
        
        if not self.scanning:
            self.root.after(0, self.scan_complete)
            return
        
        self.root.after(0, lambda: self.status_var.set(f"Found {len(alive_hosts)} hosts. Gathering device info..."))
        
        # Get gateway for better identification
        gateway_ip = self.get_default_gateway()
        
        # Detailed scanning of alive hosts with enhanced identification
        for i, ip in enumerate(alive_hosts):
            if not self.scanning:
                break
                
            self.root.after(0, lambda i=i, ip=ip, total=len(alive_hosts): 
                          self.status_var.set(f"Analyzing devices: {i+1}/{total} ({ip})"))
            
            # Gather multiple types of information
            hostname = self.get_hostname(ip)
            mac_info = self.get_mac_address(ip)
            
            # Quick port scan (still useful for some devices)
            try:
                open_ports = self.scan_host_ports(ip)
                if not self.scanning:
                    break
                
                # Enhanced device identification with safe string handling
                additional_info = {
                    'hostname': hostname,
                    'mac_vendor': mac_info.get('vendor', ''),
                    'is_gateway': (ip == gateway_ip)
                }
                device_type = self.identify_device_type(ip, open_ports, additional_info)
                
                self.discovered_hosts[ip] = {
                    'hostname': hostname,
                    'open_ports': open_ports,
                    'device_type': device_type,
                    'mac_address': mac_info.get('mac', 'Unknown'),
                    'mac_vendor': mac_info.get('vendor', 'Unknown'),
                    'is_gateway': (ip == gateway_ip)
                }
                
                # Add to network graph
                self.network_graph.add_node(ip, 
                                          hostname=hostname, 
                                          device_type=device_type,
                                          open_ports=open_ports,
                                          mac_vendor=mac_info.get('vendor', ''))
                                          
                # Update GUI periodically
                if i % 2 == 0:  # Update every 2 hosts
                    self.root.after(0, self.update_partial_results)
                    
            except Exception as e:
                print(f"Error scanning {ip}: {e}")
                # Add host with minimal info if detailed scan fails
                additional_info = {
                    'hostname': hostname,
                    'mac_vendor': mac_info.get('vendor', ''),
                    'is_gateway': (ip == gateway_ip)
                }
                device_type = self.identify_device_type(ip, [], additional_info)
                
                self.discovered_hosts[ip] = {
                    'hostname': hostname,
                    'open_ports': [],
                    'device_type': device_type,
                    'mac_address': mac_info.get('mac', 'Unknown'),
                    'mac_vendor': mac_info.get('vendor', 'Unknown'),
                    'is_gateway': (ip == gateway_ip)
                }
                continue
        
        if self.scanning:
            self.build_topology()
        
        self.root.after(0, self.scan_complete)
    
    # ==== IMPROVED SUBNET FILTERING METHODS FOR NetworkScannerGUI CLASS ====
    
    def detect_subnets(self):
        """Auto-detect meaningful subnets from discovered hosts, filtering out broadcast addresses"""
        import ipaddress
        from collections import defaultdict
        
        if not self.discovered_hosts:
            return {}
        
        subnet_groups = defaultdict(list)
        
        for ip_str in self.discovered_hosts.keys():
            try:
                ip = ipaddress.IPv4Address(ip_str)
                
                # Skip broadcast addresses and other non-host IPs
                if self.is_broadcast_or_network_address(ip_str):
                    continue
                
                # Try different subnet masks to group devices
                for prefix_len in [24, 16, 8]:  # /24, /16, /8
                    try:
                        network = ipaddress.IPv4Network(f"{ip}/{prefix_len}", strict=False)
                        subnet_key = f"{network.network_address}/{prefix_len}"
                        
                        # Only add if this creates meaningful groups
                        hosts_in_network = [h for h in self.discovered_hosts.keys() 
                                          if not self.is_broadcast_or_network_address(h) and
                                          ipaddress.IPv4Address(h) in network]
                        
                        if len(hosts_in_network) > 1:
                            subnet_groups[subnet_key].append(ip_str)
                            break
                    except:
                        continue
                        
            except:
                # If IP parsing fails, put in "Other" category (only if not broadcast)
                if not self.is_broadcast_or_network_address(ip_str):
                    subnet_groups["Other"].append(ip_str)
        
        # Remove duplicate entries and sort
        for subnet in subnet_groups:
            subnet_groups[subnet] = sorted(list(set(subnet_groups[subnet])))
        
        # Only return if we have multiple meaningful subnets
        meaningful_subnets = {k: v for k, v in subnet_groups.items() if len(v) >= 2}
        
        # Don't show filter if only one meaningful subnet
        if len(meaningful_subnets) <= 1:
            return {}
            
        return meaningful_subnets
    
    def is_broadcast_or_network_address(self, ip_str):
        """Check if IP is a broadcast, network, or other non-host address"""
        try:
            import ipaddress
            ip = ipaddress.IPv4Address(ip_str)
            
            # Check for broadcast addresses (ending in .255)
            if str(ip).endswith('.255'):
                return True
            
            # Check for network addresses (ending in .0)
            if str(ip).endswith('.0'):
                return True
                
            # Check for multicast range (224.0.0.0 to 239.255.255.255)
            if ip.is_multicast:
                return True
                
            # Check for loopback
            if ip.is_loopback:
                return True
                
            return False
        except:
            return False
    
    def create_subnet_filter_controls(self, parent_frame, canvas, ax, fig):
        """Create subnet filtering controls"""
        
        # Detect available subnets
        self.subnet_groups = self.detect_subnets()
        
        if len(self.subnet_groups) <= 1:
            # No meaningful subnets to filter - don't show filter controls
            print("DEBUG: Not showing subnet filter - only one meaningful subnet detected")
            return
        
        print(f"DEBUG: Creating subnet filter with {len(self.subnet_groups)} subnets: {list(self.subnet_groups.keys())}")
        
        # Create filter frame
        filter_frame = tk.Frame(parent_frame)
        filter_frame.pack(side=tk.LEFT, padx=10)
        
        # Subnet filter label
        filter_label = tk.Label(filter_frame, text="📶 Subnet Filter:", 
                               font=('Arial', 9, 'bold'), fg='#333')
        filter_label.pack(side=tk.LEFT, padx=(0, 5))
        
        # Subnet selection dropdown
        self.subnet_var = tk.StringVar()
        subnet_options = ["All Networks"] + list(self.subnet_groups.keys())
        
        self.subnet_dropdown = ttk.Combobox(filter_frame, textvariable=self.subnet_var,
                                           values=subnet_options, state="readonly", width=15)
        self.subnet_dropdown.set("All Networks")
        self.subnet_dropdown.pack(side=tk.LEFT, padx=2)
        
        # Apply filter button
        filter_btn = tk.Button(filter_frame, text="Apply", 
                             command=lambda: self.apply_subnet_filter(canvas, ax, fig),
                             bg='#FF9800', fg='white', font=('Arial', 9, 'bold'))
        filter_btn.pack(side=tk.LEFT, padx=2)
        
        # Device count label
        self.filter_info_label = tk.Label(filter_frame, 
                                         text=f"({len(self.discovered_hosts)} devices)",
                                         font=('Arial', 8), fg='#666')
        self.filter_info_label.pack(side=tk.LEFT, padx=5)
        
        # Bind dropdown change event
        self.subnet_dropdown.bind('<<ComboboxSelected>>', 
                                 lambda e: self.on_subnet_selection_change())
    
    def on_subnet_selection_change(self):
        """Update info when subnet selection changes"""
        selected = self.subnet_var.get()
        
        if selected == "All Networks":
            count = len(self.discovered_hosts)
            self.filter_info_label.config(text=f"({count} devices)")
        elif selected in self.subnet_groups:
            count = len(self.subnet_groups[selected])
            self.filter_info_label.config(text=f"({count} devices)")
    
    def apply_subnet_filter(self, canvas, ax, fig):
        """Apply subnet filter using your existing topology visualization style"""
        selected_subnet = self.subnet_var.get()
        
        try:
            print(f"DEBUG: Applying subnet filter: {selected_subnet}")
            
            # Determine which hosts to show
            if selected_subnet == "All Networks":
                filtered_hosts = self.discovered_hosts
                print(f"DEBUG: Showing all {len(filtered_hosts)} hosts")
            elif selected_subnet in self.subnet_groups:
                # Filter to only show hosts in selected subnet
                subnet_ips = self.subnet_groups[selected_subnet]
                filtered_hosts = {ip: info for ip, info in self.discovered_hosts.items() 
                                if ip in subnet_ips}
                print(f"DEBUG: Filtered to {len(filtered_hosts)} hosts in {selected_subnet}")
            else:
                filtered_hosts = self.discovered_hosts
                print(f"DEBUG: Unknown subnet selection, showing all {len(filtered_hosts)} hosts")
            
            # Clear the current plot
            ax.clear()
            
            # Recreate the topology using your existing method but with filtered hosts
            self.redraw_topology_with_filter(ax, filtered_hosts, selected_subnet)
            
            # Refresh the display
            canvas.draw()
            
            print(f"DEBUG: Successfully applied subnet filter")
            
        except Exception as e:
            messagebox.showerror("Filter Error", f"Failed to apply subnet filter: {str(e)}")
            print(f"DEBUG: Subnet filter error: {e}")
    
    def redraw_topology_with_filter(self, ax, filtered_hosts, subnet_name):
        """Redraw topology using your existing style but with filtered hosts"""
        
        # Create a filtered network graph
        filtered_graph = self.create_filtered_network_graph(filtered_hosts)
        
        if not filtered_graph.nodes():
            ax.text(0.5, 0.5, f'No devices in {subnet_name}' if subnet_name != "All Networks" else 'No devices found', 
                   ha='center', va='center', transform=ax.transAxes,
                   fontsize=14, color='gray')
            ax.set_title(f"Network Topology - {subnet_name}")
            return
        
        # Use your existing device mappings and layout logic
        device_mappings = self.create_legend_mappings()
        
        # Define node shapes (same as your original)
        shape_map = {
            'Gateway (.1/.254)': 'D',      # Diamond
            'Router/Gateway': 'D',          # Diamond  
            'Router/Switch': 'D',           # Diamond
            'Router/Network Device': 'D',   # Diamond
            'Router': 'D',                  # Diamond
            'Switch': 's',                  # Square
            'Access Point': '^',            # Triangle
            'Server/Web Device': 's',       # Square
            'Windows Host': 'o',            # Circle
            'Linux Host': 'o',              # Circle
            'IP Camera/CCTV': 'v',          # Inverted triangle
            'IP Camera': 'v',               # Inverted triangle
            'Mobile Device': 'o',           # Circle (smaller)
            'Network Device': 'h',          # Hexagon
            'Host (Filtered/Mobile)': 'o',  # Circle
            'Unknown': 'o'                  # Circle
        }
        
        # Categorize nodes using your existing logic
        gateway_nodes = []
        infrastructure_nodes = []
        client_nodes = []

        for node in filtered_graph.nodes():
            last_octet = int(node.split('.')[-1])
            device_type = filtered_graph.nodes[node].get('device_type', 'Unknown')

            # Use your existing gateway detection logic
            is_gateway = (last_octet in [1, 254] or 
                        'Gateway' in device_type or 
                        ('Router' in device_type and 'Network Device' not in device_type))

            if is_gateway:
                gateway_nodes.append(node)
            elif any(keyword in device_type for keyword in ['Switch', 'Access Point', 'Server', 'Camera']):
                infrastructure_nodes.append(node)
            else:
                client_nodes.append(node)
        
        # Use your existing hierarchical layout logic
        pos = self.create_hierarchical_layout(filtered_graph, gateway_nodes, infrastructure_nodes, client_nodes)
        
        # Store positions for click detection
        self.node_positions = pos.copy()
        
        # Group nodes by shape and draw them using your existing method
        nodes_by_shape = {}
        for node in filtered_graph.nodes():
            device_type = filtered_graph.nodes[node].get('device_type', 'Unknown')
            shape = shape_map.get(device_type, 'o')
    
            if shape not in nodes_by_shape:
                nodes_by_shape[shape] = []
            nodes_by_shape[shape].append(node)
        
        # Draw each shape group (using your existing drawing logic)
        for shape, nodes in nodes_by_shape.items():
            if not nodes:
                continue
            
            node_colors, node_sizes = self.prepare_node_appearance(nodes, filtered_graph, gateway_nodes)
            
            # Create position dict for this shape group
            shape_pos = {node: pos[node] for node in nodes}
    
            # Draw nodes with the specific shape
            nx.draw_networkx_nodes(filtered_graph.subgraph(nodes), shape_pos,
                                node_color=node_colors,
                                node_size=node_sizes,
                                node_shape=shape,
                                alpha=0.8,
                                edgecolors='black',
                                linewidths=1,
                                ax=ax)
        
        # Draw edges
        if filtered_graph.edges():
            nx.draw_networkx_edges(filtered_graph, pos,
                                alpha=0.4,
                                edge_color='#666666',
                                width=1.5,
                                style='solid',
                                ax=ax)
        
        # Add labels using your existing logic
        labels = self.create_node_labels(filtered_graph, gateway_nodes)
        nx.draw_networkx_labels(filtered_graph, pos, labels, 
                            font_size=8, font_weight='bold', ax=ax)
        
        # Set title
        title_suffix = f" - {subnet_name}" if subnet_name != "All Networks" else ""
        ax.set_title(f"Network Topology{title_suffix}\n(Click on any device for details)", 
                fontsize=14, fontweight='bold', pad=20)
        ax.axis('off')
        
        # Add legend (using your existing legend logic)
        self.add_topology_legend(ax, filtered_graph, device_mappings, shape_map)
        
        # Add statistics
        stats_text = f"Devices: {len(filtered_graph.nodes())} | " \
                    f"Gateways: {len(gateway_nodes)} | " \
                    f"Infrastructure: {len(infrastructure_nodes)} | " \
                    f"Clients: {len(client_nodes)}"
        
        ax.text(0.5, -0.05, stats_text, transform=ax.transAxes, 
            ha='center', va='top', fontsize=10, 
            bbox=dict(boxstyle="round,pad=0.3", facecolor="lightgray", alpha=0.8))
    
    def create_filtered_network_graph(self, filtered_hosts):
        """Create a network graph from filtered hosts"""
        import networkx as nx
        
        # Create new graph with filtered hosts
        filtered_graph = nx.Graph()
        
        # Add nodes with attributes
        for ip, host_info in filtered_hosts.items():
            filtered_graph.add_node(ip, **host_info)
        
        # Build topology for filtered hosts using your existing logic
        # This recreates the edges based on the same logic as your build_topology method
        subnets = defaultdict(list)
        infrastructure_devices = []
    
        # Group hosts by subnet
        for ip in filtered_hosts:
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            subnet = str(network.network_address)
            subnets[subnet].append(ip)
        
            # Identify infrastructure devices using your existing logic
            last_octet = int(ip.split('.')[-1])
            device_type = filtered_hosts[ip]['device_type']
            open_ports = filtered_hosts[ip]['open_ports']
        
            is_infrastructure = (
                last_octet in [1, 254] or
                'Router' in device_type or
                'Switch' in device_type or 
                'Gateway' in device_type or
                'Network Device' in device_type or
                'Access Point' in device_type or
                161 in open_ports or
                22 in open_ports or
                23 in open_ports
            )
        
            if is_infrastructure:
                infrastructure_devices.append(ip)
        
        # Build topology using your existing logic
        for subnet, hosts in subnets.items():
            if len(hosts) > 1:
                subnet_infrastructure = [h for h in hosts if h in infrastructure_devices]
                subnet_clients = [h for h in hosts if h not in infrastructure_devices]
            
                if subnet_infrastructure:
                    subnet_infrastructure.sort(key=lambda x: int(x.split('.')[-1]))
                    primary_gateway = subnet_infrastructure[0]
                
                    # Connect infrastructure devices in a chain
                    for i in range(len(subnet_infrastructure) - 1):
                        filtered_graph.add_edge(subnet_infrastructure[i], subnet_infrastructure[i + 1])
                
                    # Connect client devices to infrastructure
                    for client in subnet_clients:
                        best_infrastructure = None
                    
                        for infra in subnet_infrastructure:
                            if 'Network Device' in filtered_hosts[infra]['device_type']:
                                best_infrastructure = infra
                                break
                    
                        if best_infrastructure is None:
                            best_infrastructure = subnet_infrastructure[-1]
                    
                        filtered_graph.add_edge(best_infrastructure, client)
                else:
                    # No infrastructure - create star topology
                    hub = hosts[0]
                    for i in range(1, len(hosts)):
                        filtered_graph.add_edge(hub, hosts[i])
        
        return filtered_graph
    
    def create_hierarchical_layout(self, graph, gateway_nodes, infrastructure_nodes, client_nodes):
        """Create hierarchical layout using your existing logic"""
        import networkx as nx
        
        pos = {}
        all_nodes = list(graph.nodes())

        if len(gateway_nodes) > 0:
            # Position gateways at the top
            gateway_width = max(len(gateway_nodes) * 2, 4)
            for i, gateway in enumerate(gateway_nodes):
                x_pos = (i - (len(gateway_nodes) - 1) / 2) * (gateway_width / max(len(gateway_nodes), 1))
                pos[gateway] = (x_pos, 3.0)

            # Position infrastructure devices in middle layer
            if infrastructure_nodes:
                infra_y_level = 2.0
                if len(infrastructure_nodes) == 1:
                    pos[infrastructure_nodes[0]] = (0, infra_y_level)
                else:
                    infra_width = len(infrastructure_nodes) * 1.5
                    for i, device in enumerate(infrastructure_nodes):
                        x_pos = (i - (len(infrastructure_nodes) - 1) / 2) * (infra_width / len(infrastructure_nodes))
                        pos[device] = (x_pos, infra_y_level)

            # Position client devices in grid layout at bottom
            if client_nodes:
                client_y_level = 0.8
        
                total_clients = len(client_nodes)
                if total_clients <= 4:
                    cols = total_clients
                    rows = 1
                elif total_clients <= 9:
                    cols = 3
                    rows = (total_clients + cols - 1) // cols
                else:
                    cols = max(4, int(total_clients ** 0.6))
                    rows = (total_clients + cols - 1) // cols
        
                grid_width = cols * 1.8
                grid_height = rows * 0.6
        
                for i, device in enumerate(client_nodes):
                    row = i // cols
                    col = i % cols
            
                    x_pos = (col - (cols - 1) / 2) * (grid_width / max(cols, 1))
                    y_pos = client_y_level - (row * grid_height / max(rows, 1))
            
                    pos[device] = (x_pos, y_pos)
        else:
            # No gateways - use spring layout
            try:
                pos = nx.spring_layout(graph, k=3, iterations=50)
            except:
                # Fallback to grid layout
                nodes = list(graph.nodes())
                cols = max(1, int(len(nodes) ** 0.5))
                pos = {}
                for i, node in enumerate(nodes):
                    row = i // cols
                    col = i % cols
                    pos[node] = (col * 2, -row * 1.5)

        # Ensure all nodes have positions
        for node in all_nodes:
            if node not in pos:
                pos[node] = (0, 0)

        return pos
    
    def prepare_node_appearance(self, nodes, graph, gateway_nodes):
        """Prepare node colors and sizes using your existing logic"""
        node_colors = []
        node_sizes = []
        
        # Use your existing device mappings
        device_mappings = self.create_legend_mappings()
        
        # Vendor colors from your existing code
        vendor_colors = {
            'apple': '#007AFF',      'samsung': '#1428A0',    'google': '#4285F4',
            'microsoft': '#0078D4',  'cisco': '#049FD9',      'netgear': '#F7941D',
            'tp-link': '#4CC35E',    'asus': '#0066CC',       'linksys': '#003366',
            'ubiquiti': '#0066CC'
        }
        
        for node in nodes:
            device_type = graph.nodes[node].get('device_type', 'Unknown')
            mac_vendor = graph.nodes[node].get('mac_vendor', '')
            open_ports = graph.nodes[node].get('open_ports', [])
        
            # Color selection
            base_color = device_mappings.get(device_type, {}).get('color', '#95A5A6')
        
            vendor_color = None
            if mac_vendor:
                vendor_lower = mac_vendor.lower()
                for vendor, color in vendor_colors.items():
                    if vendor in vendor_lower:
                        vendor_color = color
                        break
        
            node_colors.append(vendor_color if vendor_color else base_color)
        
            # Size selection using your existing logic
            base_size = 1000
        
            if node in gateway_nodes:
                size = 2000
            elif device_type in ['Server/Web Device', 'Switch', 'Router/Switch']:
                size = 1600
            elif device_type in ['IP Camera/CCTV', 'Access Point']:
                size = 1200
            elif device_type == 'Mobile Device':
                size = 800
            else:
                port_count = len(open_ports) if open_ports else 0
                size = base_size + (port_count * 50)
                size = min(size, 1400)
        
            node_sizes.append(size)
        
        return node_colors, node_sizes
    
    def create_node_labels(self, graph, gateway_nodes):
        """Create node labels using your existing logic"""
        labels = {}
        for node in graph.nodes():
            hostname = graph.nodes[node].get('hostname', node)
            device_type = graph.nodes[node].get('device_type', 'Unknown')
            mac_vendor = graph.nodes[node].get('mac_vendor', '')
    
            # Truncate long hostnames
            if len(hostname) > 15:
                hostname = hostname[:12] + "..."
    
            # Create label with device type indicator
            if node in gateway_nodes:
                labels[node] = f"[GW] {hostname}\n({node})"
            elif 'Server' in device_type:
                labels[node] = f"[SRV] {hostname}\n({node})" 
            elif 'Camera' in device_type:
                labels[node] = f"[CAM] {hostname}\n({node})"
            elif 'Mobile' in device_type:
                labels[node] = f"[MOB] {hostname}\n({node})"
            elif mac_vendor and mac_vendor != 'Unknown':
                labels[node] = f"{hostname}\n({mac_vendor})"
            else:
                labels[node] = f"{hostname}\n({node})"
        
        return labels
    
    def add_topology_legend(self, ax, graph, device_mappings, shape_map):
        """Add legend using your existing logic"""
        existing_types = set()
        for node in graph.nodes():
            device_type = graph.nodes[node].get('device_type', 'Unknown')
            existing_types.add(device_type)

        legend_elements = []
        from matplotlib.lines import Line2D

        sorted_types = sorted(existing_types, 
                            key=lambda x: device_mappings.get(x, {}).get('priority', 99))

        for device_type in sorted_types:
            color = device_mappings.get(device_type, {}).get('color', '#95A5A6')
            shape = shape_map.get(device_type, 'o')
    
            marker_map = {'D': 'D', 's': 's', '^': '^', 'v': 'v', 'h': 'h', 'o': 'o'}
            marker = marker_map.get(shape, 'o')
    
            legend_elements.append(Line2D([0], [0], marker=marker, color='w',
                                        markerfacecolor=color, 
                                        markeredgecolor='black',
                                        markeredgewidth=1,
                                        markersize=10,
                                        label=device_type))

        if legend_elements:
            ax.legend(handles=legend_elements, loc='upper left', frameon=True,
                    fancybox=True, shadow=True, fontsize=9)
                    
    # End of Subnet Filtering on Map   
        
    def build_topology(self):
        """Build network topology based on discovered information"""
        subnets = defaultdict(list)
        infrastructure_devices = []
    
        # Group hosts by subnet
        for ip in self.discovered_hosts:
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            subnet = str(network.network_address)
            subnets[subnet].append(ip)
        
            # Identify infrastructure devices (gateways, switches, access points)
            last_octet = int(ip.split('.')[-1])
            device_type = self.discovered_hosts[ip]['device_type']
            open_ports = self.discovered_hosts[ip]['open_ports']
        
            # Consider as infrastructure if:
            # 1. Ends in .1 or .254 (common gateway addresses)
            # 2. Has device type suggesting network infrastructure
            # 3. Has SNMP port (161) or common network service ports
            is_infrastructure = (
                last_octet in [1, 254] or  # Common gateway IPs
                'Router' in device_type or
                'Switch' in device_type or 
                'Gateway' in device_type or
                'Network Device' in device_type or
                'Access Point' in device_type or
                161 in open_ports or  # SNMP
                22 in open_ports or   # SSH (common on network devices)
                23 in open_ports      # Telnet (common on network devices)
            )
        
            if is_infrastructure:
                infrastructure_devices.append(ip)
    
        print(f"DEBUG: Infrastructure devices detected: {infrastructure_devices}")
    
        # Build topology for each subnet
        for subnet, hosts in subnets.items():
            if len(hosts) > 1:
                # Find infrastructure devices in this subnet
                subnet_infrastructure = [h for h in hosts if h in infrastructure_devices]
                subnet_clients = [h for h in hosts if h not in infrastructure_devices]
            
                print(f"DEBUG: Subnet {subnet} - Infrastructure: {subnet_infrastructure}, Clients: {subnet_clients}")
            
                if subnet_infrastructure:
                    # Sort infrastructure devices by IP (gateway first, then others)
                    subnet_infrastructure.sort(key=lambda x: int(x.split('.')[-1]))
                    primary_gateway = subnet_infrastructure[0]
                
                    # Connect infrastructure devices in a chain (gateway -> switch -> access point, etc.)
                    for i in range(len(subnet_infrastructure) - 1):
                        self.network_graph.add_edge(subnet_infrastructure[i], subnet_infrastructure[i + 1])
                
                    # Connect client devices to the most appropriate infrastructure device
                    for client in subnet_clients:
                        # Try to find the best infrastructure device to connect to
                        best_infrastructure = None
                    
                        # If there's a "Network Device" (likely a switch), prefer that
                        for infra in subnet_infrastructure:
                            if 'Network Device' in self.discovered_hosts[infra]['device_type']:
                                best_infrastructure = infra
                                break
                    
                        # Otherwise, use the last infrastructure device (furthest from gateway)
                        if best_infrastructure is None:
                            best_infrastructure = subnet_infrastructure[-1]
                    
                        self.network_graph.add_edge(best_infrastructure, client)
                    
                else:
                    # No infrastructure devices found - create a simple mesh or star
                    # Connect the first device to all others (star topology)
                    hub = hosts[0]
                    for i in range(1, len(hosts)):
                        self.network_graph.add_edge(hub, hosts[i])
    
        print(f"DEBUG: Final topology - Nodes: {len(self.network_graph.nodes())}, Edges: {len(self.network_graph.edges())}")
        print(f"DEBUG: Edges: {list(self.network_graph.edges())}")
    
    def start_scan(self):
        """Start the network scan in a separate thread"""
        if not self.network_entry.get().strip():
            messagebox.showerror("Error", "Please enter a network range")
            return
    
        try:
            # Parse the network from the input field
            import ipaddress
            network_str = self.network_entry.get().strip()
            network = ipaddress.IPv4Network(network_str, strict=False)
        except Exception as e:
            messagebox.showerror("Error", f"Invalid network format: {e}")
            return
    
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.export_button.config(state=tk.DISABLED)
        self.view_map_button.config(state=tk.DISABLED)
    
        # Clear previous results
        self.summary_text.delete(1.0, tk.END)
        for item in self.tree.get_children():
            self.tree.delete(item)
    
        self.progress.start()
    
        # Start scan thread with network parameter
        scan_thread = threading.Thread(target=self.scan_network, args=(network,), daemon=True)
        scan_thread.start()
    
    def stop_scan(self):
        """Stop the current scan"""
        self.scanning = False
        self.status_var.set("Stopping scan... please wait")
        
        # Force GUI update and give threads time to finish
        self.root.update()
        
        # Use a timer to ensure cleanup happens
        def force_cleanup():
            self.progress.stop()
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            
            if self.discovered_hosts:
                self.export_button.config(state=tk.NORMAL)
                self.view_map_button.config(state=tk.NORMAL)
                self.update_results()
                self.status_var.set(f"Scan stopped. Found {len(self.discovered_hosts)} hosts.")
            else:
                self.status_var.set("Scan stopped.")
        
        # Schedule cleanup after a short delay to let threads finish
        self.root.after(1000, force_cleanup)
    
    def scan_complete(self):
        """Called when scan is complete"""
        self.scanning = False
        self.progress.stop()
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        if self.discovered_hosts:
            self.export_button.config(state=tk.NORMAL)
            self.view_map_button.config(state=tk.NORMAL)
            self.update_results()  # Make sure this is called!
            self.status_var.set(f"Scan complete. Found {len(self.discovered_hosts)} hosts.")
        else:
            self.status_var.set("Scan complete. No hosts found.")
    
    def update_partial_results(self):
        """Update GUI with partial results during scanning"""
        if not self.discovered_hosts:
            return
            
        # Quick update of the summary text
        summary = f"Partial Results (Scan in progress...)\n"
        summary += f"{'='*40}\n"
        summary += f"Hosts found so far: {len(self.discovered_hosts)}\n\n"
        
        # Show latest few discoveries
        recent_hosts = list(self.discovered_hosts.items())[-5:]
        for ip, info in recent_hosts:
            summary += f"{ip:15} | {info['hostname']:20} | {info['device_type']}\n"
        
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(1.0, summary)
        
        # Update tree with new entries only
        existing_ips = set()
        for item in self.tree.get_children():
            existing_ips.add(self.tree.item(item, 'values')[0])
        
        for ip, info in self.discovered_hosts.items():
            if ip not in existing_ips:
                ports_str = ', '.join(map(str, info['open_ports'][:3]))
                if len(info['open_ports']) > 3:
                    ports_str += f" (+{len(info['open_ports'])-3})"
                
                self.tree.insert('', tk.END, values=(
                    ip, 
                    info['hostname'], 
                    info['device_type'], 
                    ports_str
                ))
    
    def update_results(self):
        """Update the GUI with scan results"""
        # Update summary
        summary = f"Network Topology Scan Results\n"
        summary += f"{'='*50}\n"
        summary += f"Network Range: {self.network_entry.get()}\n"
        summary += f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        summary += f"Total Hosts Found: {len(self.discovered_hosts)}\n\n"
        
        # Group by device type
        device_types = defaultdict(list)
        for ip, info in self.discovered_hosts.items():
            device_types[info['device_type']].append((ip, info))
        
        for device_type, hosts in device_types.items():
            summary += f"{device_type} ({len(hosts)}):\n"
            for ip, info in hosts:
                ports_str = ', '.join(map(str, info['open_ports'][:5]))
                if len(info['open_ports']) > 5:
                    ports_str += f" (+{len(info['open_ports'])-5} more)"
                elif not info['open_ports']:
                    ports_str = "No open ports detected"
                
                mac_info = ""
                if 'mac_vendor' in info and info['mac_vendor'] != 'Unknown':
                    mac_info = f" | {info['mac_vendor']}"
                    
                gateway_info = " | Gateway" if info.get('is_gateway', False) else ""
                
                summary += f"  {ip:15} | {info['hostname']:20}{mac_info}{gateway_info}\n"
                summary += f"    Ports: {ports_str}\n"
            summary += "\n"
        
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(1.0, summary)
        
        # Update treeview - clear and repopulate
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for ip, info in self.discovered_hosts.items():
            ports_str = ', '.join(map(str, info['open_ports'][:3]))
            if len(info['open_ports']) > 3:
                ports_str += f" (+{len(info['open_ports'])-3})"
            elif not info['open_ports']:
                ports_str = "None detected"
            
            self.tree.insert('', tk.END, values=(
                ip, 
                info['hostname'], 
                info['device_type'], 
                ports_str
            ))
            
   
        # Replace the existing show_topology method with this enhanced version

    def show_topology(self):
        """Show enhanced topology map with different shapes, sizes, and colors"""
        # First, ensure we have discovered hosts
        if not self.discovered_hosts:
            messagebox.showwarning("Warning", "No network scan data available. Please run a scan first.")
            return

        # Debug: Print discovered hosts info
        print(f"DEBUG: Found {len(self.discovered_hosts)} discovered hosts:")
        for ip, info in self.discovered_hosts.items():
            print(f"  {ip}: {info.get('device_type', 'Unknown')}")

        # Build the network topology before visualizing
        self.build_network_graph()

        # Debug: Print network graph info
        print(f"DEBUG: Network graph has {len(self.network_graph.nodes())} nodes and {len(self.network_graph.edges())} edges")

        if not self.network_graph.nodes():
            messagebox.showwarning("Warning", "No network topology could be built from scan data.")
            return

        # Create new window
        topo_window = tk.Toplevel(self.root)
        topo_window.title("Enhanced Network Topology Map")
        topo_window.geometry("1200x900")  # Larger window for better visualization

        # Create matplotlib figure
        fig = Figure(figsize=(12, 9), dpi=100)
        ax = fig.add_subplot(111)

        # Enhanced color and shape mappings
        device_mappings = self.create_legend_mappings()

        # Define node shapes for different device types
        shape_map = {
            'Gateway (.1/.254)': 'D',      # Diamond
            'Router/Gateway': 'D',          # Diamond  
            'Router/Switch': 'D',           # Diamond
            'Router/Network Device': 'D',   # Diamond
            'Router': 'D',                  # Diamond
            'Switch': 's',                  # Square
            'Access Point': '^',            # Triangle
            'Server/Web Device': 's',       # Square
            'Windows Host': 'o',            # Circle
            'Linux Host': 'o',              # Circle
            'IP Camera/CCTV': 'v',          # Inverted triangle
            'IP Camera': 'v',               # Inverted triangle
            'Mobile Device': 'o',           # Circle (smaller)
            'Network Device': 'h',          # Hexagon
            'Host (Filtered/Mobile)': 'o',  # Circle
            'Unknown': 'o'                  # Circle
        }

        # Identify gateway nodes and categorize all nodes
        gateway_nodes = []
        infrastructure_nodes = []  # Switches, APs, servers
        client_nodes = []          # End devices

        for node in self.network_graph.nodes():
            last_octet = int(node.split('.')[-1])
            device_type = self.network_graph.nodes[node].get('device_type', 'Unknown')

            # Consider as gateway if: ends in .1 or .254, OR is identified as router/gateway
            is_gateway = (last_octet in [1, 254] or 
                        'Gateway' in device_type or 
                        ('Router' in device_type and 'Network Device' not in device_type))

            if is_gateway:
                gateway_nodes.append(node)
            elif any(keyword in device_type for keyword in ['Switch', 'Access Point', 'Server', 'Camera']):
                infrastructure_nodes.append(node)
            else:
                client_nodes.append(node)

        # Debug: Print categorization
        print(f"DEBUG: Gateways: {gateway_nodes}")
        print(f"DEBUG: Infrastructure: {infrastructure_nodes}")  
        print(f"DEBUG: Clients: {client_nodes}")

        # Create hierarchical layout
        pos = {}
        all_nodes = list(self.network_graph.nodes())

        if len(gateway_nodes) > 0:
            print(f"DEBUG: Using hierarchical layout with {len(gateway_nodes)} gateways")

            # Position gateways at the top
            gateway_width = max(len(gateway_nodes) * 2, 4)
            for i, gateway in enumerate(gateway_nodes):
                x_pos = (i - (len(gateway_nodes) - 1) / 2) * (gateway_width / max(len(gateway_nodes), 1))
                pos[gateway] = (x_pos, 3.0)  # Top level

            # Position infrastructure devices in middle layer
            if infrastructure_nodes:
                infra_y_level = 2.0
                if len(infrastructure_nodes) == 1:
                    pos[infrastructure_nodes[0]] = (0, infra_y_level)
                else:
                    infra_width = len(infrastructure_nodes) * 1.5
                    for i, device in enumerate(infrastructure_nodes):
                        x_pos = (i - (len(infrastructure_nodes) - 1) / 2) * (infra_width / len(infrastructure_nodes))
                        pos[device] = (x_pos, infra_y_level)

            # Position client devices in grid layout at bottom
            if client_nodes:
                client_y_level = 0.8
        
                # Calculate grid dimensions
                total_clients = len(client_nodes)
                if total_clients <= 4:
                    cols = total_clients
                    rows = 1
                elif total_clients <= 9:
                    cols = 3
                    rows = (total_clients + cols - 1) // cols
                else:
                    cols = max(4, int(total_clients ** 0.6))
                    rows = (total_clients + cols - 1) // cols
        
                # Calculate spacing
                grid_width = cols * 1.8
                grid_height = rows * 0.6
        
                for i, device in enumerate(client_nodes):
                    row = i // cols
                    col = i % cols
            
                    x_pos = (col - (cols - 1) / 2) * (grid_width / max(cols, 1))
                    y_pos = client_y_level - (row * grid_height / max(rows, 1))
            
                    pos[device] = (x_pos, y_pos)

        else:
            # No gateways found - use spring layout
            print("DEBUG: No gateways detected, using spring layout")
            try:
                pos = nx.spring_layout(self.network_graph, k=3, iterations=50)
                if not pos:
                    # Fallback to grid layout
                    nodes = list(self.network_graph.nodes())
                    cols = max(1, int(len(nodes) ** 0.5))
                    pos = {}
                    for i, node in enumerate(nodes):
                        row = i // cols
                        col = i % cols
                        pos[node] = (col * 2, -row * 1.5)
            except Exception as e:
                print(f"DEBUG: Layout failed: {e}")
                nodes = list(self.network_graph.nodes())
                cols = max(1, int(len(nodes) ** 0.5))
                pos = {}
                for i, node in enumerate(nodes):
                    row = i // cols
                    col = i % cols
                    pos[node] = (col * 2, -row * 1.5)

        # Ensure all nodes have positions
        for node in all_nodes:
            if node not in pos:
                print(f"DEBUG: Node {node} missing position, assigning fallback")
                pos[node] = (0, 0)

        # Store positions for click detection (we'll need this later)
        self.node_positions = pos.copy()

        # Group nodes by shape and draw them separately
        nodes_by_shape = {}
        for node in self.network_graph.nodes():
            device_type = self.network_graph.nodes[node].get('device_type', 'Unknown')
            shape = shape_map.get(device_type, 'o')
    
            if shape not in nodes_by_shape:
                nodes_by_shape[shape] = []
            nodes_by_shape[shape].append(node)

        print(f"DEBUG: Nodes by shape: {nodes_by_shape}")

        # Draw each shape group separately
        for shape, nodes in nodes_by_shape.items():
            if not nodes:
                continue
        
            # Prepare colors and sizes for this shape group
            node_colors = []
            node_sizes = []
    
            for node in nodes:
                device_type = self.network_graph.nodes[node].get('device_type', 'Unknown')
                mac_vendor = self.network_graph.nodes[node].get('mac_vendor', '')
                open_ports = self.network_graph.nodes[node].get('open_ports', [])
        
                # Color selection with vendor-based variants
                base_color = device_mappings.get(device_type, {}).get('color', '#95A5A6')
        
                # Vendor-based color variations
                vendor_colors = {
                    'apple': '#007AFF',      # Apple blue
                    'samsung': '#1428A0',    # Samsung blue  
                    'google': '#4285F4',     # Google blue
                    'microsoft': '#0078D4',  # Microsoft blue
                    'cisco': '#049FD9',      # Cisco blue
                    'netgear': '#F7941D',    # Netgear orange
                    'tp-link': '#4CC35E',    # TP-Link green
                    'asus': '#0066CC',       # ASUS blue
                    'linksys': '#003366',    # Linksys dark blue
                    'ubiquiti': '#0066CC'    # Ubiquiti blue
                }
        
                # Check if we can apply vendor-specific coloring
                vendor_color = None
                if mac_vendor:
                    vendor_lower = mac_vendor.lower()
                    for vendor, color in vendor_colors.items():
                        if vendor in vendor_lower:
                            vendor_color = color
                            break
        
                node_colors.append(vendor_color if vendor_color else base_color)
        
                # Smart sizing based on device type and open ports
                base_size = 1000
        
                if node in gateway_nodes:
                    size = 2000  # Largest for gateways
                elif device_type in ['Server/Web Device', 'Switch', 'Router/Switch']:
                    size = 1600  # Large for infrastructure
                elif device_type in ['IP Camera/CCTV', 'Access Point']:
                    size = 1200  # Medium for specialized devices
                elif device_type == 'Mobile Device':
                    size = 800   # Smaller for mobile devices
                else:
                    # Scale based on number of open ports (more ports = more important)
                    port_count = len(open_ports) if open_ports else 0
                    size = base_size + (port_count * 50)
                    size = min(size, 1400)  # Cap the maximum size
        
                node_sizes.append(size)
    
            # Create position dict for this shape group
            shape_pos = {node: pos[node] for node in nodes}
    
            # Draw nodes with the specific shape
            nx.draw_networkx_nodes(self.network_graph.subgraph(nodes), shape_pos,
                                node_color=node_colors,
                                node_size=node_sizes,
                                node_shape=shape,
                                alpha=0.8,
                                edgecolors='black',
                                linewidths=1,
                                ax=ax)

        # Draw edges with enhanced styling  
        if self.network_graph.edges():
            nx.draw_networkx_edges(self.network_graph, pos,
                                alpha=0.4,
                                edge_color='#666666',
                                width=1.5,
                                style='solid',
                                ax=ax)

        # Enhanced labels
        labels = {}
        for node in self.network_graph.nodes():
            hostname = self.network_graph.nodes[node].get('hostname', node)
            device_type = self.network_graph.nodes[node].get('device_type', 'Unknown')
            mac_vendor = self.network_graph.nodes[node].get('mac_vendor', '')
    
            # Truncate long hostnames
            if len(hostname) > 15:
                hostname = hostname[:12] + "..."
    
            # Create label with device type indicator
            if node in gateway_nodes:
                labels[node] = f"[GW] {hostname}\n({node})"
            elif 'Server' in device_type:
                labels[node] = f"[SRV] {hostname}\n({node})" 
            elif 'Camera' in device_type:
                labels[node] = f"[CAM] {hostname}\n({node})"
            elif 'Mobile' in device_type:
                labels[node] = f"[MOB] {hostname}\n({node})"
            elif mac_vendor and mac_vendor != 'Unknown':
                labels[node] = f"{hostname}\n({mac_vendor})"
            else:
                labels[node] = f"{hostname}\n({node})"

        nx.draw_networkx_labels(self.network_graph, pos, labels, 
                            font_size=8, font_weight='bold', ax=ax)

        # Set title
        ax.set_title(f"Enhanced Network Topology Map - {self.network_entry.get()}\n(Click on any device for details)", 
                fontsize=14, fontweight='bold', pad=20)
        ax.axis('off')

        # Enhanced legend with shapes and colors
        existing_types = set()
        for node in self.network_graph.nodes():
            device_type = self.network_graph.nodes[node].get('device_type', 'Unknown')
            existing_types.add(device_type)

        legend_elements = []
        from matplotlib.lines import Line2D

        # Sort device types by priority for consistent legend ordering
        sorted_types = sorted(existing_types, 
                            key=lambda x: device_mappings.get(x, {}).get('priority', 99))

        for device_type in sorted_types:
            color = device_mappings.get(device_type, {}).get('color', '#95A5A6')
            shape = shape_map.get(device_type, 'o')
    
            # Map NetworkX shapes to matplotlib marker symbols
            marker_map = {'D': 'D', 's': 's', '^': '^', 'v': 'v', 'h': 'h', 'o': 'o'}
            marker = marker_map.get(shape, 'o')
    
            legend_elements.append(Line2D([0], [0], marker=marker, color='w',
                                        markerfacecolor=color, 
                                        markeredgecolor='black',
                                        markeredgewidth=1,
                                        markersize=10,
                                        label=device_type))

        if legend_elements:
            ax.legend(handles=legend_elements, loc='upper left', frameon=True,
                    fancybox=True, shadow=True, fontsize=9)

        # Add network statistics
        stats_text = f"Devices: {len(self.network_graph.nodes())} | " \
                    f"Gateways: {len(gateway_nodes)} | " \
                    f"Infrastructure: {len(infrastructure_nodes)} | " \
                    f"Clients: {len(client_nodes)}"

        ax.text(0.5, -0.05, stats_text, transform=ax.transAxes, 
            ha='center', va='top', fontsize=10, 
            bbox=dict(boxstyle="round,pad=0.3", facecolor="lightgray", alpha=0.8))

        # Add to tkinter window with scrollable canvas # Add control buttons frame FIRST
        control_frame = tk.Frame(topo_window)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Left side - Status controls
        status_frame = tk.Frame(control_frame)
        status_frame.pack(side=tk.LEFT)
        
        def show_connection_details(self):
            """Show details of network connections"""
            if not hasattr(self, 'topology_data') or not self.topology_data:
                messagebox.showwarning("Warning", "No topology data available. Please scan network first.")
                return
    
            details_window = tk.Toplevel(self.root)
            details_window.title("Connection Details")
            details_window.geometry("600x400")
    
            # Create text widget with scrollbar
            text_frame = ttk.Frame(details_window)
            text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
            text_widget = tk.Text(text_frame, wrap=tk.WORD)
            scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_widget.yview)
            text_widget.configure(yscrollcommand=scrollbar.set)
    
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
            # Display connection information
            for device, connections in self.topology_data.items():
                text_widget.insert(tk.END, f"Device: {device}\n")
                if connections:
                    for conn in connections:
                        text_widget.insert(tk.END, f"  → Connected to: {conn}\n")
                else:
                    text_widget.insert(tk.END, "  → No connections detected\n")
                text_widget.insert(tk.END, "\n")
    
            text_widget.config(state=tk.DISABLED)

        
        # Refresh Status button
        def refresh_status():
            print("DEBUG: Refresh button was clicked!")
            try:
                self.refresh_device_status(canvas, ax, fig)
                print("DEBUG: refresh_device_status completed successfully")
            except Exception as e:
                print(f"DEBUG: Error in refresh_device_status: {e}")

        refresh_btn = tk.Button(status_frame, text="🔄 Refresh Status", 
                            command=refresh_status, bg='#4CAF50', fg='white',
                            font=('Arial', 10, 'bold'))
        refresh_btn.pack(side=tk.LEFT, padx=2)
        
        # Status info label
        info_label = tk.Label(status_frame, 
                            text="💡 Refresh to see live ping status",
                            font=('Arial', 8), fg='#666')
        info_label.pack(side=tk.LEFT, padx=5)
        
        # ADD PORT CONNECTION CONTROLS (after your existing buttons):
        port_controls_frame = tk.Frame(control_frame)
        port_controls_frame.pack(side=tk.LEFT, padx=10)
    
        self.show_port_connections = tk.BooleanVar(value=True)
    
        port_conn_check = tk.Checkbutton(port_controls_frame, 
                                    text="🔌 Port Connections",
                                    variable=self.show_port_connections,
                                    command=self.refresh_topology_display,
                                    font=('Arial', 9, 'bold'))
        port_conn_check.pack(side=tk.LEFT, padx=2)
    
        conn_details_btn = tk.Button(port_controls_frame, 
                                text="📊 Connection Details",
                                command=self.show_connection_details,
                                bg='#9C27B0', fg='white', 
                                font=('Arial', 9, 'bold'))
        conn_details_btn.pack(side=tk.LEFT, padx=2)
    
        conn_count = len(self.port_connections) if hasattr(self, 'port_connections') else 0
        self.conn_count_label = tk.Label(port_controls_frame, 
                                    text=f"({conn_count} connections)",
                                    font=('Arial', 8), fg='#666')
        self.conn_count_label.pack(side=tk.LEFT, padx=5)
    
        # Right side - Export controls
        export_frame = tk.Frame(control_frame)
        export_frame.pack(side=tk.RIGHT)

        # Export buttons using wrapper methods
        export_png_btn = tk.Button(export_frame, text="📷 PNG", 
                                command=lambda: self.export_topology_png(fig),
                                bg='#2196F3', fg='white', font=('Arial', 9, 'bold'))
        export_png_btn.pack(side=tk.RIGHT, padx=2)

        export_pdf_btn = tk.Button(export_frame, text="📄 PDF", 
                                command=lambda: self.export_topology_pdf(fig),
                                bg='#FF5722', fg='white', font=('Arial', 9, 'bold'))
        export_pdf_btn.pack(side=tk.RIGHT, padx=2)

        export_csv_btn = tk.Button(export_frame, text="📊 CSV", 
                                command=self.export_csv_wrapper,
                                bg='#4CAF50', fg='white', font=('Arial', 9, 'bold'))
        export_csv_btn.pack(side=tk.RIGHT, padx=2)

        export_report_btn = tk.Button(export_frame, text="📋 Report", 
                                    command=self.export_report_wrapper,
                                    bg='#9C27B0', fg='white', font=('Arial', 9, 'bold'))
        export_report_btn.pack(side=tk.RIGHT, padx=2)
        
        print("DEBUG: Detecting port connections for topology visualization")
        self.detect_port_connections()
        
        # NOW create the canvas (ONLY ONCE)
        canvas = FigureCanvasTkAgg(fig, topo_window)
        canvas.draw()
        
        # Add navigation toolbar RIGHT AFTER canvas
        from matplotlib.backends.backend_tkagg import NavigationToolbar2Tk
        toolbar = NavigationToolbar2Tk(canvas, topo_window)
        toolbar.update()
        toolbar.pack(side=tk.TOP, fill=tk.X)  # Pack the toolbar so it's visible
        
        # THEN pack the canvas
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Add subnet filtering controls (if multiple subnets detected)
        self.create_subnet_filter_controls(control_frame, canvas, ax, fig)
        # After creating canvas, ax, fig in show_topology method, add:
        self.current_canvas = canvas
        self.current_ax = ax  
        self.current_fig = fig
        self.current_topology_frame = topology_frame  # Store reference to the frame

        # Add click event handler for device details
        clicked_recently = {'time': 0, 'node': None}  # Track recent clicks

        def on_node_click(event):
            """Handle mouse clicks on network nodes"""
            import time
    
            # Fix: Reference ax from the outer scope
            nonlocal ax
    
            if event.inaxes != ax:
                return

            # Get click coordinates
            click_x, click_y = event.xdata, event.ydata
            if click_x is None or click_y is None:
                return

            # Find the closest node to click position
            closest_node = None
            min_distance = float('inf')
            click_threshold = 0.3  # How close the click needs to be to a node

            for node, (node_x, node_y) in self.node_positions.items():
                distance = ((click_x - node_x) ** 2 + (click_y - node_y) ** 2) ** 0.5
                if distance < min_distance and distance < click_threshold:
                    min_distance = distance
                    closest_node = node

            if closest_node:
                # Debounce: prevent multiple clicks within 1 second on same node
                current_time = time.time()
                if (current_time - clicked_recently['time'] < 1.0 and 
                    clicked_recently['node'] == closest_node):
                    print(f"DEBUG: Ignoring duplicate click on {closest_node}")
                    return
            
                clicked_recently['time'] = current_time
                clicked_recently['node'] = closest_node
        
                print(f"DEBUG: Processing click on {closest_node}")
                self.show_device_details(closest_node)
    
        # Connect the click event
        canvas.mpl_connect('button_press_event', on_node_click)

        print("DEBUG: Enhanced topology visualization with click-to-details complete")

        def refresh_topology_display(self):
            """Refresh the topology display"""
            try:
                if hasattr(self, 'current_topology_frame'):
                    # Clear existing topology
                    for widget in self.current_topology_frame.winfo_children():
                        widget.destroy()
                    # Recreate the topology
                    self.show_topology()
            except Exception as e:
                print(f"DEBUG: Error in refresh_topology_display: {e}")
        
    def ping_device_status(self, ip_address):
        """Ping a single device and return status info"""
        import subprocess
        import time
    
        try:
            start_time = time.time()
            # Use ping command (works on Windows and Linux)
            result = subprocess.run(
                ['ping', '-n', '1', '-w', '2000', ip_address] if os.name == 'nt' else 
                ['ping', '-c', '1', '-W', '2', ip_address],
                capture_output=True,
                text=True,
                timeout=3
            )
        
            response_time = (time.time() - start_time) * 1000  # Convert to ms
        
            if result.returncode == 0:
                # Parse actual ping time from output if possible
                output = result.stdout.lower()
                if 'time=' in output:
                    try:
                        # Extract time from ping output
                        time_part = output.split('time=')[1].split('ms')[0].split()[0]
                        actual_time = float(time_part.replace('<', ''))
                        response_time = actual_time
                    except:
                        pass  # Use calculated time as fallback
            
                # Categorize response time
                if response_time < 50:
                    return 'excellent', response_time
                elif response_time < 150:
                    return 'good', response_time
                elif response_time < 500:
                    return 'fair', response_time
                else:
                    return 'slow', response_time
            else:
                return 'offline', None
            
        except (subprocess.TimeoutExpired, Exception) as e:
            print(f"DEBUG: Ping failed for {ip_address}: {e}")
            return 'offline', None
            
    def refresh_device_status(self, canvas, ax, fig):
        """Refresh the status of all devices and update node colors"""
        print("DEBUG: Starting real-time status refresh...")
    
        # Show progress dialog
        progress_window = tk.Toplevel(self.root)
        progress_window.title("Refreshing Device Status")
        progress_window.geometry("300x120")
        progress_window.transient(self.root)
        progress_window.grab_set()
    
        progress_label = tk.Label(progress_window, text="Pinging devices...")
        progress_label.pack(pady=10)
    
        # Import ttk here if not at top of file
        try:
            import tkinter.ttk as ttk
        except ImportError:
            import ttk
    
        progress_bar = ttk.Progressbar(progress_window, mode='determinate')
        progress_bar.pack(pady=10, padx=20, fill=tk.X)
    
        # Get all nodes
        all_nodes = list(self.network_graph.nodes())
        progress_bar['maximum'] = len(all_nodes)
    
        # Store status results
        status_results = {}
    
        # Ping each device
        for i, node in enumerate(all_nodes):
            # Check if window still exists before updating
            try:
                if progress_window.winfo_exists():
                    progress_label.config(text=f"Pinging {node}...")
                    progress_window.update_idletasks()  # Use update_idletasks instead of update
                
                    status, response_time = self.ping_device_status(node)
                    status_results[node] = {'status': status, 'response_time': response_time}
                
                    progress_bar['value'] = i + 1
                    progress_window.update_idletasks()
            except tk.TclError:
                # Window was closed, stop the process
                break
    
        # Safely close progress window
        try:
            if progress_window.winfo_exists():
                progress_window.destroy()
        except tk.TclError:
            pass
    
        # Clear the axes and redraw with updated colors
        ax.clear()
    
        # Reapply the same layout and drawing logic but with status-based colors
        self.redraw_topology_with_status(ax, status_results)
    
        # Refresh the canvas
        canvas.draw()
    
        print("DEBUG: Status refresh complete")
        
    def redraw_topology_with_status(self, ax, status_results):
        """Redraw the topology with status-based colors"""
    
        # Get the same device mappings and positions
        device_mappings = self.create_legend_mappings()
        pos = self.node_positions  # We stored this during initial draw
    
        # Define status colors
        status_colors = {
            'excellent': '#00FF00',  # Bright green (< 50ms)
            'good': '#90EE90',       # Light green (50-150ms)  
            'fair': '#FFD700',       # Yellow/gold (150-500ms)
            'slow': '#FFA500',       # Orange (> 500ms)
            'offline': '#FF6B6B'     # Red/coral (offline)
        }
    
        # Shape map (same as before)
        shape_map = {
            'Gateway (.1/.254)': 'D', 'Router/Gateway': 'D', 'Router/Switch': 'D',
            'Router/Network Device': 'D', 'Router': 'D', 'Switch': 's',
            'Access Point': '^', 'Server/Web Device': 's', 'Windows Host': 'o',
            'Linux Host': 'o', 'IP Camera/CCTV': 'v', 'IP Camera': 'v',
            'Mobile Device': 'o', 'Network Device': 'h', 'Host (Filtered/Mobile)': 'o',
            'Unknown': 'o'
        }
    
        # Group nodes by shape again
        nodes_by_shape = {}
        for node in self.network_graph.nodes():
            device_type = self.network_graph.nodes[node].get('device_type', 'Unknown')
            shape = shape_map.get(device_type, 'o')
        
            if shape not in nodes_by_shape:
                nodes_by_shape[shape] = []
            nodes_by_shape[shape].append(node)
    
        # Draw each shape group with status colors
        for shape, nodes in nodes_by_shape.items():
            if not nodes:
                continue
            
            node_colors = []
            node_sizes = []
        
            for node in nodes:
                # Get status-based color
                status_info = status_results.get(node, {'status': 'offline'})
                status = status_info['status']
                node_colors.append(status_colors.get(status, '#FF6B6B'))
            
                # Keep same sizing logic
                device_type = self.network_graph.nodes[node].get('device_type', 'Unknown')
                last_octet = int(node.split('.')[-1])
            
                if last_octet in [1, 254] or 'Gateway' in device_type:
                    size = 2000
                elif device_type in ['Server/Web Device', 'Switch', 'Router/Switch']:
                    size = 1600
                elif device_type in ['IP Camera/CCTV', 'Access Point']:
                    size = 1200
                elif device_type == 'Mobile Device':
                    size = 800
                else:
                    size = 1000
                
                node_sizes.append(size)
        
            # Draw nodes
            shape_pos = {node: pos[node] for node in nodes}
            nx.draw_networkx_nodes(self.network_graph.subgraph(nodes), shape_pos,
                                node_color=node_colors, node_size=node_sizes,
                                node_shape=shape, alpha=0.8, edgecolors='black',
                                linewidths=1, ax=ax)
    
        # Redraw edges
        if self.network_graph.edges():
            nx.draw_networkx_edges(self.network_graph, pos, alpha=0.4,
                                edge_color='#666666', width=1.5, ax=ax)
    
        # Redraw labels (same as before)
        labels = {}
        for node in self.network_graph.nodes():
            hostname = self.network_graph.nodes[node].get('hostname', node)
            device_type = self.network_graph.nodes[node].get('device_type', 'Unknown')
        
            if len(hostname) > 15:
                hostname = hostname[:12] + "..."
            
            # Add status indicator to labels
            status_info = status_results.get(node, {'status': 'offline'})
            status = status_info['status']
            response_time = status_info.get('response_time')
        
            # Create label with status
            if last_octet in [1, 254] or 'Gateway' in device_type:
                base_label = f"[GW] {hostname}"
            elif 'Server' in device_type:
                base_label = f"[SRV] {hostname}"
            elif 'Camera' in device_type:
                base_label = f"[CAM] {hostname}"
            elif 'Mobile' in device_type:
                base_label = f"[MOB] {hostname}"
            else:
                base_label = hostname
            
            # Add response time to label if available
            if response_time is not None:
                labels[node] = f"{base_label}\n({node}) {response_time:.0f}ms"
            else:
                labels[node] = f"{base_label}\n({node}) OFFLINE"
    
        nx.draw_networkx_labels(self.network_graph, pos, labels,
                            font_size=8, font_weight='bold', ax=ax)
                            
        # After drawing all the network elements, add port connections
        if self.show_port_connections.get() and hasattr(self, 'port_connections'):
            print("DEBUG: Drawing port connection lines on topology")
            self.draw_port_connections(ax, pos, show_labels=True)                    
    
        # Update title with status info
        online_count = sum(1 for status in status_results.values() if status['status'] != 'offline')
        total_count = len(status_results)
    
        ax.set_title(f"Network Topology - Real-time Status ({online_count}/{total_count} online)\n"
                f"Colors: Green=Fast, Yellow=Slow, Red=Offline | Last updated: {time.strftime('%H:%M:%S')}", 
                fontsize=12, fontweight='bold', pad=20)
        ax.axis('off')
    
        # Add status legend
        from matplotlib.lines import Line2D
        status_legend = [
            Line2D([0], [0], marker='o', color='w', markerfacecolor='#00FF00', 
                markersize=10, label='Excellent (<50ms)'),
            Line2D([0], [0], marker='o', color='w', markerfacecolor='#90EE90', 
                markersize=10, label='Good (50-150ms)'),
            Line2D([0], [0], marker='o', color='w', markerfacecolor='#FFD700', 
                markersize=10, label='Fair (150-500ms)'),
            Line2D([0], [0], marker='o', color='w', markerfacecolor='#FFA500', 
                markersize=10, label='Slow (>500ms)'),
            Line2D([0], [0], marker='o', color='w', markerfacecolor='#FF6B6B', 
                markersize=10, label='Offline')
        ]
    
        ax.legend(handles=status_legend, loc='upper right', title='Device Status',
                frameon=True, fancybox=True, shadow=True, fontsize=8)
      

    def show_device_details(self, ip_address):
        """Show detailed information about a specific device in a popup window"""
        # Get device information from discovered hosts and network graph
        device_info = self.discovered_hosts.get(ip_address, {})
        graph_info = self.network_graph.nodes[ip_address] if ip_address in self.network_graph.nodes else {}
    
        # Create details window
        details_window = tk.Toplevel(self.root)
        details_window.title(f"Device Details - {ip_address}")
        details_window.geometry("500x600")
        details_window.resizable(True, True)
    
        # Create scrollable text widget
        frame = tk.Frame(details_window)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
        text_widget = tk.Text(frame, wrap=tk.WORD, font=('Consolas', 10))
        scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
    
        # Pack widgets
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
        # Build detailed information text
        details_text = f"DEVICE DETAILS FOR {ip_address}\n"
        details_text += "=" * 50 + "\n\n"
    
        # Basic Information
        details_text += "BASIC INFORMATION:\n"
        details_text += f"• IP Address: {ip_address}\n"
        details_text += f"• Hostname: {device_info.get('hostname', graph_info.get('hostname', 'Unknown'))}\n"
        details_text += f"• Device Type: {device_info.get('device_type', graph_info.get('device_type', 'Unknown'))}\n"
        details_text += f"• MAC Address: {device_info.get('mac', 'Unknown')}\n"
        details_text += f"• MAC Vendor: {device_info.get('mac_vendor', graph_info.get('mac_vendor', 'Unknown'))}\n"
        details_text += f"• Status: {device_info.get('status', 'Unknown')}\n\n"
    
        # Operating System Information
        if 'os' in device_info or 'os_details' in device_info:
            details_text += "OPERATING SYSTEM:\n"
            if 'os' in device_info:
                details_text += f"• OS Family: {device_info['os']}\n"
            if 'os_details' in device_info:
                details_text += f"• OS Details: {device_info['os_details']}\n"
            details_text += "\n"
    
        # Network Information
        details_text += "NETWORK INFORMATION:\n"
        subnet = ".".join(ip_address.split(".")[:-1]) + ".0/24"
        details_text += f"• Subnet: {subnet}\n"
        details_text += f"• Last Octet: {ip_address.split('.')[-1]}\n"
    
        # Response time if available
        if 'response_time' in device_info:
            details_text += f"• Response Time: {device_info['response_time']}\n"
        details_text += "\n"
    
        # Open Ports and Services
        open_ports = device_info.get('open_ports', graph_info.get('open_ports', []))
        if open_ports:
            details_text += f"OPEN PORTS ({len(open_ports)} found):\n"
        
            # Group ports by protocol if possible
            tcp_ports = []
            udp_ports = []
            other_ports = []
        
            for port_info in open_ports:
                if isinstance(port_info, dict):
                    port = port_info.get('port', str(port_info))
                    protocol = port_info.get('protocol', 'tcp').lower()
                    service = port_info.get('service', 'unknown')
                    state = port_info.get('state', 'open')
                
                    port_line = f"  • {port}/{protocol} - {service} ({state})"
                
                    if protocol == 'tcp':
                        tcp_ports.append(port_line)
                    elif protocol == 'udp':
                        udp_ports.append(port_line)
                    else:
                        other_ports.append(port_line)
                else:
                    # Simple port number
                    tcp_ports.append(f"  • {port_info}/tcp")
        
            # Add ports to details
            if tcp_ports:
                details_text += "TCP Ports:\n"
                for port in sorted(tcp_ports):
                    details_text += port + "\n"
            if udp_ports:
                details_text += "UDP Ports:\n"  
                for port in sorted(udp_ports):
                    details_text += port + "\n"
            if other_ports:
                details_text += "Other Ports:\n"
                for port in sorted(other_ports):
                    details_text += port + "\n"
            details_text += "\n"
        else:
            details_text += "OPEN PORTS:\n• No open ports detected or scan not performed\n\n"
    
        # Service Detection Results
        services = device_info.get('services', [])
        if services:
            details_text += f"DETECTED SERVICES ({len(services)} found):\n"
            for service in services:
                if isinstance(service, dict):
                    port = service.get('port', 'Unknown')
                    name = service.get('name', 'Unknown')
                    version = service.get('version', '')
                    details_text += f"• Port {port}: {name}"
                    if version:
                        details_text += f" (Version: {version})"
                    details_text += "\n"
                else:
                    details_text += f"• {service}\n"
            details_text += "\n"
  
        # Vulnerability Information (if available)
        vulns = device_info.get('vulnerabilities', [])
        if vulns:
            details_text += f"POTENTIAL VULNERABILITIES ({len(vulns)} found):\n"
            for vuln in vulns:
                details_text += f"• {vuln}\n"
            details_text += "\n"
    
        # Additional scan information
        if 'scan_time' in device_info:
            details_text += "SCAN INFORMATION:\n"
            details_text += f"• Last Scanned: {device_info['scan_time']}\n"
            if 'scan_duration' in device_info:
                details_text += f"• Scan Duration: {device_info['scan_duration']}\n"
            details_text += "\n"
    
        # Network topology information
        if ip_address in self.network_graph.nodes:
            neighbors = list(self.network_graph.neighbors(ip_address))
            if neighbors:
                details_text += f"NETWORK CONNECTIONS ({len(neighbors)} connections):\n"
                for neighbor in sorted(neighbors):
                    neighbor_type = self.network_graph.nodes[neighbor].get('device_type', 'Unknown')
                    details_text += f"• Connected to {neighbor} ({neighbor_type})\n"
                details_text += "\n"
    
        # Raw data (for debugging/advanced users)
        details_text += "RAW SCAN DATA:\n"
        details_text += "-" * 20 + "\n"
    
        # Add discovered_hosts data
        if device_info:
            details_text += "From Host Discovery:\n"
            for key, value in device_info.items():
                if key not in ['open_ports', 'services', 'vulnerabilities']:  # Already shown above
                    details_text += f"  {key}: {value}\n"
    
        # Add network graph data  
        if graph_info:
            details_text += "\nFrom Network Graph:\n"
            for key, value in graph_info.items():
                if key not in ['open_ports', 'mac_vendor', 'device_type', 'hostname']:  # Already shown above
                    details_text += f"  {key}: {value}\n"
    
        # Insert text and make it read-only
        text_widget.insert(tk.END, details_text)
        text_widget.config(state=tk.DISABLED)
    
        # Add buttons frame
        button_frame = tk.Frame(details_window)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
    
        # Close button
        close_btn = tk.Button(button_frame, text="Close", command=details_window.destroy)
        close_btn.pack(side=tk.RIGHT, padx=5)
    
        # Rescan button (rescan just this device)
        def rescan_device():
            details_window.destroy()  # Close details window
            # Add device to scan queue and perform targeted scan
            messagebox.showinfo("Rescan", f"Rescanning {ip_address}...")
            # Here you could call a method to rescan just this device
        
        rescan_btn = tk.Button(button_frame, text="Rescan Device", command=rescan_device)
        rescan_btn.pack(side=tk.RIGHT, padx=5)
    
        # Copy IP button
        def copy_ip():
            details_window.clipboard_clear()
            details_window.clipboard_append(ip_address)
            messagebox.showinfo("Copied", f"IP address {ip_address} copied to clipboard!")
        
        copy_btn = tk.Button(button_frame, text="Copy IP", command=copy_ip)
        copy_btn.pack(side=tk.RIGHT, padx=5)
    
        print(f"DEBUG: Showing device details for {ip_address}")
        

    def create_legend_mappings(self):
        """Define consistent color and icon mappings for device types"""
        return {
            "Gateway (.1/.254)": {"color": "#FF6B6B", "icon": "🌐", "priority": 1},
            "Router/Gateway": {"color": "#FF6B6B", "icon": "🌐", "priority": 1},
            "Router/Switch": {"color": "#4ECDC4", "icon": "📡", "priority": 2}, 
            "Router/Network Device": {"color": "#45B7D1", "icon": "📡", "priority": 2},
            "Router": {"color": "#FF6B6B", "icon": "🌐", "priority": 2},
            "Switch": {"color": "#96CEB4", "icon": "🔀", "priority": 3},
            "Access Point": {"color": "#FECA57", "icon": "📶", "priority": 4},
            "Server/Web Device": {"color": "#9B59B6", "icon": "🖥️", "priority": 5},
            "Windows Host": {"color": "#3498DB", "icon": "💻", "priority": 6},
            "Linux Host": {"color": "#2ECC71", "icon": "🐧", "priority": 7},
            "IP Camera/CCTV": {"color": "#E67E22", "icon": "📹", "priority": 8},
            "IP Camera": {"color": "#E67E22", "icon": "📹", "priority": 8},
            "Mobile Device": {"color": "#E74C3C", "icon": "📱", "priority": 9},
            "Network Device": {"color": "#A55EEA", "icon": "⚙️", "priority": 10},
            "Host (Filtered/Mobile)": {"color": "#95A5A6", "icon": "❓", "priority": 11},
            "Unknown": {"color": "#BDC3C7", "icon": "❓", "priority": 12}
        }
        
    def show_connection_details(self):
        """Show details of network connections"""
        if not hasattr(self, 'discovered_hosts') or not self.discovered_hosts:
            messagebox.showwarning("Warning", "No topology data available. Please scan network first.")
            return
        
        details_window = tk.Toplevel(self.root)
        details_window.title("Network Connection Details")
        details_window.geometry("700x500")
        
        # Create text widget with scrollbar
        text_frame = ttk.Frame(details_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text_widget = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True)
        
        # Display connection information
        connections_info = "Network Connection Details\n" + "="*50 + "\n\n"
        
        if hasattr(self, 'network_graph') and self.network_graph.edges():
            connections_info += f"Network Edges: {len(self.network_graph.edges())}\n\n"
            for edge in self.network_graph.edges():
                device1, device2 = edge
                info1 = self.discovered_hosts.get(device1, {})
                info2 = self.discovered_hosts.get(device2, {})
                
                connections_info += f"{device1} ({info1.get('device_type', 'Unknown')})\n"
                connections_info += f"  ↔ Connected to\n"
                connections_info += f"{device2} ({info2.get('device_type', 'Unknown')})\n\n"
        else:
            connections_info += "No network connections detected.\n"
            connections_info += "This may indicate:\n"
            connections_info += "- Devices are on different subnets\n"
            connections_info += "- Network topology couldn't be determined\n"
            connections_info += "- Devices don't respond to network discovery\n"
        
        text_widget.insert(tk.END, connections_info)
        text_widget.config(state=tk.DISABLED)    
    
    # ==== CORRECTED EXPORT METHODS FOR NetworkScannerGUI CLASS ====
    
    def export_results(self):
        """Main export method that shows export options"""
        if not self.discovered_hosts:
            messagebox.showwarning("No Data", "No network scan data available to export.")
            return
        
        # Create export options dialog
        export_window = tk.Toplevel(self.root)  # Use self.root instead of self.master
        export_window.title("Export Network Scan Results")
        export_window.geometry("400x300")
        export_window.resizable(False, False)
        
        # Center the window
        export_window.transient(self.root)
        export_window.grab_set()
        
        # Title
        title_label = ttk.Label(export_window, text="Choose Export Format", 
                               font=('Arial', 12, 'bold'))
        title_label.pack(pady=10)
        
        # Export options frame
        options_frame = ttk.Frame(export_window)
        options_frame.pack(pady=10, padx=20, fill='both', expand=True)
        
        # CSV Export
        csv_frame = ttk.LabelFrame(options_frame, text="Device List Export", padding=10)
        csv_frame.pack(fill='x', pady=5)
        ttk.Label(csv_frame, text="Export device list with details to CSV file").pack(anchor='w')
        ttk.Button(csv_frame, text="Export as CSV", 
                  command=lambda: self.handle_export('csv', export_window)).pack(pady=5)
        
        # JSON Export
        json_frame = ttk.LabelFrame(options_frame, text="Raw Data Export", padding=10)
        json_frame.pack(fill='x', pady=5)
        ttk.Label(json_frame, text="Export complete scan data in JSON format").pack(anchor='w')
        ttk.Button(json_frame, text="Export as JSON", 
                  command=lambda: self.handle_export('json', export_window)).pack(pady=5)
        
        # Report Export
        report_frame = ttk.LabelFrame(options_frame, text="Detailed Report", padding=10)
        report_frame.pack(fill='x', pady=5)
        ttk.Label(report_frame, text="Export comprehensive network report as text").pack(anchor='w')
        ttk.Button(report_frame, text="Export Report", 
                  command=lambda: self.handle_export('report', export_window)).pack(pady=5)
        
        # Topology Image Export (only if topology exists)
        if hasattr(self, 'network_graph') and self.network_graph and self.network_graph.nodes():
            topology_frame = ttk.LabelFrame(options_frame, text="Network Topology", padding=10)
            topology_frame.pack(fill='x', pady=5)
            ttk.Label(topology_frame, text="Export network topology visualization").pack(anchor='w')
            
            # Image format buttons
            img_buttons_frame = ttk.Frame(topology_frame)
            img_buttons_frame.pack(pady=5)
            
            ttk.Button(img_buttons_frame, text="PNG Image", 
                      command=lambda: self.handle_topology_export('png', export_window)).pack(side='left', padx=2)
            ttk.Button(img_buttons_frame, text="PDF Document", 
                      command=lambda: self.handle_topology_export('pdf', export_window)).pack(side='left', padx=2)
            ttk.Button(img_buttons_frame, text="SVG Vector", 
                      command=lambda: self.handle_topology_export('svg', export_window)).pack(side='left', padx=2)
        
        # Close button
        ttk.Button(export_window, text="Close", 
                  command=export_window.destroy).pack(pady=10)

    def handle_export(self, export_type, parent_window):
        """Handle different export types"""
        try:
            if export_type == 'csv':
                self.export_device_list_csv()
            elif export_type == 'json':
                self.export_json_results()
            elif export_type == 'report':
                self.export_detailed_report()
            
            # Close export dialog after successful export
            parent_window.destroy()
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export {export_type.upper()}: {str(e)}")

    def handle_topology_export(self, format_type, parent_window):
        """Handle topology image export"""
        try:
            # Try to get the current figure from matplotlib if available
            try:
                import matplotlib.pyplot as plt
                fig = plt.gcf()  # Get current figure
                if fig.get_axes():  # Check if figure has any plots
                    self.export_topology_image(fig, format_type)
                    parent_window.destroy()
                else:
                    messagebox.showwarning("No Topology", "No topology visualization is currently displayed.")
            except:
                messagebox.showwarning("No Topology", "No topology visualization is currently available to export.")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export topology: {str(e)}")

    def export_json_results(self):
        """Export scan results to JSON file"""
        from tkinter import filedialog, messagebox
        import json
        import time
        from datetime import datetime
        
        # Generate default filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        network_name = self.network_entry.get().replace('/', '_').replace('.', '_')
        default_filename = f"network_scan_{network_name}_{timestamp}.json"

        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=default_filename,
            title="Save scan results as JSON"
        )

        if not filename:
            return

        # Prepare results with metadata
        results = {
            'scan_metadata': {
                'network_range': self.network_entry.get(),
                'scan_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_hosts_found': len(self.discovered_hosts),
                'scanner_version': 'Network Topology Scanner v1.0'
            },
            'network_summary': self.generate_network_summary(),
            'discovered_hosts': self.discovered_hosts
        }

        # Add topology information if available
        if hasattr(self, 'network_graph') and self.network_graph and self.network_graph.nodes():
            results['network_topology'] = {
                'nodes': list(self.network_graph.nodes()),
                'edges': list(self.network_graph.edges()),
                'node_count': len(self.network_graph.nodes()),
                'edge_count': len(self.network_graph.edges())
            }

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Export Successful", f"Scan results exported to:\n{filename}")
            print(f"DEBUG: JSON results exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export JSON: {str(e)}")
            print(f"DEBUG: JSON export error: {e}")

    def generate_network_summary(self):
        """Generate a summary of the network scan"""
        if not self.discovered_hosts:
            return {}
        
        summary = {
            'total_devices': len(self.discovered_hosts),
            'device_types': {},
            'active_devices': 0,
            'devices_with_open_ports': 0,
            'total_open_ports': 0,
            'common_services': {}
        }
        
        for ip, info in self.discovered_hosts.items():
            # Count device types
            device_type = info.get('device_type', 'Unknown')
            summary['device_types'][device_type] = summary['device_types'].get(device_type, 0) + 1
            
            # Count active devices
            if info.get('status', '').lower() in ['up', 'online', 'active']:
                summary['active_devices'] += 1
            
            # Count devices with open ports
            open_ports = info.get('open_ports', [])
            if open_ports:
                summary['devices_with_open_ports'] += 1
                summary['total_open_ports'] += len(open_ports)
            
            # Count common services
            services = info.get('services', [])
            for service in services:
                service_name = service.get('name', service) if isinstance(service, dict) else str(service)
                summary['common_services'][service_name] = summary['common_services'].get(service_name, 0) + 1
        
        return summary

    def export_topology_image(self, fig, format_type='png'):
        """Export the topology map as an image file"""
        from tkinter import filedialog, messagebox
        import os
        from datetime import datetime

        # Generate default filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        network_name = self.network_entry.get().replace('/', '_').replace('.', '_')
        default_filename = f"network_topology_{network_name}_{timestamp}.{format_type}"

        # File dialog for save location
        filetypes = [
            ('PNG Image', '*.png'),
            ('PDF Document', '*.pdf'),
            ('SVG Vector', '*.svg'),
            ('JPEG Image', '*.jpg')
        ]

        filename = filedialog.asksaveasfilename(
            defaultextension=f".{format_type}",
            filetypes=filetypes,
            initialfile=default_filename,
            title=f"Save Topology Map as {format_type.upper()}"
        )

        if filename:
            try:
                # Save the figure with high quality settings
                save_kwargs = {
                    'dpi': 300,
                    'bbox_inches': 'tight',
                    'facecolor': 'white',
                    'edgecolor': 'none',
                    'format': format_type.lower()
                }
                
                fig.savefig(filename, **save_kwargs)
                
                messagebox.showinfo("Export Successful", 
                                f"Topology map saved as:\n{filename}")
                print(f"DEBUG: Topology exported to {filename}")

            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save file:\n{str(e)}")
                print(f"DEBUG: Export error: {e}")

    def export_device_list_csv(self):
        """Export device list as CSV file"""
        from tkinter import filedialog, messagebox
        import csv
        from datetime import datetime

        # Generate default filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        network_name = self.network_entry.get().replace('/', '_').replace('.', '_')
        default_filename = f"network_devices_{network_name}_{timestamp}.csv"

        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[('CSV files', '*.csv'), ('All files', '*.*')],
            initialfile=default_filename,
            title="Save Device List as CSV"
        )

        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)

                    # Write header
                    writer.writerow([
                        'IP Address', 'Hostname', 'Device Type', 'MAC Address', 
                        'MAC Vendor', 'Status', 'Open Ports', 'Services', 
                        'Operating System', 'Response Time', 'Last Scan'
                    ])

                    # Write device data
                    for ip, info in sorted(self.discovered_hosts.items()):
                        # Handle open ports - convert list to string
                        open_ports = info.get('open_ports', [])
                        if isinstance(open_ports, list):
                            ports_str = ', '.join([
                                f"{port['port']}/{port.get('protocol', 'tcp')}" 
                                if isinstance(port, dict) else str(port)
                                for port in open_ports
                            ])
                        else:
                            ports_str = str(open_ports)

                        # Handle services
                        services = info.get('services', [])
                        if isinstance(services, list):
                            services_str = ', '.join([
                                f"{srv.get('name', srv)}" if isinstance(srv, dict) else str(srv)
                                for srv in services
                            ])
                        else:
                            services_str = str(services)

                        # Write row
                        writer.writerow([
                            ip,
                            info.get('hostname', 'Unknown'),
                            info.get('device_type', 'Unknown'),
                            info.get('mac', 'Unknown'),
                            info.get('mac_vendor', 'Unknown'),
                            info.get('status', 'Unknown'),
                            ports_str,
                            services_str,
                            info.get('os', info.get('os_details', 'Unknown')),
                            info.get('response_time', 'N/A'),
                            info.get('scan_time', 'N/A')
                        ])

                messagebox.showinfo("Export Successful", 
                                f"Device list exported to:\n{filename}")
                print(f"DEBUG: Device list exported to {filename}")

            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save CSV file:\n{str(e)}")
                print(f"DEBUG: CSV export error: {e}")

    def export_detailed_report(self):
        """Export a comprehensive network report as text file"""
        from tkinter import filedialog, messagebox
        from datetime import datetime

        # Generate default filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        network_name = self.network_entry.get().replace('/', '_').replace('.', '_')
        default_filename = f"network_report_{network_name}_{timestamp}.txt"

        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[('Text files', '*.txt'), ('All files', '*.*')],
            initialfile=default_filename,
            title="Save Network Report as Text"
        )

        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    # Report header
                    f.write("NETWORK TOPOLOGY SCAN REPORT\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Network: {self.network_entry.get()}\n")
                    f.write(f"Total Devices Found: {len(self.discovered_hosts)}\n")
                    f.write(f"Scanner: Network Topology Scanner v1.0\n\n")

                    # Network summary
                    device_types = {}
                    online_count = 0
                    for info in self.discovered_hosts.values():
                        device_type = info.get('device_type', 'Unknown')
                        device_types[device_type] = device_types.get(device_type, 0) + 1
                        if info.get('status', '').lower() in ['up', 'online', 'active']:
                            online_count += 1

                    f.write("NETWORK SUMMARY:\n")
                    f.write("-" * 20 + "\n")
                    f.write(f"Active Devices: {online_count}\n")
                    f.write("Device Types:\n")
                    for dtype, count in sorted(device_types.items()):
                        f.write(f"  • {dtype}: {count} device(s)\n")
                    f.write("\n")

                    # Detailed device information
                    f.write("DETAILED DEVICE INFORMATION:\n")
                    f.write("=" * 40 + "\n\n")

                    # Group devices by type for better organization
                    devices_by_type = {}
                    for ip, info in self.discovered_hosts.items():
                        device_type = info.get('device_type', 'Unknown')
                        if device_type not in devices_by_type:
                            devices_by_type[device_type] = []
                        devices_by_type[device_type].append((ip, info))

                    # Write each device type section
                    for device_type, devices in sorted(devices_by_type.items()):
                        f.write(f"{device_type.upper()} DEVICES:\n")
                        f.write("-" * (len(device_type) + 9) + "\n")

                        for ip, info in sorted(devices):
                            f.write(f"\nDevice: {ip}\n")
                            f.write(f"  Hostname: {info.get('hostname', 'Unknown')}\n")
                            f.write(f"  MAC Address: {info.get('mac', 'Unknown')}\n")
                            f.write(f"  MAC Vendor: {info.get('mac_vendor', 'Unknown')}\n")
                            f.write(f"  Status: {info.get('status', 'Unknown')}\n")

                            # Operating System
                            if 'os' in info or 'os_details' in info:
                                f.write(f"  Operating System: {info.get('os', info.get('os_details', 'Unknown'))}\n")

                            # Open ports
                            open_ports = info.get('open_ports', [])
                            if open_ports:
                                f.write(f"  Open Ports ({len(open_ports)}):\n")
                                for port in open_ports:
                                    if isinstance(port, dict):
                                        port_info = f"    • {port.get('port', 'Unknown')}/{port.get('protocol', 'tcp')}"
                                        if 'service' in port:
                                            port_info += f" - {port['service']}"
                                        if 'state' in port:
                                            port_info += f" ({port['state']})"
                                        f.write(port_info + "\n")
                                    else:
                                        f.write(f"    • {port}\n")

                            # Services
                            services = info.get('services', [])
                            if services:
                                f.write(f"  Detected Services:\n")
                                for service in services:
                                    if isinstance(service, dict):
                                        service_info = f"    • {service.get('name', 'Unknown')}"
                                        if 'version' in service:
                                            service_info += f" v{service['version']}"
                                        f.write(service_info + "\n")
                                    else:
                                        f.write(f"    • {service}\n")

                            # Additional info
                            if 'response_time' in info:
                                f.write(f"  Response Time: {info['response_time']}\n")
                            if 'scan_time' in info:
                                f.write(f"  Last Scanned: {info['scan_time']}\n")

                        f.write("\n")

                    # Network topology information
                    if hasattr(self, 'network_graph') and self.network_graph and self.network_graph.nodes():
                        f.write("NETWORK TOPOLOGY:\n")
                        f.write("-" * 20 + "\n")
                        f.write(f"Network Graph: {len(self.network_graph.nodes())} nodes, {len(self.network_graph.edges())} connections\n\n")

                        # Connection information
                        f.write("Device Connections:\n")
                        for node in sorted(self.network_graph.nodes()):
                            neighbors = list(self.network_graph.neighbors(node))
                            if neighbors:
                                f.write(f"  {node} connects to: {', '.join(sorted(neighbors))}\n")
                        f.write("\n")

                    # Footer
                    f.write("-" * 50 + "\n")
                    f.write("End of Network Scan Report\n")
                    f.write(f"Generated by Network Topology Scanner\n")
                    f.write(f"Report created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

                messagebox.showinfo("Export Successful", 
                                f"Detailed network report saved to:\n{filename}")
                print(f"DEBUG: Detailed report exported to {filename}")

            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save report:\n{str(e)}")
                print(f"DEBUG: Report export error: {e}")

    # ==== WRAPPER METHODS FOR TOPOLOGY VIEWER BUTTONS ====
    
    def export_topology_png(self, fig=None):
        """Wrapper for PNG export from topology viewer"""
        try:
            if fig is None:
                import matplotlib.pyplot as plt
                fig = plt.gcf()
            self.export_topology_image(fig, 'png')
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export PNG: {str(e)}")
    
    def export_topology_pdf(self, fig=None):
        """Wrapper for PDF export from topology viewer"""
        try:
            if fig is None:
                import matplotlib.pyplot as plt
                fig = plt.gcf()
            self.export_topology_image(fig, 'pdf')
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export PDF: {str(e)}")
    
    def export_topology_svg(self, fig=None):
        """Wrapper for SVG export from topology viewer"""
        try:
            if fig is None:
                import matplotlib.pyplot as plt
                fig = plt.gcf()
            self.export_topology_image(fig, 'svg')
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export SVG: {str(e)}")
    
    def export_csv_wrapper(self):
        """Wrapper for CSV export from topology viewer"""
        try:
            self.export_device_list_csv()
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export CSV: {str(e)}")
    
    def export_report_wrapper(self):
        """Wrapper for report export from topology viewer"""
        try:
            self.export_detailed_report()
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report: {str(e)}")
    
    # Port Scanning and Visual Modules Phase 1
    
    def init_service_mapping(self):
        """Initialize common port to service name mapping"""
        self.service_map = {
            # Network services
            22: 'SSH', 23: 'Telnet', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS',
            21: 'FTP', 25: 'SMTP', 110: 'POP3', 143: 'IMAP', 993: 'IMAPS',
            995: 'POP3S', 587: 'SMTP-SSL',
        
            # Windows services
            135: 'RPC', 139: 'NetBIOS', 445: 'SMB', 3389: 'RDP',
        
            # Network management
            161: 'SNMP', 162: 'SNMP-Trap', 514: 'Syslog',
        
            # Database services
            1433: 'MSSQL', 3306: 'MySQL', 5432: 'PostgreSQL', 1521: 'Oracle',
        
            # Web services
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8888: 'HTTP-Alt2',
        
            # Remote access
            5900: 'VNC', 5901: 'VNC-1', 5902: 'VNC-2',
        
            # File services
            2049: 'NFS', 873: 'rsync', 548: 'AFP',
        
            # Media services
            554: 'RTSP', 1935: 'RTMP', 8554: 'RTSP-Alt',
        
            # IoT/Camera services
            37777: 'Dahua-DVR', 34567: 'Dahua-Web', 8000: 'iVMS',
            554: 'RTSP', 80: 'Web-Mgmt'
        }

    def detect_port_connections(self):
        """Analyze discovered hosts to detect logical port connections"""
        print("DEBUG: Starting port connection detection...")
        self.port_connections = {}
    
        # Group devices by subnet for connection analysis
        import ipaddress
        from collections import defaultdict
    
        subnet_groups = defaultdict(list)
    
        for ip, host_info in self.discovered_hosts.items():
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                subnet = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                subnet_groups[str(subnet.network_address)].append((ip, host_info))
            except:
                continue
    
        # Detect connections within each subnet
        for subnet, hosts in subnet_groups.items():
            print(f"DEBUG: Analyzing subnet {subnet} with {len(hosts)} hosts")
            self.analyze_subnet_connections(hosts)
    
        print(f"DEBUG: Port connection detection complete. Found {len(self.port_connections)} connection patterns")

    def analyze_subnet_connections(self, hosts):    
        """Analyze port connections within a subnet"""
    
        # Categorize hosts by their primary role
        gateways = []
        servers = []
        clients = []
        infrastructure = []
    
        for ip, info in hosts:
            device_type = info.get('device_type', '').lower()
            open_ports = info.get('open_ports', [])
        
            if 'gateway' in device_type or ip.endswith('.1') or ip.endswith('.254'):
                gateways.append((ip, info))
            elif any(port in open_ports for port in [22, 23, 80, 443, 161]) and len(open_ports) >= 3:
                if 'server' in device_type or 'router' in device_type or 'switch' in device_type:
                    infrastructure.append((ip, info))
                else:
                    servers.append((ip, info))
            else:
                clients.append((ip, info))
    
        # Create connection patterns
        self.create_connection_patterns(gateways, servers, clients, infrastructure)

    def create_connection_patterns(self, gateways, servers, clients, infrastructure):
        """Create logical connection patterns based on network roles"""
    
        # Pattern 1: All devices connect to gateway for internet access
        for gateway_ip, gateway_info in gateways:
            gateway_ports = gateway_info.get('open_ports', [])
            
            # Connect all other devices to gateway
            for device_list in [servers, clients, infrastructure]:
                for device_ip, device_info in device_list:
                    if device_ip == gateway_ip:
                        continue
                
                    device_ports = device_info.get('open_ports', [])
                
                    # Create connection based on common service ports
                    connection = self.create_gateway_connection(
                        gateway_ip, gateway_ports, device_ip, device_ports
                    )
                
                    if connection:
                        self.add_port_connection(connection)
    
        # Pattern 2: Clients connect to servers for services
        for server_ip, server_info in servers + infrastructure:
            server_ports = server_info.get('open_ports', [])
        
            for client_ip, client_info in clients:
                if server_ip == client_ip:
                    continue
                
                client_ports = client_info.get('open_ports', [])
            
                # Create service-based connections
                connections = self.create_service_connections(
                    server_ip, server_ports, client_ip, client_ports
                )
            
                for connection in connections:
                    self.add_port_connection(connection)

    def create_gateway_connection(self, gateway_ip, gateway_ports, device_ip, device_ports):
        """Create a connection pattern for gateway relationships"""
    
        # Default gateway connection (internet access)
        connection = {
            'source_ip': device_ip,
            'source_port': 'any',  # Clients use random source ports
            'dest_ip': gateway_ip,
            'dest_port': 'routing',  # Gateway provides routing
            'service': 'Internet Access',
            'connection_type': 'gateway',
            'bidirectional': True,
            'strength': 0.8  # Connection strength for visualization
        }
    
        return connection

    def create_service_connections(self, server_ip, server_ports, client_ip, client_ports):
        """Create service-based connection patterns"""
        connections = []
    
        # Common service patterns
        service_patterns = {
            'web': [80, 443, 8080, 8443],
            'file_sharing': [445, 139, 135, 21, 22],  # SMB, FTP, SSH
            'database': [1433, 3306, 5432, 1521],
            'email': [25, 110, 143, 587, 993, 995],
            'management': [22, 23, 161, 3389, 5900],
            'media': [554, 1935, 8554, 37777]
        }
    
        for service_name, service_ports in service_patterns.items():
            # Check if server offers any of these services
            offered_ports = [port for port in server_ports if port in service_ports]
        
            if offered_ports:
                for port in offered_ports:
                    service_display_name = self.service_map.get(port, f"Port {port}")
                    
                    connection = {
                        'source_ip': client_ip,
                        'source_port': 'dynamic',
                        'dest_ip': server_ip,
                        'dest_port': port,
                        'service': service_display_name,
                        'connection_type': service_name,
                        'bidirectional': False,
                        'strength': 0.6
                    }
                
                    connections.append(connection)
    
        return connections

    def add_port_connection(self, connection):
        """Add a port connection to the tracking structure"""
    
        # Create a unique key for this connection
        key = f"{connection['source_ip']}:{connection['source_port']}->{connection['dest_ip']}:{connection['dest_port']}"
    
        # Avoid duplicate connections
        if key not in self.port_connections:
            self.port_connections[key] = connection
            print(f"DEBUG: Added connection: {connection['source_ip']} -> {connection['dest_ip']} ({connection['service']})")

    def initialize_port_connection_system(self):
        """Initialize the complete port connection system"""
        print("DEBUG: Initializing port connection system...")
    
        # Initialize data structures
        if not hasattr(self, 'port_connections'):
            self.port_connections = {}
    
        if not hasattr(self, 'service_map'):
            self.init_service_mapping()
        
        print("DEBUG: Port connection system initialized successfully")
        
        
        # Phase 2: Add these methods to your NetworkScannerGUI class for visual port connections

    def draw_port_connections(self, ax, pos, show_labels=True):
        """Draw port connection lines on the topology map"""
    
        if not self.port_connections:
            print("DEBUG: No port connections to draw")
            return
    
        print(f"DEBUG: Drawing {len(self.port_connections)} port connections")
    
        # Connection type styling
        connection_styles = {
            'gateway': {
                'color': '#FF6B6B',     # Red for internet/gateway connections
                'linestyle': '-',
                'width': 3.0,
                'alpha': 0.8,
                'label': 'Internet Access'
            },
            'web': {
                'color': '#4ECDC4',     # Teal for web services
                'linestyle': '-',
                'width': 2.0,
                'alpha': 0.7,
                'label': 'Web Services'
            },
            'file_sharing': {
                'color': '#45B7D1',     # Blue for file sharing
                'linestyle': '--',
                'width': 2.0,
                'alpha': 0.7,
                'label': 'File Services'
            },
            'database': {
                'color': '#96CEB4',     # Green for database
                'linestyle': '-.',
                'width': 2.5,
                'alpha': 0.7,
                'label': 'Database'
            },
            'management': {
                'color': '#FFEAA7',     # Yellow for management
                'linestyle': ':',
                'width': 1.5,
                'alpha': 0.8,
                'label': 'Management'
            },
            'media': {
                'color': '#DDA0DD',     # Purple for media
                'linestyle': '-',
                'width': 2.0,
                'alpha': 0.6,
                'label': 'Media/Camera'
            },
            'default': {
                'color': '#95A5A6',     # Gray for unknown
                'linestyle': '-',
                'width': 1.0,
                'alpha': 0.5,
                'label': 'Other'
            }
        }
    
        # Group connections by type for better visualization
        connections_by_type = {}
    
        for conn_key, connection in self.port_connections.items():
            conn_type = connection.get('connection_type', 'default')
        
            if conn_type not in connections_by_type:
                connections_by_type[conn_type] = []
            connections_by_type[conn_type].append(connection)
    
        # Draw connections by type (order matters for layering)
        draw_order = ['gateway', 'database', 'web', 'file_sharing', 'management', 'media', 'default']
    
        drawn_connections = []  # Track for legend
    
        for conn_type in draw_order:
            if conn_type not in connections_by_type:
                continue
        
            connections = connections_by_type[conn_type]
            style = connection_styles.get(conn_type, connection_styles['default'])
        
            print(f"DEBUG: Drawing {len(connections)} {conn_type} connections")
        
            for connection in connections:
                source_ip = connection['source_ip']
                dest_ip = connection['dest_ip']
            
                # Check if both endpoints exist in our position map
                if source_ip not in pos or dest_ip not in pos:
                    print(f"DEBUG: Skipping connection {source_ip} -> {dest_ip} (missing position)")
                    continue
            
                # Get positions
                source_pos = pos[source_ip]
                dest_pos = pos[dest_ip]
            
                # Calculate connection strength for line width adjustment
                strength = connection.get('strength', 0.5)
                adjusted_width = style['width'] * strength
            
                # Draw the connection line
                self.draw_connection_line(
                    ax, source_pos, dest_pos, style, adjusted_width, 
                    connection.get('bidirectional', False)
                )
            
                # Add service label if requested
                if show_labels and connection.get('service'):
                    self.add_connection_label(
                        ax, source_pos, dest_pos, connection['service'], style['color']
                    )
        
            # Add to legend tracking
            if connections:
                drawn_connections.append((conn_type, style))
    
        # Create connection legend
        if drawn_connections:
            self.create_connection_legend(ax, drawn_connections)

    def draw_connection_line(self, ax, source_pos, dest_pos, style, width, bidirectional=False):
        """Draw a single connection line with optional bidirectional arrows"""
        import matplotlib.pyplot as plt
        from matplotlib.patches import FancyArrowPatch
        import numpy as np
    
        x1, y1 = source_pos
        x2, y2 = dest_pos
    
        # Create curved connection for better visibility
        # Calculate control point for bezier curve
        mid_x = (x1 + x2) / 2
        mid_y = (y1 + y2) / 2
    
        # Add slight curve offset based on distance
        dx = x2 - x1
        dy = y2 - y1
        distance = np.sqrt(dx**2 + dy**2)
    
        # Perpendicular offset for curve (reduces overlapping lines)
        curve_offset = min(0.3, distance * 0.1)
        offset_x = -dy / distance * curve_offset if distance > 0 else 0
        offset_y = dx / distance * curve_offset if distance > 0 else 0
    
        control_x = mid_x + offset_x
        control_y = mid_y + offset_y
    
        if bidirectional:
            # Draw bidirectional arrow
            arrow = FancyArrowPatch(
                (x1, y1), (x2, y2),
                arrowstyle='<->',
                shrinkA=15, shrinkB=15,  # Keep arrows away from nodes
                connectionstyle=f"arc3,rad={curve_offset/distance if distance > 0 else 0}",
                color=style['color'],
                linewidth=width,
                linestyle=style['linestyle'],
                alpha=style['alpha']
            )
        else:
            # Draw unidirectional arrow
            arrow = FancyArrowPatch(
                (x1, y1), (x2, y2),
                arrowstyle='->',
                shrinkA=15, shrinkB=15,
                connectionstyle=f"arc3,rad={curve_offset/distance if distance > 0 else 0}",
                color=style['color'],
                linewidth=width,
                linestyle=style['linestyle'],
                alpha=style['alpha']
            )
    
        ax.add_patch(arrow)

    def add_connection_label(self, ax, source_pos, dest_pos, service_name, color):
        """Add a service label to a connection line"""
    
        # Calculate midpoint
        mid_x = (source_pos[0] + dest_pos[0]) / 2
        mid_y = (source_pos[1] + dest_pos[1]) / 2
    
        # Add small offset to avoid overlapping with line
        label_offset = 0.1
    
        # Shorten long service names
        display_name = service_name
        if len(service_name) > 8:
            display_name = service_name[:6] + ".."
    
        ax.text(mid_x, mid_y + label_offset, display_name,
            fontsize=6, ha='center', va='bottom',
            color=color, fontweight='bold',
            bbox=dict(boxstyle="round,pad=0.2", facecolor='white', 
                        edgecolor=color, alpha=0.8, linewidth=0.5))

    def create_connection_legend(self, ax, drawn_connections):
        """Create a legend for port connections"""
        from matplotlib.lines import Line2D
    
        legend_elements = []
    
        for conn_type, style in drawn_connections:
            legend_elements.append(
                Line2D([0], [0], color=style['color'], 
                    linestyle=style['linestyle'],
                    linewidth=style['width'],
                    alpha=style['alpha'],
                    label=style['label'])
            )
    
        if legend_elements:
            # Position legend in bottom-right corner
            connection_legend = ax.legend(handles=legend_elements, 
                                        loc='lower right', 
                                        frameon=True,
                                        fancybox=True, 
                                        shadow=True, 
                                        fontsize=8,
                                        title="Port Connections",
                                        title_fontsize=9)
        
            # Adjust legend position to avoid overlap with device legend
            ax.add_artist(connection_legend)

    def toggle_port_connections(self, ax, fig, canvas, show_connections=True):
        """Toggle port connection visibility on/off"""
    
        if show_connections:
            # Detect and draw port connections
            self.detect_port_connections()
        
            # Get current node positions from the graph
            if hasattr(self, 'node_positions') and self.node_positions:
                pos = self.node_positions
            else:
                # Fallback: try to get positions from the current plot
                print("DEBUG: No stored node positions, using fallback layout")
                import networkx as nx
                try:
                    pos = nx.spring_layout(self.network_graph, k=3, iterations=50)
                except:
                    pos = {}
                    for i, node in enumerate(self.network_graph.nodes()):
                        pos[node] = (i % 4, i // 4)
        
            self.draw_port_connections(ax, pos)
        
        else:
            # Remove connection lines (this would require tracking drawn elements)
            print("DEBUG: Hiding port connections (requires plot refresh)")
        
        # Refresh the canvas
        canvas.draw()

    def get_connection_statistics(self):
        """Get statistics about detected port connections"""
    
        if not self.port_connections:
            return {}
    
        stats = {
            'total_connections': len(self.port_connections),
            'by_type': {},
            'by_service': {},
            'most_connected_devices': {}
        }
    
        device_connection_count = {}
    
        for connection in self.port_connections.values():
        # Count by type
            conn_type = connection.get('connection_type', 'unknown')
            stats['by_type'][conn_type] = stats['by_type'].get(conn_type, 0) + 1
        
            # Count by service
            service = connection.get('service', 'Unknown')
            stats['by_service'][service] = stats['by_service'].get(service, 0) + 1
        
            # Count per device
            source_ip = connection['source_ip']
            dest_ip = connection['dest_ip']
        
            device_connection_count[source_ip] = device_connection_count.get(source_ip, 0) + 1
            device_connection_count[dest_ip] = device_connection_count.get(dest_ip, 0) + 1
    
        # Get most connected devices (top 5)
        sorted_devices = sorted(device_connection_count.items(), key=lambda x: x[1], reverse=True)
        stats['most_connected_devices'] = dict(sorted_devices[:5])
    
        return stats
        
        
    def refresh_topology_with_connections(self, canvas, ax, fig):
        """Refresh topology visualization with/without port connections"""
        try:
            # Clear the current plot
            ax.clear()
        
            # Rebuild the entire topology (reuse your existing drawing code)
            self.redraw_complete_topology(ax)
        
            # Add port connections if enabled
            if self.show_port_connections.get() and hasattr(self, 'port_connections'):
                if hasattr(self, 'node_positions'):
                    self.draw_port_connections(ax, self.node_positions, show_labels=True)
        
            # Update connection count
            if hasattr(self, 'conn_count_label'):
                conn_count = len(self.port_connections) if hasattr(self, 'port_connections') else 0
                self.conn_count_label.config(text=f"({conn_count} connections)")
        
            # Refresh the canvas
            canvas.draw()
        
        except Exception as e:
            messagebox.showerror("Visualization Error", f"Failed to refresh topology: {str(e)}")
            print(f"DEBUG: Topology refresh error: {e}")

    def redraw_complete_topology(self, ax):
        """Redraw the complete topology (extracted from your show_topology method)"""
    
        # This should contain all your existing topology drawing code
        # from show_topology method, but extracted into a separate method
        # so it can be reused for refreshing
    
        if not self.discovered_hosts:
            ax.text(0.5, 0.5, 'No scan data available', 
                ha='center', va='center', transform=ax.transAxes,
                fontsize=14, color='gray')
            return
    
        # Build the network topology
        self.build_network_graph()
    
        if not self.network_graph.nodes():
            ax.text(0.5, 0.5, 'No network topology available', 
                ha='center', va='center', transform=ax.transAxes,
                fontsize=14, color='gray')
            return
    
        # [INSERT YOUR EXISTING TOPOLOGY DRAWING CODE HERE]
        # This includes: device mappings, node categorization, layout, 
        # drawing nodes by shape, edges, labels, legend, etc.
    
        # Enhanced color and shape mappings (from your existing code)
        device_mappings = self.create_legend_mappings()
    
        # Define node shapes (from your existing code)
        shape_map = {
            'Gateway (.1/.254)': 'D',      # Diamond
            'Router/Gateway': 'D',          # Diamond  
            'Router/Switch': 'D',           # Diamond
            'Router/Network Device': 'D',   # Diamond
            'Router': 'D',                  # Diamond
            'Switch': 's',                  # Square
            'Access Point': '^',            # Triangle
            'Server/Web Device': 's',       # Square
            'Windows Host': 'o',            # Circle
            'Linux Host': 'o',              # Circle
            'IP Camera/CCTV': 'v',          # Inverted triangle
            'IP Camera': 'v',               # Inverted triangle
            'Mobile Device': 'o',           # Circle (smaller)
            'Network Device': 'h',          # Hexagon
            'Host (Filtered/Mobile)': 'o',  # Circle
            'Unknown': 'o'                  # Circle
        }
    
        # [COPY ALL YOUR EXISTING NODE CATEGORIZATION AND POSITIONING CODE]  This has been done
        # [COPY ALL YOUR EXISTING NODE DRAWING CODE]                         This has been done
        # [COPY ALL YOUR EXISTING EDGE DRAWING CODE]                         This has been done
        # [COPY ALL YOUR EXISTING LABEL DRAWING CODE]                        This has been done
        # [COPY ALL YOUR EXISTING LEGEND CODE]                               This has been done
        
    def redraw_complete_topology(self, ax):
        """Redraw the complete topology (extracted from your show_topology method)"""
    
        if not self.discovered_hosts:
            ax.text(0.5, 0.5, 'No scan data available', 
                ha='center', va='center', transform=ax.transAxes,
                fontsize=14, color='gray')
            return
    
        # Build the network topology
        self.build_network_graph()
    
        if not self.network_graph.nodes():
            ax.text(0.5, 0.5, 'No network topology available', 
                ha='center', va='center', transform=ax.transAxes,
                fontsize=14, color='gray')
            return
    
        # Enhanced color and shape mappings
        device_mappings = self.create_legend_mappings()
    
        # Define node shapes for different device types
        shape_map = {
            'Gateway (.1/.254)': 'D',      # Diamond
            'Router/Gateway': 'D',          # Diamond  
            'Router/Switch': 'D',           # Diamond
            'Router/Network Device': 'D',   # Diamond
            'Router': 'D',                  # Diamond
            'Switch': 's',                  # Square
            'Access Point': '^',            # Triangle
            'Server/Web Device': 's',       # Square
            'Windows Host': 'o',            # Circle
            'Linux Host': 'o',              # Circle
            'IP Camera/CCTV': 'v',          # Inverted triangle
            'IP Camera': 'v',               # Inverted triangle
            'Mobile Device': 'o',           # Circle (smaller)
            'Network Device': 'h',          # Hexagon
            'Host (Filtered/Mobile)': 'o',  # Circle
            'Unknown': 'o'                  # Circle
        }
    
        # Identify gateway nodes and categorize all nodes
        gateway_nodes = []
        infrastructure_nodes = []  # Switches, APs, servers
        client_nodes = []          # End devices

        for node in self.network_graph.nodes():
            last_octet = int(node.split('.')[-1])
            device_type = self.network_graph.nodes[node].get('device_type', 'Unknown')

            # Consider as gateway if: ends in .1 or .254, OR is identified as router/gateway
            is_gateway = (last_octet in [1, 254] or 
                        'Gateway' in device_type or 
                        ('Router' in device_type and 'Network Device' not in device_type))

            if is_gateway:
                gateway_nodes.append(node)
            elif any(keyword in device_type for keyword in ['Switch', 'Access Point', 'Server', 'Camera']):
                infrastructure_nodes.append(node)
            else:
                client_nodes.append(node)

        # Create hierarchical layout
        pos = {}
        all_nodes = list(self.network_graph.nodes())

        if len(gateway_nodes) > 0:
            # Position gateways at the top
            gateway_width = max(len(gateway_nodes) * 2, 4)
            for i, gateway in enumerate(gateway_nodes):
                x_pos = (i - (len(gateway_nodes) - 1) / 2) * (gateway_width / max(len(gateway_nodes), 1))
                pos[gateway] = (x_pos, 3.0)  # Top level

            # Position infrastructure devices in middle layer
            if infrastructure_nodes:
                infra_y_level = 2.0
                if len(infrastructure_nodes) == 1:
                    pos[infrastructure_nodes[0]] = (0, infra_y_level)
                else:
                    infra_width = len(infrastructure_nodes) * 1.5
                    for i, device in enumerate(infrastructure_nodes):
                        x_pos = (i - (len(infrastructure_nodes) - 1) / 2) * (infra_width / len(infrastructure_nodes))
                        pos[device] = (x_pos, infra_y_level)

            # Position client devices in grid layout at bottom
            if client_nodes:
                client_y_level = 0.8
    
                # Calculate grid dimensions
                total_clients = len(client_nodes)
                if total_clients <= 4:
                    cols = total_clients
                    rows = 1
                elif total_clients <= 9:
                    cols = 3
                    rows = (total_clients + cols - 1) // cols
                else:
                    cols = max(4, int(total_clients ** 0.6))
                    rows = (total_clients + cols - 1) // cols
    
                # Calculate spacing
                grid_width = cols * 1.8
                grid_height = rows * 0.6
    
                for i, device in enumerate(client_nodes):
                    row = i // cols
                    col = i % cols
        
                    x_pos = (col - (cols - 1) / 2) * (grid_width / max(cols, 1))
                    y_pos = client_y_level - (row * grid_height / max(rows, 1))
        
                    pos[device] = (x_pos, y_pos)

        else:
            # No gateways found - use spring layout
            try:
                pos = nx.spring_layout(self.network_graph, k=3, iterations=50)
                if not pos:
                    # Fallback to grid layout
                    nodes = list(self.network_graph.nodes())
                    cols = max(1, int(len(nodes) ** 0.5))
                    pos = {}
                    for i, node in enumerate(nodes):
                        row = i // cols
                        col = i % cols
                        pos[node] = (col * 2, -row * 1.5)
            except Exception as e:
                print(f"DEBUG: Layout failed: {e}")
                nodes = list(self.network_graph.nodes())
                cols = max(1, int(len(nodes) ** 0.5))
                pos = {}
                for i, node in enumerate(nodes):
                    row = i // cols
                    col = i % cols
                    pos[node] = (col * 2, -row * 1.5)

        # Ensure all nodes have positions
        for node in all_nodes:
            if node not in pos:
                print(f"DEBUG: Node {node} missing position, assigning fallback")
                pos[node] = (0, 0)

        # Store positions for later use
        self.node_positions = pos.copy()

        # Group nodes by shape and draw them separately
        nodes_by_shape = {}
        for node in self.network_graph.nodes():
            device_type = self.network_graph.nodes[node].get('device_type', 'Unknown')
            shape = shape_map.get(device_type, 'o')

            if shape not in nodes_by_shape:
                nodes_by_shape[shape] = []
            nodes_by_shape[shape].append(node)

        # Draw each shape group separately
        for shape, nodes in nodes_by_shape.items():
            if not nodes:
                continue
    
            # Prepare colors and sizes for this shape group
            node_colors = []
            node_sizes = []

            for node in nodes:
                device_type = self.network_graph.nodes[node].get('device_type', 'Unknown')
                mac_vendor = self.network_graph.nodes[node].get('mac_vendor', '')
                open_ports = self.network_graph.nodes[node].get('open_ports', [])
    
                # Color selection with vendor-based variants
                base_color = device_mappings.get(device_type, {}).get('color', '#95A5A6')
    
                # Vendor-based color variations
                vendor_colors = {
                    'apple': '#007AFF',      # Apple blue
                    'samsung': '#1428A0',    # Samsung blue  
                    'google': '#4285F4',     # Google blue
                    'microsoft': '#0078D4',  # Microsoft blue
                    'cisco': '#049FD9',      # Cisco blue
                    'netgear': '#F7941D',    # Netgear orange
                    'tp-link': '#4CC35E',    # TP-Link green
                    'asus': '#0066CC',       # ASUS blue
                    'linksys': '#003366',    # Linksys dark blue
                    'ubiquiti': '#0066CC'    # Ubiquiti blue
                }
    
                # Check if we can apply vendor-specific coloring
                vendor_color = None
                if mac_vendor:
                    vendor_lower = mac_vendor.lower()
                    for vendor, color in vendor_colors.items():
                        if vendor in vendor_lower:
                            vendor_color = color
                            break
    
                node_colors.append(vendor_color if vendor_color else base_color)
    
                # Smart sizing based on device type and open ports
                base_size = 1000
    
                if node in gateway_nodes:
                    size = 2000  # Largest for gateways
                elif device_type in ['Server/Web Device', 'Switch', 'Router/Switch']:
                    size = 1600  # Large for infrastructure
                elif device_type in ['IP Camera/CCTV', 'Access Point']:
                    size = 1200  # Medium for specialized devices
                elif device_type == 'Mobile Device':
                    size = 800   # Smaller for mobile devices
                else:
                    # Scale based on number of open ports (more ports = more important)
                    port_count = len(open_ports) if open_ports else 0
                    size = base_size + (port_count * 50)
                    size = min(size, 1400)  # Cap the maximum size
    
                node_sizes.append(size)

            # Create position dict for this shape group
            shape_pos = {node: pos[node] for node in nodes}

            # Draw nodes with the specific shape
            nx.draw_networkx_nodes(self.network_graph.subgraph(nodes), shape_pos,
                                node_color=node_colors,
                                node_size=node_sizes,
                                node_shape=shape,
                                alpha=0.8,
                                edgecolors='black',
                                linewidths=1,
                                ax=ax)

        # Draw edges with enhanced styling  
        if self.network_graph.edges():
            nx.draw_networkx_edges(self.network_graph, pos,
                                alpha=0.4,
                                edge_color='#666666',
                                width=1.5,
                                style='solid',
                                ax=ax)

        # Enhanced labels
        labels = {}
        for node in self.network_graph.nodes():
            hostname = self.network_graph.nodes[node].get('hostname', node)
            device_type = self.network_graph.nodes[node].get('device_type', 'Unknown')
            mac_vendor = self.network_graph.nodes[node].get('mac_vendor', '')

            # Truncate long hostnames   
            if len(hostname) > 15:
                hostname = hostname[:12] + "..."

            # Create label with device type indicator
            if node in gateway_nodes:
                labels[node] = f"[GW] {hostname}\n({node})"
            elif 'Server' in device_type:
                labels[node] = f"[SRV] {hostname}\n({node})" 
            elif 'Camera' in device_type:
                labels[node] = f"[CAM] {hostname}\n({node})"
            elif 'Mobile' in device_type:
                labels[node] = f"[MOB] {hostname}\n({node})"
            elif mac_vendor and mac_vendor != 'Unknown':
                labels[node] = f"{hostname}\n({mac_vendor})"
            else:
                labels[node] = f"{hostname}\n({node})"

        nx.draw_networkx_labels(self.network_graph, pos, labels, 
                            font_size=8, font_weight='bold', ax=ax)

        # Enhanced legend with shapes and colors
        existing_types = set()
        for node in self.network_graph.nodes():
            device_type = self.network_graph.nodes[node].get('device_type', 'Unknown')
            existing_types.add(device_type)

        legend_elements = []
        from matplotlib.lines import Line2D

        # Sort device types by priority for consistent legend ordering
        sorted_types = sorted(existing_types, 
                            key=lambda x: device_mappings.get(x, {}).get('priority', 99))

        for device_type in sorted_types:
            color = device_mappings.get(device_type, {}).get('color', '#95A5A6')
            shape = shape_map.get(device_type, 'o')

            # Map NetworkX shapes to matplotlib marker symbols
            marker_map = {'D': 'D', 's': 's', '^': '^', 'v': 'v', 'h': 'h', 'o': 'o'}
            marker = marker_map.get(shape, 'o')

            legend_elements.append(Line2D([0], [0], marker=marker, color='w',
                                        markerfacecolor=color, 
                                        markeredgecolor='black',
                                        markeredgewidth=1,
                                        markersize=10,
                                        label=device_type))

        if legend_elements:
            ax.legend(handles=legend_elements, loc='upper left', frameon=True,
                    fancybox=True, shadow=True, fontsize=9)

        # Set title
        ax.set_title(f"Network Topology with Port Connections - {self.network_entry.get()}\n(Click devices for details)", 
                    fontsize=14, fontweight='bold', pad=20)
        ax.axis('off')
    
            # Set title
        ax.set_title(f"Network Topology with Port Connections - {self.network_entry.get()}\n(Click devices for details)", 
                        fontsize=14, fontweight='bold', pad=20)
        ax.axis('off')

        def show_connection_details(self):
            """Show detailed port connection information in a new window"""
    
            if not hasattr(self, 'port_connections') or not self.port_connections:
                messagebox.showinfo("Connection Details", "No port connections detected.\n\nRun a network scan first, then view the topology.")
                return
    
            # Create details window
            details_window = tk.Toplevel(self.root)
            details_window.title("Port Connection Details")
            details_window.geometry("800x600")
    
            # Create notebook for different views
            notebook = ttk.Notebook(details_window)
            notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
            # Tab 1: Connection List
            self.create_connection_list_tab(notebook)
    
            # Tab 2: Connection Statistics
            self.create_connection_stats_tab(notebook)
    
            # Tab 3: Service Matrix
            self.create_service_matrix_tab(notebook)
            
        def refresh_topology_display(self):
            """Refresh the topology display"""
            try:
                # Check if we have the current topology window
                if hasattr(self, 'current_topology_window'):
                    # Close existing topology window
                    try:
                        self.current_topology_window.destroy()
                    except:
                        pass
            
            # Re-open topology window
            self.show_topology()
            
        except Exception as e:
            print(f"DEBUG: Error in refresh_topology_display: {e}")
            messagebox.showerror("Refresh Error", f"Failed to refresh topology: {str(e)}")

        def create_connection_list_tab(self, notebook):
            """Create the connection list tab"""
    
            list_frame = ttk.Frame(notebook)
            notebook.add(list_frame, text="Connection List")
    
            # Create treeview for connections
            columns = ('Source', 'Source Port', 'Destination', 'Dest Port', 'Service', 'Type')
            conn_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=20)
    
            # Configure columns
            for col in columns:
                conn_tree.heading(col, text=col)
                conn_tree.column(col, width=120)
    
            # Add scrollbar
            conn_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=conn_tree.yview)
            conn_tree.configure(yscrollcommand=conn_scroll.set)
    
            # Populate with connection data
            for conn_key, connection in self.port_connections.items():
                source_port = connection.get('source_port', '')
                if source_port == 'any' or source_port == 'dynamic':
                    source_port = f"[{source_port}]"
        
                dest_port = connection.get('dest_port', '')
                if dest_port == 'routing':
                    dest_port = "[routing]"
        
                conn_tree.insert('', tk.END, values=(
                    connection['source_ip'],
                    source_port,
                    connection['dest_ip'],
                    dest_port,
                    connection.get('service', 'Unknown'),
                    connection.get('connection_type', 'default').title()
                ))
    
            # Pack the treeview and scrollbar
            conn_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0), pady=5)
            conn_scroll.pack(side=tk.RIGHT, fill=tk.Y, pady=5)

        def create_connection_stats_tab(self, notebook):    
            """Create the connection statistics tab"""
    
            stats_frame = ttk.Frame(notebook)
            notebook.add(stats_frame, text="Statistics")
    
            # Get connection statistics
            stats = self.get_connection_statistics()
    
            # Create scrolled text widget for statistics
            stats_text = scrolledtext.ScrolledText(stats_frame, wrap=tk.WORD, height=25, font=('Courier', 10))
            stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
            # Format statistics display
            stats_content = "PORT CONNECTION ANALYSIS\n"
            stats_content += "=" * 50 + "\n\n"
    
            stats_content += f"Total Connections: {stats.get('total_connections', 0)}\n\n"
    
            # Connection types
            stats_content += "CONNECTIONS BY TYPE:\n"
            stats_content += "-" * 25 + "\n"
            for conn_type, count in stats.get('by_type', {}).items():
                stats_content += f"{conn_type.title():20} {count:3d} connections\n"
    
            stats_content += "\n"
    
            # Services
            stats_content += "CONNECTIONS BY SERVICE:\n"
            stats_content += "-" * 27 + "\n"
            sorted_services = sorted(stats.get('by_service', {}).items(), key=lambda x: x[1], reverse=True)
            for service, count in sorted_services[:15]:  # Top 15 services
                stats_content += f"{service:20} {count:3d} connections\n"
    
            stats_content += "\n"
    
            # Most connected devices
            stats_content += "MOST CONNECTED DEVICES:\n"
            stats_content += "-" * 26 + "\n"
            for device_ip, count in stats.get('most_connected_devices', {}).items():
                device_info = self.discovered_hosts.get(device_ip, {})
                hostname = device_info.get('hostname', 'Unknown')
                device_type = device_info.get('device_type', 'Unknown')
        
                stats_content += f"{device_ip:15} {hostname:20} ({device_type})\n"
                stats_content += f"{'':15} {count} connections\n\n"
    
            # Insert content
            stats_text.insert(1.0, stats_content)
            stats_text.config(state=tk.DISABLED)  # Make read-only

        def create_service_matrix_tab(self, notebook):
            """Create the service matrix tab"""
    
            matrix_frame = ttk.Frame(notebook)
            notebook.add(matrix_frame, text="Service Matrix")
    
            # Create a matrix showing which devices offer which services
            matrix_text = scrolledtext.ScrolledText(matrix_frame, wrap=tk.NONE, height=25, font=('Courier', 9))
            matrix_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
            # Build service matrix
            device_services = {}
            all_services = set()
    
            for connection in self.port_connections.values():
                dest_ip = connection['dest_ip']
                service = connection.get('service', 'Unknown')
        
                if dest_ip not in device_services:
                    device_services[dest_ip] = set()
        
                device_services[dest_ip].add(service)
                all_services.add(service)
    
            # Sort services for consistent display
            sorted_services = sorted(all_services)
    
            # Create matrix header
            matrix_content = "SERVICE AVAILABILITY MATRIX\n"
            matrix_content += "=" * 60 + "\n\n"
            matrix_content += f"{'Device':<15} {'Hostname':<20} Services\n"
            matrix_content += "-" * 80 + "\n"
    
            # Create matrix rows
            for device_ip in sorted(device_services.keys()):
                device_info = self.discovered_hosts.get(device_ip, {})
                hostname = device_info.get('hostname', 'Unknown')[:18]
        
                services = device_services[device_ip]
                service_list = ", ".join(sorted(services)[:5])  # Show first 5 services
                if len(services) > 5:
                    service_list += f" (+{len(services)-5} more)"
        
                matrix_content += f"{device_ip:<15} {hostname:<20} {service_list}\n"
    
            matrix_text.insert(1.0, matrix_content)
            matrix_text.config(state=tk.DISABLED)  # Make read-only

        def create_legend_mappings(self):
            """Enhanced device mappings including connection-aware colors"""
            # This should be your existing create_legend_mappings method
            # but you might want to add some connection-aware enhancements
    
            return {
                'Gateway (.1/.254)': {'color': '#E74C3C', 'priority': 1},
                'Router/Gateway': {'color': '#E74C3C', 'priority': 2},
                'Router/Switch': {'color': '#3498DB', 'priority': 3},
                'Router/Network Device': {'color': '#3498DB', 'priority': 4},
                'Router': {'color': '#E74C3C', 'priority': 5},
                'Switch': {'color': '#2980B9', 'priority': 6},
                'Access Point': {'color': '#8E44AD', 'priority': 7},
                'Server/Web Device': {'color': '#27AE60', 'priority': 8},
                'Windows Host': {'color': '#F39C12', 'priority': 9},
                'Linux Host': {'color': '#E67E22', 'priority': 10},
                'IP Camera/CCTV': {'color': '#9B59B6', 'priority': 11},
                'IP Camera': {'color': '#9B59B6', 'priority': 12},
                'Mobile Device': {'color': '#16A085', 'priority': 13},
                'Network Device': {'color': '#34495E', 'priority': 14},
                'Host (Filtered/Mobile)': {'color': '#95A5A6', 'priority': 15},
                'Unknown': {'color': '#BDC3C7', 'priority': 16}
            }

        # MODIFICATION TO YOUR EXISTING scan_complete METHOD
        def scan_complete(self):
            """Called when scan is complete - now includes port connection detection"""
            self.scanning = False
            self.progress.stop()
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
    
            if self.discovered_hosts:
                self.export_button.config(state=tk.NORMAL)
                self.view_map_button.config(state=tk.NORMAL)
                self.update_results()
        
                # ADDITION: Detect port connections after scan completes
                print("DEBUG: Scan complete, analyzing port connections...")
                try:
                    self.detect_port_connections()
                    connection_count = len(self.port_connections) if hasattr(self, 'port_connections') else 0
                    print(f"DEBUG: Detected {connection_count} port connections")
                except Exception as e:
                    print(f"DEBUG: Port connection detection failed: {e}")
                    self.port_connections = {}
        
                self.status_var.set(f"Scan complete. Found {len(self.discovered_hosts)} hosts, {len(self.port_connections) if hasattr(self, 'port_connections') else 0} connections.")
            else:
                self.status_var.set("Scan complete. No hosts found.")
    
   
        # HELPER METHOD FOR PORT CONNECTION EXPORT
        def export_port_connections_csv(self):
            """Export port connections to CSV file"""
    
            if not hasattr(self, 'port_connections') or not self.port_connections:
                messagebox.showwarning("Export Warning", "No port connections to export.")
                return
    
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                title="Export Port Connections"
            )
    
            if filename:
                try:
                    import csv
                    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                        fieldnames = ['Source_IP', 'Source_Port', 'Destination_IP', 'Destination_Port', 
                                    'Service', 'Connection_Type', 'Bidirectional', 'Strength']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                        writer.writeheader()
                        for connection in self.port_connections.values():
                            writer.writerow({
                                'Source_IP': connection['source_ip'],
                                'Source_Port': connection.get('source_port', ''),
                                'Destination_IP': connection['dest_ip'], 
                                'Destination_Port': connection.get('dest_port', ''),
                                'Service': connection.get('service', ''),
                                'Connection_Type': connection.get('connection_type', ''),
                                'Bidirectional': connection.get('bidirectional', False),
                                'Strength': connection.get('strength', 0.5)
                            })
            
                    messagebox.showinfo("Export Success", f"Port connections exported to {filename}")
            
                except Exception as e:
                    messagebox.showerror("Export Error", f"Failed to export port connections: {str(e)}")

        def export_topology_with_connections_png(self, fig):
            """Export topology with port connections as PNG"""
            filename = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG files", "*.png"), ("All files", "*.*")],
                title="Export Network Topology with Connections"
            )
    
            if filename:
                try:
                    # Ensure port connections are visible before export
                    if hasattr(self, 'show_port_connections') and self.show_port_connections.get():
                        fig.savefig(filename, dpi=300, bbox_inches='tight', 
                                facecolor='white', edgecolor='none')
                    else:
                        fig.savefig(filename, dpi=300, bbox_inches='tight',
                                facecolor='white', edgecolor='none') 
            
                    messagebox.showinfo("Export Success", f"Topology with connections saved as {filename}")
                except Exception as e:
                    messagebox.showerror("Export Error", f"Failed to export image: {str(e)}")

        
    
def main():
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()
    
if __name__ == "__main__":
    main()
    
