"""
Enhanced Network Scanner Module for Multinedor!!!
- Keeps original ping-based threaded scanning.
- Adds ARP-table fallback to obtain MAC addresses (OS 'arp' parsing).
- Adds a minimal OUI vendor lookup (extendable).
- Optionally integrates with the PortScanner (from modules.port_scanner).
"""

import socket
import subprocess
import threading
import ipaddress
import platform
import time
import re
from collections import OrderedDict

class NetworkScanner:
    def __init__(self):
        self.discovered_hosts = []
        self.scan_results = {}
        self.timeout = 2
        self.max_threads = 50

        # Minimal OUI table (extend this with more prefixes as needed)
        # Prefixes are normalized to lowercase without separators: '001a2b'
        self.oui_table = {
            "001a2b": "Apple, Inc.",
            "a4c3f0": "Samsung Electronics",
            "5c514d": "Xiaomi Communications",
            "dca632": "Hewlett-Packard",
            "f4f5f8": "Realtek Semiconductor",
            # add more OUIs for better detection
        }

    # --------------------
    # Existing ping-based helpers
    # --------------------
    def ping_host(self, host):
        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), host]
            else:
                # On many UNIXes -W is per-packet timeout in seconds
                # We use -c 1 for single ping
                cmd = ["ping", "-c", "1", "-W", str(int(self.timeout)), host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout + 1)
            return result.returncode == 0
        except Exception:
            return False

    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    def scan_single_host(self, ip):
        if self.ping_host(ip):
            host_info = {
                'ip': ip,
                'status': 'up',
                'hostname': self.get_hostname(ip)
            }
            self.discovered_hosts.append(host_info)
            self.scan_results[ip] = host_info
            return host_info
        return None

    def generate_ip_range(self, network):
        try:
            # Accept either a single IP (e.g. "192.168.1.34") or CIDR
            if '/' in network:
                network_obj = ipaddress.IPv4Network(network, strict=False)
                return [str(ip) for ip in network_obj.hosts()]
            else:
                # single host
                ipaddress.IPv4Address(network)  # validate
                return [network]
        except ValueError:
            return []

    def threaded_scan(self, ip_list):
        def worker():
            while True:
                try:
                    ip = ip_list.pop(0)
                except IndexError:
                    break
                self.scan_single_host(ip)
        threads = []
        for _ in range(min(self.max_threads, max(1, len(ip_list)))):
            t = threading.Thread(target=worker)
            t.daemon = True
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        return self.scan_results

    def scan_network(self, network):
        self.discovered_hosts = []
        self.scan_results = {}
        ip_list = self.generate_ip_range(network)
        start_time = time.time()
        results = self.threaded_scan(ip_list.copy())
        scan_duration = round(time.time() - start_time, 2)
        return {
            'network': network,
            'total_ips_scanned': len(ip_list),
            'active_hosts': len(results),
            'scan_duration': scan_duration,
            'hosts': results
        }

    def format_scan_results(self, results):
        out = []
        out.append(f"Network Scan Results for {results.get('network', 'Unknown')}")
        out.append("="*50)
        out.append(f"Total IPs Scanned: {results.get('total_ips_scanned', 0)}")
        out.append(f"Active Hosts Found: {results.get('active_hosts', 0)}")
        out.append(f"Scan Duration: {results.get('scan_duration', 0)} seconds\nActive Hosts:")
        out.append("-"*30)
        for ip, info in results.get('hosts', {}).items():
            out.append(f"IP: {info.get('ip')}")
            if info.get('hostname'): out.append(f"  Hostname: {info.get('hostname')}")
            if info.get('mac'): out.append(f"  MAC: {info.get('mac')}  Vendor: {info.get('vendor')}")
            if info.get('open_ports'):
                out.append(f"  Open Ports: {', '.join(str(p['port'])+'/'+p['protocol'] for p in info['open_ports'])}")
            out.append("")
        return "\n".join(out)

    # --------------------
    # New helpers: ARP & OUI vendor lookup
    # --------------------
    def _parse_arp_output(self, output):
        """
        Parse various `arp` output formats and return dict ip->mac (lowercase).
        Works with Windows 'arp -a' and Linux/mac 'arp -n' output.
        """
        entries = {}
        # Regex patterns for common arp outputs
        # Windows lines like:  192.168.1.1          00-1a-2b-3c-4d-5e     dynamic
        win_matches = re.findall(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})', output)
        for ip, mac in win_matches:
            entries[ip] = mac.replace('-', ':').lower()

        # Linux/mac typical: 192.168.1.10 ether 00:1a:2b:3c:4d:5e C eth0
        unix_matches = re.findall(r'(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:]{17})', output)
        for ip, mac in unix_matches:
            entries[ip] = mac.lower()

        return entries

    def arp_table(self):
        """
        Return a dict mapping ip -> mac for entries present in the OS ARP table.
        This is a best-effort fallback (no scapy required). Must run after network activity
        so ARP cache populates; run `ping` first to populate cache on many OSes.
        """
        system = platform.system().lower()
        try:
            if system == "windows":
                out = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
            else:
                # On Linux/mac try 'ip neigh' first (modern), else 'arp -n'
                try:
                    out = subprocess.check_output(["ip", "neigh"], text=True, stderr=subprocess.DEVNULL)
                except Exception:
                    out = subprocess.check_output(["arp", "-n"], text=True, stderr=subprocess.DEVNULL)
            return self._parse_arp_output(out)
        except Exception:
            return {}

    def get_mac_for_ip(self, ip):
        """
        Return MAC address for the given IP if present in ARP table.
        If not present, attempt a single ping to populate ARP, then re-read table.
        """
        table = self.arp_table()
        if ip in table:
            return table[ip]
        # attempt to populate ARP and re-read
        try:
            subprocess.run(["ping", "-c", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        except Exception:
            pass
        table = self.arp_table()
        return table.get(ip)

    def lookup_vendor(self, mac):
        """
        Minimal OUI lookup using the built-in table. mac like '00:1a:2b:3c:4d:5e'
        Normalize prefix & lookup.
        """
        if not mac:
            return None
        normal = mac.replace(":", "").replace("-", "").lower()
        prefix = normal[:6]
        return self.oui_table.get(prefix, None)

    # --------------------
    # Enhanced high-level scan combining ping + ARP + optional port scan
    # --------------------
    def enhanced_scan_network(self, network, do_portscan=False, port_list=None, port_scanner_obj=None):
        """
        Run the regular scan_network(), then enrich found hosts with MAC/vendor and optionally port scan.
        - network: string (CIDR or single IP)
        - do_portscan: bool
        - port_list: list of ints
        - port_scanner_obj: optional PortScanner instance to reuse
        Returns an enriched results dict.
        """
        raw = self.scan_network(network)
        hosts = raw.get('hosts', {})
        # Attempt to populate ARP table after ping sweep
        arp = self.arp_table()

        # Attach mac/vendor and optionally run port scanner
        for ip, info in list(hosts.items()):
            mac = arp.get(ip) or self.get_mac_for_ip(ip)
            vendor = self.lookup_vendor(mac) if mac else None
            info['mac'] = mac
            info['vendor'] = vendor
            info['open_ports'] = []

            # Optionally run port scan per host
            if do_portscan and port_list and port_scanner_obj is not None:
                try:
                    res = port_scanner_obj.scan_host_ports(ip, port_list)
                    info['open_ports'] = res.get('open_ports', [])
                except Exception:
                    info['open_ports'] = []

            hosts[ip] = info

        raw['hosts'] = hosts
        return raw


# Quick command-line usage for debugging
if __name__ == "__main__":
    scanner = NetworkScanner()
    net = input("Enter network range (e.g. 192.168.1.0/24 or single IP): ")
    res = scanner.enhanced_scan_network(net, do_portscan=False)
    print(scanner.format_scan_results(res))
