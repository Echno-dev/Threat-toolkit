# src/modules/port_scanner.py
"""
Interactive Advanced Port Scanner (with improved service guessing)

- Threaded TCP connect scans
- Banner grabbing and protocol-aware quick checks (HTTP, SSH, SMTP-ish)
- Enhanced service guessing using:
    - socket.getservbyport(port, 'tcp')
    - COMMON_PORTS fallback
    - banner heuristics
    - local process lookup via psutil (if available and target is local)
- Separate OPEN / CLOSED sections with details
- Programmatic API (PortScanner) + interactive menu when run directly
"""

import socket
import threading
import time
from typing import List, Dict, Any

# optional psutil for local process discovery (best-effort)
try:
    import psutil
    _HAS_PSUTIL = True
except Exception:
    _HAS_PSUTIL = False

# small common port name hints
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP', 110: 'POP3',
    111: 'rpcbind', 123: 'NTP', 135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP',
    161: 'SNMP', 179: 'BGP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
    995: 'POP3S', 1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5900: 'VNC',
    6379: 'Redis', 8000: 'HTTP-alt', 8080: 'HTTP-proxy'
}


class PortScanner:
    def __init__(self, timeout: float = 3.0, max_threads: int = 200):
        self.timeout = float(timeout)
        self.max_threads = int(max_threads)
        self._stop_flag = False

    def stop(self):
        self._stop_flag = True

    def reset_stop(self):
        self._stop_flag = False

    def generate_port_list(self, spec: str) -> List[int]:
        """Parse spec like '22,80,8000-8010' into sorted list of ints."""
        if not spec:
            return []
        ports = set()
        for part in spec.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                try:
                    a, b = part.split('-', 1)
                    start, end = int(a), int(b)
                    if start > end:
                        start, end = end, start
                    for p in range(max(1, start), min(65535, end) + 1):
                        ports.add(p)
                except Exception:
                    continue
            else:
                try:
                    p = int(part)
                    if 1 <= p <= 65535:
                        ports.add(p)
                except Exception:
                    continue
        return sorted(ports)

    # ---------------- service identification helpers ----------------

    @staticmethod
    def identify_from_banner(banner: str) -> str:
        """Heuristic detection of service from banner text."""
        if not banner:
            return ""
        b = banner.lower()
        if "http/" in b or "http" in b or "server:" in b:
            return "http"
        if b.startswith("ssh-") or "openssh" in b or "sshd" in b:
            return "ssh"
        if "smtp" in b or "esmtp" in b or b.startswith("220"):
            return "smtp"
        if "imap" in b:
            return "imap"
        if "pop3" in b:
            return "pop3"
        if "mysql" in b or "mariadb" in b:
            return "mysql"
        if "redis" in b:
            return "redis"
        if "vnc" in b:
            return "vnc"
        if "ftp" in b:
            return "ftp"
        if "mongodb" in b or "mongod" in b:
            return "mongodb"
        if "rdp" in b or "ms-wbt-server" in b:
            return "rdp"
        # fallback keywords
        for kw in ("ssh", "smtp", "http", "imap", "pop3", "mysql", "redis", "vnc", "ftp", "mongodb", "rdp"):
            if kw in b:
                return kw
        return ""

    def _local_addresses(self) -> List[str]:
        """Return a list of local IP addresses (best-effort)."""
        addrs = []
        try:
            for name, if_addrs in (psutil.net_if_addrs().items() if _HAS_PSUTIL else []):
                for a in if_addrs:
                    addr = getattr(a, "address", None)
                    if addr:
                        addrs.append(addr)
        except Exception:
            pass
        # always include localhost variants
        addrs.extend(["127.0.0.1", "localhost", "0.0.0.0"])
        # dedupe
        return list(dict.fromkeys(addrs))

    def guess_service(self, port: int, host_resolved: str = None, banner: str = "") -> str:
        """
        Improved service guess:
        1) Try socket.getservbyport(port, 'tcp')
        2) COMMON_PORTS fallback
        3) banner heuristics (if banner provided)
        4) if local host and psutil available, try to find process name
        """
        # 1) socket mapping (explicitly for tcp)
        try:
            name = socket.getservbyport(port, 'tcp')
            if name:
                return name
        except Exception:
            pass

        # 2) built-in mapping
        if port in COMMON_PORTS:
            return COMMON_PORTS[port]

        # 3) banner heuristics
        banner_guess = self.identify_from_banner(banner)
        if banner_guess:
            return banner_guess

        # 4) psutil local check (best-effort)
        if _HAS_PSUTIL and host_resolved:
            try:
                local_addrs = self._local_addresses()
            except Exception:
                local_addrs = ["127.0.0.1", "localhost"]

            # normalize host_resolved for local check: it may be IP or hostname
            is_local = False
            try:
                if host_resolved in local_addrs:
                    is_local = True
                else:
                    # resolve host_resolved to its IP and compare
                    try:
                        resolved = socket.gethostbyname(host_resolved)
                        if resolved in local_addrs:
                            is_local = True
                    except Exception:
                        pass
            except Exception:
                is_local = False

            if is_local:
                try:
                    for conn in psutil.net_connections(kind='inet'):
                        laddr = getattr(conn, "laddr", None)
                        if not laddr:
                            continue
                        # laddr can be a tuple (ip, port)
                        try:
                            l_ip = laddr[0]
                            l_port = int(laddr[1])
                        except Exception:
                            continue
                        if l_port == int(port):
                            pid = getattr(conn, "pid", None)
                            if pid:
                                try:
                                    p = psutil.Process(pid)
                                    pname = p.name()
                                    return f"{pname} (pid:{pid})"
                                except Exception:
                                    return f"listening (pid:{pid})"
                            else:
                                return "listening"
                except Exception:
                    pass

        # final fallback
        return "unknown"

    # ---------------- core scanning ----------------

    def _connect_and_banner(self, ip: str, port: int) -> Dict[str, Any]:
        """
        Attempt connection, return dict with state, err code (if any), banner (if any),
        rtt (float seconds)
        """
        start = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            err = s.connect_ex((ip, port))
            rtt = round(time.time() - start, 3)
            if err == 0:
                banner = ""
                try:
                    s.settimeout(1.0)
                    banner = s.recv(2048).decode('utf-8', errors='ignore').strip()
                except Exception:
                    banner = ""
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass
                return {'state': 'open', 'err': None, 'banner': banner, 'rtt': rtt}
            else:
                try:
                    s.close()
                except Exception:
                    pass
                return {'state': 'closed', 'err': err, 'banner': "", 'rtt': rtt}
        except Exception as e:
            rtt = round(time.time() - start, 3)
            try:
                s.close()
            except Exception:
                pass
            return {'state': 'closed', 'err': str(e), 'banner': "", 'rtt': rtt}

    def _scan_worker(self, ip: str, ports_list: List[int], lock: threading.Lock,
                     results_open: List[Dict[str, Any]], results_closed: List[Dict[str, Any]]):
        while True:
            with lock:
                if not ports_list or self._stop_flag:
                    return
                port = ports_list.pop(0)
            res = self._connect_and_banner(ip, port)
            # pass banner and host_resolved to guesser
            service = self.guess_service(port, host_resolved=ip, banner=res.get('banner', ''))
            if res['state'] == 'open':
                results_open.append({
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'open',
                    'service': service,
                    'banner': res.get('banner', ''),
                    'rtt': res.get('rtt', 0.0)
                })
            else:
                results_closed.append({
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'closed',
                    'service': service,
                    'err': res.get('err'),
                    'rtt': res.get('rtt', 0.0)
                })

    def scan_host_ports(self, host: str, ports: List[int]) -> Dict[str, Any]:
        """
        Scan given ports on host. Returns dict with open_ports, closed_ports, resolved_ip, hostname, etc.
        """
        start_all = time.time()
        try:
            resolved_ip = socket.gethostbyname(host)
        except Exception as e:
            raise RuntimeError(f"Unable to resolve host {host}: {e}")

        try:
            hostname = socket.gethostbyaddr(resolved_ip)[0]
        except Exception:
            hostname = None

        results_open: List[Dict[str, Any]] = []
        results_closed: List[Dict[str, Any]] = []
        ports_list = list(ports)

        if not ports_list:
            return {
                'target': host,
                'resolved_ip': resolved_ip,
                'hostname': hostname,
                'open_ports': results_open,
                'closed_ports': results_closed,
                'scan_duration': 0.0,
                'total_ports': 0
            }

        lock = threading.Lock()
        threads = []
        num_threads = min(self.max_threads, max(1, len(ports_list)))
        for _ in range(num_threads):
            t = threading.Thread(target=self._scan_worker,
                                 args=(resolved_ip, ports_list, lock, results_open, results_closed),
                                 daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        duration = round(time.time() - start_all, 3)
        return {
            'target': host,
            'resolved_ip': resolved_ip,
            'hostname': hostname,
            'open_ports': sorted(results_open, key=lambda x: x['port']),
            'closed_ports': sorted(results_closed, key=lambda x: x['port']),
            'scan_duration': duration,
            'total_ports': len(results_open) + len(results_closed)
        }

    # --- Detailed analysis helpers ---

    def _http_quick_info(self, ip: str, port: int) -> Dict[str, Any]:
        """Send a minimal HTTP HEAD request to capture Server header / first response lines."""
        info = {}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((ip, port))
            req = "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n".format(ip)
            s.send(req.encode('utf-8'))
            data = b""
            try:
                s.settimeout(1.0)
                data = s.recv(4096)
            except Exception:
                pass
            finally:
                try:
                    s.close()
                except Exception:
                    pass
            txt = data.decode('utf-8', errors='ignore')
            first_line = txt.splitlines()[0] if txt.splitlines() else ""
            server_hdr = ""
            for line in txt.splitlines():
                if line.lower().startswith("server:"):
                    server_hdr = line.partition(":")[2].strip()
                    break
            info['http_status_line'] = first_line
            info['server_header'] = server_hdr
            info['raw'] = txt[:1000]
        except Exception as e:
            info['error'] = str(e)
        return info

    def _ssh_quick_info(self, ip: str, port: int) -> Dict[str, Any]:
        """Try to read SSH banner line."""
        info = {}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((ip, port))
            try:
                s.settimeout(2.0)
                banner = s.recv(256).decode('utf-8', errors='ignore').strip()
            except Exception:
                banner = ""
            finally:
                try:
                    s.close()
                except Exception:
                    pass
            info['ssh_banner'] = banner
        except Exception as e:
            info['error'] = str(e)
        return info

    def _smtp_quick_info(self, ip: str, port: int) -> Dict[str, Any]:
        """Read SMTP-like greeting (if any)."""
        info = {}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((ip, port))
            try:
                s.settimeout(2.0)
                greet = s.recv(512).decode('utf-8', errors='ignore').strip()
            except Exception:
                greet = ""
            finally:
                try:
                    s.close()
                except Exception:
                    pass
            info['greeting'] = greet
        except Exception as e:
            info['error'] = str(e)
        return info

    def detailed_port_analysis(self, host: str, port: int) -> Dict[str, Any]:
        """
        Perform an in-depth check for a single port: connect, banner, protocol-aware extra probes.
        Returns dict with resolution, basic connect result, and protocol-specific info.
        """
        try:
            resolved_ip = socket.gethostbyname(host)
        except Exception as e:
            raise RuntimeError(f"Cannot resolve host {host}: {e}")

        try:
            hostname = socket.gethostbyaddr(resolved_ip)[0]
        except Exception:
            hostname = None

        base = self._connect_and_banner(resolved_ip, port)
        # pass banner into guesser for best accuracy
        service_guess = self.guess_service(port, host_resolved=resolved_ip, banner=base.get('banner', ''))
        result = {
            'target': host,
            'resolved_ip': resolved_ip,
            'hostname': hostname,
            'port': port,
            'service_guess': service_guess,
            'state': base.get('state'),
            'rtt': base.get('rtt'),
            'banner': base.get('banner'),
        }

        # protocol-aware extra checks
        if base.get('state') == 'open':
            svc = result['service_guess'].lower() if result['service_guess'] else ""
            # HTTP family ports
            if svc in ('http', 'http-alt') or port in (80, 8080, 8000, 8008, 443):
                try:
                    result['http'] = self._http_quick_info(resolved_ip, port)
                except Exception as e:
                    result['http_error'] = str(e)
            # SSH
            if svc in ('ssh',) or port == 22:
                try:
                    result['ssh'] = self._ssh_quick_info(resolved_ip, port)
                except Exception as e:
                    result['ssh_error'] = str(e)
            # SMTP/POP/IMAP style greeting
            if svc in ('smtp', 'pop3', 'imap') or port in (25, 110, 143, 993, 995):
                try:
                    result['mail'] = self._smtp_quick_info(resolved_ip, port)
                except Exception as e:
                    result['mail_error'] = str(e)

        return result

    # ---------------- formatting helpers ----------------

    def format_scan_results(self, results: Dict[str, Any]) -> str:
        lines = []
        lines.append(f"Scan report for: {results.get('target')} ({results.get('resolved_ip')})")
        if results.get('hostname'):
            lines.append(f"Reverse DNS: {results.get('hostname')}")
        lines.append(f"Total ports checked: {results.get('total_ports')}")
        lines.append(f"Scan duration: {results.get('scan_duration')}s")
        lines.append("=" * 60)
        lines.append("\nOPEN PORTS:")
        if results.get('open_ports'):
            for ent in results['open_ports']:
                lines.append(f" - {ent['port']}/tcp : {ent.get('service','unknown')} (rtt: {ent.get('rtt')}s)")
                if ent.get('banner'):
                    preview = ent['banner'].splitlines()[0][:200]
                    lines.append(f"    banner: {preview}")
        else:
            lines.append("  (none)")
        lines.append("\nCLOSED / FILTERED PORTS:")
        if results.get('closed_ports'):
            for ent in results['closed_ports']:
                lines.append(f" - {ent['port']}/tcp : {ent.get('service','unknown')} (rtt: {ent.get('rtt')}s) err: {ent.get('err')}")
        else:
            lines.append("  (none)")
        return "\n".join(lines)

    def format_detailed(self, detail: Dict[str, Any]) -> str:
        lines = []
        lines.append(f"Detailed port analysis for {detail.get('target')} ({detail.get('resolved_ip')}) port {detail.get('port')}")
        if detail.get('hostname'):
            lines.append(f"Reverse DNS: {detail.get('hostname')}")
        lines.append(f"Service guess: {detail.get('service_guess')}")
        lines.append(f"State: {detail.get('state')} (rtt: {detail.get('rtt')}s)")
        if detail.get('banner'):
            lines.append("Banner:")
            for ln in detail['banner'].splitlines()[:5]:
                lines.append("  " + ln)
        # HTTP
        if 'http' in detail:
            lines.append("\nHTTP quick info:")
            h = detail['http']
            if h.get('http_status_line'):
                lines.append(f"  Status: {h.get('http_status_line')}")
            if h.get('server_header'):
                lines.append(f"  Server header: {h.get('server_header')}")
            if h.get('raw'):
                raw_preview = h.get('raw', '')[:300].splitlines()
                if raw_preview:
                    lines.append(f"  Raw snippet: {raw_preview[0]}")
            if h.get('error'):
                lines.append(f"  HTTP probe error: {h.get('error')}")
        # SSH
        if 'ssh' in detail:
            lines.append("\nSSH quick info:")
            lines.append(f"  Banner: {detail['ssh'].get('ssh_banner','')}")
        if 'mail' in detail:
            lines.append("\nMail greeting:")
            lines.append(f"  {detail['mail'].get('greeting','')}")
        # errors
        for key in ('http_error', 'ssh_error', 'mail_error'):
            if key in detail:
                lines.append(f"{key}: {detail[key]}")
        if 'error' in detail:
            lines.append(f"Error: {detail['error']}")
        return "\n".join(lines)


# ---------------------- Interactive menu ----------------------
def _interactive():
    ps = PortScanner()
    print("Interactive Port Scanner")
    print("1) Scan ports")
    print("2) Detailed analysis of a port")
    print("3) Detailed analysis of a port range")
    print("q) Quit")
    while True:
        choice = input("\nChoose option (1/2/3/q): ").strip().lower()
        if choice == 'q':
            break

        if choice == '1':
            host = input("Enter host (IP or hostname): ").strip()
            spec = input("Enter ports (e.g. 22,80,8000-8005): ").strip()
            ports = ps.generate_port_list(spec)
            if not ports:
                print("No valid ports parsed.")
                continue
            print("Scanning... (this may take a few seconds)")
            scan_res = ps.scan_host_ports(host, ports)
            print(ps.format_scan_results(scan_res))

            # Ask the user if they want full details for all ports (open + closed)
            want_all = input("\nShow detailed info for ALL ports (open+closed)? (y/N): ").strip().lower()
            if want_all == 'y':
                print("Gathering detailed info for all ports (this will re-run checks per port)...")
                # Build complete port list (open + closed)
                ports_to_analyze = [ent['port'] for ent in scan_res.get('open_ports', [])] \
                                   + [ent['port'] for ent in scan_res.get('closed_ports', [])]
                ports_to_analyze = sorted(set(ports_to_analyze))

                detailed_results = {}
                detail_lock = threading.Lock()

                def analyze_port_worker(port_list):
                    while True:
                        with detail_lock:
                            if not port_list:
                                return
                            p = port_list.pop(0)
                        try:
                            d = ps.detailed_port_analysis(host, p)
                        except Exception as e:
                            d = {'target': host, 'resolved_ip': None, 'port': p, 'error': str(e)}
                        with detail_lock:
                            detailed_results[p] = d

                # prepare thread pool (bounded)
                pool_threads = min(20, max(1, len(ports_to_analyze)))
                thread_list = []
                port_list_shared = list(ports_to_analyze)
                for _ in range(pool_threads):
                    t = threading.Thread(target=analyze_port_worker, args=(port_list_shared,), daemon=True)
                    thread_list.append(t)
                    t.start()

                for t in thread_list:
                    t.join()

                # Print detailed results in port order
                for p in sorted(detailed_results.keys()):
                    print("\n" + "=" * 40)
                    det = detailed_results[p]
                    if isinstance(det, dict) and 'port' in det:
                        print(ps.format_detailed(det))
                    else:
                        print(f"Port {p}: could not analyze. Raw: {det}")
                print("\nDetailed analysis complete.")

        elif choice == '2':
            host = input("Enter host (IP or hostname): ").strip()
            port_s = input("Enter single port (e.g. 22): ").strip()
            try:
                port = int(port_s)
            except Exception:
                print("Invalid port.")
                continue
            print("Analyzing... (may take a few seconds)")
            detail = ps.detailed_port_analysis(host, port)
            print(ps.format_detailed(detail))

        elif choice == '3':
            host = input("Enter host (IP or hostname): ").strip()
            spec = input("Enter port range/spec (e.g. 20-25 or 22,80): ").strip()
            ports = ps.generate_port_list(spec)
            if not ports:
                print("No valid ports parsed.")
                continue
            print("Scanning and collecting details for open ports...")
            scan_res = ps.scan_host_ports(host, ports)
            print(ps.format_scan_results(scan_res))
            # For each open port, show detailed quick analysis
            if scan_res.get('open_ports'):
                for ent in scan_res['open_ports']:
                    print("\n" + "-" * 40)
                    detail = ps.detailed_port_analysis(host, ent['port'])
                    print(ps.format_detailed(detail))
            else:
                print("No open ports to analyze.")
        else:
            print("Unknown choice.")


if __name__ == "__main__":
    _interactive()
