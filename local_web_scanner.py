"""
Local IP Website Scanner & Browser Opener
Scans local network IP addresses for active HTTP and HTTPS web servers,
displays titles and statuses in a Tkinter GUI, and allows 1-click opening in the browser.
"""

import sys
import os
import socket
import ipaddress
import concurrent.futures
import threading
import time
import re
import webbrowser
import csv
import queue
import collections
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

try:
    import urllib.request
    import urllib.error
    import ssl
except ImportError:
    pass


# Default ports (ALL ports 1 to 65535)
DEFAULT_PORTS = "1-65535"

# Common ports that default to HTTPS
HTTPS_PORTS = {443, 8443, 9443}


def get_local_ip():
    """Detect the machine's primary local network IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def get_default_subnet():
    """Generate default /24 CIDR for the local machine's IP."""
    local_ip = get_local_ip()
    if local_ip.startswith("127."):
        return "192.168.1.0/24"
    parts = local_ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return "192.168.1.0/24"


def parse_ip_targets(ip_input):
    """
    Parse various IP input formats:
    - CIDR (e.g. 192.168.1.0/24)
    - Range (e.g. 192.168.1.1-192.168.1.50)
    - Comma/space separated IPs (e.g. 192.168.1.1, 192.168.1.2)
    - Single IP (e.g. 192.168.1.10)
    """
    targets = []
    ip_input = ip_input.strip()
    if not ip_input:
        return []

    raw_entries = [e.strip() for e in re.split(r'[,;\s]+', ip_input) if e.strip()]

    for entry in raw_entries:
        if '-' in entry:
            parts = entry.split('-')
            if len(parts) == 2:
                start_str, end_str = parts[0].strip(), parts[1].strip()
                try:
                    start_ip = ipaddress.IPv4Address(start_str)
                    if '.' in end_str:
                        end_ip = ipaddress.IPv4Address(end_str)
                    else:
                        base = start_str.rsplit('.', 1)[0]
                        end_ip = ipaddress.IPv4Address(f"{base}.{end_str}")
                    
                    if int(start_ip) <= int(end_ip):
                        curr = int(start_ip)
                        while curr <= int(end_ip):
                            targets.append(str(ipaddress.IPv4Address(curr)))
                            curr += 1
                        continue
                except Exception:
                    pass

        try:
            if '/' in entry:
                net = ipaddress.IPv4Network(entry, strict=False)
                if net.num_addresses > 2:
                    for ip in net.hosts():
                        targets.append(str(ip))
                else:
                    for ip in net:
                        targets.append(str(ip))
            else:
                ip = ipaddress.IPv4Address(entry)
                targets.append(str(ip))
        except Exception:
            continue

    seen = set()
    unique_targets = []
    for ip in targets:
        if ip not in seen:
            seen.add(ip)
            unique_targets.append(ip)

    return unique_targets


def parse_ports(port_input):
    """Parse port numbers from comma/space separated string or ranges (e.g., 80, 443, 8000-8010)."""
    ports = []
    for item in re.split(r'[,;\s]+', port_input.strip()):
        if not item:
            continue
        if '-' in item:
            p_parts = item.split('-')
            if len(p_parts) == 2 and p_parts[0].isdigit() and p_parts[1].isdigit():
                start, end = int(p_parts[0]), int(p_parts[1])
                for p in range(max(1, start), min(65535, end) + 1):
                    ports.append(p)
        elif item.isdigit():
            p = int(item)
            if 1 <= p <= 65535:
                ports.append(p)
    return sorted(list(set(ports)))


def is_port_open(ip, port, timeout=1.0):
    """Fast socket check to see if a port is open."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        res = s.connect_ex((ip, port))
        return res == 0
    except Exception:
        return False
    finally:
        s.close()


def extract_title(html_text):
    """Extract <title> from HTML content."""
    if not html_text:
        return ""
    match = re.search(r'<title[^>]*>(.*?)</title>', html_text, re.IGNORECASE | re.DOTALL)
    if match:
        title = match.group(1).strip()
        title = re.sub(r'\s+', ' ', title)
        return title[:120]
    return ""


def probe_web_service(ip, port, timeout=1.5):
    """
    Probe an IP:Port for HTTP/HTTPS web service.
    Returns dict with details or None if not a web service.
    """
    if not is_port_open(ip, port, timeout=min(timeout, 0.8)):
        return None

    if port in HTTPS_PORTS:
        protocols = ["https", "http"]
    else:
        protocols = ["http", "https"]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for protocol in protocols:
        url = f"{protocol}://{ip}" if (protocol == "http" and port == 80) or (protocol == "https" and port == 443) else f"{protocol}://{ip}:{port}"
        
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx if protocol == "https" else None) as response:
                status_code = response.getcode()
                server_header = response.headers.get('Server', '')
                
                title = ""
                try:
                    raw_body = response.read(32768)
                    charset = response.headers.get_content_charset() or 'utf-8'
                    html_text = raw_body.decode(charset, errors='ignore')
                    title = extract_title(html_text)
                except Exception:
                    pass

                return {
                    'ip': ip,
                    'port': port,
                    'protocol': protocol.upper(),
                    'url': url,
                    'status': f"{status_code} OK",
                    'title': title or (f"Server: {server_header}" if server_header else "Web Service"),
                    'server': server_header,
                }

        except urllib.error.HTTPError as e:
            status_code = e.code
            server_header = e.headers.get('Server', '') if hasattr(e, 'headers') and e.headers else ''
            
            title = ""
            try:
                raw_body = e.read(16384)
                html_text = raw_body.decode('utf-8', errors='ignore')
                title = extract_title(html_text)
            except Exception:
                pass

            status_str = f"{status_code} {e.reason if hasattr(e, 'reason') else ''}".strip()
            if not title:
                if status_code == 401:
                    title = "Auth Required (401)"
                elif status_code == 403:
                    title = "Forbidden (403)"
                elif server_header:
                    title = f"Server: {server_header}"
                else:
                    title = f"HTTP {status_code}"

            return {
                'ip': ip,
                'port': port,
                'protocol': protocol.upper(),
                'url': url,
                'status': status_str,
                'title': title,
                'server': server_header,
            }

        except Exception:
            continue

    return None


DISCLAIMER_CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".local_web_scanner_disclaimer.json")


def check_or_show_disclaimer(parent_root):
    """Check if the user has accepted the legal disclaimer on first launch. Exit if declined."""
    try:
        if os.path.exists(DISCLAIMER_CONFIG_PATH):
            with open(DISCLAIMER_CONFIG_PATH, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if data.get("accepted") is True:
                    return True
    except Exception:
        pass

    dialog = tk.Toplevel(parent_root)
    dialog.title("⚖️ Legal Terms & Disclaimer Agreement")
    dialog.geometry("640x500")
    dialog.minsize(560, 420)
    dialog.transient(parent_root)
    dialog.grab_set()

    # Center dialog on screen
    dialog.update_idletasks()
    x = (dialog.winfo_screenwidth() - 640) // 2
    y = (dialog.winfo_screenheight() - 500) // 2
    dialog.geometry(f"640x500+{max(0, x)}+{max(0, y)}")

    accepted = [False]

    def on_agree():
        accepted[0] = True
        try:
            with open(DISCLAIMER_CONFIG_PATH, 'w', encoding='utf-8') as f:
                json.dump({"accepted": True, "accepted_at": time.time()}, f)
        except Exception:
            pass
        dialog.destroy()

    def on_decline():
        accepted[0] = False
        dialog.destroy()
        parent_root.destroy()
        sys.exit(0)

    dialog.protocol("WM_DELETE_WINDOW", on_decline)

    frame = ttk.Frame(dialog, padding="20")
    frame.pack(fill=tk.BOTH, expand=True)

    ttk.Label(frame, text="⚖️ LEGAL TERMS OF USE & DISCLAIMER", font=("Segoe UI", 12, "bold"), foreground="#0284c7").pack(pady=(0, 10))

    text_frame = ttk.Frame(frame)
    text_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

    txt = tk.Text(text_frame, wrap=tk.WORD, font=("Segoe UI", 9), relief=tk.SOLID, borderwidth=1, padx=12, pady=12)
    vsb = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=txt.yview)
    txt.configure(yscrollcommand=vsb.set)

    disclaimer_text = (
        "IMPORTANT LEGAL NOTICE & END-USER AGREEMENT:\n\n"
        "By launching and using this software ('Local IP Website Scanner & Stress Testing Utility'), you explicitly "
        "acknowledge, understand, and agree to the following legally binding terms:\n\n"
        "1. NO LIABILITY / CREATOR DISCLAIMER:\n"
        "The creator, author, and contributors of this software accept ABSOLUTELY NO RESPONSIBILITY OR LIABILITY "
        "whatsoever for how you use this application, nor for any damages, downtime, service interruptions, data losses, "
        "penalties, or legal consequences arising directly or indirectly from its operation.\n\n"
        "2. AUTHORIZED USE ONLY:\n"
        "This tool is designed and provided exclusively for authorized diagnostic benchmarking, authorized cybersecurity "
        "research, educational testing, and personal lab network exploration on systems that you own or have explicit written "
        "permission to test.\n\n"
        "3. USER RESPONSIBILITY & COMPLIANCE WITH THE LAW:\n"
        "You assume 100% full personal and legal responsibility for all network traffic, scans, and stress tests generated. "
        "You certify that your use complies strictly with all applicable local, national, and international laws (including computer fraud, "
        "cybercrime, and denial-of-service regulations).\n\n"
        "By clicking 'I Agree & Continue', you accept full legal responsibility and release the creator from all liability."
    )
    txt.insert(tk.END, disclaimer_text)
    txt.config(state=tk.DISABLED, bg="#f8fafc", fg="#1e293b")
    txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    vsb.pack(side=tk.RIGHT, fill=tk.Y)

    btn_frame = ttk.Frame(frame)
    btn_frame.pack(fill=tk.X)

    btn_decline = ttk.Button(btn_frame, text="❌ Decline & Exit", command=on_decline)
    btn_decline.pack(side=tk.LEFT, padx=(0, 10))

    btn_agree = ttk.Button(btn_frame, text="✅ I Agree & Continue", style="Primary.TButton", command=on_agree)
    btn_agree.pack(side=tk.RIGHT)

    dialog.wait_window()
    return accepted[0]


class EmbeddedCameraServer:
    """Mock low-resource test web server with configurable RAM and real-time attack detection."""

    def __init__(self, port=8080, host='0.0.0.0', initial_ram_mb=32.0):
        self.port = port
        self.host = host
        self.server = None
        self.thread = None
        self.is_running = False

        self.lock = threading.Lock()
        self.request_timestamps = collections.deque()
        self.active_conns = 0
        self.total_requests = 0
        self.total_ram_mb = max(4.0, float(initial_ram_mb))
        self.base_ram_mb = max(2.0, self.total_ram_mb * 0.72)
        self.max_workers = 3
        self._update_worker_limits()

    def _update_worker_limits(self):
        if self.total_ram_mb <= 16:
            self.max_workers = 2
        elif self.total_ram_mb <= 32:
            self.max_workers = 3
        elif self.total_ram_mb <= 64:
            self.max_workers = 5
        elif self.total_ram_mb <= 128:
            self.max_workers = 8
        elif self.total_ram_mb <= 256:
            self.max_workers = 12
        else:
            self.max_workers = 20

    def set_ram(self, ram_mb):
        with self.lock:
            try:
                self.total_ram_mb = max(4.0, min(8192.0, float(ram_mb)))
                self.base_ram_mb = max(2.0, self.total_ram_mb * 0.72)
                self._update_worker_limits()
            except Exception:
                pass

    def record_request(self):
        now = time.time()
        with self.lock:
            self.total_requests += 1
            self.active_conns += 1
            self.request_timestamps.append(now)
            while self.request_timestamps and self.request_timestamps[0] < now - 2.0:
                self.request_timestamps.popleft()
            rps = len(self.request_timestamps) / 2.0
            is_attacked = (rps >= 4.0 or self.active_conns >= self.max_workers)
            curr_conns = self.active_conns
            total_reqs = self.total_requests
        return is_attacked, rps, curr_conns, total_reqs

    def finish_request(self):
        with self.lock:
            self.active_conns = max(0, self.active_conns - 1)

    def get_stats(self):
        now = time.time()
        with self.lock:
            while self.request_timestamps and self.request_timestamps[0] < now - 2.0:
                self.request_timestamps.popleft()
            rps = len(self.request_timestamps) / 2.0
            is_attacked = (rps >= 4.0 or self.active_conns >= self.max_workers)
            ram_used = min(self.total_ram_mb, self.base_ram_mb + (self.active_conns * 2.2) + (min(10.0, rps) * 0.4))
            ram_free = max(0.0, self.total_ram_mb - ram_used)
            return {
                "is_attacked": is_attacked,
                "rps": rps,
                "active_conns": self.active_conns,
                "max_workers": self.max_workers,
                "total_requests": self.total_requests,
                "ram_total": self.total_ram_mb,
                "ram_used": round(ram_used, 2),
                "ram_free": round(ram_free, 2),
                "port": self.port,
                "model": "Local Test Site (Simulated Low-Resource Server)",
                "cpu": "Simulated Single-Core CPU @ 400 MHz",
                "os": "Embedded Linux 3.4.35 (Test OS)",
                "server": "mini_httpd/1.30 (Test Site)",
                "flash": "8 MB SPI NOR Flash",
                "network": "10/100M Fast Ethernet"
            }

    def start(self):
        if self.is_running:
            return True
        manager = self

        class RequestHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "mini_httpd/1.30 (Embedded Linux/AK3918)"
            sys_version = ""

            def log_message(self, format, *args):
                pass

            def send_json(self, data_dict):
                try:
                    data = json.dumps(data_dict).encode('utf-8')
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(data)))
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    self.wfile.write(data)
                    self.wfile.flush()
                except Exception:
                    pass
                self.close_connection = True

            def send_html(self, html_str):
                try:
                    data = html_str.encode('utf-8')
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.send_header('Content-Length', str(len(data)))
                    self.send_header('Server', 'mini_httpd/1.30 (Embedded Linux)')
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    self.wfile.write(data)
                    self.wfile.flush()
                except Exception:
                    pass
                self.close_connection = True

            def do_GET(self):
                # Immediate API handling without concurrency throttle/sleep so RAM and status UI are instant
                if self.path.startswith('/api/set_ram') or self.path.startswith('/set_ram'):
                    match = re.search(r'(?:[?&](?:ram|mb|val|value)=|/set_ram/)(\d+(?:\.\d+)?)', self.path)
                    if match:
                        new_ram = float(match.group(1))
                        manager.set_ram(new_ram)
                    self.send_json(manager.get_stats())
                    return

                if self.path.startswith('/api/status') or self.path.startswith('/status'):
                    self.send_json(manager.get_stats())
                    return

                if self.path == '/favicon.ico':
                    self.send_response(204)
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    self.close_connection = True
                    return

                is_attacked, rps, curr_conns, total_reqs = manager.record_request()
                try:
                    stats = manager.get_stats()
                    # Simulate low-resource embedded hardware slowdown under flood
                    if curr_conns > manager.max_workers:
                        time.sleep(0.25 + (curr_conns - manager.max_workers) * 0.2)
                        if stats['ram_used'] >= stats['ram_total'] * 0.95:
                            try:
                                self.send_response(503)
                                self.send_header('Content-Type', 'text/plain')
                                self.send_header('Connection', 'close')
                                self.end_headers()
                                self.wfile.write(b"503 Service Unavailable: Low Memory / Overload\n")
                                self.wfile.flush()
                            except Exception:
                                pass
                            self.close_connection = True
                            return

                    time.sleep(0.015)

                    if self.path in ('/', '/index.html') or not self.path:
                        html = manager.render_html(stats)
                        self.send_html(html)
                    else:
                        try:
                            self.send_response(404)
                            self.send_header('Content-Type', 'text/plain')
                            self.send_header('Connection', 'close')
                            self.end_headers()
                            self.wfile.write(b"404 Not Found")
                            self.wfile.flush()
                        except Exception:
                            pass
                        self.close_connection = True
                finally:
                    manager.finish_request()

            def do_POST(self):
                if self.path.startswith('/api/set_ram') or self.path.startswith('/set_ram'):
                    match = re.search(r'(?:[?&](?:ram|mb|val|value)=|/set_ram/)(\d+(?:\.\d+)?)', self.path)
                    if match:
                        new_ram = float(match.group(1))
                        manager.set_ram(new_ram)
                    self.send_json(manager.get_stats())
                    return
                self.do_GET()

        class LimitedServer(ThreadingMixIn, HTTPServer):
            daemon_threads = True
            allow_reuse_address = True
            request_queue_size = 128

        try:
            self.server = LimitedServer((self.host, self.port), RequestHandler)
            self.is_running = True
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            return True
        except Exception:
            self.is_running = False
            return False

    def stop(self):
        if self.server and self.is_running:
            self.is_running = False
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
            self.server = None

    def render_html(self, stats):
        is_attacked = stats['is_attacked']
        status_text = "🚨 ATTACKED!" if is_attacked else "🟢 NOT ATTACKED"
        card_class = "attacked" if is_attacked else "normal"
        ram_pct = (stats['ram_used'] / stats['ram_total']) * 100

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Test Website - Attack Monitor & Specs</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{
            background: #090d16;
            color: #f8fafc;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }}
        
        /* Central Attack Status Display */
        .status-wrapper {{
            width: 100%;
            max-width: 740px;
            margin-bottom: 20px;
            text-align: center;
        }}
        .status-card {{
            width: 100%;
            border-radius: 20px;
            padding: 45px 25px;
            text-align: center;
            transition: all 0.25s ease;
        }}
        .status-card.normal {{
            background: linear-gradient(135deg, rgba(6, 78, 59, 0.9), rgba(15, 23, 42, 0.98));
            border: 4px solid #10b981;
            box-shadow: 0 0 45px rgba(16, 185, 129, 0.35);
        }}
        .status-card.attacked {{
            background: linear-gradient(135deg, rgba(185, 28, 28, 0.95), rgba(69, 10, 10, 0.98));
            border: 4px solid #ef4444;
            box-shadow: 0 0 60px rgba(239, 68, 68, 0.7);
            animation: pulse-border 0.7s infinite alternate;
        }}
        @keyframes pulse-border {{
            from {{ border-color: #ef4444; box-shadow: 0 0 30px rgba(239, 68, 68, 0.5); }}
            to {{ border-color: #fecaca; box-shadow: 0 0 75px rgba(239, 68, 68, 0.95); }}
        }}
        .status-title {{
            font-size: 3.8rem;
            font-weight: 900;
            letter-spacing: 1px;
            margin: 0;
            line-height: 1.1;
        }}
        .status-subtitle {{
            font-size: 1.1rem;
            color: #cbd5e1;
            margin-top: 10px;
            font-family: monospace;
        }}

        /* Website Specs Section */
        .specs-card {{
            background: #131d31;
            border: 1px solid #233554;
            border-radius: 14px;
            width: 100%;
            max-width: 740px;
            padding: 22px;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
            margin-bottom: 18px;
        }}
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #233554;
            padding-bottom: 12px;
            margin-bottom: 14px;
        }}
        .card-title {{
            font-size: 1.15rem;
            font-weight: 700;
            color: #38bdf8;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .specs-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px 14px;
        }}
        .spec-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(15, 23, 42, 0.6);
            padding: 9px 12px;
            border-radius: 6px;
            border: 1px solid rgba(255, 255, 255, 0.05);
            font-size: 0.88rem;
        }}
        .spec-label {{
            color: #94a3b8;
            font-weight: 500;
        }}
        .spec-value {{
            font-family: monospace;
            font-weight: 700;
            color: #f1f5f9;
        }}

        /* RAM Progress Bar */
        .progress-bar-bg {{
            background: #0f172a;
            border-radius: 6px;
            height: 12px;
            width: 100%;
            overflow: hidden;
            margin-top: 12px;
            border: 1px solid #334155;
        }}
        .progress-bar-fill {{
            background: linear-gradient(90deg, #10b981, #f59e0b, #ef4444);
            height: 100%;
            border-radius: 4px;
            transition: width 0.25s ease;
        }}

        /* RAM Allocation Controls */
        .ram-section {{
            background: #131d31;
            border: 1px solid #233554;
            border-radius: 14px;
            width: 100%;
            max-width: 740px;
            padding: 18px 22px;
        }}
        .ram-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            font-size: 0.95rem;
            font-weight: 600;
            color: #e2e8f0;
        }}
        .ram-badge {{
            color: #38bdf8;
            font-family: monospace;
            font-size: 1.1rem;
            font-weight: bold;
        }}
        .ram-buttons {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 12px;
        }}
        .ram-btn {{
            background: #1e293b;
            color: #e2e8f0;
            border: 1px solid #334155;
            padding: 8px 14px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.88rem;
            transition: all 0.15s;
        }}
        .ram-btn:hover {{
            background: #0284c7;
            border-color: #38bdf8;
            color: #fff;
        }}
        .ram-btn.active {{
            background: #0284c7;
            border-color: #38bdf8;
            color: #fff;
            box-shadow: 0 0 10px rgba(56, 189, 248, 0.4);
        }}
        .custom-ram-form {{
            display: flex;
            gap: 8px;
            align-items: center;
            margin-top: 8px;
        }}
        .custom-ram-input {{
            background: #0f172a;
            border: 1px solid #334155;
            color: #fff;
            padding: 7px 12px;
            border-radius: 6px;
            width: 110px;
            font-family: monospace;
            font-size: 0.95rem;
        }}
        .custom-ram-btn {{
            background: #059669;
            color: white;
            border: none;
            padding: 7px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.88rem;
        }}
        .custom-ram-btn:hover {{ background: #10b981; }}
    </style>
</head>
<body>

    <!-- Middle: ONLY ATTACKED / NOT ATTACKED -->
    <div class="status-wrapper">
        <div id="status-card" class="status-card {card_class}">
            <h1 id="status-title" class="status-title">{status_text}</h1>
            <p id="status-sub" class="status-subtitle">Traffic: {stats['rps']:.1f} req/s | RAM Used: {stats['ram_used']:.1f} / {stats['ram_total']:.0f} MB ({ram_pct:.1f}%) | Active: {stats['active_conns']}/{stats['max_workers']}</p>
        </div>
    </div>

    <!-- Website Specs -->
    <div class="specs-card">
        <div class="card-header">
            <span class="card-title">📋 Website & Hardware Specs</span>
            <span style="font-size:0.8rem; color:#94a3b8; font-family:monospace;">mini_httpd/1.30</span>
        </div>
        <div class="specs-grid">
            <div class="spec-item"><span class="spec-label">Device Type</span><span class="spec-value">{stats['model']}</span></div>
            <div class="spec-item"><span class="spec-label">Processor</span><span class="spec-value">{stats['cpu']}</span></div>
            <div class="spec-item"><span class="spec-label">RAM Allocated</span><span id="spec-ram-total" class="spec-value" style="color:#38bdf8;">{stats['ram_total']:.0f} MB</span></div>
            <div class="spec-item"><span class="spec-label">RAM Used</span><span id="spec-ram-used" class="spec-value" style="color:#f59e0b;">{stats['ram_used']:.1f} MB ({ram_pct:.1f}%)</span></div>
            <div class="spec-item"><span class="spec-label">RAM Available / Free</span><span id="spec-ram-free" class="spec-value" style="color:#10b981;">{stats['ram_free']:.1f} MB</span></div>
            <div class="spec-item"><span class="spec-label">Max Concurrency</span><span id="spec-workers" class="spec-value">{stats['max_workers']} Workers</span></div>
            <div class="spec-item"><span class="spec-label">Operating System</span><span class="spec-value">{stats['os']}</span></div>
            <div class="spec-item"><span class="spec-label">Web Server</span><span class="spec-value">{stats['server']}</span></div>
            <div class="spec-item"><span class="spec-label">Flash ROM</span><span class="spec-value">{stats['flash']}</span></div>
            <div class="spec-item"><span class="spec-label">Network</span><span class="spec-value">{stats['network']}</span></div>
        </div>
        <div class="progress-bar-bg">
            <div id="ram-progress" class="progress-bar-fill" style="width: {ram_pct:.1f}%;"></div>
        </div>
    </div>

    <!-- RAM Allocation Adjuster -->
    <div class="ram-section">
        <div class="ram-header">
            <span>⚙️ Allocate Website RAM: <strong id="ram-badge" class="ram-badge">{stats['ram_total']:.0f} MB</strong></span>
            <span style="font-size:0.85rem; color:#94a3b8;">Used: <strong id="ram-used-badge" style="color:#f59e0b;">{stats['ram_used']:.1f} MB</strong></span>
        </div>
        <div class="ram-buttons">
            <button class="ram-btn" onclick="setRam(8)">8 MB</button>
            <button class="ram-btn" onclick="setRam(16)">16 MB</button>
            <button class="ram-btn" onclick="setRam(32)">32 MB</button>
            <button class="ram-btn" onclick="setRam(64)">64 MB</button>
            <button class="ram-btn" onclick="setRam(128)">128 MB</button>
            <button class="ram-btn" onclick="setRam(256)">256 MB</button>
            <button class="ram-btn" onclick="setRam(512)">512 MB</button>
            <button class="ram-btn" onclick="setRam(1024)">1024 MB</button>
        </div>
        <div class="custom-ram-form">
            <input type="number" id="custom-ram" class="custom-ram-input" placeholder="Custom MB" min="4" max="4096" value="{stats['ram_total']:.0f}">
            <button class="custom-ram-btn" onclick="applyCustomRam()">Apply RAM</button>
        </div>
    </div>

    <script>
        let currentRam = {stats['ram_total']:.0f};

        async function setRam(mb) {{
            const val = parseFloat(mb);
            if (isNaN(val) || val <= 0) return;
            currentRam = val;
            document.getElementById('ram-badge').innerText = val + ' MB';
            document.getElementById('spec-ram-total').innerText = val + ' MB';
            document.getElementById('custom-ram').value = val;
            
            try {{
                const res = await fetch('/api/set_ram?ram=' + encodeURIComponent(val) + '&_t=' + Date.now());
                if (res.ok) {{
                    const data = await res.json();
                    applyStats(data);
                }}
            }} catch(err) {{
                console.error('setRam error:', err);
            }}
        }}

        function applyCustomRam() {{
            const input = document.getElementById('custom-ram');
            const val = parseFloat(input.value);
            if (!isNaN(val) && val >= 4 && val <= 8192) {{
                setRam(val);
            }} else {{
                alert('Please enter a valid RAM value between 4 and 8192 MB.');
            }}
        }}

        function applyStats(data) {{
            const card = document.getElementById('status-card');
            const title = document.getElementById('status-title');
            const sub = document.getElementById('status-sub');
            const specRamTotal = document.getElementById('spec-ram-total');
            const specRamUsed = document.getElementById('spec-ram-used');
            const specRamFree = document.getElementById('spec-ram-free');
            const specWorkers = document.getElementById('spec-workers');
            const ramBadge = document.getElementById('ram-badge');
            const ramUsedBadge = document.getElementById('ram-used-badge');
            const ramProgress = document.getElementById('ram-progress');

            const pct = ((data.ram_used / data.ram_total) * 100).toFixed(1);

            if (data.is_attacked) {{
                card.className = 'status-card attacked';
                title.innerText = '🚨 ATTACKED!';
                sub.innerText = 'Traffic: ' + data.rps.toFixed(1) + ' req/s (HEAVY FLOOD) | RAM Used: ' + data.ram_used.toFixed(1) + ' / ' + data.ram_total.toFixed(0) + ' MB (' + pct + '%) | Active: ' + data.active_conns + '/' + data.max_workers;
            }} else {{
                card.className = 'status-card normal';
                title.innerText = '🟢 NOT ATTACKED';
                sub.innerText = 'Traffic: ' + data.rps.toFixed(1) + ' req/s (Normal) | RAM Used: ' + data.ram_used.toFixed(1) + ' / ' + data.ram_total.toFixed(0) + ' MB (' + pct + '%) | Active: ' + data.active_conns + '/' + data.max_workers;
            }}

            specRamTotal.innerText = data.ram_total.toFixed(0) + ' MB';
            specRamUsed.innerText = data.ram_used.toFixed(1) + ' MB (' + pct + '%)';
            specRamFree.innerText = data.ram_free.toFixed(1) + ' MB';
            specWorkers.innerText = data.max_workers + ' Workers';
            ramBadge.innerText = data.ram_total.toFixed(0) + ' MB';
            ramUsedBadge.innerText = data.ram_used.toFixed(1) + ' MB';
            if (ramProgress) ramProgress.style.width = Math.min(100, pct) + '%';

            // Highlight active button
            document.querySelectorAll('.ram-btn').forEach(btn => {{
                if (parseFloat(btn.innerText) === data.ram_total) {{
                    btn.classList.add('active');
                }} else {{
                    btn.classList.remove('active');
                }}
            }});
        }}

        async function updateStatus() {{
            try {{
                const res = await fetch('/api/status?_t=' + Date.now());
                if (res.ok) {{
                    const data = await res.json();
                    applyStats(data);
                }}
            }} catch(e) {{}}
        }}

        setInterval(updateStatus, 250);
        updateStatus();
    </script>
</body>
</html>
"""


class StressTestDialog:
    """Dedicated dialog window for stress-testing a specific target IP and port."""

    def __init__(self, parent, target_info):
        self.parent = parent
        self.target_info = target_info
        self.ip = target_info.get('ip', '127.0.0.1')
        self.port = target_info.get('port', 80)
        self.protocol = target_info.get('protocol', 'HTTP')
        self.default_url = target_info.get('url', f"http://{self.ip}:{self.port}")
        self.title_info = target_info.get('title', '')

        self.window = tk.Toplevel(parent)
        self.window.title(f"⚡ Port Stress Tester - {self.ip}:{self.port}")
        self.window.geometry("1080x720")
        self.window.minsize(920, 540)

        # State variables
        self.is_running = False
        self.stop_event = threading.Event()
        self.result_queue = queue.Queue()
        self.results_log = []
        self.worker_threads = []

        # Metrics
        self.start_time = 0.0
        self.total_target_reqs = 100
        self.completed_count = 0
        self.success_count = 0
        self.error_count = 0
        self.latencies = []
        self.status_breakdown = {}

        self._build_ui()
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)
        self.window.after(50, self._process_queue_loop)

    def _build_ui(self):
        container = ttk.Frame(self.window, padding="12 10 12 10")
        container.pack(fill=tk.BOTH, expand=True)

        # 1. Target & Parameters Frame
        config_frame = ttk.LabelFrame(container, text=" Stress Test Parameters ", padding="10 8 10 8")
        config_frame.pack(fill=tk.X, pady=(0, 8))

        # Row 0: Target URL / Endpoint
        row0 = ttk.Frame(config_frame)
        row0.pack(fill=tk.X, pady=2)

        ttk.Label(row0, text="Target URL / Endpoint:", width=22).pack(side=tk.LEFT)
        self.url_entry = ttk.Entry(row0, font=("Consolas", 10))
        self.url_entry.insert(0, self.default_url)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        ttk.Label(row0, text="Method:").pack(side=tk.LEFT, padx=(0, 4))
        self.method_combo = ttk.Combobox(
            row0,
            values=["GET (HTTP)", "HEAD (HTTP)", "POST (HTTP)", "TCP Socket Connect"],
            width=18,
            state="readonly"
        )
        self.method_combo.set("GET (HTTP)")
        self.method_combo.pack(side=tk.LEFT)

        # Row 1: Threads, Total Requests, Mode, Timeout, Delay
        row1 = ttk.Frame(config_frame)
        row1.pack(fill=tk.X, pady=(6, 2))

        ttk.Label(row1, text="Concurrency (Threads):").pack(side=tk.LEFT)
        self.threads_spin = ttk.Spinbox(row1, from_=1, to=200, width=5)
        self.threads_spin.set(10)
        self.threads_spin.pack(side=tk.LEFT, padx=(4, 12))

        ttk.Label(row1, text="Total Requests:").pack(side=tk.LEFT)
        self.requests_spin = ttk.Spinbox(row1, from_=1, to=100000, width=7)
        self.requests_spin.set(100)
        self.requests_spin.pack(side=tk.LEFT, padx=(4, 12))

        self.continuous_var = tk.BooleanVar(value=False)
        self.chk_continuous = ttk.Checkbutton(
            row1,
            text="Continuous Mode (Run until stopped)",
            variable=self.continuous_var,
            command=self._on_toggle_continuous
        )
        self.chk_continuous.pack(side=tk.LEFT, padx=(0, 12))

        ttk.Label(row1, text="Timeout (s):").pack(side=tk.LEFT)
        self.timeout_spin = ttk.Spinbox(row1, from_=0.1, to=10.0, increment=0.5, width=5)
        self.timeout_spin.set(2.0)
        self.timeout_spin.pack(side=tk.LEFT, padx=(4, 12))

        ttk.Label(row1, text="Delay (ms):").pack(side=tk.LEFT)
        self.delay_spin = ttk.Spinbox(row1, from_=0, to=5000, increment=10, width=5)
        self.delay_spin.set(0)
        self.delay_spin.pack(side=tk.LEFT, padx=(4, 0))

        # Row 2: Control buttons
        row2 = ttk.Frame(config_frame)
        row2.pack(fill=tk.X, pady=(8, 2))

        self.target_desc_label = ttk.Label(
            row2,
            text=f"Target: {self.ip}:{self.port} | Protocol: {self.protocol} | {self.title_info[:50]}",
            font=("Segoe UI", 8, "italic")
        )
        self.target_desc_label.pack(side=tk.LEFT)

        self.btn_clear = ttk.Button(row2, text="Clear Log", command=self.clear_results)
        self.btn_clear.pack(side=tk.RIGHT, padx=(4, 0))

        self.btn_export = ttk.Button(row2, text="Export CSV...", command=self.export_csv)
        self.btn_export.pack(side=tk.RIGHT, padx=(4, 0))

        self.btn_stop = ttk.Button(row2, text="⏹ Stop Test", state=tk.DISABLED, command=self.stop_test)
        self.btn_stop.pack(side=tk.RIGHT, padx=(4, 0))

        self.btn_start = ttk.Button(row2, text="▶ Start Stress Test", style="Primary.TButton", command=self.start_test)
        self.btn_start.pack(side=tk.RIGHT)

        # 2. Real-Time Performance Dashboard Frame
        stats_frame = ttk.LabelFrame(container, text=" Real-Time Metrics & Statistics ", padding="10 8 10 8")
        stats_frame.pack(fill=tk.X, pady=(0, 8))

        # KPI Row
        kpi_row = ttk.Frame(stats_frame)
        kpi_row.pack(fill=tk.X, pady=2)

        # KPI Cards
        self.card_completed = self._create_kpi_card(kpi_row, "Requests Completed", "0 / 100", "#1e293b")
        self.card_success = self._create_kpi_card(kpi_row, "Successful (2xx/3xx)", "0 (0.0%)", "#166534")
        self.card_errors = self._create_kpi_card(kpi_row, "Errors / Failed", "0 (0.0%)", "#991b1b")
        self.card_rps = self._create_kpi_card(kpi_row, "Throughput (RPS)", "0.0 req/s", "#0369a1")
        self.card_avg_lat = self._create_kpi_card(kpi_row, "Avg Latency", "0.0 ms", "#4338ca")
        self.card_min_max = self._create_kpi_card(kpi_row, "Min / Max Latency", "0.0 / 0.0 ms", "#374151")

        # Progress bar
        self.progress = ttk.Progressbar(stats_frame, mode='determinate', style="Green.Horizontal.TProgressbar")
        self.progress.pack(fill=tk.X, pady=(6, 4))

        # Status summary label
        self.status_summary_label = ttk.Label(
            stats_frame,
            text="Status: Ready to stress test. Configure parameters and click 'Start Stress Test'.",
            font=("Segoe UI", 9)
        )
        self.status_summary_label.pack(anchor=tk.W)

        # 3. Live Request Log Table Frame
        log_frame = ttk.Frame(container)
        log_frame.pack(fill=tk.BOTH, expand=True)

        log_top_row = ttk.Frame(log_frame)
        log_top_row.pack(fill=tk.X, pady=(0, 4))

        ttk.Label(log_top_row, text="Live Request Log:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)

        self.autoscroll_var = tk.BooleanVar(value=True)
        chk_autoscroll = ttk.Checkbutton(log_top_row, text="Auto-scroll to latest", variable=self.autoscroll_var)
        chk_autoscroll.pack(side=tk.RIGHT)

        table_subframe = ttk.Frame(log_frame)
        table_subframe.pack(fill=tk.BOTH, expand=True)

        cols = ("num", "time", "method", "status", "latency", "details")
        self.tree = ttk.Treeview(table_subframe, columns=cols, show="headings", selectmode="browse")

        self.tree.heading("num", text="#")
        self.tree.heading("time", text="Time")
        self.tree.heading("method", text="Type")
        self.tree.heading("status", text="Status / Code")
        self.tree.heading("latency", text="Latency (ms)")
        self.tree.heading("details", text="Message / Details")

        self.tree.column("num", width=55, minwidth=40, anchor=tk.CENTER)
        self.tree.column("time", width=75, minwidth=65, anchor=tk.CENTER)
        self.tree.column("method", width=65, minwidth=50, anchor=tk.CENTER)
        self.tree.column("status", width=110, minwidth=80, anchor=tk.CENTER)
        self.tree.column("latency", width=95, minwidth=70, anchor=tk.E)
        self.tree.column("details", width=380, minwidth=180)

        # Color tags
        self.tree.tag_configure("success", foreground="#15803d")
        self.tree.tag_configure("warn", foreground="#b45309")
        self.tree.tag_configure("error", foreground="#b91c1c")

        vsb = ttk.Scrollbar(table_subframe, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(table_subframe, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        table_subframe.grid_rowconfigure(0, weight=1)
        table_subframe.grid_columnconfigure(0, weight=1)

    def _create_kpi_card(self, parent, title, initial_val, color):
        card = ttk.Frame(parent, relief=tk.GROOVE, borderwidth=1, padding="6 4 6 4")
        card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=2)

        lbl_title = ttk.Label(card, text=title, font=("Segoe UI", 8), foreground="#64748b")
        lbl_title.pack(anchor=tk.CENTER)

        lbl_val = ttk.Label(card, text=initial_val, font=("Segoe UI", 10, "bold"), foreground=color)
        lbl_val.pack(anchor=tk.CENTER)
        return lbl_val

    def _on_toggle_continuous(self):
        if self.continuous_var.get():
            self.requests_spin.config(state=tk.DISABLED)
        else:
            self.requests_spin.config(state=tk.NORMAL)

    def start_test(self):
        if self.is_running:
            return

        target_url = self.url_entry.get().strip()
        if not target_url:
            messagebox.showerror("Error", "Please provide a valid Target URL or Endpoint.")
            return

        method_type = self.method_combo.get()

        try:
            concurrency = int(self.threads_spin.get())
            concurrency = max(1, min(300, concurrency))
        except ValueError:
            concurrency = 10

        is_continuous = self.continuous_var.get()
        if not is_continuous:
            try:
                total_reqs = int(self.requests_spin.get())
                total_reqs = max(1, min(1000000, total_reqs))
            except ValueError:
                total_reqs = 100
        else:
            total_reqs = 0

        try:
            timeout_val = float(self.timeout_spin.get())
            timeout_val = max(0.05, min(30.0, timeout_val))
        except ValueError:
            timeout_val = 2.0

        try:
            delay_ms = int(self.delay_spin.get())
            delay_ms = max(0, min(60000, delay_ms))
        except ValueError:
            delay_ms = 0

        # Reset counters & state
        self.is_running = True
        self.stop_event.clear()
        self.results_log.clear()
        self.tree.delete(*self.tree.get_children())
        self.latencies.clear()
        self.status_breakdown.clear()
        self.completed_count = 0
        self.success_count = 0
        self.error_count = 0
        self.total_target_reqs = total_reqs
        self.start_time = time.time()

        # Update UI controls
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.btn_export.config(state=tk.DISABLED)
        self.btn_clear.config(state=tk.DISABLED)
        self.url_entry.config(state=tk.DISABLED)
        self.method_combo.config(state=tk.DISABLED)
        self.threads_spin.config(state=tk.DISABLED)
        self.requests_spin.config(state=tk.DISABLED)
        self.chk_continuous.config(state=tk.DISABLED)
        self.timeout_spin.config(state=tk.DISABLED)
        self.delay_spin.config(state=tk.DISABLED)

        if is_continuous:
            self.progress.config(mode='indeterminate')
            self.progress.start(10)
        else:
            self.progress.config(mode='determinate')
            self.progress['maximum'] = total_reqs
            self.progress['value'] = 0

        self.status_summary_label.config(
            text=f"Testing in progress... Target: {target_url} | Threads: {concurrency} | Method: {method_type}"
        )

        threading.Thread(
            target=self._stress_coordinator,
            args=(target_url, self.ip, self.port, method_type, total_reqs, is_continuous, concurrency, timeout_val, delay_ms),
            daemon=True
        ).start()

    def stop_test(self):
        if self.is_running:
            self.stop_event.set()
            self.status_summary_label.config(text="Stopping stress test... Waiting for active workers to complete.")
            self.btn_stop.config(state=tk.DISABLED)

    def _stress_coordinator(self, target_url, ip, port, method_type, total_reqs, is_continuous, concurrency, timeout, delay_ms):
        req_counter = [0]
        counter_lock = threading.Lock()

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        def run_single_probe(req_id):
            t0 = time.perf_counter()
            if "TCP" in method_type:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                try:
                    res = s.connect_ex((ip, port))
                    latency = (time.perf_counter() - t0) * 1000.0
                    if res == 0:
                        return {
                            'id': req_id,
                            'time': time.strftime("%H:%M:%S"),
                            'method': 'TCP',
                            'status': 'Connected',
                            'code': 200,
                            'latency': latency,
                            'success': True,
                            'msg': 'TCP Connection Established'
                        }
                    else:
                        err_str = os.strerror(res) if res else "Refused"
                        return {
                            'id': req_id,
                            'time': time.strftime("%H:%M:%S"),
                            'method': 'TCP',
                            'status': f'Err {res}',
                            'code': res,
                            'latency': latency,
                            'success': False,
                            'msg': f'Connection failed: {err_str}'
                        }
                except Exception as ex:
                    latency = (time.perf_counter() - t0) * 1000.0
                    return {
                        'id': req_id,
                        'time': time.strftime("%H:%M:%S"),
                        'method': 'TCP',
                        'status': 'Error',
                        'code': 0,
                        'latency': latency,
                        'success': False,
                        'msg': str(ex)[:60]
                    }
                finally:
                    s.close()
            else:
                # HTTP Request probe
                http_verb = "GET"
                if "POST" in method_type:
                    http_verb = "POST"
                elif "HEAD" in method_type:
                    http_verb = "HEAD"

                req = urllib.request.Request(
                    target_url,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) LocalWebScanner-Stress/1.0',
                        'Accept': '*/*',
                        'Connection': 'close'
                    },
                    method=http_verb
                )
                try:
                    with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx if target_url.lower().startswith('https') else None) as resp:
                        _ = resp.read(2048)
                        latency = (time.perf_counter() - t0) * 1000.0
                        code = resp.getcode()
                        return {
                            'id': req_id,
                            'time': time.strftime("%H:%M:%S"),
                            'method': http_verb,
                            'status': f"{code} OK",
                            'code': code,
                            'latency': latency,
                            'success': (200 <= code < 400),
                            'msg': 'Success'
                        }
                except urllib.error.HTTPError as e:
                    latency = (time.perf_counter() - t0) * 1000.0
                    return {
                        'id': req_id,
                        'time': time.strftime("%H:%M:%S"),
                        'method': http_verb,
                        'status': f"HTTP {e.code}",
                        'code': e.code,
                        'latency': latency,
                        'success': (200 <= e.code < 400),
                        'msg': str(e.reason)[:60]
                    }
                except urllib.error.URLError as e:
                    latency = (time.perf_counter() - t0) * 1000.0
                    return {
                        'id': req_id,
                        'time': time.strftime("%H:%M:%S"),
                        'method': http_verb,
                        'status': 'URL Error',
                        'code': 0,
                        'latency': latency,
                        'success': False,
                        'msg': str(e.reason)[:60]
                    }
                except Exception as ex:
                    latency = (time.perf_counter() - t0) * 1000.0
                    return {
                        'id': req_id,
                        'time': time.strftime("%H:%M:%S"),
                        'method': http_verb,
                        'status': 'Error',
                        'code': 0,
                        'latency': latency,
                        'success': False,
                        'msg': str(ex)[:60]
                    }

        def worker_loop():
            while not self.stop_event.is_set():
                with counter_lock:
                    if not is_continuous and req_counter[0] >= total_reqs:
                        break
                    req_counter[0] += 1
                    curr_id = req_counter[0]

                res = run_single_probe(curr_id)
                self.result_queue.put(res)

                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)

        threads = []
        for _ in range(concurrency):
            t = threading.Thread(target=worker_loop, daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.result_queue.put("__FINISHED__")

    def _process_queue_loop(self):
        batch = []
        finished = False

        try:
            while len(batch) < 100:
                item = self.result_queue.get_nowait()
                if item == "__FINISHED__":
                    finished = True
                    break
                batch.append(item)
        except queue.Empty:
            pass

        if batch:
            for item in batch:
                self._record_item(item)
            self._update_kpi_display()

        if finished:
            self._test_finished()

        if self.window.winfo_exists():
            self.window.after(50, self._process_queue_loop)

    def _record_item(self, item):
        self.results_log.append(item)
        self.completed_count += 1
        lat = item['latency']
        self.latencies.append(lat)

        if item['success']:
            self.success_count += 1
            tag = "success"
        elif 400 <= item.get('code', 0) < 500:
            self.error_count += 1
            tag = "warn"
        else:
            self.error_count += 1
            tag = "error"

        st = item['status']
        self.status_breakdown[st] = self.status_breakdown.get(st, 0) + 1

        # Keep treeview performant: only keep last 2500 entries in treeview
        if len(self.tree.get_children()) > 2500:
            first_child = self.tree.get_children()[0]
            self.tree.delete(first_child)

        self.tree.insert("", tk.END, values=(
            item['id'],
            item['time'],
            item['method'],
            item['status'],
            f"{lat:.1f} ms",
            item['msg']
        ), tags=(tag,))

    def _update_kpi_display(self):
        elapsed = time.time() - self.start_time
        rps = self.completed_count / elapsed if elapsed > 0 else 0.0

        is_continuous = self.continuous_var.get()
        target_str = "∞" if is_continuous else str(self.total_target_reqs)
        self.card_completed.config(text=f"{self.completed_count} / {target_str}")

        succ_pct = (self.success_count / self.completed_count * 100.0) if self.completed_count > 0 else 0.0
        err_pct = (self.error_count / self.completed_count * 100.0) if self.completed_count > 0 else 0.0

        self.card_success.config(text=f"{self.success_count} ({succ_pct:.1f}%)")
        self.card_errors.config(text=f"{self.error_count} ({err_pct:.1f}%)")
        self.card_rps.config(text=f"{rps:.1f} req/s")

        if self.latencies:
            avg_lat = sum(self.latencies) / len(self.latencies)
            min_lat = min(self.latencies)
            max_lat = max(self.latencies)
            self.card_avg_lat.config(text=f"{avg_lat:.1f} ms")
            self.card_min_max.config(text=f"{min_lat:.1f} / {max_lat:.1f} ms")

        if not is_continuous:
            self.progress['value'] = min(self.completed_count, self.total_target_reqs)

        if self.autoscroll_var.get():
            self.tree.yview_moveto(1.0)

    def _test_finished(self):
        self.is_running = False
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.btn_export.config(state=tk.NORMAL)
        self.btn_clear.config(state=tk.NORMAL)
        self.url_entry.config(state=tk.NORMAL)
        self.method_combo.config(state=tk.NORMAL)
        self.threads_spin.config(state=tk.NORMAL)
        if not self.continuous_var.get():
            self.requests_spin.config(state=tk.NORMAL)
        self.chk_continuous.config(state=tk.NORMAL)
        self.timeout_spin.config(state=tk.NORMAL)
        self.delay_spin.config(state=tk.NORMAL)

        if self.continuous_var.get():
            self.progress.stop()
            self.progress.config(mode='determinate')
            self.progress['value'] = 100

        elapsed = time.time() - self.start_time
        rps = self.completed_count / elapsed if elapsed > 0 else 0.0
        breakdown_str = " | ".join(f"{k}: {v}" for k, v in sorted(self.status_breakdown.items()))

        if self.stop_event.is_set():
            self.status_summary_label.config(
                text=f"Test stopped by user after {elapsed:.1f}s. Sent {self.completed_count} reqs ({rps:.1f} RPS). Breakdown: {breakdown_str}"
            )
        else:
            self.status_summary_label.config(
                text=f"Stress test finished in {elapsed:.1f}s! ({rps:.1f} RPS). Breakdown: {breakdown_str}"
            )

    def clear_results(self):
        if self.is_running:
            return
        self.results_log.clear()
        self.latencies.clear()
        self.status_breakdown.clear()
        self.completed_count = 0
        self.success_count = 0
        self.error_count = 0
        self.tree.delete(*self.tree.get_children())
        self.progress['value'] = 0
        self.card_completed.config(text="0 / 100")
        self.card_success.config(text="0 (0.0%)")
        self.card_errors.config(text="0 (0.0%)")
        self.card_rps.config(text="0.0 req/s")
        self.card_avg_lat.config(text="0.0 ms")
        self.card_min_max.config(text="0.0 / 0.0 ms")
        self.status_summary_label.config(text="Results cleared. Ready for next test.")

    def export_csv(self):
        if not self.results_log:
            messagebox.showinfo("Export", "No test results to export.")
            return

        file_path = filedialog.asksaveasfilename(
            parent=self.window,
            defaultextension=".csv",
            filetypes=[("CSV Files (*.csv)", "*.csv"), ("All Files (*.*)", "*.*")],
            initialfile=f"stress_test_{self.ip}_{self.port}.csv",
            title="Export Stress Test Results to CSV"
        )
        if not file_path:
            return

        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=["id", "time", "method", "status", "code", "latency", "success", "msg"])
                writer.writeheader()
                for r in self.results_log:
                    writer.writerow(r)
            messagebox.showinfo("Export Success", f"Successfully exported {len(self.results_log)} records!", parent=self.window)
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export CSV:\n{e}", parent=self.window)

    def _on_close(self):
        if self.is_running:
            if messagebox.askyesno("Confirm Exit", "Stress test is currently running. Stop test and close window?", parent=self.window):
                self.stop_event.set()
                self.window.destroy()
        else:
            self.window.destroy()


class LocalWebScannerApp:
    def __init__(self, root):
        self.root = root

        if not check_or_show_disclaimer(self.root):
            return

        self.root.title("Local IP Website Scanner")
        self.root.geometry("1120x680")
        self.root.minsize(940, 560)

        # Scanner state variables
        self.is_scanning = False
        self.stop_requested = False
        self.mock_server = None
        self.results = []
        self.total_targets = 0
        self.completed_targets = 0
        self.start_time = 0

        self._setup_styles()
        self._build_ui()
        self._auto_detect_subnet()

    def _setup_styles(self):
        self.style = ttk.Style()
        try:
            self.style.theme_use('clam')
        except Exception:
            pass

        self.style.configure(".", font=("Segoe UI", 9))
        self.style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"), padding=5)
        self.style.configure("Treeview", rowheight=26, font=("Segoe UI", 9))
        self.style.configure("Primary.TButton", font=("Segoe UI", 9, "bold"))
        self.style.configure("Status.TLabel", font=("Segoe UI", 9))
        self.style.configure("Header.TLabel", font=("Segoe UI", 10, "bold"))

        # Green progress bar style
        self.style.configure(
            "Green.Horizontal.TProgressbar",
            troughcolor="#e9ecef",
            background="#28a745",
            lightcolor="#28a745",
            darkcolor="#218838",
            bordercolor="#dee2e6",
            thickness=14
        )

    def _build_ui(self):
        main_frame = ttk.Frame(self.root, padding="10 10 10 10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 1. Config Section
        config_group = ttk.LabelFrame(main_frame, text=" Scan Configuration ", padding="10 8 10 8")
        config_group.pack(fill=tk.X, pady=(0, 10))

        # Row 0: Subnet / IP Range
        row0 = ttk.Frame(config_group)
        row0.pack(fill=tk.X, pady=2)

        ttk.Label(row0, text="IP Range / Subnet:", width=18).pack(side=tk.LEFT)
        self.ip_entry = ttk.Entry(row0, font=("Consolas", 10))
        self.ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        
        btn_autodetect = ttk.Button(row0, text="Auto-Detect Subnet", command=self._auto_detect_subnet)
        btn_autodetect.pack(side=tk.LEFT)

        # Row 1: Ports
        row1 = ttk.Frame(config_group)
        row1.pack(fill=tk.X, pady=4)

        ttk.Label(row1, text="Ports to Scan:", width=18).pack(side=tk.LEFT)
        self.port_entry = ttk.Entry(row1, font=("Consolas", 10))
        self.port_entry.insert(0, DEFAULT_PORTS)
        self.port_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        btn_all_web = ttk.Button(row1, text="🌐 ALL Web Ports (1-65535)", command=lambda: self._set_ports("1-65535"))
        btn_all_web.pack(side=tk.LEFT)

        # Row 2: Concurrency, Timeout, and Action Buttons
        row2 = ttk.Frame(config_group)
        row2.pack(fill=tk.X, pady=(4, 0))

        ttk.Label(row2, text="Threads:").pack(side=tk.LEFT)
        self.threads_spin = ttk.Spinbox(row2, from_=10, to=1000, increment=50, width=6)
        self.threads_spin.set(200)
        self.threads_spin.pack(side=tk.LEFT, padx=(4, 15))

        ttk.Label(row2, text="Timeout (s):").pack(side=tk.LEFT)
        self.timeout_spin = ttk.Spinbox(row2, from_=0.1, to=5.0, increment=0.1, width=5)
        self.timeout_spin.set(0.5)
        self.timeout_spin.pack(side=tk.LEFT, padx=(4, 15))

        ttk.Label(row2, text="Host RAM:").pack(side=tk.LEFT)
        self.host_ram_var = tk.StringVar(value="32")
        self.host_ram_spin = ttk.Spinbox(row2, from_=4, to=4096, increment=16, textvariable=self.host_ram_var, width=6, command=self._on_host_ram_spin_change)
        self.host_ram_spin.pack(side=tk.LEFT, padx=(4, 2))
        self.host_ram_spin.bind("<KeyRelease>", self._on_host_ram_spin_change)
        self.host_ram_var.trace_add("write", lambda *a: self._on_host_ram_spin_change())
        ttk.Label(row2, text="MB").pack(side=tk.LEFT, padx=(0, 10))

        # Scan and Stop buttons
        self.btn_scan = ttk.Button(row2, text="▶ Start Scan", style="Primary.TButton", command=self.start_scan)
        self.btn_scan.pack(side=tk.RIGHT, padx=(4, 0))

        self.btn_stop = ttk.Button(row2, text="⏹ Stop", state=tk.DISABLED, command=self.stop_scan)
        self.btn_stop.pack(side=tk.RIGHT, padx=(4, 0))

        self.btn_top_stress = ttk.Button(row2, text="⚡ Stress Test Port", command=self.open_stress_test)
        self.btn_top_stress.pack(side=tk.RIGHT, padx=(4, 6))

        self.btn_top_host = ttk.Button(row2, text="🌐 Host Test Site (8080)", command=self.toggle_test_server)
        self.btn_top_host.pack(side=tk.RIGHT, padx=(4, 6))

        # 2. Progress and Filter Bar
        status_bar_frame = ttk.Frame(main_frame)
        status_bar_frame.pack(fill=tk.X, pady=(0, 6))

        self.progress = ttk.Progressbar(status_bar_frame, mode='determinate', style="Green.Horizontal.TProgressbar")
        self.progress.pack(fill=tk.X, pady=(0, 4))

        stat_filter_row = ttk.Frame(status_bar_frame)
        stat_filter_row.pack(fill=tk.X)

        self.status_label = ttk.Label(stat_filter_row, text="Ready. Enter IP range and click 'Start Scan'.", style="Status.TLabel")
        self.status_label.pack(side=tk.LEFT)

        self.search_entry = ttk.Entry(stat_filter_row, width=22)
        self.search_entry.pack(side=tk.RIGHT)
        self.search_entry.bind("<KeyRelease>", self._on_search_filter)
        ttk.Label(stat_filter_row, text="Filter Results:").pack(side=tk.RIGHT, padx=(10, 4))

        # 3. Results Table
        table_frame = ttk.Frame(main_frame)
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("protocol", "ip", "port", "status", "title", "url")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("protocol", text="Proto", command=lambda: self._sort_by("protocol"))
        self.tree.heading("ip", text="IP Address", command=lambda: self._sort_by("ip"))
        self.tree.heading("port", text="Port", command=lambda: self._sort_by("port"))
        self.tree.heading("status", text="Status", command=lambda: self._sort_by("status"))
        self.tree.heading("title", text="Web Page Title / Server Info", command=lambda: self._sort_by("title"))
        self.tree.heading("url", text="Website URL (Click to Open)", command=lambda: self._sort_by("url"))

        self.tree.column("protocol", width=65, minwidth=50, anchor=tk.CENTER)
        self.tree.column("ip", width=120, minwidth=100)
        self.tree.column("port", width=65, minwidth=50, anchor=tk.CENTER)
        self.tree.column("status", width=95, minwidth=70)
        self.tree.column("title", width=280, minwidth=150)
        self.tree.column("url", width=290, minwidth=180)

        # Highlight green tag for the test website
        self.tree.tag_configure("test_server_highlight", background="#d1fae5", foreground="#047857")

        vsb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        # Bind events
        self.tree.bind("<Double-1>", self._on_row_double_click)
        self.tree.bind("<ButtonRelease-1>", self._on_tree_click)
        self.tree.bind("<Return>", self._on_row_double_click)
        self.tree.bind("<Button-3>", self._show_context_menu)

        # Context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="🌐 Open in Browser", command=self.open_selected_in_browser, font=("Segoe UI", 9, "bold"))
        self.context_menu.add_command(label="⚡ Stress Test Port", command=self.open_stress_test)
        self.context_menu.add_command(label="🌐 Host / Toggle Test Site (8080)", command=self.toggle_test_server)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="📋 Copy URL", command=self._copy_selected_url)
        self.context_menu.add_command(label="📋 Copy IP Address", command=self._copy_selected_ip)
        self.context_menu.add_command(label="📋 Copy Full Line", command=self._copy_selected_details)

        # 4. Bottom Action Bar
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(fill=tk.X, pady=(8, 0))

        self.btn_open_browser = ttk.Button(
            bottom_frame,
            text="🌐 Open Selected in Browser",
            style="Primary.TButton",
            command=self.open_selected_in_browser
        )
        self.btn_open_browser.pack(side=tk.LEFT)

        self.btn_stress_test = ttk.Button(
            bottom_frame,
            text="⚡ Stress Test Port",
            command=self.open_stress_test
        )
        self.btn_stress_test.pack(side=tk.LEFT, padx=(6, 0))

        self.btn_bottom_host = ttk.Button(
            bottom_frame,
            text="🌐 Host Test Site (8080)",
            command=self.toggle_test_server
        )
        self.btn_bottom_host.pack(side=tk.LEFT, padx=(6, 0))

        ttk.Label(bottom_frame, text=" Tip: Host test site, or select row & click Stress Test.", font=("Segoe UI", 8, "italic")).pack(side=tk.LEFT, padx=10)

        self.btn_clear = ttk.Button(bottom_frame, text="Clear Results", command=self.clear_results)
        self.btn_clear.pack(side=tk.RIGHT, padx=(4, 0))

        self.btn_export = ttk.Button(bottom_frame, text="Export CSV...", command=self.export_csv)
        self.btn_export.pack(side=tk.RIGHT)

        self.found_label = ttk.Label(bottom_frame, text="Websites Found: 0", font=("Segoe UI", 9, "bold"))
        self.found_label.pack(side=tk.RIGHT, padx=15)

    def _auto_detect_subnet(self):
        subnet = get_default_subnet()
        self.ip_entry.delete(0, tk.END)
        self.ip_entry.insert(0, subnet)
        local_ip = get_local_ip()
        self.status_label.config(text=f"Detected local IP: {local_ip} | Suggested subnet: {subnet}")

    def _set_ports(self, port_str):
        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, port_str)

    def _on_search_filter(self, event=None):
        query = self.search_entry.get().strip().lower()
        self._refresh_tree(query)

    def _is_test_server(self, item):
        port = str(item.get('port', ''))
        ip = str(item.get('ip', ''))
        title = str(item.get('title', ''))
        return port == '8080' and (ip in ('127.0.0.1', 'localhost', get_local_ip()) or 'Attack Monitor' in title or 'Test Site' in title or 'Test' in title)

    def _refresh_tree(self, filter_query=""):
        self.tree.delete(*self.tree.get_children())
        query = filter_query.lower()

        for item in self.results:
            if not query or any(query in str(v).lower() for v in item.values()):
                tag = ("test_server_highlight",) if self._is_test_server(item) else ()
                self.tree.insert("", tk.END, values=(
                    item['protocol'],
                    item['ip'],
                    item['port'],
                    item['status'],
                    item['title'],
                    item['url']
                ), tags=tag)

    def _sort_by(self, col):
        try:
            if col == 'port':
                self.results.sort(key=lambda x: int(x['port']))
            elif col == 'ip':
                self.results.sort(key=lambda x: [int(p) for p in x['ip'].split('.') if p.isdigit()])
            else:
                self.results.sort(key=lambda x: str(x.get(col, '')).lower())
        except Exception:
            self.results.sort(key=lambda x: str(x.get(col, '')).lower())
        self._refresh_tree(self.search_entry.get())

    def _on_tree_click(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            values = self.tree.item(item, "values")
            if values and len(values) >= 6:
                self.status_label.config(text=f"Selected: {values[5]} (Double-click to open)")

    def _on_row_double_click(self, event=None):
        self.open_selected_in_browser()

    def _show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def open_selected_in_browser(self):
        selected_items = self.tree.selection()
        if not selected_items:
            children = self.tree.get_children()
            if children:
                selected_items = [children[0]]
            else:
                messagebox.showinfo("Information", "No website selected or found yet.")
                return

        item = selected_items[0]
        values = self.tree.item(item, "values")
        if values and len(values) >= 6:
            url = values[5]
            try:
                webbrowser.open(url, new=2)
                self.status_label.config(text=f"Opened in browser: {url}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open browser: {e}")

    def open_stress_test(self):
        selected_items = self.tree.selection()
        if selected_items:
            item = selected_items[0]
            values = self.tree.item(item, "values")
            if values and len(values) >= 6:
                try:
                    port_num = int(values[2])
                except Exception:
                    port_num = 80

                target_info = {
                    'protocol': values[0],
                    'ip': values[1],
                    'port': port_num,
                    'status': values[3],
                    'title': values[4],
                    'url': values[5]
                }
                StressTestDialog(self.root, target_info)
                return

        children = self.tree.get_children()
        if children:
            item = children[0]
            self.tree.selection_set(item)
            values = self.tree.item(item, "values")
            if values and len(values) >= 6:
                try:
                    port_num = int(values[2])
                except Exception:
                    port_num = 80

                target_info = {
                    'protocol': values[0],
                    'ip': values[1],
                    'port': port_num,
                    'status': values[3],
                    'title': values[4],
                    'url': values[5]
                }
                StressTestDialog(self.root, target_info)
                return

        # Fallback to entered IP & Port if no scan results exist yet
        ip_raw = self.ip_entry.get().strip()
        port_raw = self.port_entry.get().strip()

        parsed_ips = parse_ip_targets(ip_raw)
        parsed_ports = parse_ports(port_raw)

        target_ip = parsed_ips[0] if parsed_ips else (ip_raw.split('/')[0] if ip_raw else get_local_ip())
        target_port = parsed_ports[0] if parsed_ports else 80

        proto = "HTTPS" if target_port in HTTPS_PORTS else "HTTP"
        target_url = f"{proto.lower()}://{target_ip}" if (proto == "HTTP" and target_port == 80) or (proto == "HTTPS" and target_port == 443) else f"{proto.lower()}://{target_ip}:{target_port}"

        target_info = {
            'protocol': proto,
            'ip': target_ip,
            'port': target_port,
            'status': 'Manual Target',
            'title': f'{target_ip}:{target_port}',
            'url': target_url
        }
        StressTestDialog(self.root, target_info)

    def _on_host_ram_spin_change(self, event=None):
        try:
            val_str = self.host_ram_var.get().strip() if hasattr(self, 'host_ram_var') else self.host_ram_spin.get().strip()
            if not val_str:
                return
            val = float(val_str)
            if self.mock_server and self.mock_server.is_running:
                self.mock_server.set_ram(val)
                self.status_label.config(text=f"Updated test site simulated RAM to {val:.0f} MB")
        except Exception:
            pass

    def toggle_test_server(self):
        if self.mock_server and self.mock_server.is_running:
            self.mock_server.stop()
            self.mock_server = None
            self.btn_top_host.config(text="🌐 Host Test Site (8080)")
            self.btn_bottom_host.config(text="🌐 Host Test Site (8080)")
            self.status_label.config(text="Test Site server stopped.")
        else:
            try:
                val_str = self.host_ram_var.get().strip() if hasattr(self, 'host_ram_var') else self.host_ram_spin.get().strip()
                ram_val = float(val_str)
            except Exception:
                ram_val = 32.0

            server = EmbeddedCameraServer(port=8080, initial_ram_mb=ram_val)
            if server.start():
                self.mock_server = server
                self.btn_top_host.config(text="🛑 Stop Test Site (8080)")
                self.btn_bottom_host.config(text="🛑 Stop Test Site (8080)")

                self.ip_entry.delete(0, tk.END)
                self.ip_entry.insert(0, "127.0.0.1")
                self.port_entry.delete(0, tk.END)
                self.port_entry.insert(0, "8080")

                exists = any(r.get('port') == 8080 and r.get('ip') == '127.0.0.1' for r in self.results)
                if not exists:
                    res_item = {
                        'protocol': 'HTTP',
                        'ip': '127.0.0.1',
                        'port': 8080,
                        'status': '200 OK',
                        'title': 'Test Site - Attack Monitor',
                        'url': 'http://127.0.0.1:8080/',
                        'server': 'mini_httpd/1.30 (Embedded Linux/AK3918)'
                    }
                    self.results.append(res_item)
                    self.tree.insert("", 0, values=(
                        res_item['protocol'],
                        res_item['ip'],
                        res_item['port'],
                        res_item['status'],
                        res_item['title'],
                        res_item['url']
                    ), tags=("test_server_highlight",))
                    self.found_label.config(text=f"Websites Found: {len(self.results)}")
                    first_child = self.tree.get_children()[0]
                    self.tree.selection_set(first_child)

                url = "http://127.0.0.1:8080/"
                try:
                    webbrowser.open(url, new=2)
                except Exception:
                    pass
                self.status_label.config(text=f"Test Site running at {url} (Simulated {ram_val:.0f}MB RAM, Live Attack Detector)")
            else:
                messagebox.showerror("Error", "Could not start test server on port 8080 (port may already be in use).")

    def _copy_selected_url(self):
        selected = self.tree.selection()
        if selected:
            url = self.tree.item(selected[0], "values")[5]
            self.root.clipboard_clear()
            self.root.clipboard_append(url)
            self.status_label.config(text=f"Copied to clipboard: {url}")

    def _copy_selected_ip(self):
        selected = self.tree.selection()
        if selected:
            ip = self.tree.item(selected[0], "values")[1]
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)
            self.status_label.config(text=f"Copied IP to clipboard: {ip}")

    def _copy_selected_details(self):
        selected = self.tree.selection()
        if selected:
            vals = self.tree.item(selected[0], "values")
            text = " | ".join(vals)
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status_label.config(text="Copied details to clipboard.")

    def clear_results(self):
        if self.is_scanning:
            messagebox.showwarning("Warning", "Cannot clear while scan is in progress.")
            return
        self.results.clear()
        self.tree.delete(*self.tree.get_children())
        self.found_label.config(text="Websites Found: 0")
        self.progress['value'] = 0
        self.status_label.config(text="Results cleared.")

    def export_csv(self):
        if not self.results:
            messagebox.showinfo("Export", "No results to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files (*.csv)", "*.csv"), ("All Files (*.*)", "*.*")],
            title="Export Results to CSV"
        )
        if not file_path:
            return

        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=["protocol", "ip", "port", "status", "title", "url", "server"])
                writer.writeheader()
                for r in self.results:
                    writer.writerow(r)
            messagebox.showinfo("Success", f"Exported {len(self.results)} results successfully!")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to save CSV file:\n{e}")

    def start_scan(self):
        if self.is_scanning:
            return

        ip_raw = self.ip_entry.get().strip()
        port_raw = self.port_entry.get().strip()

        ips = parse_ip_targets(ip_raw)
        if not ips:
            messagebox.showerror("Input Error", "Please enter a valid IP range or subnet.\nExample: 192.168.1.0/24 or 192.168.1.1-192.168.1.100")
            return

        ports = parse_ports(port_raw)
        if not ports:
            messagebox.showerror("Input Error", "Please enter valid port numbers.\nExample: 1-65535 or 80, 443, 8080")
            return

        try:
            num_threads = int(self.threads_spin.get())
            num_threads = max(1, min(1000, num_threads))
        except ValueError:
            num_threads = 200

        try:
            timeout_val = float(self.timeout_spin.get())
            timeout_val = max(0.05, min(5.0, timeout_val))
        except ValueError:
            timeout_val = 0.5

        all_targets = [(ip, port) for ip in ips for port in ports]
        self.total_targets = len(all_targets)
        self.completed_targets = 0
        self.start_time = time.time()

        self.is_scanning = True
        self.stop_requested = False
        self.btn_scan.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.progress['maximum'] = self.total_targets
        self.progress['value'] = 0

        self.status_label.config(text=f"Scanning {self.total_targets} targets across {len(ips)} IPs and {len(ports)} ports ({num_threads} threads)...")

        # Start periodic GUI progress tick
        self.root.after(100, self._tick_progress)

        threading.Thread(
            target=self._scan_worker,
            args=(all_targets, num_threads, timeout_val),
            daemon=True
        ).start()

    def stop_scan(self):
        if self.is_scanning:
            self.stop_requested = True
            self.status_label.config(text="Stopping scan... Please wait.")
            self.btn_stop.config(state=tk.DISABLED)

    def _tick_progress(self):
        if not self.is_scanning:
            return

        completed = self.completed_targets
        self.progress['value'] = completed
        elapsed = time.time() - self.start_time
        rate = completed / elapsed if elapsed > 0 else 0
        pct = int((completed / self.total_targets) * 100) if self.total_targets > 0 else 0

        self.status_label.config(
            text=f"Progress: {completed}/{self.total_targets} ({pct}%) | {rate:.1f} checks/sec | Elapsed: {int(elapsed)}s"
        )

        if self.is_scanning:
            self.root.after(100, self._tick_progress)

    def _scan_worker(self, targets, max_workers, timeout):
        work_queue = queue.Queue(maxsize=10000)
        lock = threading.Lock()

        def worker():
            while not self.stop_requested:
                try:
                    item = work_queue.get(timeout=0.2)
                except queue.Empty:
                    if producer_finished[0]:
                        break
                    continue

                if item is None:
                    work_queue.task_done()
                    break

                ip, port = item
                try:
                    res = probe_web_service(ip, port, timeout=timeout)
                    if res and not self.stop_requested:
                        self.root.after(0, self._add_result, res)
                except Exception:
                    pass
                finally:
                    with lock:
                        self.completed_targets += 1
                    work_queue.task_done()

        producer_finished = [False]
        threads = []
        actual_workers = min(max_workers, len(targets)) if len(targets) > 0 else 1
        for _ in range(actual_workers):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        for target in targets:
            if self.stop_requested:
                break
            work_queue.put(target)

        producer_finished[0] = True
        work_queue.join()

        for _ in threads:
            try:
                work_queue.put(None, block=False)
            except Exception:
                pass

        for t in threads:
            t.join(timeout=0.5)

        self.root.after(0, self._scan_finished)

    def _add_result(self, res):
        self.results.append(res)
        query = self.search_entry.get().strip().lower()
        if not query or any(query in str(v).lower() for v in res.values()):
            tag = ("test_server_highlight",) if self._is_test_server(res) else ()
            self.tree.insert("", tk.END, values=(
                res['protocol'],
                res['ip'],
                res['port'],
                res['status'],
                res['title'],
                res['url']
            ), tags=tag)
        self.found_label.config(text=f"Websites Found: {len(self.results)}")

    def _update_progress(self, completed):
        self.progress['value'] = completed
        elapsed = time.time() - self.start_time
        rate = completed / elapsed if elapsed > 0 else 0
        pct = int((completed / self.total_targets) * 100) if self.total_targets > 0 else 0
        self.status_label.config(
            text=f"Progress: {completed}/{self.total_targets} ({pct}%) | {rate:.1f} checks/sec | Elapsed: {int(elapsed)}s"
        )

    def _scan_finished(self):
        self.is_scanning = False
        self.btn_scan.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        elapsed = time.time() - self.start_time

        if self.stop_requested:
            self.status_label.config(text=f"Scan stopped by user after {int(elapsed)}s. Found {len(self.results)} web servers.")
        else:
            self.progress['value'] = self.total_targets
            self.status_label.config(text=f"Scan complete in {elapsed:.1f}s! Found {len(self.results)} active web servers.")


def main():
    root = tk.Tk()
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    app = LocalWebScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
