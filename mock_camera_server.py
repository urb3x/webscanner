"""
Low-Resource Embedded IP Camera Mock Server
Simulates the web interface and memory/CPU resource constraints of a cheap IoT/IP camera.
- Configurable Simulated RAM: 4 MB - 8192 MB
- Centered Attack Monitor: Displays ATTACKED / NOT ATTACKED directly in the middle.
- Full Specs Display: Processor, RAM, OS, Web Server, Flash ROM, Network.
- Instant RAM Allocation: Live dynamic adjustment via web buttons, custom input, or API.
"""

import sys
import os
import time
import socket
import threading
import collections
import json
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

PORT = 8080
HOST = '0.0.0.0'

SIMULATED_TOTAL_RAM_MB = 32.0
BASE_RAM_USAGE_MB = 24.2
MAX_CONCURRENT_CONNECTIONS = 3

request_timestamps = collections.deque()
active_connections = 0
connections_lock = threading.Lock()
total_requests_handled = 0


def set_simulated_ram(ram_mb):
    global SIMULATED_TOTAL_RAM_MB, BASE_RAM_USAGE_MB, MAX_CONCURRENT_CONNECTIONS
    with connections_lock:
        try:
            SIMULATED_TOTAL_RAM_MB = max(4.0, min(8192.0, float(ram_mb)))
            BASE_RAM_USAGE_MB = max(2.0, SIMULATED_TOTAL_RAM_MB * 0.72)
            if SIMULATED_TOTAL_RAM_MB <= 16:
                MAX_CONCURRENT_CONNECTIONS = 2
            elif SIMULATED_TOTAL_RAM_MB <= 32:
                MAX_CONCURRENT_CONNECTIONS = 3
            elif SIMULATED_TOTAL_RAM_MB <= 64:
                MAX_CONCURRENT_CONNECTIONS = 5
            elif SIMULATED_TOTAL_RAM_MB <= 128:
                MAX_CONCURRENT_CONNECTIONS = 8
            elif SIMULATED_TOTAL_RAM_MB <= 256:
                MAX_CONCURRENT_CONNECTIONS = 12
            else:
                MAX_CONCURRENT_CONNECTIONS = 20
        except Exception:
            pass


def get_stats():
    now = time.time()
    with connections_lock:
        while request_timestamps and request_timestamps[0] < now - 2.0:
            request_timestamps.popleft()
        rps = len(request_timestamps) / 2.0
        is_attacked = (rps >= 4.0 or active_connections >= MAX_CONCURRENT_CONNECTIONS)
        ram_used = min(SIMULATED_TOTAL_RAM_MB, BASE_RAM_USAGE_MB + (active_connections * 2.2) + (min(10.0, rps) * 0.4))
        ram_free = max(0.0, SIMULATED_TOTAL_RAM_MB - ram_used)
        return {
            "is_attacked": is_attacked,
            "rps": rps,
            "active_conns": active_connections,
            "max_workers": MAX_CONCURRENT_CONNECTIONS,
            "total_requests": total_requests_handled,
            "ram_total": SIMULATED_TOTAL_RAM_MB,
            "ram_used": round(ram_used, 2),
            "ram_free": round(ram_free, 2),
            "port": PORT,
            "model": "Local Test Site (Simulated Low-Resource Server)",
            "cpu": "ARM926EJ-S @ 400 MHz (1 Core)",
            "os": "Embedded Linux 3.4.35",
            "server": "mini_httpd/1.30",
            "flash": "8 MB SPI NOR Flash",
            "network": "10/100M Fast Ethernet"
        }


class LimitedThreadingServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


class CameraHTTPRequestHandler(BaseHTTPRequestHandler):
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
        global active_connections, total_requests_handled, request_timestamps

        # Fast path for API: Bypass throttling/sleep delays so controls remain instant
        if self.path.startswith('/api/set_ram') or self.path.startswith('/set_ram'):
            match = re.search(r'(?:[?&](?:ram|mb|val|value)=|/set_ram/)(\d+(?:\.\d+)?)', self.path)
            if match:
                new_ram = float(match.group(1))
                set_simulated_ram(new_ram)
            self.send_json(get_stats())
            return

        if self.path.startswith('/api/status') or self.path.startswith('/status'):
            self.send_json(get_stats())
            return

        if self.path == '/favicon.ico':
            self.send_response(204)
            self.send_header('Connection', 'close')
            self.end_headers()
            self.close_connection = True
            return

        now = time.time()
        with connections_lock:
            active_connections += 1
            curr_active = active_connections
            total_requests_handled += 1
            req_id = total_requests_handled
            request_timestamps.append(now)
            while request_timestamps and request_timestamps[0] < now - 2.0:
                request_timestamps.popleft()
            rps = len(request_timestamps) / 2.0
            is_attacked = (rps >= 4.0 or curr_active >= MAX_CONCURRENT_CONNECTIONS)
            sim_total = SIMULATED_TOTAL_RAM_MB
            max_workers = MAX_CONCURRENT_CONNECTIONS

        simulated_ram = min(sim_total, BASE_RAM_USAGE_MB + (curr_active * 2.2) + (min(10.0, rps) * 0.4))

        try:
            if curr_active > max_workers:
                time.sleep(0.25 + (curr_active - max_workers) * 0.2)
                if simulated_ram >= sim_total * 0.95:
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
                stats = get_stats()
                html = render_html_page(stats)
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

        except Exception as e:
            pass
        finally:
            with connections_lock:
                active_connections = max(0, active_connections - 1)

    def do_POST(self):
        if self.path.startswith('/api/set_ram') or self.path.startswith('/set_ram'):
            match = re.search(r'(?:[?&](?:ram|mb|val|value)=|/set_ram/)(\d+(?:\.\d+)?)', self.path)
            if match:
                new_ram = float(match.group(1))
                set_simulated_ram(new_ram)
            self.send_json(get_stats())
            return
        self.do_GET()


def render_html_page(stats):
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


def run_server(port=PORT, host=HOST, initial_ram=32.0):
    set_simulated_ram(initial_ram)
    server = LimitedThreadingServer((host, port), CameraHTTPRequestHandler)
    print("=" * 65)
    print(" [CAMERA] LOW-RESOURCE IP CAMERA EMBEDDED WEB SERVER RUNNING")
    print(f" * Local URL:           http://127.0.0.1:{port}/")
    print(f" * Network URL:         http://{get_local_ip()}:{port}/")
    print(f" * Hardware Specs:      Anyka AK3918 SoC (Single-Core ARM9 @ 400MHz)")
    print(f" * Configurable RAM:    {SIMULATED_TOTAL_RAM_MB:.0f} MB (Change via web or /api/set_ram)")
    print(f" * Concurrency Limit:   {MAX_CONCURRENT_CONNECTIONS} concurrent HTTP workers")
    print("=" * 65)
    print(f"Listening on {host}:{port}... (Press Ctrl+C to stop)\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping camera server...")
    finally:
        server.server_close()


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    except Exception:
        return '127.0.0.1'
    finally:
        s.close()


if __name__ == '__main__':
    port = PORT
    ram = 32.0
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    if len(sys.argv) > 2:
        try:
            ram = float(sys.argv[2])
        except ValueError:
            pass
    run_server(port=port, initial_ram=ram)
