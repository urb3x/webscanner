# 🔍 Local IP Website Scanner & Test Site Utility

A multithreaded network scanning utility and diagnostics tool built with Python & Tkinter. It scans local network IP ranges and subnets for active HTTP and HTTPS web services across ALL ports (1-65535), provides one-click browser launching, includes an embedded low-resource **Test Site** with dynamic RAM allocation and live attack detection, and features a built-in **DoS Stress Testing / Benchmarking Engine**.

---

## ⚖️ Legal Disclaimer & Terms of Use

> **IMPORTANT**: This software is provided strictly for **authorized network diagnostics**, **security research**, **educational testing**, and **personal lab environments** on systems that you own or have explicit authorization to test.
> 
> The creator/author assumes **no liability or responsibility** for misuse or damages caused by this application. Users are solely responsible for ensuring compliance with all local, national, and international laws. On first launch, users must agree to these terms before accessing the utility.

---

## ✨ Features

- 🌐 **Fast Multithreaded Subnet Scanner**:
  - Auto-detects local subnet (e.g., `192.168.1.0/24`) and IP ranges.
  - Scans **ALL web ports (1 to 65535)** or custom ranges/comma-separated lists.
  - Extracts HTTP/HTTPS web page titles, status codes, and server banners.
  - Highlights local test servers in green for fast identification.

- 🖥️ **Built-in Local Test Site (Port 8080)**:
  - One-click hosting of an embedded low-resource test web server.
  - **Dynamic Simulated RAM Allocation**: Adjust memory from `4 MB` up to `8192 MB` on the fly.
  - **Live Attack & Memory Monitor**: Centered real-time display showing whether the server is currently under attack, live RAM used / free metrics, and request rates (RPS).

- ⚡ **DoS Stress Tester & Load Benchmarking**:
  - Configurable HTTP request floods (GET, HEAD, POST) with adjustable concurrency, thread pools, and delays.
  - Real-time statistics: Total Requests, Successes, Failures/Errors, RPS, Latency (Min / Avg / Max), and HTTP status code breakdowns.
  - Export stress test results and scan results to CSV.

---

## 🚀 Getting Started

### Prerequisites
- Windows 10 / 11
- Python 3.10+ (Standard Library `tkinter`, `urllib`, `socket`, `concurrent.futures`, etc. — no external pip dependencies required to run the script)

### Running from Source
```bash
python local_web_scanner.py
```

### Standalone Executable
You can run `LocalWebScanner.exe` directly without installing Python or dependencies.

To rebuild the `.exe`:
```bash
pip install pyinstaller
pyinstaller LocalWebScanner.spec
```

---

## 📄 License

**Personal Use Only License**

Copyright (c) 2026 Pepper. All rights reserved.

This software is provided strictly for **personal, non-commercial, educational, and authorized private lab testing use only**. Any commercial exploitation, resale, sublicensing, or unauthorized distribution is prohibited. See the [LICENSE](LICENSE) file for complete details.