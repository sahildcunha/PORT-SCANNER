#!/usr/bin/env python3
"""
Simple TCP Port Scanner
Usage:
    python port_scanner.py <target> [-p PORTS] [-t THREADS] [--timeout SECONDS]

Examples:
    python port_scanner.py 192.168.1.1
    python port_scanner.py scanme.nmap.org -p 1-1000
    python port_scanner.py 127.0.0.1 -p 22,80,443,8080 -t 200
"""

import argparse
import socket
import sys
import threading
import queue
import time
from datetime import datetime

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 6379: "Redis", 27017: "MongoDB"
}


def parse_ports(port_string):
    ports = set()
    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {target}")
        sys.exit(1)


def grab_banner(sock):
    try:
        sock.settimeout(0.5)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner.splitlines()[0] if banner else ""
    except Exception:
        return ""


def scan_port(ip, port, timeout, results, lock, grab_banners):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "unknown")
                banner = grab_banner(sock) if grab_banners else ""
                with lock:
                    results.append((port, service, banner))
    except socket.error:
        pass


def worker(ip, timeout, port_queue, results, lock, grab_banners):
    while True:
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            return
        scan_port(ip, port, timeout, results, lock, grab_banners)
        port_queue.task_done()


def run_scan(target, ports, threads, timeout, grab_banners):
    ip = resolve_target(target)
    print(f"\nScanning target: {target} ({ip})")
    print(f"Ports to scan:   {len(ports)}")
    print(f"Threads:         {threads}")
    print(f"Started at:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    port_queue = queue.Queue()
    for p in ports:
        port_queue.put(p)

    results = []
    lock = threading.Lock()
    start_time = time.time()

    thread_list = []
    for _ in range(min(threads, len(ports)) or 1):
        t = threading.Thread(
            target=worker,
            args=(ip, timeout, port_queue, results, lock, grab_banners),
            daemon=True,
        )
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    elapsed = time.time() - start_time
    results.sort(key=lambda r: r[0])

    print("PORT      STATE   SERVICE      BANNER")
    print("-" * 60)
    if results:
        for port, service, banner in results:
            print(f"{port:<9} open    {service:<12} {banner}")
    else:
        print("No open ports found.")

    print(f"\nScan completed in {elapsed:.2f} seconds.")
    return results


def main():
    parser = argparse.ArgumentParser(description="Simple multithreaded TCP port scanner")
    parser.add_argument("target", help="Hostname or IP address to scan")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Ports to scan, e.g. '80', '1-1000', or '22,80,443' (default: 1-1024)"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=100,
        help="Number of concurrent threads (default: 100)"
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Socket timeout in seconds per port (default: 1.0)"
    )
    parser.add_argument(
        "--banner", action="store_true",
        help="Attempt to grab service banners from open ports (slower)"
    )
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    if not ports:
        print("[!] No valid ports specified.")
        sys.exit(1)

    try:
        run_scan(args.target, ports, args.threads, args.timeout, args.banner)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)


if __name__ == "__main__":
    main()