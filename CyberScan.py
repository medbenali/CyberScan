#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# CyberScan - Network Reconnaissance Tool (Fixed Version)
# Updated for Python 3, safe socket handling, and robust input/errors.

import os
import sys
import socket
import ipaddress
import platform
import logging
from datetime import datetime

# Optional imports
try:
    import pcapy
except Exception:
    pcapy = None
    print("[!] Warning: 'pcapy' not found. Packet capture features disabled.")

try:
    import pygeoip
except Exception:
    pygeoip = None
    print("[!] Warning: 'pygeoip' not found. GeoIP lookup disabled.")

# Suppress noisy scapy warnings if scapy is present
try:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
except Exception:
    pass


def write(string):
    """Cross-platform print handling (keeps compatibility)."""
    if platform.system() == 'Windows':
        sys.stdout.write(string + '\n')
        sys.stdout.flush()
    else:
        print(string)
        sys.stdout.flush()


def geo_ip(host):
    """Return a short GeoIP string if pygeoip and DB available."""
    if not pygeoip:
        return "GeoIP lookup unavailable (pygeoip not installed)."
    try:
        if not os.path.exists('GeoLiteCity.dat'):
            return "GeoLiteCity.dat not found."
        rawdata = pygeoip.GeoIP('GeoLiteCity.dat')
        data = rawdata.record_by_name(host)
        if not data:
            return "No GeoIP data."
        city = data.get('city', 'N/A')
        country = data.get('country_name', 'N/A')
        return f"{city}, {country}"
    except Exception as e:
        return f"GeoIP lookup failed: {e}"


def check_port(host, port, timeout=0.5):
    """
    Check a TCP port on host.
    Returns:
      True  -> open
      False -> closed
      None  -> error scanning
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((host, port))
            return (code == 0)
    except Exception:
        return None


def superscan(host, start_port, end_port):
    """
    Scans each port in the inclusive range and prints status lines.
    """
    write(f"\n[*] Starting CyberScan SuperScan on {host}")
    write(f"[*] Scanning ports {start_port} to {end_port}...\n")

    try:
        for port in range(start_port, end_port + 1):
            state = check_port(host, port)
            if state is True:
                write(f"[+] Port {port} is OPEN")
            elif state is False:
                write(f"[-] Port {port} is closed")
            else:
                write(f"[!] Port {port}: scan error")
    except KeyboardInterrupt:
        write("\n[!] Scan aborted by user.")
        sys.exit(0)
    except socket.gaierror:
        write("[!] Hostname could not be resolved.")
    except socket.error as e:
        write(f"[!] Socket error: {e}")

    write("\n[*] Scan complete.")


def main():
    write("""
  ____        _               _____                 
 / ___|  ___ | |__   ___ _ __| ____|_ __   ___  ___ 
 \___ \\ / _ \\| '_ \\ / _ \\ '__|  _| | '_ \\ / _ \\/ __|
  ___) | (_) | |_) |  __/ |  | |___| | | |  __/\\__ \\
 |____/ \\___/|_.__/ \\___|_|  |_____|_| |_|\\___||___/
                                                    
        CyberScan - Simple Network Recon Tool
        Fixed Version
    """)

    # Interactive input
    host = input("Enter target host (e.g. example.com): ").strip()
    if not host:
        write("[!] No host provided. Exiting.")
        return

    # Read ports with basic defaults and robust handling
    try:
        sp = input("Enter start port (default 20): ").strip()
        ep = input("Enter end port (default 1024): ").strip()
        start_port = int(sp) if sp != "" else 20
        end_port = int(ep) if ep != "" else 1024
    except ValueError:
        write("[!] Invalid port range. Please enter numeric values.")
        return

    # Ensure valid bounds and order
    start_port = max(0, min(65535, start_port))
    end_port = max(0, min(65535, end_port))
    if end_port < start_port:
        write("[!] Note: end port < start port — swapping values.")
        start_port, end_port = end_port, start_port

    # Resolve host to IP
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        write(f"[!] Could not resolve host: {host}")
        return

    # Print resolved IP
    write(f"[*] Target IP: {ip}")

    # Skip GeoIP for localhost/private addresses to avoid errors
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback:
            write("[*] GeoIP: Local/private IP — skipping GeoIP lookup.")
        else:
            write(f"[*] GeoIP: {geo_ip(ip)}")
    except Exception as e:
        write(f"[*] GeoIP: lookup skipped ({e})")

    # Run the scan
    superscan(ip, start_port, end_port)


if __name__ == "__main__":
    main()
