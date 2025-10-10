#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  CyberScan - Network scanning & pcap analysis toolkit
#  Author: Mohamed BEN ALI
#  Updated & fixed for Python 3 by Ajay (2025)
#
#  License: GNU GPL v3

import os
import sys
import platform
import argparse
import logging
import time
import socket
import pygeoip
from scapy.all import *
from libs.colorama import *
from libs import FileUtils

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

if platform.system() == 'Windows':
    from libs.colorama.win32 import *

__version__ = '1.1.2'
__description__ = f"""
  ___________________________________________

  CyberScan | v.{__version__}
  Author: BEN ALI Mohamed
  Updated: 2025
  ___________________________________________
"""


def header():
    MAYOR_VERSION = 1
    MINOR_VERSION = 1
    REVISION = 2
    VERSION = {
        "MAYOR_VERSION": MAYOR_VERSION,
        "MINOR_VERSION": MINOR_VERSION,
        "REVISION": REVISION
    }

    banner_path = FileUtils.buildPath('banner.txt')
    if os.path.exists(banner_path):
        with open(banner_path, 'r', encoding='utf-8') as f:
            PROGRAM_BANNER = f.read().format(**VERSION)
            message = Style.BRIGHT + Fore.RED + PROGRAM_BANNER + Style.RESET_ALL
            write(message)
    else:
        print("Banner file missing: banner.txt")


def usage():
    print("""\033[92m
CyberScan v.1.1.2  https://github.com/medbenali/CyberScan
This tool is for server testing only. Use responsibly.

  ___________________________________________

  CyberScan | v.1.1.2
  Author: BEN ALI Mohamed
  ___________________________________________

\033[0m""")


def write(string):
    """Safe console output (fixed indentation)."""
    if platform.system() == 'Windows':
        sys.stdout.write(string + "\n")
        sys.stdout.flush()
    else:
        sys.stdout.write(string + "\n")
        sys.stdout.flush()


def geo_ip(host):
    try:
        rawdata = pygeoip.GeoIP('GeoLiteCity.dat')
        data = rawdata.record_by_name(host)
        for key, val in data.items():
            print(f"[*] {key.title().replace('_', ' ')}: {val}")
    except Exception as e:
        print(f"[*] Please verify your IP! Error: {e}")


def arp_ping(host):
    print(f"[*] Starting CyberScan ARP Ping for {host}")
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host), timeout=2, verbose=False)
    for s, r in ans:
        print(f"{r[Ether].src}  {r[ARP].psrc}")


def icmp_ping(host):
    print(f"[*] Starting CyberScan ICMP Ping for {host}")
    ans, _ = sr(IP(dst=host) / ICMP(), timeout=2, verbose=False)
    for s, r in ans:
        print(f"{r[IP].src} is alive")


def tcp_ping(host, dport):
    print(f"[*] Starting CyberScan TCP Ping for {host}:{dport}")
    ans, _ = sr(IP(dst=host) / TCP(dport=int(dport), flags="S"), timeout=2, verbose=False)
    for s, r in ans:
        print(f"{r[IP].src} is alive")


def udp_ping(host, port=0):
    print(f"[*] Starting CyberScan UDP Ping for {host}")
    ans, _ = sr(IP(dst=host) / UDP(dport=port), timeout=2, verbose=False)
    for s, r in ans:
        print(f"{r[IP].src} is alive")


def superscan(host, start_port, end_port, flag):
    print("[*] CyberScan Port Scanner")
    open_ports = []
    common_ports = {
        21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP', 53: 'DNS',
        69: 'TFTP', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        3306: 'MYSQL', 8080: 'HTTP-ALT'
    }

    start_time = time.time()
    print(f"[*] Scanning {host}...")

    def check_port(host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((host, port))
                return result == 0
        except Exception:
            return False

    ports = common_ports.keys() if flag else range(start_port, end_port + 1)
    for port in ports:
        sys.stdout.write(f"\rScanning port {port}...")
        sys.stdout.flush()
        if check_port(host, port):
            open_ports.append(port)
    print("\n[*] Scan complete.\n")

    if open_ports:
        print("[*] Open Ports:")
        for port in open_ports:
            service = common_ports.get(port, "Unknown")
            print(f"  {port} ({service}) - Open")
    else:
        print("[*] No open ports found.")

    elapsed = time.time() - start_time
    print(f"[*] Completed in {elapsed:.2f} seconds")


def pcap_analyser_eth(file):
    pkts = rdpcap(file)
    for i, pkt in enumerate(pkts, 1):
        print("-" * 40)
        print(f"[*] Packet: {i}")
        print(f"[*] MAC Destination: {pkt.dst}")
        print(f"[*] MAC Source: {pkt.src}")
        print(f"[*] Ethernet Type: {pkt.type}")


def pcap_analyser_ip(file):
    pkts = rdpcap(file)
    for i, pkt in enumerate(pkts, 1):
        if pkt.haslayer(IP):
            print("-" * 40)
            ip = pkt[IP]
            print(f"[*] Packet: {i}")
            for k, v in ip.fields.items():
                print(f"[*] {k}: {v}")


def main():
    parser = argparse.ArgumentParser(
        description=__description__,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-s", "--serveur", help="Target server IP")
    parser.add_argument("-p", "--level", help="Select mode (scan, arp, icmp, tcp, udp, geoip, eth, ip)")
    parser.add_argument("-d", "--sport", help="Start port")
    parser.add_argument("-t", "--eport", help="End port")
    parser.add_argument("-f", "--file", help="Read pcap file")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args()

    serveur = args.serveur
    file = args.file
    level = args.level
    sport = args.sport
    eport = args.eport

    if not (serveur or file):
        print("Usage: python CyberScan.py -s <ip> -p <mode> [-d start_port -t end_port] [-f file]")
        sys.exit(0)

    header()
    usage()

    if file:
        if level == "eth":
            pcap_analyser_eth(file)
        elif level == "ip":
            pcap_analyser_ip(file)
        else:
            print("[*] Unsupported file level.")
        return

    if level == "geoip":
        geo_ip(serveur)
    elif level == "arp":
        arp_ping(serveur)
    elif level == "icmp":
        icmp_ping(serveur)
    elif level == "tcp" and sport:
        tcp_ping(serveur, sport)
    elif level == "udp":
        udp_ping(serveur)
    elif level == "scan":
        if sport and eport:
            superscan(serveur, int(sport), int(eport), flag=False)
        else:
            superscan(serveur, 0, 0, flag=True)
    else:
        print("[*] Invalid mode specified.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] User interrupted. Exiting...")
        sys.exit(0)
