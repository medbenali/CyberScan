#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# CyberScan v1.1.1 - Full Python 3 compatible version
# Author: Mohamed BEN ALI
# License: GPLv3

import os
import sys
import platform
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import time
import socket

from scapy.all import *
from libs.colorama import *
import libs.FileUtils as FileUtils
import geoip2.database

if platform.system() == 'Windows':
    from libs.colorama.win32 import *

__version__ = '1.1.1'
__description__ = f'''\
  ___________________________________________

  CyberScan | v.{__version__}
  Author: BEN ALI Mohamed
  ___________________________________________
'''

def header():
    MAYOR_VERSION = 1
    MINOR_VERSION = 1
    REVISION = 1
    VERSION = {
        "MAYOR_VERSION": MAYOR_VERSION,
        "MINOR_VERSION": MINOR_VERSION,
        "REVISION": REVISION
    }
    banner_path = FileUtils.buildPath('banner.txt')
    if os.path.exists(banner_path):
        PROGRAM_BANNER = open(banner_path).read().format(**VERSION)
    else:
        PROGRAM_BANNER = "CyberScan v1.1.1"
    message = Style.BRIGHT + Fore.RED + PROGRAM_BANNER + Style.RESET_ALL
    write(message)

def usage():
    print('''\033[92m
CyberScan v.1.1.1 http://github.com/medbenali/CyberScan
It is the end user's responsibility to obey all applicable laws.
It is just for server testing script. Your IP is visible.

Levels with IP address:
  scan : scan ports
  arp : ping arp
  icmp : ping icmp
  tcp : ping tcp
  udp : ping udp
  geoip : geolocalisation

Levels with pcap file:
  eth : extract ethernet headers
  ip : extract IP headers
  tcp : extract TCP headers
  udp : extract UDP headers
  icmp : extract ICMP headers
\033[0m''')

def write(string):
    sys.stdout.write(string + '\n')
    sys.stdout.flush()

def geo_ip(host):
    db_path = FileUtils.buildPath('GeoLite2-City.mmdb')
    try:
        reader = geoip2.database.Reader(db_path)
        rec = reader.city(host)
        country = rec.country.name
        city = rec.city.name
        lat = rec.location.latitude
        lon = rec.location.longitude
        print(f'[*] IP Address: {host}')
        print(f'[*] City: {city}')
        print(f'[*] Latitude: {lat}')
        print(f'[*] Longitude: {lon}')
        print(f'[*] Country Name: {country}')
        reader.close()
    except Exception as e:
        print(f"[*] Please verify your IP! Error: {e}")

def arp_ping(host):
    print(f'[*] Starting CyberScan Ping ARP for {host}')
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=host), timeout=2, verbose=0)
    for s, r in ans:
        print(r.sprintf("%Ether.src% %ARP.psrc%"))

def icmp_ping(host):
    print(f'[*] Starting CyberScan Ping ICMP for {host}')
    ans, _ = sr(IP(dst=host)/ICMP(), timeout=2, verbose=0)
    for s, r in ans:
        print(r.sprintf("%IP.src% is alive"))

def tcp_ping(host, dport):
    print(f'[*] Starting CyberScan Ping TCP for {host}:{dport}')
    ans, _ = sr(IP(dst=host)/TCP(dport=int(dport), flags="S"), timeout=2, verbose=0)
    for s, r in ans:
        print(r.sprintf("%IP.src% is alive"))

def udp_ping(host, port=0):
    print(f'[*] Starting CyberScan Ping UDP for {host}')
    ans, _ = sr(IP(dst=host)/UDP(dport=int(port)), timeout=2, verbose=0)
    for s, r in ans:
        print(r.sprintf("%IP.src% is alive"))

def superscan(host, start_port, end_port):
    print('[*] CyberScan Port Scanner')
    open_ports = []
    common_ports = {
        21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP', 53: 'DNS', 69: 'TFTP',
        80: 'HTTP', 109: 'POP2', 110: 'POP3', 123: 'NTP', 137: 'NETBIOS-NS',
        138: 'NETBIOS-DGM', 139: 'NETBIOS-SSN', 143: 'IMAP', 156: 'SQL-SERVER',
        389: 'LDAP', 443: 'HTTPS', 546: 'DHCP-CLIENT', 547: 'DHCP-SERVER',
        993: 'IMAP-SSL', 995: 'POP3-SSL', 2082: 'CPANEL', 2083: 'CPANEL',
        2086: 'WHM/CPANEL', 2087: 'WHM/CPANEL', 3306: 'MYSQL', 8443: 'PLESK',
        10000: 'VIRTUALMIN/WEBIN'
    }
    starting_time = time.time()
    print(f"[*] Scanning {host} from port {start_port} to {end_port}")
    
    def check_port(host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            sock.close()
            return result
        except Exception:
            return 1

    def get_service(port):
        return common_ports.get(port, "Unknown service")

    try:
        for p in range(start_port, end_port+1):
            sys.stdout.flush()
            print(p, end=' ', flush=True)
            response = check_port(host, p)
            if response == 0:
                open_ports.append(p)
        print("\n[*] Scan Completed at", time.strftime("%Y-%m-%d %H:%M %Z"))
        total_time = time.time() - starting_time
        print(f"[*] CyberScan done: 1 IP scanned in {total_time:.2f} seconds")
        if open_ports:
            print("[*] Open Ports:")
            for p in sorted(open_ports):
                print(f"\t{p} {get_service(p)}: Open")
        else:
            print("[*] Sorry, No Open Ports Found!")
    except KeyboardInterrupt:
        print("\n[*] You Pressed Ctrl+C. Exiting")
        sys.exit(1)

# --- Pcap analyzers ---

def pcap_analyser_eth(file):
    pkts = rdpcap(file)
    for i, pkt in enumerate(pkts, start=1):
        print("-"*40)
        print(f"[*] Packet {i}")
        print("[+] ### [ Ethernet ] ###")
        print(f"[*] Mac Destination: {pkt.dst}")
        print(f"[*] Mac Source: {pkt.src}")
        print(f"[*] Ethernet Type: {pkt.type}")

def pcap_analyser_ip(file):
    pkts = rdpcap(file)
    for i, pkt in enumerate(pkts, start=1):
        if pkt.haslayer(IP):
            ip = pkt[IP]
            print("-"*40)
            print(f"[*] Packet {i}")
            print("[+] ### [ IP ] ###")
            print(f"[*] IP Source: {ip.src}")
            print(f"[*] IP Destination: {ip.dst}")
            print(f"[*] IP Version: {ip.version}")
            print(f"[*] IP IHL: {ip.ihl}")
            print(f"[*] IP TOS: {ip.tos}")
            print(f"[*] IP Length: {ip.len}")
            print(f"[*] IP ID: {ip.id}")
            print(f"[*] IP Flags: {ip.flags}")
            print(f"[*] IP Frag: {ip.frag}")
            print(f"[*] IP TTL: {ip.ttl}")
            print(f"[*] IP Protocol: {ip.proto}")
            print(f"[*] IP Checksum: {ip.chksum}")
            print("[*] IP Dump:")
            hexdump(ip)

def pcap_analyser_tcp(file):
    pkts = rdpcap(file)
    for i, pkt in enumerate(pkts, start=1):
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            print("-"*40)
            print(f"[*] Packet {i}")
            print("[+] ### [ TCP ] ###")
            print(f"[*] TCP Source Port: {tcp.sport}")
            print(f"[*] TCP Destination Port: {tcp.dport}")
            print(f"[*] TCP Seq: {tcp.seq}")
            print(f"[*] TCP Ack: {tcp.ack}")
            print(f"[*] TCP Flags: {tcp.flags}")
            print("[*] TCP Dump:")
            hexdump(tcp)

def pcap_analyser_udp(file):
    pkts = rdpcap(file)
    for i, pkt in enumerate(pkts, start=1):
        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            print("-"*40)
            print(f"[*] Packet {i}")
            print("[+] ### [ UDP ] ###")
            print(f"[*] UDP Source Port: {udp.sport}")
            print(f"[*] UDP Destination Port: {udp.dport}")
            print(f"[*] UDP Length: {udp.len}")
            print("[*] UDP Dump:")
            hexdump(udp)

def pcap_analyser_icmp(file):
    pkts = rdpcap(file)
    for i, pkt in enumerate(pkts, start=1):
        if pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            print("-"*40)
            print(f"[*] Packet {i}")
            print("[+] ### [ ICMP ] ###")
            print(f"[*] ICMP Type: {icmp.type}")
            print(f"[*] ICMP Code: {icmp.code}")
            print("[*] ICMP Dump:")
            hexdump(icmp)

# --- Main function ---

def main():
    parser = argparse.ArgumentParser(description=__description__,
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-s", "--serveur", dest="serveur", help="Target server IP")
    parser.add_argument("-p", "--level", dest="level", help="Scan level or type")
    parser.add_argument("-d", "--sport", dest="sport", help="Start port for scan")
    parser.add_argument("-t", "--eport", dest="eport", help="End port for scan")
    parser.add_argument("-f", "--file", dest="file", help="Read pcap file")
    args = parser.parse_args()

    header()
    usage()

    try:
        if args.file:
            if args.level == "eth":
                pcap_analyser_eth(args.file)
            elif args.level == "ip":
                pcap_analyser_ip(args.file)
            elif args.level == "tcp":
                pcap_analyser_tcp(args.file)
            elif args.level == "udp":
                pcap_analyser_udp(args.file)
            elif args.level == "icmp":
                pcap_analyser_icmp(args.file)
        elif args.serveur:
            if args.level == "arp":
                arp_ping(args.serveur)
            elif args.level == "icmp":
                icmp_ping(args.serveur)
            elif args.level == "tcp" and args.sport:
                tcp_ping(args.serveur, args.sport)
            elif args.level == "udp":
                udp_ping(args.serveur)
            elif args.level == "scan":
                start = int(args.sport) if args.sport else 1
                end = int(args.eport) if args.eport else 1024
                superscan(args.serveur, start, end)
            elif args.level == "geoip":
                geo_ip(args.serveur)
        else:
            print("Usage: CyberScan.py -h for help")
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
        sys.exit(1)

if __name__ == "__main__":
    main()
