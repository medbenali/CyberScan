#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor Boston,
#  MA 02110-1301, USA.
#
#  Author: Mohamed BEN ALI
#  Converted to Python 3 by ChatGPT

from concurrent.futures import ThreadPoolExecutor
import os
import sys
import platform
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from threading import Lock

import time
import socket
import geoip2.database

from scapy.all import *
# colorama should be installed via pip: pip install colorama
from colorama import *

init(autoreset=True) # Initialize colorama

__version__ = '1.1.1'
__description__ = f'''\
  ___________________________________________

  CyberScan | v.{__version__}
  Author: BEN ALI Mohamed
  ___________________________________________
'''


def header():
    """Prints the application banner."""
    # Determine the path to banner.txt relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    banner_path = os.path.join(script_dir, 'banner.txt')
    
    try:
        with open(banner_path, 'r', encoding='utf-8') as f:
            # Split version for banner formatting
            mayor, minor, revision = __version__.split('.')
            version_dict = {"MAYOR_VERSION": mayor, "MINOR_VERSION": minor, "REVISION": revision}
            banner = f.read().format(**version_dict)
            print(Style.BRIGHT + Fore.RED + banner)
    except FileNotFoundError:
        print(Style.BRIGHT + Fore.RED + f"CyberScan | v.{__version__}")
    except Exception as e:
        print(f"Error loading banner: {e}")


def geo_ip(host):
    try:
        # Note: This requires the GeoLite2-City.mmdb file.
        # Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
        with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
            response = reader.city(host)

            print(f'[*] --- GeoIP Data for {host} ---')
            print(f"[*] IP Address:   {host}")
            print(f"[*] Country:      {response.country.name} ({response.country.iso_code})")
            if response.subdivisions:
                print(f"[*] Region:       {response.subdivisions.most_specific.name}")
            print(f"[*] City:         {response.city.name}")
            print(f"[*] Postal Code:  {response.postal.code}")
            print(f"[*] Coordinates:  (Lat: {response.location.latitude}, Lon: {response.location.longitude})")
            print(f"[*] Time Zone:    {response.location.time_zone}")
            print(f"[*] Continent:    {response.continent.name} ({response.continent.code})")

    except FileNotFoundError:
        print("[!] Error: 'GeoLite2-City.mmdb' not found.")
        print("[!] Please download it from MaxMind and place it in the same directory.")
    except geoip2.errors.AddressNotFoundError:
        print(f"[*] Could not find GeoIP data for the address: {host}")
    except Exception as e:
        print(f"[*] Could not get GeoIP data for {host}. Error: {e}")


def arp_ping(host):
    print('[*] Starting CyberScan Ping ARP for {}'.format(host))
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host), timeout=2, verbose=0)
    # scapy will call the lambda with two args (sent, received)
    ans.summary(lambda s, r: r.sprintf("%Ether.src% %ARP.psrc%"))


def icmp_ping(host):
    print('[*] Starting CyberScan Ping ICMP for {}'.format(host))
    ans, unans = sr(IP(dst=host) / ICMP())
    ans.summary(lambda s, r: r.sprintf("%IP.src% is alive"))


def tcp_ping(host, dport):
    print('[*] Starting CyberScan Ping TCP for {} port {}'.format(host, dport))
    ans, unans = sr(IP(dst=host) / TCP(dport=dport, flags="S"))
    ans.summary(lambda s, r: r.sprintf("%IP.src% is alive"))


def udp_ping(host, port=0):
    print('[*] Starting CyberScan Ping UDP for {}'.format(host))
    ans, unans = sr(IP(dst=host) / UDP(dport=port))
    ans.summary(lambda s, r: r.sprintf("%IP.src% is alive"))


def superscan(host, start_port=None, end_port=None):
    print('[*] CyberScan Port Scanner')
    open_ports = []
    common_ports = {
        '21': 'FTP',
        '22': 'SSH',
        '23': 'TELNET',
        '25': 'SMTP',
        '53': 'DNS',
        '69': 'TFTP',
        '80': 'HTTP',
        '109': 'POP2',
        '110': 'POP3',
        '123': 'NTP',
        '137': 'NETBIOS-NS',
        '138': 'NETBIOS-DGM',
        '139': 'NETBIOS-SSN',
        '143': 'IMAP',
        '156': 'SQL-SERVER',
        '389': 'LDAP',
        '443': 'HTTPS',
        '546': 'DHCP-CLIENT',
        '547': 'DHCP-SERVER',
        '993': 'IMAP-SSL',
        '995': 'POP3-SSL',
        '2082': 'CPANEL',
        '2083': 'CPANEL',
        '2086': 'WHM/CPANEL',
        '2087': 'WHM/CPANEL',
        '3306': 'MYSQL',
        '8443': 'PLESK',
        '10000': 'VIRTUALMIN/WEBIN'
    }

    # Determine which ports to scan
    if start_port is None and end_port is None:
        ports_to_scan = [int(p) for p in common_ports.keys()]
        scan_type_msg = f"[*] Scanning For Most Common Ports On {host}"
    else:
        ports_to_scan = range(start_port, end_port + 1)
        scan_type_msg = f"[*] Scanning {host} From Port {start_port} To {end_port}"

    starting_time = time.time()
    print(scan_type_msg)
    print("[*] Starting CyberScan 1.01 at {}".format(time.strftime("%Y-%m-%d %H:%M %Z")))

    print_lock = Lock()

    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            r = sock.connect_ex((host, port))
            if r == 0:
                with print_lock:
                    open_ports.append(port)
            sock.close()
        except socket.error as e:
            with print_lock:
                print(f"\nError on port {port}: {e}")

    def get_service(port):
        port_s = str(port)
        return common_ports.get(port_s, "Unknown service")

    try:
        print("[*] Scan In Progress ...")
        
        # Use a thread pool to scan ports concurrently
        with ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(check_port, ports_to_scan)

        print("\n[*] Scanning Completed at {}".format(time.strftime("%Y-%m-%d %H:%M %Z")))
        ending_time = time.time()
        total_time = ending_time - starting_time
        if total_time <= 60:
            print("[*] CyberScan done: 1IP address (1host up) scanned in {:.2f} seconds".format(total_time))
        else:
            total_time = total_time / 60
            print("[*] CyberScan done: 1IP address (1host up) scanned in {:.2f} Minutes".format(total_time))

        if open_ports:
            print("[*] Open Ports: ")
            for i in sorted(open_ports):
                service = get_service(i)
                print(f"\t{i:<5} {service}: Open")
        else:
            print("[*] Sorry, No Open Ports Found.!!")

    except KeyboardInterrupt:
        print("\n[*] You Pressed Ctrl+C. Exiting")
        sys.exit(1)


def pcap_analyser(file_path, layer_name):
    """Analyzes a pcap file and prints details for a specific protocol layer."""
    try:
        pkts = rdpcap(file_path)
    except Scapy_Exception as e:
        print(f"Error reading pcap file: {e}")
        return

    layer_map = {"eth": Ether, "ip": IP, "tcp": TCP, "udp": UDP, "icmp": ICMP}
    layer_to_check = layer_map.get(layer_name.lower())

    if not layer_to_check:
        print(f"Error: Invalid layer '{layer_name}'. Choose from {list(layer_map.keys())}.")
        return

    print(f"[*] Analyzing for {layer_to_check.name} layer in {file_path}")
    count = 0
    for i, pkt in enumerate(pkts):
        if pkt.haslayer(layer_to_check):
            count += 1
            print("-" * 40)
            print(f"[*] Packet : {i+1} (Match #{count})")
            print(f"[+] ###[ {layer_to_check.name} ] ###")
            
            # Print detailed summary of the layer
            pkt[layer_to_check].show(dump=True)
            
            # For IP-based protocols, show src/dst
            if pkt.haslayer(IP):
                print(f"    IP Source: {pkt[IP].src}, IP Destination: {pkt[IP].dst}")
            
            print("[*] Hexdump:")
            hexdump(pkt[layer_to_check])
    
    if count == 0:
        print(f"[*] No packets with layer '{layer_to_check.name}' found.")

# The individual pcap analyser functions are now obsolete and can be removed.
# pcap_analyser_eth, pcap_analyser_ip, etc. are no longer needed.

"""
def pcap_analyser_ip(file):
    pkts = rdpcap(file)
    i = 0
    for pkt in pkts:
        if pkt.haslayer(IP):
            i += 1
            print("-" * 40)
            print("[*] Packet : {}".format(i))
            print("[+] ###[ IP ] ###")
            IPpkt = pkt[IP]
            srcIP = IPpkt.fields.get('src')
            dstIP = IPpkt.fields.get('dst')
            print("[*] IP Source : {}".format(srcIP))
            print("[*] IP Destination : {}".format(dstIP))
            print("[*] IP Version : {}".format(IPpkt.version))
            print("[*] IP Ihl : {}".format(IPpkt.ihl))
            print("[*] IP Tos : {}".format(IPpkt.tos))
            print("[*] IP Len : {}".format(IPpkt.len))
            print("[*] IP Id : {}".format(IPpkt.id))
            print("[*] IP Flags : {}".format(IPpkt.flags))
            print("[*] IP Frag : {}".format(IPpkt.frag))
            print("[*] IP Ttl : {}".format(IPpkt.ttl))
            print("[*] IP Protocol : {}".format(IPpkt.proto))
            print("[*] IP Chksum : {}".format(IPpkt.chksum))
            print("[*] IP Options : {}".format(IPpkt.options))
            print("[*] IP Dump : ")
            hexdump(IPpkt)


def pcap_analyser_tcp(file):
    pkts = rdpcap(file)
    i = 0
    SYN = 0x02
    FIN = 0x01
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20

    for pkt in pkts:
        if pkt.haslayer(TCP):
            i += 1
            print("-" * 40)
            print("[*] Packet : {}".format(i))
            print("[+] ###[ TCP ] ###")
            TCPpkt = pkt[TCP]
            sportTCP = TCPpkt.sport
            print("[*] TCP Source Port : {}".format(sportTCP))
            dportTCP = TCPpkt.dport
            print("[*] TCP Destination Port : {}".format(dportTCP))
            print("[*] TCP Seq : {}".format(TCPpkt.seq))
            print("[*] TCP Ack : {}".format(TCPpkt.ack))
            print("[*] TCP Dataofs : {}".format(TCPpkt.dataofs))
            print("[*] TCP Reserved : {}".format(TCPpkt.reserved))
            flagsTCP = TCPpkt.flags
            print("[*] TCP Flags : {}".format(flagsTCP))
            print("[*] TCP Window : {}".format(TCPpkt.window))
            print("[*] TCP Chksum : {}".format(TCPpkt.chksum))
            print("[*] TCP Urgptr : {}".format(TCPpkt.urgptr))
            print("[*] TCP Options : {}".format(TCPpkt.options))
            nbrsyn = 0
            nbrrst = 0
            nbrack = 0
            nbrfin = 0
            nbrurg = 0
            nbrpsh = 0
            FlagsTCP = pkt[TCP].flags
            if FlagsTCP == SYN:
                nbrsyn = 1
                print("[*] TCP SYN FLAGS : {}".format(nbrsyn))
            elif FlagsTCP == RST:
                nbrrst = 1
                print("[*] TCP RST FLAGS : {}".format(nbrrst))
            elif FlagsTCP == ACK:
                nbrack = 1
                print("[*] TCP ACK FLAGS : {}".format(nbrack))
            elif FlagsTCP == FIN:
                nbrfin = 1
                print("[*] TCP FIN FLAGS : {}".format(nbrfin))
            elif FlagsTCP == URG:
                nbrurg = 1
                print("[*] TCP URG FLAGS : {}".format(nbrurg))
            elif FlagsTCP == PSH:
                nbrpsh = 1
                print("[*] TCP PSH FLAGS : {}".format(nbrpsh))
            print("[*] TCP Dump : ")
            hexdump(TCPpkt)


def pcap_analyser_udp(file):
    pkts = rdpcap(file)
    i = 0
    for pkt in pkts:
        if pkt.haslayer(UDP):
            i += 1
            print("-" * 40)
            print("[*] Packet : {}".format(i))
            print("[+] ###[ UDP ] ###")
            UDPpkt = pkt[UDP]
            print("[*] UDP Source Port : {}".format(UDPpkt.sport))
            print("[*] UDP Destination Port : {}".format(UDPpkt.dport))
            print("[*] UDP Len : {}".format(UDPpkt.len))
            print("[*] UDP Chksum : {}".format(UDPpkt.chksum))
            print("[*] UDP Dump : ")
            hexdump(UDPpkt)


def pcap_analyser_icmp(file):
    pkts = rdpcap(file)
    i = 0
    for pkt in pkts:
        if pkt.haslayer(ICMP):
            i += 1
            print("-" * 40)
            print("[*] Packet : {}".format(i))
            print("[+] ###[ ICMP ] ###")
            ICMPpkt = pkt[ICMP]
            print("[*] ICMP Type : {}".format(ICMPpkt.type))
            print("[*] ICMP Code : {}".format(ICMPpkt.code))
            print("[*] ICMP Chksum : {}".format(ICMPpkt.chksum))
            print("[*] ICMP Id : {}".format(ICMPpkt.id))
            print("[*] ICMP Seq : {}".format(ICMPpkt.seq))
            print("[*] ICMP Dump : ")
            hexdump(ICMPpkt)
"""

def main():
    parser = argparse.ArgumentParser(
        description=__description__,
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f'''\
{Style.BRIGHT}Examples:{Style.RESET_ALL}
  # Scan common ports on a host
  {sys.argv[0]} -s 192.168.1.1 -p scan

  # Scan a specific port range
  {sys.argv[0]} -s 192.168.1.1 -p scan -d 1 -t 1024

  # Perform an ARP ping on the local network
  {sys.argv[0]} -s 192.168.1.0/24 -p arp

  # Analyze TCP headers in a pcap file
  {sys.argv[0]} -f capture.pcap -p tcp
'''
    )
    parser.add_argument("-s", "--serveur", dest="host", help="Target host IP address or domain")
    parser.add_argument("-p", "--level", dest="mode", help="Mode of operation (e.g., scan, arp, icmp, geoip, etc.)")
    parser.add_argument("-d", "--sport", dest="start_port", type=int, help="Start port for scanning")
    parser.add_argument("-t", "--eport", dest="end_port", type=int, help="End port for scanning")
    parser.add_argument("-f", "--file", dest="pcap_file", help="PCAP file to read and analyze")
    parser.add_argument('--version', action='version', version=f"CyberScan {__version__}")

    args = parser.parse_args()

    if not any([args.host, args.pcap_file]):
        parser.print_help()
        sys.exit(1)

    header()
    print(f'''{Fore.GREEN}CyberScan v{__version__} | http://github/medbenali/CyberScan
It is the end user's responsibility to obey all applicable laws.
This is a server testing script. Your IP is visible.{Fore.RESET}\n''')

    try:
        if args.host:
            if args.mode == "scan":
                if args.start_port and args.end_port:
                    superscan(args.host, args.start_port, args.end_port)
                else:
                    superscan(args.host) # Scan common ports
            elif args.mode == "arp":
                arp_ping(args.host)
            elif args.mode == "icmp":
                icmp_ping(args.host)
            elif args.mode == "tcp":
                if not args.start_port:
                    print("Error: TCP ping requires a port. Use -d <port>.")
                    sys.exit(1)
                tcp_ping(args.host, args.start_port)
            elif args.mode == "udp":
                udp_ping(args.host, port=0)
            elif args.mode == "geoip":
                geo_ip(args.host)
            else:
                print(f"Error: Invalid mode '{args.mode}' for a host target.")
        
        elif args.pcap_file:
            if args.mode in ["eth", "ip", "tcp", "udp", "icmp"]:
                pcap_analyser(args.pcap_file, args.mode)
            else:
                print(f"Error: Invalid mode '{args.mode}' for a pcap file.")
        else:
            parser.print_help()

    except KeyboardInterrupt:
        print("\n[*] You Pressed Ctrl+C. Exiting")
        sys.exit(1)


if __name__ == '__main__':
    main()
