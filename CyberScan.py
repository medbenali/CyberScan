#!/usr/bin/env python

import sys
import os
import argparse
import time
import socket

try:
    from scapy.all import sr, srp, rdpcap, Ether, ARP, IP, TCP, UDP, ICMP, hexdump
except ImportError:
    print("Scapy is not installed. Please run: pip install scapy")
    sys.exit(1)

try:
    import pygeoip
except ImportError:
    print("pygeoip is not installed. Please run: pip install pygeoip")
    sys.exit(1)

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("colorama is not installed. Please run: pip install colorama")
    sys.exit(1)

__version__ = '1.1.1'
__description__ = (
    "  ___________________________________________\n"
    f"  CyberScan | v.{__version__}\n"
    "  Author: BEN ALI Mohamed\n"
    "  ___________________________________________\n"
)

def header():
    banner_file = 'banner.txt'
    if not os.path.isfile(banner_file):
        print(Style.BRIGHT + Fore.RED + "CyberScan Banner\n" + Style.RESET_ALL)
        return
    with open(banner_file, 'r') as f:
        program_banner = f.read()
    message = Style.BRIGHT + Fore.RED + program_banner + Style.RESET_ALL
    print(message)

def usage():
    print(
        f"\033[92m CyberScan v.{__version__} http://github/medbenali/CyberScan\n"
        "It is the end user's responsibility to obey all applicable laws.\n"
        "It is just for server testing script. Your ip is visible.\n\n"
        "  ___________________________________________\n\n"
        f"  CyberScan | v.{__version__}\n"
        "  Author: BEN ALI Mohamed\n"
        "  ___________________________________________\n\n\033[0m"
    )

def geo_ip(host):
    geo_db = 'GeoLiteCity.dat'
    if not os.path.isfile(geo_db):
        print("[*] GeoLiteCity.dat file is missing!")
        return
    try:
        rawdata = pygeoip.GeoIP(geo_db)
        data = rawdata.record_by_name(host)
        if not data:
            print("[*] No geolocation data found for IP.")
            return
        for k, v in data.items():
            print(f"[*] {k.replace('_', ' ').title()}: {v}")
    except Exception:
        print("[*] Please verify your ip or GeoLiteCity.dat file!")

def arp_ping(host):
    print(f'[*] Starting CyberScan Ping ARP for {host}')
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=host), timeout=2)
    ans.summary(lambda s_r: s_r[1].sprintf("%Ether.src% %ARP.psrc%"))

def icmp_ping(host):
    print(f'[*] Starting CyberScan Ping ICMP for {host}')
    ans, unans = sr(IP(dst=host)/ICMP())
    ans.summary(lambda s_r: s_r[1].sprintf("%IP.src% is alive"))

def tcp_ping(host, dport):
    ans, unans = sr(IP(dst=host)/TCP(dport=int(dport), flags="S"))
    ans.summary(lambda s_r: s_r[1].sprintf("%IP.src% is alive"))

def udp_ping(host, port=0):
    print(f'[*] Starting CyberScan Ping UDP for {host}')
    ans, unans = sr(IP(dst=host)/UDP(dport=int(port)))
    ans.summary(lambda s_r: s_r[1].sprintf("%IP.src% is alive"))

def superscan(host, start_port, end_port, flag):
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
    if flag:
        print(f"[*] Scanning For Most Common Ports On {host}")
        ports_to_scan = sorted(common_ports.keys())
    else:
        print(f"[*] Scanning {host} From Port {start_port} To {end_port}: ")
        ports_to_scan = range(start_port, end_port + 1)
    print(f"[*] Starting CyberScan {__version__} at {time.strftime('%Y-%m-%d %H:%M %Z')}")

    def check_port(host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            r = sock.connect_ex((host, port))
            sock.close()
            return r
        except Exception:
            return 1

    print("[*] Scan In Progress ...")
    print("[*] Connecting To Port : ", end='')
    for p in ports_to_scan:
        sys.stdout.flush()
        print(p, end=' ')
        response = check_port(host, p)
        if response == 0:
            open_ports.append(p)
    print(f"\n[*] Scanning Completed at {time.strftime('%Y-%m-%d %H:%M %Z')}")
    ending_time = time.time()
    total_time = ending_time - starting_time
    if total_time <= 60:
        print(f"[*] CyberScan done: 1IP address (1host up) scanned in {total_time:.2f} seconds")
    else:
        print(f"[*] CyberScan done: 1IP address (1host up) scanned in {total_time/60:.2f} Minutes")

    if open_ports:
        print("[*] Open Ports: ")
        for i in sorted(open_ports):
            service = common_ports.get(i, "Unknown service")
            print(f"\t{i} {service}: Open")
    else:
        print("[*] Sorry, No Open Ports Found.!!")

def pcap_analyser_eth(file):
    pkts = rdpcap(file)
    for i, pkt in enumerate(pkts, 1):
        print("-" * 40)
        print(f"[*] Packet : {i}")
        print("[+] ### [ Ethernet ] ###")
        print(f"[*] Mac Destination : {pkt.dst}")
        print(f"[*] Mac Source : {pkt.src}")
        print(f"[*] Ethernet Type : {pkt.type}")

def pcap_analyser_ip(file):
    pkts = rdpcap(file)
    for i, pkt in enumerate(pkts, 1):
        if pkt.haslayer(IP):
            print("-" * 40)
            print(f"[*] Packet : {i}")
            print("[+] ###[ IP ] ###")
            IPpkt = pkt[IP]
            print(f"[*] IP Source : {IPpkt.src}")
            print(f"[*] IP Destination : {IPpkt.dst}")
            print(f"[*] IP Version : {IPpkt.version}")
            print(f"[*] IP Ihl : {IPpkt.ihl}")
            print(f"[*] IP Tos : {IPpkt.tos}")
            print(f"[*] IP Len : {IPpkt.len}")
            print(f"[*] IP Id : {IPpkt.id}")
            print(f"[*] IP Flags : {IPpkt.flags}")
            print(f"[*] IP Frag : {IPpkt.frag}")
            print(f"[*] IP Ttl : {IPpkt.ttl}")
            print(f"[*] IP Protocol : {IPpkt.proto}")
            print(f"[*] IP Chksum : {IPpkt.chksum}")
            print(f"[*] IP Options : {IPpkt.options}")
            print("[*] IP Dump :")
            print(hexdump(IPpkt))

def pcap_analyser_tcp(file):
    pkts = rdpcap(file)
    for i, pkt in enumerate(pkts, 1):
        if pkt.haslayer(TCP):
            print("-" * 40)
            print(f"[*] Packet : {i}")
            print("[+] ###[ TCP ] ###")
            TCPpkt = pkt[TCP]
            print(f"[*] TCP Source Port : {TCPpkt.sport}")
            print(f"[*] TCP Destination Port : {TCPpkt.dport}")
            print(f"[*] TCP Seq : {TCPpkt.seq}")
            print(f"[*] TCP Ack : {TCPpkt.ack}")
            print(f"[*] TCP Dataofs : {TCPpkt.dataofs}")
            print(f"[*] TCP Reserved : {TCPpkt.reserved}")
            print(f"[*] TCP Flags : {TCPpkt.flags}")
            print(f"[*] TCP Window : {TCPpkt.window}")
            print(f"[*] TCP Chksum : {TCPpkt.chksum}")
            print(f"[*] TCP Urgptr : {TCPpkt.urgptr}")
            print(f"[*] TCP Options : {TCPpkt.options}")
            print("[*] TCP Dump :")
            print(hexdump(TCPpkt))

def pcap_analyser_udp(file):
    pkts = rdpcap(file)
    for i, pkt in enumerate(pkts, 1):
        if pkt.haslayer(UDP):
            print("-" * 40)
            print(f"[*] Packet : {i}")
            print("[+] ###[ UDP ] ###")
            UDPpkt = pkt[UDP]
            print(f"[*] UDP Source Port : {UDPpkt.sport}")
            print(f"[*] UDP Destination Port : {UDPpkt.dport}")
            print(f"[*] UDP Len : {UDPpkt.len}")
            print(f"[*] UDP Chksum : {UDPpkt.chksum}")
            print("[*] UDP Dump :")
            print(hexdump(UDPpkt))

def pcap_analyser_icmp(file):
    pkts = rdpcap(file)
    for i, pkt in enumerate(pkts, 1):
        if pkt.haslayer(ICMP):
            print("-" * 40)
            print(f"[*] Packet : {i}")
            print("[+] ###[ ICMP ] ###")
            ICMPpkt = pkt[ICMP]
            print(f"[*] ICMP Type : {ICMPpkt.type}")
            print(f"[*] ICMP Code : {ICMPpkt.code}")
            print(f"[*] ICMP Chksum : {ICMPpkt.chksum}")
            print(f"[*] ICMP Id : {ICMPpkt.id}")
            print(f"[*] ICMP Seq : {ICMPpkt.seq}")
            print("[*] ICMP Dump :")
            print(hexdump(ICMPpkt))

def main():
    parser = argparse.ArgumentParser(
        description=__description__,
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "levels with ip address:\n"
            "  scan : scan ports\n"
            "  arp : ping arp\n"
            "  icmp : ping icmp\n"
            "  tcp : ping tcp\n"
            "  udp : ping udp\n"
            "  geoip : geolocalisation\n\n"
            "levels with pcap file:\n"
            "  eth : extract ethernet headers\n"
            "  ip : extract ip headers\n"
            "  tcp : extract tcp headers\n"
            "  udp : extract udp headers\n"
            "  icmp : extract icmp headers\n"
        )
    )

    parser.add_argument("-s", "--serveur", dest="serveur", help="attack to serveur ip")
    parser.add_argument("-p", "--level", dest="level", help="stack to level")
    parser.add_argument("-d", "--sport", dest="sport", help="start port to scan")
    parser.add_argument("-t", "--eport", dest="eport", help="end port to scan")
    parser.add_argument("-f", "--file", dest="file", help="read pcap file")

    args = parser.parse_args()
    serveur = args.serveur
    file = args.file
    level = args.level
    sport = args.sport
    eport = args.eport

    try:
        if file or serveur:
            header()
            usage()
            if file and level == "eth":
                pcap_analyser_eth(file)
            elif file and level == "ip":
                pcap_analyser_ip(file)
            elif file and level == "tcp":
                pcap_analyser_tcp(file)
            elif file and level == "udp":
                pcap_analyser_udp(file)
            elif file and level == "icmp":
                pcap_analyser_icmp(file)
            elif serveur and level == "arp":
                arp_ping(serveur)
            elif serveur and level == "icmp":
                icmp_ping(serveur)
            elif serveur and level == "tcp" and sport:
                tcp_ping(serveur, sport)
            elif serveur and level == "scan" and sport and eport:
                superscan(serveur, int(sport), int(eport), flag=False)
            elif serveur and level == "scan" and not sport and not eport:
                superscan(serveur, 0, 0, flag=True)
            elif serveur and level == "udp":
                udp_ping(serveur, port=0)
            elif serveur and level == "geoip":
                geo_ip(serveur)
        else:
            print(
                "usage: CyberScan.py [-h] [-s SERVEUR] [-p LEVEL] [-d SPORT] [-t EPORT] [-f FILE]\n"
                "use cyberscan -h to help"
            )
    except KeyboardInterrupt:
        print("\n[*] You Pressed Ctrl+C. Exiting")
        sys.exit(1)

if __name__ == '__main__':
    main()