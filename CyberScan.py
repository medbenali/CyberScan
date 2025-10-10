#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  CyberScan (Python3 port & fixes)
#  Author (original): Mohamed BEN ALI
#  Port & fixes: ChatGPT
#
#  Converted to Python 3 and adapted to use scapy_local package name.
#

import os
import sys
import platform
import argparse
import logging

from scapy.layers.inet import ICMP, IP, TCP, UDP

from scapy_local.layers.l2 import ARP, Ether
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import time
import socket

# pygeoip is optional; if not installed geo_ip will print an error.
try:
    import pygeoip
except Exception:
    pygeoip = None

# Use your local renamed scapy package
from scapy import *
from scapy.all import *

# libs (assumed to be in your project)
from libs.colorama import *
from libs import FileUtils

if platform.system() == 'Windows':
    try:
        from libs.colorama.win32 import *
    except Exception:
        pass

__version__ = '1.1.1'
__description__ = '''\
  ___________________________________________

  CyberScan | v.''' + __version__ + '''
  Author: BEN ALI Mohamed
  ___________________________________________
'''


def write(string: str):
    """Cross-platform safe write."""
    try:
        if platform.system() == 'Windows':
            # On Windows, avoid issues with flush/newline differences
            sys.stdout.write(string)
            sys.stdout.flush()
            sys.stdout.write('\n')
            sys.stdout.flush()
        else:
            sys.stdout.write(string + '\n')
            sys.stdout.flush()
    except Exception:
        # Fallback
        print(string)


def header():
    MAYOR_VERSION = 1
    MINOR_VERSION = 1
    REVISION = 1
    VERSION = {
        "MAYOR_VERSION": MAYOR_VERSION,
        "MINOR_VERSION": MINOR_VERSION,
        "REVISION": REVISION
    }

    try:
        PROGRAM_BANNER = open(FileUtils.buildPath('banner.txt'), 'r', encoding='utf-8').read().format(**VERSION)
    except Exception:
        PROGRAM_BANNER = "CyberScan v.{MAYOR_VERSION}.{MINOR_VERSION}.{REVISION}".format(**VERSION)

    message = Style.BRIGHT + Fore.RED + PROGRAM_BANNER + Style.RESET_ALL
    write(message)


def usage():
    print('''\033[92m CyberScan v.1.1.1 http://github/medbenali/CyberScan
It is the end user's responsibility to obey all applicable laws.
It is just for server testing script. Your ip is visible.

  ___________________________________________

  CyberScan | v.1.1.1
  Author: BEN ALI Mohamed
  ___________________________________________

\033[0m''')


def geo_ip(host: str):
    if pygeoip is None:
        print("[*] pygeoip not installed. Install with `pip install pygeoip` to enable geo IP lookup.")
        return

    try:
        rawdata = pygeoip.GeoIP('GeoLiteCity.dat')
        data = rawdata.record_by_name(host)
        if not data:
            print("[*] No geo data found for IP/host:", host)
            return

        country = data.get('country_name')
        city = data.get('city')
        longi = data.get('longitude')
        lat = data.get('latitude')
        time_zone = data.get('time_zone')
        area_code = data.get('area_code')
        country_code = data.get('country_code')
        region_code = data.get('region_code')
        dma_code = data.get('dma_code')
        metro_code = data.get('metro_code')
        country_code3 = data.get('country_code3')
        zip_code = data.get('postal_code')
        continent = data.get('continent')

        print('[*] IP Address:', host)
        print('[*] City:', city)
        print('[*] Region Code:', region_code)
        print('[*] Area Code:', area_code)
        print('[*] Time Zone:', time_zone)
        print('[*] Dma Code:', dma_code)
        print('[*] Metro Code:', metro_code)
        print('[*] Latitude:', lat)
        print('[*] Longitude:', longi)
        print('[*] Zip Code:', zip_code)
        print('[*] Country Name:', country)
        print('[*] Country Code:', country_code)
        print('[*] Country Code3:', country_code3)
        print('[*] Continent:', continent)

    except Exception as exc:
        print("[*] Please verify your ip ! Error:", exc)


def arp_ping(host: str):
    print('[*] Starting CyberScan Ping ARP for {}'.format(host))
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host), timeout=2, verbose=0)
    # ans is a list-like of (sent, received) pairs
    if len(ans) == 0:
        print("[*] No ARP replies.")
    for s, r in ans:
        try:
            print(r.sprintf("%Ether.src% %ARP.psrc%"))
        except Exception:
            print(r.summary())


def icmp_ping(host: str):
    print('[*] Starting CyberScan Ping ICMP for {}'.format(host))
    # Use sr for ICMP echo request; sr returns (ans, unans)
    ans, unans = sr(IP(dst=host) / ICMP(), timeout=2, verbose=0)
    if len(ans) == 0:
        print("[*] No ICMP replies.")
    for s, r in ans:
        try:
            # r is response packet
            print("{} is alive".format(r.src))
        except Exception:
            print(r.summary())


def tcp_ping(host: str, dport: int):
    print('[*] Starting CyberScan Ping TCP SYN for {}:{}'.format(host, dport))
    try:
        pkt = IP(dst=host) / TCP(dport=int(dport), flags="S")
        ans, unans = sr(pkt, timeout=2, verbose=0)
        if len(ans) == 0:
            print("[*] No TCP replies.")
        for s, r in ans:
            try:
                print("{} is alive".format(r.src))
            except Exception:
                print(r.summary())
    except Exception as exc:
        print("[*] tcp_ping error:", exc)


def udp_ping(host: str, port: int = 0):
    print('[*] Starting CyberScan Ping UDP for {}:{}'.format(host, port))
    try:
        pkt = IP(dst=host) / UDP(dport=int(port))
        ans, unans = sr(pkt, timeout=2, verbose=0)
        if len(ans) == 0:
            print("[*] No UDP replies.")
        for s, r in ans:
            try:
                print("{} is alive".format(r.src))
            except Exception:
                print(r.summary())
    except Exception as exc:
        print("[*] udp_ping error:", exc)


def superscan(host: str, start_port: int, end_port: int):
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

    starting_time = time.time()
    if flag:
        print("[*] Scanning For Most Common Ports On {}".format(host))
    else:
        print("[*] Scanning {} From Port {} To {}: ".format(host, start_port, end_port))
    print("[*] Starting CyberScan 1.01 at {}".format(time.strftime("%Y-%m-%d %H:%M %Z")))

    def check_port(host_inner: str, port_inner: int):
        result = 1
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            r = sock.connect_ex((host_inner, int(port_inner)))
            if r == 0:
                result = 0
            sock.close()
        except Exception:
            pass
        return result

    def get_service(port_inner: int):
        p = str(port_inner)
        return common_ports.get(p, None)

    try:
        print("[*] Scan In Progress ...")
        print("[*] Connecting To Port : ", end='', flush=True)

        if flag:
            for p in sorted(map(int, common_ports.keys())):
                sys.stdout.flush()
                print(p, end=' ', flush=True)
                response = check_port(host, p)
                if response == 0:
                    open_ports.append(p)
        else:
            for p in range(int(start_port), int(end_port) + 1):
                sys.stdout.flush()
                print(p, end=' ', flush=True)
                response = check_port(host, p)
                if response == 0:
                    open_ports.append(p)

        print("\n[*] Scanning Completed at {}".format(time.strftime("%Y-%m-%d %H:%M %Z")))
        ending_time = time.time()
        total_time = ending_time - starting_time
        if total_time <= 60:
            print("[*] CyberScan done: 1 IP address (1 host up) scanned in {:.2f} seconds".format(total_time))
        else:
            total_time = total_time / 60
            print("[*] CyberScan done: 1 IP address (1 host up) scanned in {:.2f} Minutes".format(total_time))

        if open_ports:
            print("[*] Open Ports:")
            for i in sorted(open_ports):
                service = get_service(i) or "Unknown service"
                print("\t{} {}: Open".format(i, service))
        else:
            print("[*] Sorry, No Open Ports Found.!!")

    except KeyboardInterrupt:
        print("\n[*] You Pressed Ctrl+C. Exiting")
        sys.exit(1)


def pcap_analyser_eth(file: str):
    pkts = rdpcap(file)
    i = 0
    for pkt in pkts:
        i += 1
        print("-" * 40)
        print("[*] Packet : {}".format(i))
        print("[+] ### [ Ethernet ] ###")
        try:
            print("[*] Mac Destination : {}".format(pkt.dst))
            print("[*] Mac Source : {}".format(pkt.src))
            print("[*] Ethernet Type : {}".format(pkt.type))
        except Exception:
            print(pkt.summary())


def pcap_analyser_ip(file: str):
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
            print(hexdump(IPpkt, dump=True))


def pcap_analyser_tcp(file: str):
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
            print("[*] TCP Source Port : {}".format(TCPpkt.sport))
            print("[*] TCP Destination Port : {}".format(TCPpkt.dport))
            print("[*] TCP Seq : {}".format(TCPpkt.seq))
            print("[*] TCP Ack : {}".format(TCPpkt.ack))
            print("[*] TCP Dataofs : {}".format(TCPpkt.dataofs))
            print("[*] TCP Reserved : {}".format(TCPpkt.reserved))
            print("[*] TCP Flags : {}".format(TCPpkt.flags))
            print("[*] TCP Window : {}".format(TCPpkt.window))
            print("[*] TCP Chksum : {}".format(TCPpkt.chksum))
            print("[*] TCP Urgptr : {}".format(TCPpkt.urgptr))
            print("[*] TCP Options : {}".format(TCPpkt.options))
            FlagsTCP = int(pkt[TCP].flags)
            if FlagsTCP & SYN:
                print("[*] TCP SYN FLAGS : 1")
            if FlagsTCP & RST:
                print("[*] TCP RST FLAGS : 1")
            if FlagsTCP & ACK:
                print("[*] TCP ACK FLAGS : 1")
            if FlagsTCP & FIN:
                print("[*] TCP FIN FLAGS : 1")
            if FlagsTCP & URG:
                print("[*] TCP URG FLAGS : 1")
            if FlagsTCP & PSH:
                print("[*] TCP PSH FLAGS : 1")
            print("[*] TCP Dump : ")
            print(hexdump(TCPpkt, dump=True))


def pcap_analyser_udp(file: str):
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
            print(hexdump(UDPpkt, dump=True))


def pcap_analyser_icmp(file: str):
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
            print(hexdump(ICMPpkt, dump=True))


def main():
    global serveur
    global level
    global sport
    global eport
    global file
    global flag
    flag = 0

    try:
        parser = argparse.ArgumentParser(description=__description__, formatter_class=argparse.RawTextHelpFormatter, epilog='''\
levels with ip adress:
  scan : scan ports
  arp : ping arp
  icmp : ping icmp
  tcp : ping tcp
  udp : ping udp
  geoip : geolocalisation

levels with pcap file:
  eth : extract ethernet headers
  ip : extract 	ip headers
  tcp : extract tcp headers
  udp : extract udp headers
  icmp : extract icmp headers

                    ''')

        parser.add_argument("-s", "--serveur", dest="serveur", help="attack to serveur ip")
        parser.add_argument("-p", "--level", dest="level", help="stack to level")
        parser.add_argument("-d", "--sport", dest="sport", help="start port to scan")
        parser.add_argument("-t", "--eport", dest="eport", help="end port to scan")
        parser.add_argument("-f", "--file", dest="file", help="read pcap file")
        parser.add_argument("--version", action="version", version=__version__)

        args = parser.parse_args()
        serveur = args.serveur
        file = args.file
        level = args.level
        sport = args.sport
        eport = args.eport

        if file is not None or serveur is not None:
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
            elif serveur is not None and level == "arp":
                arp_ping(serveur)
            elif serveur is not None and level == "icmp":
                icmp_ping(serveur)
            elif serveur is not None and level == "tcp" and sport is not None:
                tcp_ping(serveur, sport)
            elif serveur is not None and level == "scan" and sport is not None and eport is not None:
                start_port = int(sport)
                end_port = int(eport)
                flag = 0
                superscan(serveur, start_port, end_port)
            elif serveur is not None and level == "scan" and sport is None and eport is None:
                start_port = 0
                end_port = 0
                flag = 1
                superscan(serveur, start_port, end_port)
            elif serveur is not None and level == "udp":
                udp_ping(serveur, port=0)
            elif serveur is not None and level == "geoip":
                geo_ip(serveur)
            else:
                print("No matching action. Use -h for help.")
        else:
            print('''usage: CyberScan.py [-h] [-s SERVEUR] [-p LEVEL] [-d SPORT] [-t EPORT] [-f FILE]
use cyberscan -h to help ''')

    except KeyboardInterrupt:
        print("\n[*] You Pressed Ctrl+C. Exiting")
        sys.exit(1)
    except Exception as exc:
        print("An error occurred:", exc)
        # For debugging uncomment next line:
        # import traceback; traceback.print_exc()


if __name__ == '__main__':
    main()
