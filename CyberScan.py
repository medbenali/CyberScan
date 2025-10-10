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

import os
import sys
import platform
import argparse
import logging
# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import time
import socket
import pygeoip

# scapy and helper libs
try:
	# Try to use an installed scapy (preferred)
	from scapy.all import *
	SCAPY_AVAILABLE = True
except Exception:
	# Fallback: if a local scapy package exists, add it to path but don't import
	# immediately (the bundled copy in this repo may be Python2-only).
	SCAPY_AVAILABLE = False
	SCAPY_PATH = os.path.join(os.path.dirname(__file__), 'scapy')
	if os.path.isdir(SCAPY_PATH) and SCAPY_PATH not in sys.path:
		sys.path.insert(0, SCAPY_PATH)

	# Provide minimal stubs so the rest of the script (e.g., -h) can run.
	def srp(*a, **k):
		raise RuntimeError('scapy is not available')

	def sr(*a, **k):
		raise RuntimeError('scapy is not available')

	def rdpcap(*a, **k):
		return []

	def hexdump(*a, **k):
		return ''

	class _Layer: pass
	IP = ICMP = TCP = UDP = _Layer

from libs.colorama import *
from libs import FileUtils


if platform.system() == 'Windows':
	from libs.colorama.win32 import *

_version_ = '1.1.1'
_description_ = f'''
	___________________________________________

	CyberScan | v.{_version_}
	Author: BEN ALI Mohamed
	___________________________________________
'''

def write(string):
	# simple wrapper to ensure flushed output
	print(string, flush=True)

def header():
	VERSION = {"MAYOR_VERSION": 1, "MINOR_VERSION": 1, "REVISION": 1}
	try:
		banner_path = FileUtils.buildPath('banner.txt')
		with open(banner_path, 'r', encoding='utf-8') as f:
			program_banner = f.read().format(**VERSION)
	except Exception:
		program_banner = f"CyberScan | v.{_version_}\n"
	message = program_banner
	write(message)

def usage():
	print(''' \033[92m CyberScan v.1.1.1 http://github/medbenali/CyberScan
	It is the end user's responsibility to obey all applicable laws.
	It is just for server testing script. Your ip is visible. \n
  ___________________________________________
 
  CyberScan | v.1.1.1   
  Author: BEN ALI Mohamed
  ___________________________________________


\n \033[0m''')

def geo_ip(host):
	try:
		rawdata = pygeoip.GeoIP('GeoLiteCity.dat')
		data = rawdata.record_by_name(host)
		if not data:
			print('[*] No GeoIP data found for', host)
			return
		print(f"[*] IP Address: {host}")
		print(f"[*] City: {data.get('city')}")
		print(f"[*] Region Code: {data.get('region_code')}")
		print(f"[*] Country Name: {data.get('country_name')}")
	except Exception as e:
		print("[*] Please verify your ip !", str(e))

def icmp_ping(host):
    print(f'[*] Starting CyberScan Ping ICMP for {host}')
    # The tuple unpacking in lambda must be removed in Python 3
    ans, unans = srp(IP(dst=host)/ICMP(), verbose=0)
    ans.summary(lambda s, r: r.sprintf("%IP.src% is alive"))

def tcp_ping(host,dport):
    # The tuple unpacking in lambda must be removed in Python 3
    ans, unans = sr(IP(dst=host)/TCP(dport=int(dport),flags="S"), verbose=0)
    ans.summary(lambda s, r: r.sprintf("%IP.src% is alive"))

def udp_ping(host,port=0):
    print(f'[*] Starting CyberScan Ping UDP for {host}')
    # The tuple unpacking in lambda must be removed in Python 3
    ans, unans = sr(IP(dst=host)/UDP(dport=port), verbose=0)
    ans.summary(lambda s, r: r.sprintf("%IP.src% is alive"))

def superscan(host,start_port,end_port):
	print('[*] CyberScan Port Scanner')
	open_ports = []
	common_ports = {
		'21': 'FTP', '22': 'SSH', '23': 'TELNET', '25': 'SMTP', '53': 'DNS',
		'69': 'TFTP', '80': 'HTTP', '109': 'POP2', '110': 'POP3', '123': 'NTP',
		'137': 'NETBIOS-NS', '138': 'NETBIOS-DGM', '139': 'NETBIOS-SSN', '143': 'IMAP',
		'156': 'SQL-SERVER', '389': 'LDAP', '443': 'HTTPS', '546': 'DHCP-CLIENT',
		'547': 'DHCP-SERVER', '993': 'IMAP-SSL', '995': 'POP3-SSL', '2082': 'CPANEL',
		'2083': 'CPANEL', '2086': 'WHM/CPANEL', '2087': 'WHM/CPANEL', '3306' :'MYSQL',
		'8443': 'PLESK', '10000': 'VIRTUALMIN/WEBIN'
	}

	starting_time=time.time()
	if(flag):
		print(f"[*] Scanning For Most Common Ports On {host}")
	else:
		print(f"[*] Scanning {host} From Port {start_port} To {end_port}: ")
	
	print(f"[*] Starting CyberScan 1.01 at {time.strftime('%Y-%m-%d %H:%M %Z')}")

	def check_port(host,port,result= 1):
		try:
			sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.settimeout(0.5)
			r = sock.connect_ex((host,port))
			if r ==0:
				result = r
			sock.close()
		except Exception as e: # Python 3 exception syntax
			pass
		return result

	def get_service(port):
		port = str(port)
		if port in common_ports:
			return common_ports[port]
		else:
			return 0
	try:
		print("[*] Scan In Progress ...")
		
		# Print without newline and ensure immediate flush
		print("[*] Connecting To Port : ", end=' ', flush=True) 
		
		if flag:
			for p in sorted(common_ports):
				# Use print with end=' ' and flush=True for the real-time update effect
				p = int(p)
				print(p, end=' ', flush=True) 
				response = check_port(host,p)

				if response ==0:
					open_ports.append(p)
				
				# Write backspaces to delete the printed port number on the same line
				sys.stdout.write('\b' * (len(str(p)) + 1)) # +1 for the space ' ' in print(p, end=' ')
				sys.stdout.flush()

		else:
			for p in range(start_port,end_port+1):
				# Use print with end=' ' and flush=True for the real-time update effect
				print(p, end=' ', flush=True) 
				response = check_port(host,p)
			
				if response ==0:
					open_ports.append(p)
				
				# Write backspaces only if it's not the last port, to maintain the rolling effect
				if not p == end_port:
					# +1 for the space ' ' in print(p, end=' ')
					sys.stdout.write('\b' * (len(str(p)) + 1))
					sys.stdout.flush()

		print(f"\n[*] Scanning Completed at {time.strftime('%Y-%m-%d %H:%M %Z')}")
		ending_time = time.time()
		total_time = ending_time - starting_time
		
		if total_time <= 60:
			print(f"[*] CyberScan done: 1IP address (1host up) scanned in {total_time:.2f} seconds")
		else:
			total_time = total_time / 60
			print(f"[*] CyberScan done: 1IP address (1host up) scanned in {total_time:.2f} Minutes")


		if open_ports:
			print("[*] Open Ports: ")
			for i in sorted(open_ports):
				service = get_service(i)
				if not service:
					service= "Unknown service"
				print(f"\t{i} {service}: Open")

		else:
			print("[*] Sorry, No Open Ports Found.!!")
	
			
	except KeyboardInterrupt:
		print("\n[*] You Pressed Ctrl+C. Exiting")
		sys.exit(1)		


def pcap_analyser_eth(file):
	pkts = rdpcap(file)
	i=0
	for pkt in pkts:
		i += 1
		print("-" * 40)
		print(f"[*] Packet : {i}")
		print("[+] ### [ Ethernet ] ###")
		print(f"[*] Mac Destination : {pkt.dst}")
		print(f"[*] Mac Source : {pkt.src}")
		print(f"[*] Ethernet Type : {pkt.type}")
          
def pcap_analyser_ip(file):
	pkts = rdpcap(file)
	i=0
	for pkt in pkts:
	
		if pkt.haslayer(IP):
			i += 1
			print("-" * 40)
			print(f"[*] Packet : {i}")
			print("[+] ###[ IP ] ###")
			IPpkt = pkt[IP]
			srcIP = IPpkt.fields['src']
			dstIP = IPpkt.fields['dst']
			print(f"[*] IP Source : {srcIP}")
			print(f"[*] IP Destination : {dstIP}")
			verIP = IPpkt.version
			print("[*] IP Version : ", verIP)
			ihlIP = IPpkt.ihl
			print("[*] IP Ihl : ", ihlIP)
			tosIP = IPpkt.tos
			print("[*] IP Tos : ", tosIP)
			lenIP = IPpkt.len
			print("[*] IP Len : ", lenIP)
			idIP = IPpkt.id	
			print("[*] IP Id : ", idIP)
			flagsIP = IPpkt.flags
			print("[*] IP Flags : ", flagsIP)
			fragIP = IPpkt.frag
			print("[*] IP Frag : ", fragIP)
			ttlIP = IPpkt.ttl
			print("[*] IP Ttl : ", ttlIP)
			protoIP = IPpkt.proto
			print("[*] IP Protocol : ", protoIP)
			chksumIP = IPpkt.chksum
			print("[*] IP Chksum : ", chksumIP)
			optionsIP = IPpkt.options
			print("[*] IP Options : ", optionsIP)
			print("[*] IP Dump : ") 
			print(hexdump(IPpkt))

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
			print(f"[*] Packet : {i}")
			print("[+] ###[ TCP ] ###")
			TCPpkt = pkt[TCP]
			sportTCP = TCPpkt.sport
			print("[*] TCP Source Port : ", sportTCP)
			dportTCP = TCPpkt.dport
			print("[*] TCP Destination Port : ", dportTCP)
			seqTCP = TCPpkt.seq
			print("[*] TCP Seq : ", seqTCP)
			ackTCP = TCPpkt.ack
			print("[*] TCP Ack : ", ackTCP)
			dataofsTCP = TCPpkt.dataofs
			print("[*] TCP Dataofs : ", dataofsTCP)
			reservedTCP = TCPpkt.reserved
			print("[*] TCP Reserved : ", reservedTCP)
			flagsTCP = TCPpkt.flags
			print("[*] TCP Flags : ", flagsTCP)
			windowTCP = TCPpkt.window
			print("[*] TCP Window : ", windowTCP)
			chksumTCP = TCPpkt.chksum
			print("[*] TCP Chksum : ", chksumTCP)
			urgptrTCP = TCPpkt.urgptr
			print("[*] TCP Urgptr : ", urgptrTCP)
			optionsTCP = TCPpkt.options
			print("[*] TCP Options : ", optionsTCP)

			# Interpret flags using bitwise checks (more robust than equality)
			nbrsyn = 1 if (flagsTCP & SYN) != 0 else 0
			nbrrst = 1 if (flagsTCP & RST) != 0 else 0
			nbrack = 1 if (flagsTCP & ACK) != 0 else 0
			nbrfin = 1 if (flagsTCP & FIN) != 0 else 0
			nbrurg = 1 if (flagsTCP & URG) != 0 else 0
			nbrpsh = 1 if (flagsTCP & PSH) != 0 else 0

			if nbrsyn:
				print("[*] TCP SYN FLAGS : ", nbrsyn)
			if nbrrst:
				print("[*] TCP RST FLAGS : ", nbrrst)
			if nbrack:
				print("[*] TCP ACK FLAGS : ", nbrack)
			if nbrfin:
				print("[*] TCP FIN FLAGS : ", nbrfin)
			if nbrurg:
				print("[*] TCP URG FLAGS : ", nbrurg)
			if nbrpsh:
				print("[*] TCP PSH FLAGS : ", nbrpsh)

			print("[*] TCP Dump : ")
			print(hexdump(TCPpkt))


def pcap_analyser_udp(file):
	pkts = rdpcap(file)
	i = 0
	for pkt in pkts:
		if pkt.haslayer(UDP):
			i += 1
			print("-" * 40)
			print(f"[*] Packet : {i}")
			print("[+] ###[ UDP ] ###")
			UDPpkt = pkt[UDP]
			sportUDP = UDPpkt.sport
			print("[*] UDP Source Port : ", sportUDP)
			dportUDP = UDPpkt.dport
			print("[*] UDP Destination Port : ", dportUDP)
			lenUDP = UDPpkt.len
			print("[*] UDP Len : ", lenUDP)
			chksumUDP = UDPpkt.chksum
			print("[*] UDP Chksum : ", chksumUDP)
			print("[*] UDP Dump : ")
			print(hexdump(UDPpkt))


def pcap_analyser_icmp(file):
	pkts = rdpcap(file)
	i = 0
	for pkt in pkts:
		if pkt.haslayer(ICMP):
			i += 1
			print("-" * 40)
			print(f"[*] Packet : {i}")
			print("[+] ###[ ICMP ] ###")
			ICMPpkt = pkt[ICMP]
			typeICMP = ICMPpkt.type
			print("[*] ICMP Type : ", typeICMP)
			codeICMP = ICMPpkt.code
			print("[*] ICMP Code : ", codeICMP)
			chksumICMP = ICMPpkt.chksum
			print("[*] ICMP Chksum : ", chksumICMP)
			idICMP = ICMPpkt.id
			print("[*] ICMP Id : ", idICMP)
			seqICMP = ICMPpkt.seq
			print("[*] ICMP Seq : ", seqICMP)
			print("[*] ICMP Dump : ")
			print(hexdump(ICMPpkt))


def main():

	global serveur
	global level
	global sport
	global eport
	global file
	global flag
	flag = 0

	# Construct the argument parser
	parser = argparse.ArgumentParser(
		description=_description_,
		formatter_class=argparse.RawTextHelpFormatter,
		epilog=('''\
levels with ip adress:
  scan : scan ports
  arp : ping arp
  icmp : ping arp
  tcp : ping tcp
  udp : ping udp
  geoip : geolocalisation

levels with pcap file:
  eth : extract ethernet headers
  ip  : extract ip headers
  tcp : extract tcp headers
  udp : extract udp headers
  icmp: extract icmp headers

					''')
	)

	parser.add_argument('-v', '--version', action='version', version=_version_)
	parser.add_argument('-s', '--serveur', dest='serveur', help='attack to serveur ip')
	parser.add_argument('-p', '--level', dest='level', help='stack to level')
	parser.add_argument('-d', '--sport', dest='sport', help='start port to scan')
	parser.add_argument('-t', '--eport', dest='eport', help='end port to scan')
	parser.add_argument('-f', '--file', dest='file', help='read pcap file')

	try:
		args = parser.parse_args()
		serveur = args.serveur
		file = args.file
		level = args.level
		sport = args.sport
		eport = args.eport

		if file is not None or serveur is not None:
			header()
			usage()

			# pcap file based operations
			if file and level == 'eth':
				pcap_analyser_eth(file)
			elif file and level == 'ip':
				pcap_analyser_ip(file)
			elif file and level == 'tcp':
				pcap_analyser_tcp(file)
			elif file and level == 'udp':
				pcap_analyser_udp(file)
			elif file and level == 'icmp':
				pcap_analyser_icmp(file)

			# live network based operations
			elif serveur is not None and level == 'arp':
				arp_ping(serveur)
			elif serveur is not None and level == 'icmp':
				icmp_ping(serveur)
			elif serveur is not None and level == 'tcp' and sport is not None:
				port = sport
				tcp_ping(serveur, port)
			elif serveur is not None and level == 'scan' and sport is not None and eport is not None:
				start_port = int(sport)
				end_port = int(eport)
				flag = 0
				superscan(serveur, start_port, end_port)
			elif serveur is not None and level == 'scan' and sport is None and eport is None:
				# scan most common ports
				start_port = 0
				end_port = 0
				flag = 1
				superscan(serveur, start_port, end_port)
			elif serveur is not None and level == 'udp':
				udp_ping(serveur, port=0)
			elif serveur is not None and level == 'geoip':
				geo_ip(serveur)
		else:
			print('''usage: CyberScan.py [-h] [-s SERVEUR] [-p LEVEL] [-d SPORT] [-t EPORT]
					[-f FILE]
use cyberscan -h to help ''')

	except KeyboardInterrupt:
		print('\n[*] You Pressed Ctrl+C. Exiting')
		sys.exit(1)


if __name__ == '__main__':
	main()
