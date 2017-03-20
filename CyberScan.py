#!/usr/bin/python
# -*- coding utf-8 -*-
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
import time
import socket

from scapy.all import *
from optparse import OptionParser
from libs.colorama import *
from libs import FileUtils


if platform.system() == 'Windows':
    from libs.colorama.win32 import *

__version__ = '1.1'
__description__ = '''\
  ___________________________________________

  CyberScan | v.''' + __version__ + '''
  Author: BEN ALI Mohamed
  ___________________________________________
'''


def header():
    MAYOR_VERSION = 1
    MINOR_VERSION = 1
    REVISION = 0
    VERSION = {
	"MAYOR_VERSION": MAYOR_VERSION,
	"MINOR_VERSION": MINOR_VERSION,
	"REVISION": REVISION
    }

    PROGRAM_BANNER = open(FileUtils.buildPath("banner.txt")).read().format(**VERSION)
    message = Style.BRIGHT + Fore.MAGENTA + PROGRAM_BANNER + Style.RESET_ALL
    write(message)


def usage():
	print (''' \033[92m CyberScan v.1 http://github/medbenali/CyberScan
	It is the end user's responsibility to obey all applicable laws.
	It is just for server testing script. Your ip is visible. \n
	usage : python CyberScan.py [-s] [-p] [-d]
        -h : help
	-s : server ip
	-p : port default 80
	-d : turbo default 135 
	
	Test Network Connection With Ping :
	arp : ARP Ping   Ex : CyberScan -s 192.168.1.0/24 -p arp
	icmp : ICMP Ping Ex : CyberScan -s 192.168.1.1-254 -p icmp 
	tcp : TCP Ping Ex :  
	
	\n \033[0m''')
	


def write(string):
    if platform.system() == 'Windows':
	sys.stdout.write(string)
        sys.stdout.flush()
	sys.stdout.write('\n')
	sys.stdout.flush()
    else:
	sys.stdout.write(string + '\n')
    sys.stdout.flush()
    sys.stdout.flush()



def arp_ping(host):
    print '[*] Starting Ping ARP for %s' %(host)
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=host), timeout=2)
    ans.summary(lambda (s,r): r.sprintf("%Ether.src% %ARP.psrc%"))

def icmp_ping(host):
    print '[*] Starting Ping ICMP for %s' %(host)
    ans, unans =srp(IP(dst=host)/ICMP())
    ans.summary(lambda (s,r): r.sprint("%IP.src% is alive"))

def tcp_ping(host,dport):
    ans, unans = sr(IP(dst=host)/TCP(dport,flags="S"))
    ans.summary(lambda (s,r): r.sprintf("%IP.src% is alive"))

def udp_ping(host,port=0):
    print '[*] Starting Ping UDP for %s' %(host)
    ans, unans = sr(IP(dst=host)/UDP(dport=port))
    ans.summary(lambda(s, r): r.sprintf("%IP.src% is alive"))

def superscan(host,start_port,end_port):
	print "super scan"
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
		'3306' :'MYSQL',
		'8443': 'PLESK',
		'10000': 'VIRTUALMIN/WEBIN'
		
	
	}

	starting_time=time.time()
	if(flag):
		print "Scanning For Most Common Ports On %s" % (host)
	else:
		print "Scanning %s From Port %s To %s: " % (host,start_port,end_port)
	print "Starting CyberScan 1.01 at %s" %(time.strftime("%Y-%m-%d %H:%M %Z"))
	def check_port(host,port,result= 1):
		try:
			sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.settimeout(0.5)
			r = sock.connect_ex((host,port))
			if r ==0:
				result = r
			sock.close()
		except Exception, e:
			pass
		return result

	def get_service(port):
		port = str(port)
		if port in common_ports:
			return common_ports[port]
		else:
			return 0
	try:
		print "Scan In Progress ..."
		print "Connecting To Port : ",
		
		if flag:
			for p in sorted(common_ports):
				sys.stdout.flush()
				p = int(p)
				print p,
				response = check_port(host,p)

				if response ==0:
					open_ports.append(p)

					sys.stdout.write('\b' * len(str(p)))

	
		else:
			for p in range(start_port,end_port+1):
				sys.stdout.flush()
				print p,
				response = check_port(host,p)
			
				if response ==0:
					open_ports.append(p)
				if not p == end_port:
					sys.stdout.write('\b' * len(str(p)))

		print "\nScanning Completed at %s" %(time.strftime("%Y-%m-%d %H:%M %Z"))
		ending_time = time.time()
		total_time = ending_time - starting_time
		
		if total_time <=60:
			print "CyberScan done: 1IP address (1host up) scanned in %s seconds" %(total_time)

		else:
			total_time = total_time / 60
			print "CyberScan done: 1IP address (1host up) scanned in %s Minutes" %(total_time)


		if open_ports:
			print "Open Ports: "
			for i in sorted(open_ports):
				service = get_service(i)
				if not service:
					service= "Unknown service"
				print "\t%s %s: Open" % (i,service)

		else:
			print "Sorry, No Open Ports Found.!!"
	
			
	except KeyboardInterrupt:
		print "You Pressed Ctrl+C. Exiting"
		sys.exit(1)		


def pcap_analyser_eth(file):
	pkts = rdpcap(file)
	i=0
	for pkt in pkts:
		i += 1
		print "-" * 40
		print "[*] Packet : " + str(i)
		print "[+] ### [ Ethernet ] ###"
		print "[*] Mac Destination : " + pkt.dst
		print "[*] Mac Source : " + pkt.src
		print "[*] Ethernet Type : " + str(pkt.type)


def pcap_analyser_ip(file):
	pkts = rdpcap(file)
	i=0
	for pkt in pkts:
	
		if pkt.haslayer(IP):
			i += 1
			print "-" * 40
			print "[*] Packet : " + str(i)
			print "[+] ###[ IP ] ###"
			IPpkt = pkt[IP]
			srcIP = IPpkt.fields['src']
			dstIP = IPpkt.fields['dst']
			print "[*] IP Source : " + srcIP
			print "[*] IP Destination : " + dstIP
			verIP = IPpkt.version
			print "[*] IP Version : " ,verIP
			ihlIP = IPpkt.ihl
			print "[*] IP Ihl : " ,ihlIP
			tosIP = IPpkt.tos
			print "[*] IP Tos : " ,tosIP
			lenIP = IPpkt.len
			print "[*] IP Len : " ,lenIP
			idIP = IPpkt.id	
			print "[*] IP Id : " ,idIP
			flagsIP = IPpkt.flags
			print "[*] IP Flags : " ,flagsIP
			fragIP = IPpkt.frag
			print "[*] IP Frag : " ,fragIP
			ttlIP = IPpkt.ttl
			print "[*] IP Ttl : " ,ttlIP
			protoIP = IPpkt.proto
			print "[*] IP Protocol : " ,protoIP
			chksumIP = IPpkt.chksum
			print "[*] IP Chksum : " ,chksumIP
			optionsIP = IPpkt.options
			print "[*] IP Options : " ,optionsIP

def pcap_analyser_tcp(file):
	pkts = rdpcap(file)
	i=0
	for pkt in pkts:
			
		if pkt.haslayer(TCP):
			i += 1
			print "-" * 40
			print "[*] Packet : " + str(i)
			print "[+] ###[ TCP ] ###"
			TCPpkt = pkt[TCP]
			sportTCP = TCPpkt.sport
			print "[*] TCP Source Port : " ,sportTCP
			dportTCP = TCPpkt.dport
			print "[*] TCP Destination Port : " ,dportTCP
			seqTCP = TCPpkt.seq
			print "[*] TCP Seq : " ,seqTCP
			ackTCP = TCPpkt.ack
			print "[*] TCP Ack : " ,ackTCP
			dataofsTCP = TCPpkt.dataofs
			print "[*] TCP Dataofs : " ,dataofsTCP
			reservedTCP = TCPpkt.reserved
			print "[*] TCP Reserved : " ,reservedTCP
			flagsTCP = TCPpkt.flags
			print "[*] TCP Flags : " ,flagsTCP
			windowTCP = TCPpkt.window
			print "[*] TCP Window : " ,windowTCP
			chksumTCP = TCPpkt.chksum
			print "[*] TCP Chksum : " ,chksumTCP
			urgptrTCP = TCPpkt.urgptr
			print "[*] TCP Urgptr : " ,urgptrTCP
			optionsTCP = TCPpkt.options
			print "[*] TCP Options : " ,optionsTCP	

def pcap_analyser_udp(file):
	pkts = rdpcap(file)
	i=0
	for pkt in pkts:
		
		if pkt.haslayer(UDP):
			i += 1
			print "-" * 40
			print "[*] Packet : " + str(i)
			print "[+] ###[ UDP ] ###"
			UDPpkt = pkt[UDP]
			sportUDP = UDPpkt.sport
			print "[*] UDP Source Port : " ,sportUDP
			dportUDP = UDPpkt.dport
			print "[*] UDP Destination Port : " ,dportUDP
			lenUDP = UDPpkt.len
			print "[*] UDP Len : " ,lenUDP
			chksumUDP = UDPpkt.chksum
			print "[*] UDP Chksum : " ,chksumUDP


def pcap_analyser_icmp(file):
	pkts = rdpcap(file)
	i=0
	for pkt in pkts:

		if pkt.haslayer(ICMP):
			i += 1
			print "-" * 40
			print "[*] Packet : " + str(i)	
			print "[+] ###[ ICMP ] ###"
			ICMPpkt = pkt[ICMP]
			typeICMP = ICMPpkt.type
			print "[*] ICMP Type : " ,typeICMP
			codeICMP = ICMPpkt.code	
			print "[*] ICMP Code : " ,codeICMP
			chksumICMP = ICMPpkt.chksum
			print "[*] ICMP Chksum : " ,chksumICMP
			idICMP = ICMPpkt.id
			print "[*] ICMP Id : " ,idICMP
			seqICMP = ICMPpkt.seq
			print "[*] ICMP Seq : " ,seqICMP		


def main():
	header()
	usage()
        

	global serveur
	global level
	global sport
	global eport
	global file
	global flag
	flag=0
	

	optp = OptionParser(add_help_option=False,epilog="CyberScan")
	optp.add_option("-q","--quiet", help="set logging to ERROR",action="store_const", dest="loglevel",const=logging.ERROR,default=logging.INFO)
	optp.add_option("-s","--serveur", dest="serveur",help="attack to serveur ip -s")
	optp.add_option("-p","--level",dest="level",help="stack to level")
	optp.add_option("-d","--sport",dest="sport",help="-start port")
	optp.add_option("-t","--eport",dest="eport",help="-end_port")
	optp.add_option("-f", "--file", dest="file",
                      help="read pcap file")
	optp.add_option("-h","--help",dest="help",action="store_true",help="help you")
	
	opts, args = optp.parse_args()
	if opts.help:
	    print "help"
	    #usage()
	if opts.file and opts.level == "eth":
		file=opts.file
		pcap_analyser_eth(file)
	elif opts.file and opts.level == "ip":
		file=opts.file
		pcap_analyser_ip(file)
	elif opts.file and opts.level == "tcp":
		file=opts.file
		pcap_analyser_tcp(file)
	elif opts.file and opts.level == "udp":
		file=opts.file
		pcap_analyser_udp(file)	
	if opts.serveur is not None:
	    serveur = opts.serveur
	if opts.level == "arp":
            level = opts.level
	    arp_ping(serveur)	
	elif opts.level == "icmp":
	    level = opts.serveur
	    icmp_ping(serveur)

	elif opts.level == "tcp" and opts.sport is not None:
	    level = opts.serveur
	    port = opts.sport
	    tcp_ping(serveur,port)
	
	elif opts.level == "Scan" and opts.sport is not None and opts.eport is not None:
	    level = opts.serveur
	    start_port = int(opts.sport)
	    end_port = int(opts.eport)
	    flag = 0
	    print "flage0"
	    superscan(serveur,start_port,end_port)

	elif opts.level == "Scan" and opts.sport is None and opts.eport is None:
	    level = opts.serveur
	    start_port = int(opts.sport)
	    end_port = int(opts.eport)
	    flag=1
	    print "flag1"
	    superscan(serveur,start_port,end_port)
	
	elif opts.serveur is not None and opts.level == "udp":
	    level = opts.serveur
	    #port = 0
	    udp_ping(serveur,port=0)
	    
		
	    



	elif opts.level == "level2":
	    level = opts.level
	    print "level 2" + level

	
	

	

	


if __name__ == '__main__':
    main()
    
    	


