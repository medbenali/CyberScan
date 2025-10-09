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
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import time
import socket
import pygeoip

#new imports
import urllib2
import re
import urllib
import json
import csv

from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy import *
from scapy.all import *
from libs.colorama import *
from libs import FileUtils


output_file = args.output

if platform.system() == 'Windows':
    from libs.colorama.win32 import *

__version__ = '1.1.1'
__description__ = '''\
  ___________________________________________

  CyberScan | v.''' + __version__ + '''
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

    PROGRAM_BANNER = open(FileUtils.buildPath('banner.txt')).read().format(**VERSION)
    message = Style.BRIGHT + Fore.RED + PROGRAM_BANNER + Style.RESET_ALL
    write(message)

#new write function
def write(string):
    sys.stdout.write(string + '\n')
    sys.stdout.flush()
    sys.stdout.flush()

def usage():
	print (''' \033[92m CyberScan v.1.1.1 http://github/medbenali/CyberScan
	It is the end user's responsibility to obey all applicable laws.
	It is just for server testing script. Your ip is visible. \n
	  ___________________________________________
	 
 	  CyberScan | v.1.1.1   
	  Author: BEN ALI Mohamed
 	  ___________________________________________

levels with ip adress:
  scan : scan ports
  arp : ping arp
  icmp : ping arp
  tcp : ping tcp
  udp : ping udp
  geoip : geolocalisation
  subdomain : subdomain enumeration using dnsdumpster.com

levels with pcap file:
  eth : extract ethernet headers
  ip : extract 	ip headers
  tcp : extract tcp headers
  udp : extract udp headers
  icmp : extract icmp headers

	\n \033[0m''')

def geo_ip(host):

    try:

       rawdata = pygeoip.GeoIP('GeoLiteCity.dat')
       data = rawdata.record_by_name(host)	
       country = data['country_name']
       city = data['city']
       longi = data['longitude']
       lat = data['latitude']
       time_zone = data['time_zone']
       area_code = data['area_code']
       country_code = data['country_code']
       region_code = data['region_code']
       dma_code = data['dma_code']
       metro_code = data['metro_code']
       country_code3 = data['country_code3']
       zip_code = data['postal_code']
       continent = data['continent']

       print '[*] IP Address: ',host
       print '[*] City: ',city
       print '[*] Region Code: ',region_code
       print '[*] Area Code: ',area_code
       print '[*] Time Zone: ',time_zone
       print '[*] Dma Code: ',dma_code
       print '[*] Metro Code: ',metro_code
       print '[*] Latitude: ',lat
       print '[*] Longitude: ',longi
       print '[*] Zip Code: ',zip_code
       print '[*] Country Name: ',country
       print '[*] Country Code: ',country_code
       print '[*] Country Code3: ',country_code3
       print '[*] Continent: ',continent

    except :
           print "[*] Please verify your ip !"
	   	

    	
def arp_ping(host):
    print '[*] Starting CyberScan Ping ARP for %s' %(host)
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=host), timeout=2)
    ans.summary(lambda (s,r): r.sprintf("%Ether.src% %ARP.psrc%"))

def icmp_ping(host):
    print '[*] Starting CyberScan Ping ICMP for %s' %(host)
    ans, unans =srp(IP(dst=host)/ICMP())
    ans.summary(lambda (s,r): r.sprint("%IP.src% is alive"))

def tcp_ping(host,dport):
    ans, unans = sr(IP(dst=host)/TCP(dport,flags="S"))
    ans.summary(lambda (s,r): r.sprintf("%IP.src% is alive"))

def udp_ping(host,port=0):
    print '[*] Starting CyberScan Ping UDP for %s' %(host)
    ans, unans = sr(IP(dst=host)/UDP(dport=port))
    ans.summary(lambda(s, r): r.sprintf("%IP.src% is alive"))

from concurrent.futures import ThreadPoolExecutor, as_completed

#Updated superscan function with threading and output options
import json
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

def superscan(host, start_port, end_port, max_threads=100, output_file=None):
    print '[*] CyberScan Threaded Port Scanner'
    open_ports = []
    common_ports = {
        '21': 'FTP', '22': 'SSH', '23': 'TELNET', '25': 'SMTP', '53': 'DNS',
        '69': 'TFTP', '80': 'HTTP', '109': 'POP2', '110': 'POP3', '123': 'NTP',
        '137': 'NETBIOS-NS', '138': 'NETBIOS-DGM', '139': 'NETBIOS-SSN',
        '143': 'IMAP', '156': 'SQL-SERVER', '389': 'LDAP', '443': 'HTTPS',
        '546': 'DHCP-CLIENT', '547': 'DHCP-SERVER', '993': 'IMAP-SSL',
        '995': 'POP3-SSL', '2082': 'CPANEL', '2083': 'CPANEL',
        '2086': 'WHM/CPANEL', '2087': 'WHM/CPANEL', '3306': 'MYSQL',
        '8443': 'PLESK', '10000': 'VIRTUALMIN/WEBIN'
    }

    def get_service(port):
        port = str(port)
        return common_ports.get(port, "Unknown service")

    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return port
        except:
            pass
        return None

    starting_time = time.time()

    # Ports to scan
    if flag:
        ports_to_scan = [int(p) for p in common_ports.keys()]
        print "[*] Scanning most common ports on %s" % host
    else:
        ports_to_scan = range(start_port, end_port + 1)
        print "[*] Scanning %s from port %s to %s" % (host, start_port, end_port)

    print "[*] Starting threaded scan with %d threads..." % max_threads

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {executor.submit(check_port, port): port for port in ports_to_scan}
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            result = future.result()
            if result is not None:
                service = get_service(result)
                open_ports.append({"port": result, "service": service})
                print "\t[+] Port %d (%s): Open" % (result, service)

    ending_time = time.time()
    total_time = ending_time - starting_time

    print "[*] Scan completed in %.2f seconds" % total_time if total_time <= 60 else "[*] Scan completed in %.2f minutes" % (total_time / 60)

    if open_ports:
        print "\n[*] Summary of Open Ports:"
        for p in sorted(open_ports, key=lambda x: x['port']):
            print "\t%s (%s)" % (p['port'], p['service'])
    else:
        print "[*] No open ports found."

    if output_file:
        try:
            if output_file.endswith('.json'):
                result_data = {
                    "host": host,
                    "start_port": start_port,
                    "end_port": end_port,
                    "total_ports_scanned": len(ports_to_scan),
                    "open_ports": open_ports,
                    "scan_duration": total_time
                }
                with open(output_file, 'w') as f:
                    json.dump(result_data, f, indent=4)
                print "[*] Results saved to %s (JSON)" % output_file

            elif output_file.endswith('.csv'):
                with open(output_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Port", "Service"])
                    for p in sorted(open_ports, key=lambda x: x['port']):
                        writer.writerow([p['port'], p['service']])
                print "[*] Results saved to %s (CSV)" % output_file

            else:
                print "[*] Unsupported file format. Use .json or .csv"
        except Exception as e:
            print "[!] Error writing output file:", str(e)


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
			print "[*] IP Dump : " 
			print hexdump(IPpkt)

def pcap_analyser_tcp(file):
	pkts = rdpcap(file)
	i=0
	SYN = 0x02
	FIN = 0X01
	RST = 0x04
	PSH = 0X08
	ACK = 0X10
	URG = 0x20
	
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
			nbrsyn=0
			nbrrst=0
			nbrack=0
			nbrfin=0
			nbrurg=0
			nbrpsh=0
			FlagsTCP=pkt[TCP].flags
          	        if FlagsTCP==SYN:
                		nbrsun=1
				print "[*] TCP SYN FLAGS : " ,nbrsyn
    	      	        elif FlagsTCP==RST:
				nbrrst=1
				print "[*] TCP RST FLAGS : " ,nbrrst	     	
                        elif FlagsTCP==ACK:
                		nbrack=1
				print "[*] TCP ACK FLAGS : " ,nbrack
		        elif FlagsTCP==FIN:
				nbrfin=1
				print "[*] TCP FIN FLAGS : " ,nbrfin
		        elif FlagsTCP==URG:
				nbrurg=1
				print "[*] TCP URG FLAGS : " ,nbrurg
		        elif FlagsTCP==PSH:
				nbrpsh=1
				print "[*] TCP PSH FLAGS : " ,nbrpsh
                        print "[*] TCP Dump : " 
			print hexdump(TCPpkt)


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
                        print "[*] UDP Dump : " 
			print hexdump(UDPpkt)


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
            print "[*] ICMP Dump : "
			print hexdump(ICMPpkt)


def subdomain_scan(domain):
    print '[*] Starting CyberScan Subdomain Enumeration for %s' %(domain)
    try:
        url = "https://dnsdumpster.com/"
        req = urllib2.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1')
        response = urllib2.urlopen(req)
        html = response.read()
        # Find the CSRF token
        csrf_token = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', html).group(1)
        # Prepare the POST data
        data = urllib.urlencode({'csrfmiddlewaretoken': csrf_token, 'targetip': domain})
        req = urllib2.Request(url, data)
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1')
        req.add_header('Referer', url)
        response = urllib2.urlopen(req)
        html = response.read()
        # Extract subdomains
        subdomains = re.findall(r'([a-zA-Z0-9\-\.]+\.' + re.escape(domain) + ')', html)
        unique_subdomains = list(set(subdomains))
        if unique_subdomains:
            print "[*] Found subdomains:"
            for sub in unique_subdomains:
                print "\t" + sub
        else:
            print "[*] No subdomains found."
    except Exception as e:
        print "[*] Error: " + str(e)


def main():

	global serveur
	global level
	global sport
	global eport
	global file
	global flag
	flag=0
	
	try:

	    parser = argparse.ArgumentParser(version=__version__,description=__description__,formatter_class=argparse.RawTextHelpFormatter,epilog='''\
levels with ip adress:
  scan : scan ports
  arp : ping arp
  icmp : ping arp
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

	    parser.add_argument("-s","--serveur", dest="serveur",help="attack to serveur ip")
	    parser.add_argument("-p","--level",dest="level",help="stack to level")
	    parser.add_argument("-d","--sport",dest="sport",help="start port to scan")
	    parser.add_argument("-t","--eport",dest="eport",help="end port to scan")
	    parser.add_argument("-f", "--file", dest="file",
                      help="read pcap file")
	    parser.add_argument("--domain", dest="domain", help="domain for subdomain enumeration")
        parser.add_argument("--output", dest="output", help="Save scan results to file (JSON or CSV)") #New line added
	

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
	      			port = sport
              			tcp_ping(serveur,port)
	
			elif serveur is not None and level == "scan" and sport is not None and eport is not None:
	 			start_port = int(sport)
	  			end_port = int(eport)
	  			flag = 0
	  			superscan(serveur,start_port,end_port)

			elif serveur is not None and level == "scan" and sport is None and eport is None:
		    		start_port = int(0)
		        	end_port = int(0)
	 	        	flag=1
	 	        	superscan(serveur,start_port,end_port)
	
			elif serveur is not None and level == "udp":
	    	    			udp_ping(serveur,port=0)
		
                	elif serveur is not None and level == "geoip":
				geo_ip(serveur)
			#Output file option added to subdomain_scan
            elif serveur is not None and level == "scan" and sport is not None and eport is not None:
				start_port = int(sport)
				end_port = int(eport)
				flag = 0
				superscan(serveur, start_port, end_port, output_file=output_file)

			elif serveur is not None and level == "scan" and sport is None and eport is None:
				start_port = 0
				end_port = 0
				flag = 1
				superscan(serveur, start_port, end_port, output_file=output_file)

            else:
         
            	print '''usage: CyberScan.py [-h] [-s SERVEUR] [-p LEVEL] [-d SPORT] [-t EPORT]
                    [-f FILE]
use cyberscan -h to help '''	
	
	except KeyboardInterrupt:
		print "\n[*] You Pressed Ctrl+C. Exiting"
		sys.exit(1)	


	
if __name__ == '__main__':
    main()
