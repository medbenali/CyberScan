import os
import sys
import platform
import argparse
import time
import threading
import socket

from scapy.all import *
from optparse import OptionParser
from libs.colorama import *
from libs import FileUtils
file ="1.pcap"
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
			#print pkt.summary()
			print hexdump(pkt)
			#print str(packet).encode("HEX")
			#print str(packet)
		

if __name__ == '__main__':
    #os.system('clear')
    file ="1.pcap"
    pcap_analyser_tcp(file)
 
   
