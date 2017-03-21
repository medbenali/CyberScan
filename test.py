import os
import sys
import platform
import argparse
import time
import socket

parser = argparse.ArgumentParser(description='CyberScan')

parser.add_argument("-s","--serveur", dest="serveur",help="attack to serveur ip -s",nargs=1)
parser.add_argument("-p","--level",dest="level",help="stack to level")
parser.add_argument("-d","--sport",dest="sport",help="-start port")
parser.add_argument("-t","--eport",dest="eport",help="-end_port")
parser.add_argument("-f", "--file", dest="file",
                      help="read pcap file",nargs=1)

args = parser.parse_args()
if args.serveur is not None and args.level == "arp" :
	print "arp"
else:
	print "other"
