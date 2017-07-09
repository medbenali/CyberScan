#!/usr/bin/env python

__author__ = "bt3"

from scapy.all import *

str(IP())
a = Ether()/IP(dst="www.google.com")/TCP()/"GET /index.html HTTP/1.1"
hexdump(a)