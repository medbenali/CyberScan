#!/usr/bin/env python

__author__ = "bt3"

from scapy.all import *

def os_finger(target):
    ip = IP()
    ping = ICMP()
    ip.dst = target
    send = sr1(ip/ping)
    if send.ttl < 65:
            print("IP:%s: Linux"%(target))

    else:
            print("IP:%s: Windows"%(target))


if __name__ == '__main__':
    target = raw_input("Type the IP: ")
    os_finger(target)
