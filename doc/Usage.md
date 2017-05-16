# The CyberScan Module Usage


[CyberScan](https://github.com/medbenali/CyberScan)  is able to send and capture packets of several protocols, forging and decoding them to be used to most network tasks such as scanning, tracerouting, probing, attacks, and network discovery.

Make sure you have CyberScan in your machine:

```sh
$ pip install scapy
$ git clone https://github.com/medbenali/CyberScan.git
```

You can test the installation firing up CyberScan iteratively. These are some useful functions:
```sh
$ python CyberScan.py -h 
```
---

## Pinging The Network

We can perform **ping** operations with several protocols using CyberScan The fastest way to discover hosts on a local Ethernet network is to use ARP:

### ARP Ping

```python
$ CyberScan -s 192.168.1.0/24 -p arp
[*] Starting Ping ARP for 192.168.1.0/24
Begin emission:
Finished to send 256 packets.

Received 0 packets, got 0 answers, remaining 256 packets
```

### ICMP Ping

In other cases we can use ICMP ping:

```sh
$ CyberScan -s 192.168.1.1-254 -p icmp
[*] Starting Ping ARP for 192.168.1.0/24
Begin emission:
Finished to send 256 packets.

Received 0 packets, got 0 answers, remaining 256 packets
```

### TCP Ping

In case when  ICMP echo requests are blocked, we can still use TCP:

```sh
$ CyberScan -s 192.168.1.1-254 -p tcp -d 80
```

### UDP Ping

Or even  UDP  (which produces ICMP port unreachable errors from live hosts). We can pick any port which is most likely to be closed,  such as port 0:

```sh
$ CyberScan -s 192.168.*.1-10 -p udp
```

---

## Network Scanning and Sniffing

### Port Scanner

This is result of port scanner with [Nmap](https://nmap.org):

![](https://github.com/medbenali/CyberScan/blob/master/images/NmapPortScan.png)

In CyberSan Tool we can scan with or without specify start and end port 

```sh
$ CyberScan -s 192.168.1.1 -p scan -d 1 -t 100
[*] CyberScan Port Scanner
[*] Scanning 192.168.1.1 From Port 1 To 100: 
[*] Starting CyberScan 1.01 at 2017-05-16 03:13 CEST
[*] Scan In Progress ...
[*] Connecting To Port :  100 
[*] Scanning Completed at 2017-05-16 03:13 CEST
[*] CyberScan done: 1IP address (1host up) scanned in 0.11 seconds
[*] Open Ports: 
	23 TELNET: Open
	53 DNS: Open
	80 HTTP: Open
```

and CyberScan is  more rapid then Nmap when we compare the duration of network scan port

```sh
$ CyberScan -s 8.8.8.8 -p scan
[*] CyberScan Port Scanner
[*] Scanning For Most Common Ports On 8.8.8.8
[*] Starting CyberScan 1.01 at 2017-05-16 03:03 CEST
[*] Scan In Progress ...
[*] Connecting To Port :  10000 109 110 123 137 138 139 143 156 2082 2083 2086 2087 21 22 23 25 3306 389 443 546 547 69 80 8443 993 995 
[*] Scanning Completed at 2017-05-16 03:03 CEST
[*] CyberScan done: 1IP address (1host up) scanned in 13.58 seconds
[*] Open Ports: 
	53 DNS: Open
```
















