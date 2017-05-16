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

![](https://github.com/medbenali/CyberScan/blob/master/images/CyberScanPortScanWi.png)

and CyberScan is  more rapid then Nmap when we compare the duration of network scan port

![](https://github.com/medbenali/CyberScan/blob/master/images/CyberScanPortScanWo.png)


```sh
$ CyberScan -s 192.168.*.1-10 -p udp
```















