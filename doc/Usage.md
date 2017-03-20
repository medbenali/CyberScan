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

### Pinging the Network

We can perform **ping** operations with several protocols using CyberScan The fastest way to discover hosts on a local Ethernet network is to use ARP:

```python
$ CyberScan -s 192.168.1.0/24 -p arp
[*] Starting Ping ARP for 192.168.1.0/24
Begin emission:
Finished to send 256 packets.

Received 0 packets, got 0 answers, remaining 256 packets
```






