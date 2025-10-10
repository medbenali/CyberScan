## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Packet sending and receiving with libdnet and libpcap/WinPcap.
"""

import time
import struct
import sys

# On non‑Windows, use ioctl
if not sys.platform.startswith("win"):
    try:
        from fcntl import ioctl
    except ImportError:
        ioctl = None

from scapy_local.data import *
from scapy_local.config import conf
from scapy_local.utils import warning
from scapy_local.supersocket import SuperSocket
from scapy_local.error import Scapy_Exception
import scapy_local.arch

# Try importing pcap / pcapy
pcap = None
_have_pcap = False
try:
    import pcap
    pcap = pcap
    _have_pcap = True
except ImportError:
    try:
        import pcapy as pcap
        _have_pcap = True
    except ImportError:
        pcap = None
        _have_pcap = False

if _have_pcap and conf.use_pcap:
    # From BSD net/bpf.h
    BIOCIMMEDIATE = -2147204496

    # Wrapper based on what API is available
    if hasattr(pcap, "pcap"):
        class _PcapWrapper_pypcap(object):
            def __init__(self, device, snaplen, promisc, to_ms):
                try:
                    self.pcap = pcap.pcap(device, snaplen, promisc, immediate=1, timeout_ms=to_ms)
                except TypeError:
                    self.pcap = pcap.pcap(device, snaplen, promisc, immediate=1)

            def __getattr__(self, name):
                return getattr(self.pcap, name)

        open_pcap = lambda *args, **kwargs: _PcapWrapper_pypcap(*args, **kwargs)

    elif hasattr(pcap, "pcapObject"):
        class _PcapWrapper_libpcap(object):
            def __init__(self, device, snaplen, promisc, timeout_ms):
                self.pcap = pcap.pcapObject()
                self.pcap.open_live(device, snaplen, promisc, timeout_ms)

            def setfilter(self, filter_str):
                self.pcap.setfilter(filter_str, 0, 0)

            def __next__(self):
                c = next(self.pcap)
                if c is None:
                    return None
                length, pkt, ts = c
                return ts, pkt

            def __getattr__(self, name):
                return getattr(self.pcap, name)

        open_pcap = lambda *args, **kwargs: _PcapWrapper_libpcap(*args, **kwargs)

    elif hasattr(pcap, "open_live"):
        class _PcapWrapper_pcapy(object):
            def __init__(self, device, snaplen, promisc, timeout_ms):
                self.pcap = pcap.open_live(device, snaplen, promisc, timeout_ms)

            def __next__(self):
                try:
                    h, p = next(self.pcap)
                except Exception:
                    return None
                if h is None:
                    return None
                s, us = h.getts()
                return (s + 0.000001 * us, p)

            def fileno(self):
                warning("fileno: pcapy API may not support file descriptor reading")
                return 0

            def __getattr__(self, name):
                return getattr(self.pcap, name)

        open_pcap = lambda *args, **kwargs: _PcapWrapper_pcapy(*args, **kwargs)
    else:
        # No compatible pcap API found
        conf.use_pcap = False

    class PcapTimeoutElapsed(Scapy_Exception):
        pass

    class L2pcapListenSocket(SuperSocket):
        desc = "read packets at layer 2 using libpcap"
        def __init__(self, iface=None, type=ETH_P_ALL, promisc=None, filter_str=None):
            self.type = type
            self.iface = iface or conf.iface
            self.promisc = promisc if promisc is not None else conf.sniff_promisc

            # Try opening pcap
            try:
                self.ins = open_pcap(self.iface, 1600, self.promisc, 100)
            except Exception as e:
                raise Scapy_Exception("Could not open pcap: %s" % e)

            if ioctl and hasattr(self.ins, "fileno"):
                try:
                    ioctl(self.ins.fileno(), BIOCIMMEDIATE, struct.pack("I", 1))
                except Exception:
                    pass

            if type == ETH_P_ALL and conf.except_filter:
                if filter_str:
                    filter_str = "(%s) and not (%s)" % (filter_str, conf.except_filter)
                else:
                    filter_str = "not (%s)" % conf.except_filter
            if filter_str:
                try:
                    self.ins.setfilter(filter_str)
                except Exception as e:
                    warning("Failed to set filter: %s" % e)

        def close(self):
            try:
                del self.ins
            except Exception:
                pass

        def recv(self, x=MTU):
            ll = self.ins.datalink()
            if ll in conf.l2types:
                cls = conf.l2types[ll]
            else:
                cls = conf.default_l2
                warning("Unable to guess datalink type (iface=%s linktype=%i). Using %s" %
                        (self.iface, ll, cls.name))
            pkt = None
            ts = None
            while pkt is None:
                data = next(self.ins)
                if data is None:
                    if scapy_local.arch.WINDOWS:
                        raise PcapTimeoutElapsed
                    continue
                ts, pkt = data
            try:
                pkt = cls(pkt)
            except KeyboardInterrupt:
                raise
            except Exception:
                if conf.debug_dissector:
                    raise
                pkt = conf.raw_layer(pkt)
            pkt.time = ts
            return pkt

        def send(self, x):
            raise Scapy_Exception("Cannot send using L2pcapListenSocket")

    conf.L2listen = L2pcapListenSocket

# dnet part
_have_dnet = False
try:
    import dnet
    _have_dnet = True
except ImportError:
    dnet = None
    _have_dnet = False

if _have_dnet and conf.use_dnet:
    # define get_if_raw_hwaddr, get_if_raw_addr, get_if_list
    def get_if_raw_hwaddr(iff):
        if iff == scapy_local.arch.LOOPBACK_NAME:
            return (772, b"\x00" * 6)
        try:
            i = dnet.intf()
            l = i.get(iff)["link_addr"]
        except Exception:
            raise Scapy_Exception("Error getting hw address for %s" % iff)
        return l.type, l.data

    def get_if_raw_addr(ifname):
        return dnet.intf().get(ifname)["addr"].data

    def get_if_list():
        return [i.get("name") for i in dnet.intf()]

else:
    # fallback stubs
    def get_if_raw_hwaddr(iff):
        return (0, b"\x00" * 6)
    def get_if_raw_addr(ifname):
        return b"\x00" * 4
    def get_if_list():
        return []

if _have_pcap and _have_dnet and conf.use_pcap and conf.use_dnet:
    class L3dnetSocket(SuperSocket):
        desc = "read/write packets at layer 3 using libdnet + libpcap"
        def __init__(self, type=ETH_P_ALL, filter_str=None, promisc=None, iface=None, nofilter=False):
            self.iflist = {}
            if iface is None:
                iface = conf.iface
            self.iface = iface
            try:
                self.ins = open_pcap(iface, 1600, 0, 100)
            except Exception as e:
                raise Scapy_Exception("Could not open pcap for L3: %s" % e)

            if ioctl and hasattr(self.ins, "fileno"):
                try:
                    ioctl(self.ins.fileno(), BIOCIMMEDIATE, struct.pack("I", 1))
                except Exception:
                    pass

            # build filter
            if nofilter:
                if type != ETH_P_ALL:
                    filter_str = "ether proto %i" % type
                else:
                    filter_str = None
            else:
                if conf.except_filter:
                    if filter_str:
                        filter_str = "(%s) and not (%s)" % (filter_str, conf.except_filter)
                    else:
                        filter_str = "not (%s)" % conf.except_filter
                if type != ETH_P_ALL:
                    if filter_str:
                        filter_str = "(ether proto %i) and (%s)" % (type, filter_str)
                    else:
                        filter_str = "ether proto %i" % type
            if filter_str:
                try:
                    self.ins.setfilter(filter_str)
                except Exception:
                    warning("Failed to set filter: %s" % filter_str)

        def send(self, pkt):
            iface, addr, gw = pkt.route()
            if iface is None:
                iface = conf.iface
            ifs, cls = self.iflist.get(iface, (None, None))
            if ifs is None:
                intf = dnet.intf()
                typ = intf.get(iface)["type"]
                if typ == dnet.INTF_TYPE_ETH:
                    try:
                        cls = conf.l2types[1]
                    except KeyError:
                        cls = None
                        warning("Ether class missing")
                    ifs = dnet.eth(iface)
                else:
                    ifs = dnet.ip()
                self.iflist[iface] = (ifs, cls)
            if cls is None:
                data = str(pkt)
            else:
                data = str(cls() / pkt)
            pkt.sent_time = time.time()
            ifs.send(data)

        def recv(self, x=MTU):
            ll = self.ins.datalink()
            if ll in conf.l2types:
                cls = conf.l2types[ll]
            else:
                cls = conf.default_l2
                warning("Guessing link type, using %s" % cls.name)
            res = next(self.ins)
            if res is None:
                return None
            ts, pkt = res
            try:
                pkt = cls(pkt)
            except KeyboardInterrupt:
                raise
            except Exception:
                if conf.debug_dissector:
                    raise
                pkt = conf.raw_layer(pkt)
            pkt.time = ts
            return pkt.payload

        def nonblock_recv(self):
            try:
                self.ins.setnonblock(1)
            except Exception:
                pass
            pkt = self.recv()
            try:
                self.ins.setnonblock(0)
            except Exception:
                pass
            return pkt

        def close(self):
            try:
                del self.ins
            except Exception:
                pass

    class L2dnetSocket(SuperSocket):
        desc = "read/write packets at layer 2 using libdnet + libpcap"
        def __init__(self, iface=None, type=ETH_P_ALL, filter_str=None, nofilter=False):
            self.iface = iface or conf.iface
            try:
                self.ins = open_pcap(self.iface, 1600, 0, 100)
            except Exception as e:
                raise Scapy_Exception("Cannot open pcap for L2dnet: %s" % e)

            if ioctl and hasattr(self.ins, "fileno"):
                try:
                    ioctl(self.ins.fileno(), BIOCIMMEDIATE, struct.pack("I", 1))
                except Exception:
                    pass

            if nofilter:
                if type != ETH_P_ALL:
                    filter_str = "ether proto %i" % type
                else:
                    filter_str = None
            else:
                if conf.except_filter:
                    if filter_str:
                        filter_str = "(%s) and not (%s)" % (filter_str, conf.except_filter)
                    else:
                        filter_str = "not (%s)" % conf.except_filter
                if type != ETH_P_ALL:
                    if filter_str:
                        filter_str = "(ether proto %i) and (%s)" % (type, filter_str)
                    else:
                        filter_str = "ether proto %i" % type
            if filter_str:
                try:
                    self.ins.setfilter(filter_str)
                except Exception:
                    warning("Failed setfilter: %s" % filter_str)

            self.outs = dnet.eth(self.iface)

        def recv(self, x=MTU):
            ll = self.ins.datalink()
            if ll in conf.l2types:
                cls = conf.l2types[ll]
            else:
                cls = conf.default_l2
                warning("Guessing link type %s" % cls.name)
            res = next(self.ins)
            if res is None:
                return None
            ts, pkt = res
            try:
                pkt = cls(pkt)
            except KeyboardInterrupt:
                raise
            except Exception:
                if conf.debug_dissector:
                    raise
                pkt = conf.raw_layer(pkt)
            pkt.time = ts
            return pkt

        def nonblock_recv(self):
            try:
                self.ins.setnonblock(1)
            except Exception:
                pass
            pkt = self.recv()
            try:
                self.ins.setnonblock(0)
            except Exception:
                pass
            return pkt

        def send(self, pkt):
            # pkt is L2 frame
            try:
                data = str(pkt)
            except Exception:
                data = bytes(pkt)
            self.outs.send(data)

        def close(self):
            try:
                del self.ins
            except Exception:
                pass
            try:
                del self.outs
            except Exception:
                pass

    conf.L3socket = L3dnetSocket
    conf.L2socket = L2dnetSocket

# End of patched pcapdnet.py
