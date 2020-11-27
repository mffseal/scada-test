from scapy.all import *
from scapy.layers.l2 import Ether
from protocol.basic_protocol import *
import random

TIME = 0.000000


def random_time():
    uniform = random.uniform(0.3, 1)
    return round(uniform, 6)


def pcap_wrapper(pkts, path):
    global TIME
    writers = PcapWriter(path)

    for p in pkts:
        pacp_pkt = Ether(p)
        pacp_pkt.time = TIME
        TIME += random_time()
        writers.write(pkt=pacp_pkt)
    TIME = 0


def make_basic_protocol(dmac, smac, dip, sip, dport, sport, pid):
    ethernet = Ethernet()
    ethernet.set_basic(dmac, smac)
    ipv4 = IPv4()
    ipv4.set_basic(dip, sip)
    tcp = MyTCP()
    tcp.set_basic(dport, sport, pid)
    udp = UDP()
    udp.set_basic(dport, sport)
    return ethernet, ipv4, tcp, udp
