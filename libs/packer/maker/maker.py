from scapy.all import *
from scapy.layers.l2 import Ether
from libs.packer.protocol.basic_protocol import *
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


def make_basic_protocol(dmac, smac, dip, sip):
    ethernet = Ethernet()
    ethernet.set_basic(dmac, smac)
    ipv4 = IPv4()
    ipv4.set_basic(dip, sip)

    return ethernet, ipv4


def make_tcp(dport, sport, pid):
    tcp = MyTCP()
    tcp.set_basic(dport, sport, pid)
    return tcp


def make_udp(dport, sport):
    udp = UDP()
    udp.set_basic(dport, sport)
    return udp


def make_tcp_ask(dmac, smac, dip, sip, dport, sport):
    s_ethernet, s_ipv4 = make_basic_protocol(dmac, smac, dip, sip)
    s_tcp = make_tcp(dport, sport, 0)
    s_tcp.flag['value'] = b'\x50\x10'
    s_ipv4.set_total_length(s_tcp.bit_lens)
    s_tcp.set_connection_status(0)

    s_pkt = pile_up(s_ethernet, s_ipv4, s_tcp)
    return s_pkt


def make_tcp_hello(dmac, smac, dip, sip, dport, sport):
    s_ethernet1, s_ipv41 = make_basic_protocol(dmac, smac, dip, sip)
    d_ethernet1, d_ipv41 = make_basic_protocol(smac, dmac, sip, dip)
    s_ethernet2, s_ipv42 = make_basic_protocol(dmac, smac, dip, sip)

    s_tcp1 = make_tcp(dport, sport, 0)
    s_tcp1.option['enabled'] = True
    s_tcp1.flag['value'] = b'\x70\x02'
    s_ipv41.set_total_length(s_tcp1.bit_lens)
    s_tcp1.set_connection_status(0, 8)

    d_tcp1 = make_tcp(sport, dport, 1)
    d_tcp1.option['enabled'] = True
    d_tcp1.flag['value'] = b'\x70\x12'
    d_ipv41.set_total_length(d_tcp1.bit_lens)
    d_tcp1.set_connection_status(1, 8)

    s_tcp2 = make_tcp(dport, sport, 0)
    s_tcp2.flag['value'] = b'\x50\x10'
    s_ipv42.set_total_length(s_tcp2.bit_lens)
    s_tcp2.set_connection_status(0)

    s_pkt1 = pile_up(s_ethernet1, s_ipv41, s_tcp1)
    d_pkt1 = pile_up(d_ethernet1, d_ipv41, d_tcp1)
    s_pkt2 = pile_up(s_ethernet2, s_ipv42, s_tcp2)

    return s_pkt1, d_pkt1, s_pkt2


def pcap_maker(pkt_maker, path, DMAC, SMAC, DIP, SIP, dport, sport, address):
    pkts = []
    data_bit_lens = 4
    if pkt_maker.__name__.startswith('make_dnp3'):
        data_bit_lens = 1
    for i in range(1, 51):
        if i == 35:
            data = int_to_bytes(100, data_bit_lens)
        else:
            data = int_to_bytes(i, data_bit_lens)
        spr, dpr = pkt_maker(DMAC, SMAC, DIP, SIP, dport, sport, address, data)
        pkts.append(spr)
        pkts.append(dpr)
        if i == 50:
            pkts.append(make_tcp_ask(DMAC, SMAC, DIP, SIP, dport, sport))

    pcap_wrapper(pkts, path)


def pcap_maker2(pkt_maker, path, DMAC, SMAC, DIP, SIP, dport, sport, address):
    pkts = []
    t1, t2, t3 = make_tcp_hello(DMAC, SMAC, DIP, SIP, dport, sport)
    pkts.append(t1)
    pkts.append(t2)
    pkts.append(t3)
    for i in range(1, 51):
        if i == 35:
            data = int_to_bytes(100, 4)
        else:
            data = int_to_bytes(i, 4)
        spr, dpr = pkt_maker(DMAC, SMAC, DIP, SIP, dport, sport, address, data)
        pkts.append(spr)
        pkts.append(dpr)
        if i == 50:
            pkts.append(make_tcp_ask(DMAC, SMAC, DIP, SIP, dport, sport))

    pcap_wrapper(pkts, path)
