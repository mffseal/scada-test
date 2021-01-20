from maker import *
from libs.packer.protocol import *
from setting import *


def make_basic_dnp3():
    dnp3 = DNP3()
    return dnp3


def make_dnp3_read_packets(dmac, smac, dip, sip, dport, sport, address, data):
    s_ethernet, s_ipv4 = make_basic_protocol(dmac, smac, dip, sip)
    s_tcp = make_tcp(dport, sport, 0)
    s_dnp3 = make_basic_dnp3()
    s_dnp3.to_read_ack(address, data)
    s_ipv4.set_total_length(s_tcp.bit_lens, s_dnp3.bit_lens)
    s_tcp.set_connection_status(0, s_dnp3.bit_lens)

    d_ethernet, d_ipv4 = make_basic_protocol(smac, dmac, sip, dip)
    d_tcp = make_tcp(sport, dport, 1)
    d_dnp3 = make_basic_dnp3()
    d_dnp3.to_read_res()
    d_ipv4.set_total_length(d_tcp.bit_lens, d_dnp3.bit_lens)
    d_tcp.set_connection_status(1, d_dnp3.bit_lens)

    s_pkt = pile_up(s_ethernet, s_ipv4, s_tcp, s_dnp3)
    d_pkt = pile_up(d_ethernet, d_ipv4, d_tcp, d_dnp3)
    return s_pkt, d_pkt


def make_dnp3_write_packets(dmac, smac, dip, sip, dport, sport, address, data):
    s_ethernet, s_ipv4 = make_basic_protocol(dmac, smac, dip, sip)
    s_tcp = make_tcp(dport, sport, 0)
    s_dnp3 = make_basic_dnp3()
    s_dnp3.to_write_ack(address, data)
    s_ipv4.set_total_length(s_tcp.bit_lens, s_dnp3.bit_lens)
    s_tcp.set_connection_status(0, s_dnp3.bit_lens)

    d_ethernet, d_ipv4 = make_basic_protocol(smac, dmac, sip, dip)
    d_tcp = make_tcp(sport, dport, 1)
    d_dnp3 = make_basic_dnp3()
    d_dnp3.to_write_res()
    d_ipv4.set_total_length(d_tcp.bit_lens, d_dnp3.bit_lens)
    d_tcp.set_connection_status(1, d_dnp3.bit_lens)

    s_pkt = pile_up(s_ethernet, s_ipv4, s_tcp, s_dnp3)
    d_pkt = pile_up(d_ethernet, d_ipv4, d_tcp, d_dnp3)
    return s_pkt, d_pkt


def sens_r():
    pkts = []
    for i in range(1, 50):
        if i == 35:
            data = int_to_bytes(100, 4)
        else:
            data = int_to_bytes(i, 4)
        spr, dpr = make_dnp3_read_packets(DMAC, SMAC, DIP, SIP, 20000, 42942, b'\x05', data)
        pkts.append(spr)
        pkts.append(dpr)
        if i == 50:
            pkts.append(make_tcp_ask(SMAC, DMAC, SIP, DIP, 502, 9699))
    pcap_wrapper(pkts, '../out/dnp3_r.pcap')


if __name__ == '__main__':
    pcap_maker(make_dnp3_read_packets, '../out/dnp3_r.pcap', DMAC, SMAC, DIP, SIP, 20000, 42942, b'\x02')
    pcap_maker(make_dnp3_write_packets, '../out/dnp3_w.pcap', DMAC, SMAC, DIP, SIP, 20000, 42942, b'\x02')
