from maker import *
from protocol.dnp3_protocol import *
from setting import *


def make_basic_dnp3():
    dnp3 = DNP3()
    return dnp3


def make_dnp3_read_packets(dmac, smac, dip, sip, dport, sport, address, data):
    s_ethernet, s_ipv4, s_tcp, s_udp = make_basic_protocol(dmac, smac, dip, sip, dport, sport, 0)
    s_dnp3 = make_basic_dnp3()
    s_dnp3.to_read_ack(b'\x0a\x00')
    s_ipv4.set_total_length(s_tcp.bit_lens, s_dnp3.bit_lens)
    s_tcp.set_connection_status(0, s_dnp3.bit_lens)



    s_pkt = pile_up(s_ethernet, s_ipv4, s_tcp, s_dnp3)
    return s_pkt


if __name__ == '__main__':
    spr = make_dnp3_read_packets(SMAC, DMAC, SIP, DIP, 20000, 42942, b'\x00\x64', b'\x00\x01\x00\x02')
    pcap_wrapper([spr], 'out/dnp3_test.pcap')
