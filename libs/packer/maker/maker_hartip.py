from libs.packer.maker.maker import *
from libs.packer.protocol import *
from setting import *


def make_basic_hartip():
    hartip = Hartip()
    return hartip


def make_hartip_read_packets(dmac, smac, dip, sip, dport, sport, address, data):
    s_ethernet, s_ipv4 = make_basic_protocol(dmac, smac, dip, sip)
    s_tcp = make_tcp(dport, sport, 0)
    s_hartip = make_basic_hartip()
    s_hartip.to_read_ack()
    s_ipv4.set_total_length(s_tcp.bit_lens, s_hartip.bit_lens)
    s_tcp.set_connection_status(0, s_hartip.bit_lens)

    d_ethernet, d_ipv4 = make_basic_protocol(smac, dmac, sip, dip)
    d_tcp = make_tcp(sport, dport, 1)
    d_hartip = make_basic_hartip()
    d_hartip.to_read_res(data)
    d_ipv4.set_total_length(d_tcp.bit_lens, d_hartip.bit_lens)
    d_tcp.set_connection_status(1, d_hartip.bit_lens)

    s_pkt = pile_up(s_ethernet, s_ipv4, s_tcp, s_hartip)
    d_pkt = pile_up(d_ethernet, d_ipv4, d_tcp, d_hartip)
    return s_pkt, d_pkt


if __name__ == '__main__':
    pcap_maker(make_hartip_read_packets, '../out/hartip_r.pcap', DMAC, SMAC, DIP, SIP, 5094, 49559, b'\x02')
    # pcap_maker(make_hartip_write_packets, '../out/hartip_w.pcap', DMAC, SMAC, DIP, SIP, 20000, 42942, b'\x02')
