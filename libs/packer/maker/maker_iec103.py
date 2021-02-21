from libs.packer.maker.maker import *
from libs.packer.protocol import *
from setting import *


def make_basic_iec103():
    iec103 = IEC103()
    return iec103


def make_iec103_read_packets(dmac, smac, dip, sip, dport, sport, address, data):
    s_ethernet, s_ipv4 = make_basic_protocol(dmac, smac, dip, sip)
    s_tcp = make_tcp(dport, sport, 0)
    s_iec103 = make_basic_iec103()
    s_iec103.to_read_ack()
    s_ipv4.set_total_length(s_tcp.bit_lens, s_iec103.bit_lens)
    s_tcp.set_connection_status(0, s_iec103.bit_lens)

    d_ethernet, d_ipv4 = make_basic_protocol(smac, dmac, sip, dip)
    d_tcp = make_tcp(sport, dport, 1)
    d_iec103 = make_basic_iec103()
    d_iec103.to_read_res(data)
    d_ipv4.set_total_length(d_tcp.bit_lens, d_iec103.bit_lens)
    d_tcp.set_connection_status(1, d_iec103.bit_lens)

    s_pkt = pile_up(s_ethernet, s_ipv4, s_tcp, s_iec103)
    d_pkt = pile_up(d_ethernet, d_ipv4, d_tcp, d_iec103)
    return s_pkt, d_pkt


if __name__ == '__main__':
    pcap_maker(make_iec103_read_packets, '../out/iec103_r.pcap', DMAC, SMAC, DIP, SIP, 1111, 22403, b'\x02')
    # pcap_maker(make_iec103_write_packets, '../out/iec103_w.pcap', DMAC, SMAC, DIP, SIP, 20000, 42942, b'\x02')
