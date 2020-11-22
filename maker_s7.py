from maker import *
from protocol.s7_protocol import *
from setting import *


def make_basic_s7():
    tpkt = TPKT()
    cotp = COTP()
    s7 = S7()
    return tpkt, cotp, s7


def make_s7_read_packets(dmac, smac, dip, sip, dport, sport, address, data):
    s_ethernet, s_ipv4, s_tcp = make_basic_protocol(dmac, smac, dip, sip, dport, sport, 0)
    s_tpkt, s_cotp, s_s7 = make_basic_s7()
    s_cotp.to_function()
    s_s7.to_ack_read(b'\x00\x00', b'\x02', address)
    s_tpkt.set_length(s_cotp.bit_lens, s_s7.bit_lens)
    s_ipv4.set_total_length(s_tcp.bit_lens, s_tpkt.bit_lens, s_cotp.bit_lens, s_s7.bit_lens)
    s_tcp.set_connection_status(0, s_tpkt.bit_lens, s_cotp.bit_lens, s_s7.bit_lens)

    d_ethernet, d_ipv4, d_tcp = make_basic_protocol(smac, dmac, sip, dip, sport, dport, 1)
    d_tpkt, d_cotp, d_s7 = make_basic_s7()
    d_cotp.to_function()
    d_s7.to_res_read(b'\x04', data, b'\x00\x20', 4)
    d_tpkt.set_length(d_cotp.bit_lens, d_s7.bit_lens)
    d_ipv4.set_total_length(d_tcp.bit_lens, d_tpkt.bit_lens, d_cotp.bit_lens, d_s7.bit_lens)
    d_tcp.set_connection_status(1, d_tpkt.bit_lens, d_cotp.bit_lens, d_s7.bit_lens)

    s_pkt = pile_up(s_ethernet, s_ipv4, s_tcp, s_tpkt, s_cotp, s_s7)
    d_pkt = pile_up(d_ethernet, d_ipv4, d_tcp, d_tpkt, d_cotp, d_s7)
    return s_pkt, d_pkt


def make_s7_write_packets(dmac, smac, dip, sip, dport, sport, address, data):
    s_ethernet, s_ipv4, s_tcp = make_basic_protocol(dmac, smac, dip, sip, dport, sport, 0)
    s_tpkt, s_cotp, s_s7 = make_basic_s7()
    s_cotp.to_function()
    s_s7.to_ack_write(b'\x04', data, 4, address)
    s_tpkt.set_length(s_cotp.bit_lens, s_s7.bit_lens)
    s_ipv4.set_total_length(s_tcp.bit_lens, s_tpkt.bit_lens, s_cotp.bit_lens, s_s7.bit_lens)
    s_tcp.set_connection_status(0, s_tpkt.bit_lens, s_cotp.bit_lens, s_s7.bit_lens)

    d_ethernet, d_ipv4, d_tcp = make_basic_protocol(smac, dmac, sip, dip, sport, dport, 1)
    d_tpkt, d_cotp, d_s7 = make_basic_s7()
    d_cotp.to_function()
    d_s7.to_res_write(1)
    d_tpkt.set_length(d_cotp.bit_lens, d_s7.bit_lens)
    d_ipv4.set_total_length(d_tcp.bit_lens, d_tpkt.bit_lens, d_cotp.bit_lens, d_s7.bit_lens)
    d_tcp.set_connection_status(1, d_tpkt.bit_lens, d_cotp.bit_lens, d_s7.bit_lens)

    s_pkt = pile_up(s_ethernet, s_ipv4, s_tcp, s_tpkt, s_cotp, s_s7)
    d_pkt = pile_up(d_ethernet, d_ipv4, d_tcp, d_tpkt, d_cotp, d_s7)
    return s_pkt, d_pkt


if __name__ == '__main__':
    # spr, dpr = make_s7_read_packets(SMAC, DMAC, SIP, DIP, 102, 4185, b'\x05', b'\x00\x01\x00\x02')
    spw, dpw = make_s7_write_packets(SMAC, DMAC, SIP, DIP, 102, 4185, b'\x05', b'\x00\x01\x00\x04')

    pkts = []
    for i in range(1, 10):
        spr, dpr = make_s7_read_packets(SMAC, DMAC, SIP, DIP, 102, 4185, b'\x05', b'\x00\x01\x00\x02')
        pkts.append(spr)
        pkts.append(dpr)
    pcap_wrapper([spw, dpw] + pkts, 'out/s7_test.pcap')
