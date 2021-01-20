from maker import *
from libs.packer.protocol import *
from setting import *


def make_basic_s7():
    tpkt = TPKT()
    cotp = COTP()
    s7 = S7()
    return tpkt, cotp, s7


def make_s7_read_packets(dmac, smac, dip, sip, dport, sport, address, data):
    s_ethernet, s_ipv4 = make_basic_protocol(dmac, smac, dip, sip)
    s_tcp = make_tcp(dport, sport, 0)
    s_tpkt, s_cotp, s_s7 = make_basic_s7()
    s_cotp.to_function()
    s_s7.to_ack_read(b'\x00\x00', b'\x02', address)
    s_tpkt.set_length(s_cotp.bit_lens, s_s7.bit_lens)
    s_ipv4.set_total_length(s_tcp.bit_lens, s_tpkt.bit_lens, s_cotp.bit_lens, s_s7.bit_lens)
    s_tcp.set_connection_status(0, s_tpkt.bit_lens, s_cotp.bit_lens, s_s7.bit_lens)

    d_ethernet, d_ipv4 = make_basic_protocol(smac, dmac, sip, dip)
    d_tcp = make_tcp(sport, dport, 1)
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
    s_ethernet, s_ipv4 = make_basic_protocol(dmac, smac, dip, sip)
    s_tcp = make_tcp(dport, sport, 0)
    s_tpkt, s_cotp, s_s7 = make_basic_s7()
    s_cotp.to_function()
    s_s7.to_ack_write(b'\x04', data, 8, address)
    s_tpkt.set_length(s_cotp.bit_lens, s_s7.bit_lens)
    s_ipv4.set_total_length(s_tcp.bit_lens, s_tpkt.bit_lens, s_cotp.bit_lens, s_s7.bit_lens)
    s_tcp.set_connection_status(0, s_tpkt.bit_lens, s_cotp.bit_lens, s_s7.bit_lens)

    d_ethernet, d_ipv4 = make_basic_protocol(smac, dmac, sip, dip)
    d_tcp = make_tcp(sport, dport, 1)
    d_tpkt, d_cotp, d_s7 = make_basic_s7()
    d_cotp.to_function()
    d_s7.to_res_write(1)
    d_tpkt.set_length(d_cotp.bit_lens, d_s7.bit_lens)
    d_ipv4.set_total_length(d_tcp.bit_lens, d_tpkt.bit_lens, d_cotp.bit_lens, d_s7.bit_lens)
    d_tcp.set_connection_status(1, d_tpkt.bit_lens, d_cotp.bit_lens, d_s7.bit_lens)

    s_pkt = pile_up(s_ethernet, s_ipv4, s_tcp, s_tpkt, s_cotp, s_s7)
    d_pkt = pile_up(d_ethernet, d_ipv4, d_tcp, d_tpkt, d_cotp, d_s7)
    return s_pkt, d_pkt


def legal_rw():
    spr, dpr = make_s7_read_packets(DMAC, SMAC, DIP, SIP, 102, 4185, b'\x01', b'\x00\x00\x00\x10')
    spw, dpw = make_s7_write_packets(DMAC, SMAC, DIP, SIP, 102, 4185, b'\x01', b'\x00\x00\x00\x12')
    return spr, dpr, spw, dpw


def illegal_address_rw():
    spr, dpr = make_s7_read_packets(DMAC, SMAC, DIP, SIP, 102, 4185, b'\x05', b'\x00\x00\x10\x02')
    spw, dpw = make_s7_write_packets(DMAC, SMAC, DIP, SIP, 102, 4185, b'\x05', b'\x00\x00\x10\x04')
    return spr, dpr, spw, dpw


def max_min_rw():
    spr, dpr = make_s7_read_packets(DMAC, SMAC, DIP, SIP, 102, 4185, b'\x05', b'\x00\x00\x10\x02')
    spw, dpw = make_s7_write_packets(DMAC, SMAC, DIP, SIP, 102, 4185, b'\x05', b'\x00\x00\x10\x04')
    return spr, dpr, spw, dpw


if __name__ == '__main__':
    pcap_maker(make_s7_read_packets, '../out/s7_r.pcap', DMAC, SMAC, DIP, SIP, 102, 4185, b'\x05')
    pcap_maker2(make_s7_write_packets, '../out/s7_w.pcap', DMAC, SMAC, DIP, SIP, 102, 4185, b'\x05')
