from maker import *
from protocol.omron_fins_protocol import *
from setting import *


def make_basic_fins():
    fins = OmronFins()
    return fins


def make_fins_read_packets(dmac, smac, dip, sip, dport, sport, address, data):
    s_ethernet, s_ipv4, s_tcp, s_udp = make_basic_protocol(dmac, smac, dip, sip, dport, sport, 0)
    s_ipv4.protocol['value'] = b'\x11'
    s_fins = make_basic_fins()
    s_fins.to_udp_ask_read(address)
    s_ipv4.set_total_length(s_udp.bit_lens, s_fins.bit_lens)
    s_udp.set_total_length(s_fins.bit_lens)

    d_ethernet, d_ipv4, d_tcp, d_udp = make_basic_protocol(smac, dmac, sip, dip, sport, dport, 1)
    d_ipv4.protocol['value'] = b'\x11'
    d_fins = make_basic_fins()
    d_fins.to_udp_res_read(data)
    d_ipv4.set_total_length(d_udp.bit_lens, d_fins.bit_lens)
    d_udp.set_total_length(d_fins.bit_lens)

    s_pkt = pile_up(s_ethernet, s_ipv4, s_udp, s_fins)
    d_pkt = pile_up(d_ethernet, d_ipv4, d_udp, d_fins)
    return s_pkt, d_pkt


def make_fins_write_packets(dmac, smac, dip, sip, dport, sport, address, data):
    s_ethernet, s_ipv4, s_tcp, s_udp = make_basic_protocol(dmac, smac, dip, sip, dport, sport, 0)
    s_ipv4.protocol['value'] = b'\x11'
    s_fins = make_basic_fins()
    s_fins.to_udp_ask_write(address, data)
    s_ipv4.set_total_length(s_udp.bit_lens, s_fins.bit_lens)
    s_udp.set_total_length(s_fins.bit_lens)

    d_ethernet, d_ipv4, d_tcp, d_udp = make_basic_protocol(smac, dmac, sip, dip, sport, dport, 1)
    d_ipv4.protocol['value'] = b'\x11'
    d_fins = make_basic_fins()
    d_fins.to_udp_res_write()
    d_ipv4.set_total_length(d_udp.bit_lens, d_fins.bit_lens)
    d_udp.set_total_length(d_fins.bit_lens)

    s_pkt = pile_up(s_ethernet, s_ipv4, s_udp, s_fins)
    d_pkt = pile_up(d_ethernet, d_ipv4, d_udp, d_fins)
    return s_pkt, d_pkt


if __name__ == '__main__':
    # spr, dpr = make_fins_read_packets(SMAC, DMAC, SIP, DIP, 9600, 13472, b'\x00\x64', b'\x00\x01\x00\x02')
    spw, dpw = make_fins_write_packets(SMAC, DMAC, SIP, DIP, 9600, 13472, b'\x00\x64', b'\x00\x01\x00\x02')

    pkts = []
    for i in range(1, 50):
        if i == 35:
            data = int_to_bytes(100, 4)
        else:
            data = int_to_bytes(i, 4)
        spr, dpr = make_fins_read_packets(SMAC, DMAC, SIP, DIP, 9600, 13472, b'\x00\x64', data)
        pkts.append(spr)
        pkts.append(dpr)
    pcap_wrapper([spw, dpw] + pkts, 'out/fins_test.pcap')
