from libs.packer.maker.maker import *
from libs.packer.protocol import *
from setting import *


def make_basic_fins():
    fins = OmronFins()
    return fins


def make_tcp_fins_read_packets(dmac, smac, dip, sip, dport, sport, address, data):
    s_ethernet, s_ipv4 = make_basic_protocol(dmac, smac, dip, sip)
    s_tcp = make_tcp(dport, sport, 0)
    s_fins = make_basic_fins()
    s_fins.to_ask_read(address)
    s_ipv4.set_total_length(s_tcp.bit_lens, s_fins.bit_lens)
    s_tcp.set_connection_status(0, s_fins.bit_lens)

    d_ethernet, d_ipv4 = make_basic_protocol(smac, dmac, sip, dip)
    d_tcp = make_tcp(sport, dport, 1)
    d_fins = make_basic_fins()
    d_fins.to_res_read(data)
    d_ipv4.set_total_length(d_tcp.bit_lens, d_fins.bit_lens)
    d_tcp.set_connection_status(1, d_fins.bit_lens)

    s_pkt = pile_up(s_ethernet, s_ipv4, s_tcp, s_fins)
    d_pkt = pile_up(d_ethernet, d_ipv4, d_tcp, d_fins)
    return s_pkt, d_pkt


def make_tcp_fins_write_packets(dmac, smac, dip, sip, dport, sport, address, data):
    s_ethernet, s_ipv4 = make_basic_protocol(dmac, smac, dip, sip)
    s_tcp = make_tcp(dport, sport, 0)
    s_fins = make_basic_fins()
    s_fins.to_ask_write(address, data)
    s_ipv4.set_total_length(s_tcp.bit_lens, s_fins.bit_lens)
    s_tcp.set_connection_status(0, s_fins.bit_lens)

    d_ethernet, d_ipv4 = make_basic_protocol(smac, dmac, sip, dip)
    d_tcp = make_tcp(sport, dport, 1)
    d_fins = make_basic_fins()
    d_fins.to_res_write()
    d_ipv4.set_total_length(d_tcp.bit_lens, d_fins.bit_lens)
    d_tcp.set_connection_status(1, d_fins.bit_lens)

    s_pkt = pile_up(s_ethernet, s_ipv4, s_tcp, s_fins)
    d_pkt = pile_up(d_ethernet, d_ipv4, d_tcp, d_fins)
    return s_pkt, d_pkt


def sens_r():
    pkts = []
    for i in range(1, 50):
        if i == 35:
            data = int_to_bytes(100, 4)
        else:
            data = int_to_bytes(i, 4)
        spr, dpr = make_tcp_fins_read_packets(SMAC, DMAC, SIP, DIP, 9600, 13472, b'\x05', data)
        pkts.append(spr)
        pkts.append(dpr)
    pcap_wrapper(pkts, 'out/fins_tcp_r.pcap')


def sens_w():
    pkts = []
    for i in range(1, 50):
        if i == 35:
            data = int_to_bytes(100, 4)
        else:
            data = int_to_bytes(i, 4)
        spr, dpr = make_tcp_fins_write_packets(DMAC, SMAC, DIP, SIP, 9600, 13472, b'\x05', data)
        pkts.append(spr)
        pkts.append(dpr)
    pcap_wrapper(pkts, 'out/fins_tcp_w.pcap')


if __name__ == '__main__':
    # spr, dpr = make_fins_read_packets(SMAC, DMAC, SIP, DIP, 9600, 13472, b'\x00\x64', b'\x00\x01\x00\x02')
    # spw, dpw = make_tcp_fins_write_packets(SMAC, DMAC, SIP, DIP, 9600, 13472, b'\x00\x64', b'\x00\x01\x00\x02')
    #
    # pkts = []
    # for i in range(1, 10):
    #     spr, dpr = make_tcp_fins_read_packets(SMAC, DMAC, SIP, DIP, 9600, 13472, b'\x00\x64', b'\x00\x01\x00\x02')
    #     pkts.append(spr)
    #     pkts.append(dpr)
    # pcap_wrapper([spw, dpw] + pkts, 'out/fins_test.pcap')

    pcap_maker(make_tcp_fins_read_packets, '../out/fins_tcp_r.pcap', DMAC, SMAC, DIP, SIP, 9600, 13472, b'\x05')
    pcap_maker(make_tcp_fins_write_packets, '../out/fins_tcp_w.pcap', DMAC, SMAC, DIP, SIP, 9600, 13472, b'\x05')
