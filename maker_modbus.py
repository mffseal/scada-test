from maker import *
from protocol.modbus_protocol import *
from setting import *


def make_basic_modbus():
    modbus = Modbus()
    return modbus


def make_modbus_read_packets(dmac, smac, dip, sip, dport, sport, address, data):
    s_ethernet, s_ipv4, s_tcp = make_basic_protocol(dmac, smac, dip, sip, dport, sport, 0)
    s_modbus = make_basic_modbus()
    s_modbus.to_read_ack(address)
    s_ipv4.set_total_length(s_tcp.bit_lens, s_modbus.bit_lens)
    s_tcp.set_connection_status(0, s_modbus.bit_lens)

    d_ethernet, d_ipv4, d_tcp = make_basic_protocol(smac, dmac, sip, dip, sport, dport, 1)
    d_modbus = make_basic_modbus()
    d_modbus.to_read_res(data)
    d_ipv4.set_total_length(d_tcp.bit_lens, d_modbus.bit_lens)
    d_tcp.set_connection_status(1, d_modbus.bit_lens)

    s_pkt = pile_up(s_ethernet, s_ipv4, s_tcp, s_modbus)
    d_pkt = pile_up(d_ethernet, d_ipv4, d_tcp, d_modbus)
    return s_pkt, d_pkt


def make_modbus_write_packets(dmac, smac, dip, sip, dport, sport, address, data):
    s_ethernet, s_ipv4, s_tcp = make_basic_protocol(dmac, smac, dip, sip, dport, sport, 0)
    s_modbus = make_basic_modbus()
    s_modbus.to_write_ack(address, data)
    s_ipv4.set_total_length(s_tcp.bit_lens, s_modbus.bit_lens)
    s_tcp.set_connection_status(0, s_modbus.bit_lens)

    d_ethernet, d_ipv4, d_tcp = make_basic_protocol(smac, dmac, sip, dip, sport, dport, 1)
    d_modbus = make_basic_modbus()
    d_modbus.to_write_res(address, data)
    d_ipv4.set_total_length(d_tcp.bit_lens, d_modbus.bit_lens)
    d_tcp.set_connection_status(1, d_modbus.bit_lens)

    s_pkt = pile_up(s_ethernet, s_ipv4, s_tcp, s_modbus)
    d_pkt = pile_up(d_ethernet, d_ipv4, d_tcp, d_modbus)
    return s_pkt, d_pkt


if __name__ == '__main__':
    spr, dpr = make_modbus_read_packets(SMAC, DMAC, SIP, DIP, 502, 9699, b'\x05', b'\x00\x02')
    spw, dpw = make_modbus_write_packets(SMAC, DMAC, SIP, DIP, 502, 9699, b'\x05', b'\x00\x02')

    pkts = []
    for i in range(1, 20):
        spr, dpr = make_modbus_read_packets(SMAC, DMAC, SIP, DIP, 502, 9699, b'\x05', b'\x00\x02')
        pkts.append(spr)
        pkts.append(dpr)
    pcap_wrapper([spw, dpw] + pkts, 'out/modbus_test.pcap')
