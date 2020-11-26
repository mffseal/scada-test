from binascii import *
import crcmod.predefined


def pile_up(*protocols):
    """
    协议组合为数据包
    :param protocols: bytes类型的各个协议层
    :return: bytes类型的数据包
    """
    packet = 0
    bit_lens = 0
    for p in protocols:
        p.check()
        # p.packed
        bit_lens += p.bit_lens
        packet <<= p.bit_lens
        packet |= p.segment
    packet = packet.to_bytes(int(bit_lens / 8), byteorder='big')
    return packet


def int_to_bytes(num, lens):
    """
    int转bytes
    :param num: 整数
    :param lens: 目标bytes的字节长度
    :return: bytes类型
    """
    int_bytes = int(num).to_bytes(lens, byteorder='big')
    return int_bytes


def ip_to_bytes(ip):
    ip_bytes = bytes(map(int, ip.split('.')))
    return ip_bytes


def mac_to_bytes(mac):
    mac_bytes = b''
    for m in mac.split(':'):
        mac_bytes += bytes(a2b_hex(m.lower()))
    return mac_bytes


def sum_bit_to_bytes(bit_lens, *nums):
    """
    int求和后转为bytes
    :param bit_lens: 接收结果的变量比特长度
    :param nums: 需要求和的int类型
    :return: 求和结果的bytes表示
    """
    lens = int(bit_lens / 8)
    sum_int = 0
    for n in nums:
        sum_int += n
    sum_int = int(sum_int / 8)
    sum_bytes = int_to_bytes(sum_int, lens)
    return sum_bytes


def calc_crc(*words, pattern):
    stream = b''
    for w in words:
        stream += w
    crc16 = crcmod.predefined.Crc(pattern)
    crc16.update(stream)
    return crc16.crcValue.to_bytes(2, byteorder='little')
