from .tools import *


class Protocol:
    def __init__(self):
        self._bit_lens = 0
        self._segment = 0
        # {'value': , 'lens': , 'enabled': True}

    def calc_bit_lens(self):
        self._bit_lens = 0
        for name, value in vars(self).items():
            if name.startswith('_'):
                continue
            if not value['enabled']:
                continue
            self._bit_lens += value['lens']

    def set_all_false(self):
        for name, value in vars(self).items():
            if name.startswith('_'):
                continue
            temp = getattr(self, name)
            temp['enabled'] = False
            setattr(self, name, temp)

    def enable_field(self, *fields):
        for f in fields:
            f['enabled'] = True

    @property
    def packed(self):
        packet = 0
        for name, value in vars(self).items():
            if name.startswith('_'):
                continue
            if not value['enabled']:
                continue
            packet <<= value['lens']
            packet |= int.from_bytes(value['value'], byteorder='big')
        self._segment = packet
        return packet

    @property
    def bit_lens(self):
        self.calc_bit_lens()
        return self._bit_lens

    @property
    def segment(self):
        return self._segment

    def check(self):
        print('------\t', self.__class__.__name__, '检查\t------')
        print(self.packed.to_bytes(int(self.bit_lens / 8), byteorder='big'))
        print('------------------------------')


class Ethernet(Protocol):
    def __init__(self):
        super().__init__()
        self.destination = {'value': b'\x00\x0f\xb5\x4d\xbe\xf3', 'lens': 48, 'enabled': True}  # 目的mac
        self.source = {'value': b'\x00\x0c\x29\xc0\x32\xf4', 'lens': 48, 'enabled': True}  # 源mac
        self.type = {'value': b'\x08\x00', 'lens': 16, 'enabled': True}  # 指定IPv4

    def set_basic(self, dmac, smac):
        self.destination['value'] = mac_to_bytes(dmac)
        self.source['value'] = mac_to_bytes(smac)


class IPv4(Protocol):
    def __init__(self):
        super().__init__()
        self.version = {'value': b'\x04', 'lens': 4, 'enabled': True}  # ip版本4
        self.header_length = {'value': b'\x05', 'lens': 4, 'enabled': True}  # 首部长度
        self.diff_service = {'value': b'\x00', 'lens': 8, 'enabled': True}  # 差异服务
        self.total_length = {'value': b'\x00\x47', 'lens': 16, 'enabled': True}  # 总长
        self.id = {'value': b'\x23\xf6', 'lens': 16, 'enabled': True}  # 标识，ip累加计数器
        self.flag = {'value': b'\x02', 'lens': 3, 'enabled': True}  # 分片标识 010不分片 001后面还有分片
        self.offset = {'value': b'\x00', 'lens': 13, 'enabled': True}  # 片偏移
        self.ttl = {'value': b'\x80', 'lens': 8, 'enabled': True}  # 最大跳数
        self.protocol = {'value': b'\x06', 'lens': 8, 'enabled': True}  # tcp
        self.header_checksum = {'value': b'\x52\xab', 'lens': 16, 'enabled': True}  # 首部校验和
        self.source = {'value': b'\xc0\xa8\x01\xb4', 'lens': 32, 'enabled': True}  # 源ip地址
        self.destination = {'value': b'\xc0\xa8\x01\x0b', 'lens': 32, 'enabled': True}  # 目的ip地址

    def set_basic(self, dip, sip):
        self.destination['value'] = ip_to_bytes(dip)
        self.source['value'] = ip_to_bytes(sip)

    def set_total_length(self, tcp_lens, tpkt_lens, cotp_lens, s7_lens):
        self.total_length['value'] = sum_bit_to_bytes(self.total_length['lens'], self.bit_lens, tcp_lens, tpkt_lens,
                                                      cotp_lens, s7_lens)


class MyTCP(Protocol):
    __global_tcp_seq = [1, 1]

    def __init__(self):
        super().__init__()
        self.source = {'value': b'\x04\x5d', 'lens': 16, 'enabled': True}  # 源端口
        self.destination = {'value': b'\x00\x66', 'lens': 16, 'enabled': True}  # 目的端口
        self.sequence_num = {'value': b'\xd9\x0a\x79\x64', 'lens': 32, 'enabled': True}  # 顺序号，首个数据字节的序列号
        self.ack_num = {'value': b'\xd3\x37\x77\x98', 'lens': 32, 'enabled': True}  # 应答号，预期收到的顺序号
        self.header_length = {'value': b'\x05', 'lens': 4, 'enabled': True}  # tcp首部长度
        self.flag = {'value': b'\x18', 'lens': 12, 'enabled': True}  # 标志位，多个标志
        self.window = {'value': b'\xff\xce', 'lens': 16, 'enabled': True}  # 滑动窗口大小
        self.checksum = {'value': b'\xe1\xe0', 'lens': 16, 'enabled': True}  # 校验和
        self.urgent_pointer = {'value': b'\x00\x00', 'lens': 16, 'enabled': True}  # 紧急指针

    def set_basic(self, dport, sport, pid):
        self.destination['value'] = int_to_bytes(dport, self.destination['lens'])
        self.source['value'] = int_to_bytes(sport, self.source['lens'])
        # 自己的序号设置成预备序号
        # 预期收到的序号设置成对方的预备序号
        self.sequence_num['value'] = int_to_bytes(MyTCP.__global_tcp_seq[pid], int(self.sequence_num['lens'] / 8))
        self.ack_num['value'] = int_to_bytes(MyTCP.__global_tcp_seq[not pid], int(self.sequence_num['lens'] / 8))

    def set_connection_status(self, pid, tpkt, cotp, s7):
        MyTCP.__global_tcp_seq[pid] += int((tpkt + cotp + s7) / 8)
