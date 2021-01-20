from .tools import *


class Protocol:
    def __init__(self):
        self._bit_lens = 0
        self._segment = 0
        # {'value': , 'lens': , 'enabled': True}

    def calc_bit_lens(self):
        """
        计算协议总bit长度
        :return: int
        """
        self._bit_lens = 0
        for name, value in vars(self).items():
            if name.startswith('_'):
                continue
            if not value['enabled']:
                continue
            self._bit_lens += value['lens']

    def calc_inner_lens(self, layer):
        """
        计算某字段以下的bit长度（不包含本字段）
        :param layer:  指定开始计算的字段（不包含）
        :return: int
        """
        inner_lens = 0
        flag = 0
        for name, value in vars(self).items():
            if name.startswith('_'):
                continue
            if not value['enabled']:
                continue
            if name == layer:
                flag = 1
                continue
            if flag == 1:
                inner_lens += value['lens']
        return inner_lens

    def set_all_false(self):
        """
        关闭所有字段
        :return:
        """
        for name, value in vars(self).items():
            if name.startswith('_'):
                continue
            temp = getattr(self, name)
            temp['enabled'] = False
            setattr(self, name, temp)

    def enable_field(self, *fields):
        """
        开启指定字段
        :param fields: self变量
        :return:
        """
        for f in fields:
            f['enabled'] = True

    @property
    def packed(self):
        """
        协议对象打包为bytes
        :return: bytes
        """
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
        """
        debug函数
        :return:
        """
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
        """
        设置mac
        :param dmac: 目的mac
        :param smac: 源mac
        :return:
        """
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
        """
        设置ip
        :param dip: 目的ip
        :param sip: 源ip
        :return:
        """
        self.destination['value'] = ip_to_bytes(dip)
        self.source['value'] = ip_to_bytes(sip)

    def set_total_length(self, *protocols_lens):
        self.total_length['value'] = sum_bit_to_bytes(self.total_length['lens'], self.bit_lens, *protocols_lens)


class MyTCP(Protocol):
    __global_tcp_seq = [0, 0]

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
        self.option = {'value': b'\x02\x04\x05\xb4\x01\x01\x04\x02', 'lens': 64, 'enabled': False}

    def set_basic(self, dport, sport, pid):
        """
        设置端口和身份
        :param dport: 目的端口
        :param sport: 源端口
        :param pid: 身份
        :return:
        """
        self.destination['value'] = int_to_bytes(dport, self.destination['lens'])
        self.source['value'] = int_to_bytes(sport, self.source['lens'])
        # 自己的序号设置成预备序号
        # 预期收到的序号设置成对方的预备序号
        self.sequence_num['value'] = int_to_bytes(MyTCP.__global_tcp_seq[pid], int(self.sequence_num['lens'] / 8))
        self.ack_num['value'] = int_to_bytes(MyTCP.__global_tcp_seq[not pid], int(self.sequence_num['lens'] / 8))

    def set_connection_status(self, pid, *protocols_lens):
        """
        设置序列号
        :param pid: 身份 0 or 1
        :param protocols_lens: 上级协议长度，计算下一次序列号
        :return:
        """
        super_lens = 0
        for pl in protocols_lens:
            super_lens += pl
        MyTCP.__global_tcp_seq[pid] += int(super_lens / 8)


class UDP(Protocol):
    def __init__(self):
        super().__init__()
        self.source = {'value': b'\xe5\x62', 'lens': 16, 'enabled': True}
        self.destination = {'value': b'\x25\x80', 'lens': 16, 'enabled': True}
        self.length = {'value': b'\x00\x1a', 'lens': 16, 'enabled': True}
        self.checksum = {'value': b'\x69\x52', 'lens': 16, 'enabled': True}

    def set_basic(self, dport, sport):
        self.destination['value'] = int_to_bytes(dport, self.destination['lens'])
        self.source['value'] = int_to_bytes(sport, self.source['lens'])

    def set_total_length(self, *protocols_lens):
        self.length['value'] = sum_bit_to_bytes(self.length['lens'], self.bit_lens, *protocols_lens)
