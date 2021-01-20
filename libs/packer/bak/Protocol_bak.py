class Protocol:
    def __init__(self):
        self.bit_lens = 0

    def calc_bit_lens(self):
        for name, value in vars(self).items():
            self.bit_lens += value.bin.bit_length()
        return self.bit_lens


class Ethernet(Protocol):
    def __init__(self):
        super().__init__()
        self.destination = '\x00\x0f\xb5\x4d\xbe\xf3'  # 目的mac
        self.source = '\x00\x0c\x29\xc0\x32\xf4'  # 源mac
        self.type = b'\x08\x00'  # 指定IPv4


class IPv4(Protocol):
    def __init__(self):
        super().__init__()
        self.version = 0b0100  # ip版本4
        self.header_length = 0b0101  # 首部长度45
        self.diff_service = b'\x00'  # 差异服务
        self.total_length = b'\x00\x47'  # 总长
        self.id = b'\x23\xf6'  # 标识，ip累加计数器
        self.flag = 0b010  # 分片标识 010不分片 001后面还有分片
        self.offset = 0b0  # 片偏移
        self.ttl = b'\x80'  # 最大跳数
        self.protocol = b'\x06'  # tcp
        self.header_checksum = b'\x52\xab'  # 首部校验和
        self.source = b'\xc0\xa8\x01\xb4'  # 源ip地址
        self.destination = b'\xc0\xa8\x01\x0b'  # 目的ip地址


class TCP(Protocol):
    def __init__(self):
        super().__init__()
        self.source = b'\x04\x5d'  # 源端口
        self.destination = b'\x00\x66'  # 目的端口
        self.sequence_num = b'\xd9\x0a\x79\x64'  # 顺序号，首个数据字节的序列号
        self.ack_num = b'\xd3\x37\x77\x98'  # 应答号，预期收到的顺序号
        self.header_length = 0b0100  # tcp首部长度
        self.flag = 0b000000011000  # 标志位，多个标志
        self.window = b'\xff\xce'  # 滑动窗口大小
        self.checksum = b'\xe1\xe0'  # 校验和
        self.urgent_pointer = b'\x00\x00'  # 紧急指针


class TPKT(Protocol):
    def __init__(self):
        super().__init__()
        self.version = b'\x03'
        self.reserved = b'\x00'
        self.length = b'\x00\x1f'  # TPKT总长度（包含上层payload）


class COTP(Protocol):
    def __init__(self):
        super().__init__()
        self.length = b'\x02'
        self.pdu_type = b'\x0f'  # pdu:协议数据单元
        self.tpdu_num = 0b0000000
        self.last_data_unit = 0b1


class S7(Protocol):
    def __init__(self):
        super().__init__()
        # header 包含长度信息，PDU参考和消息类型常量
        self.rotocol_id = b'\x32'  # 协议常量，固定值
        self.osctr = b'\x01'  # 消息类型 1job:主站请求 2ack:从站无数据确认 3ack-data:带数据确认 7userdata:协议扩展
        self.eserved = b'\x00\x00'  # 固定值
        self.du_reference = b'\x00\x00'  # 主站生成，每次新传输递增
        self.arameter_length = b'\x00\x0e'  # 参数长度
        self.ata_length = b'\x00\x00'  # 数据长度
        # ack包特有字段
        self.rror_class = b'\x00'  # 有无错误
        self.rror_code = b'\x00'  # 错误码

        # parameter
        # | 0x00 | diagnostics |
        # | 0x04 | read |
        # | 0x05 | write |
        # | 0x1a | request_download |
        # | 0x1b | download_block |
        # | 0x1c | end_download |
        # | 0x1d | start_download |
        # | 0x1e | upload |
        # | 0x1f | end_upload |
        # | 0x28 | plc_control |
        # | 0x29 | plc_stop |
        # | 0xf0 | setup
        self.unction = b'\x04'  # 功能码，见上表
        self.tem_count = b'\x01'

        # data
        self.eturn_code = b'\xff'  # success
        self.rans_size = b'\x04'  # 传输字长
        self.ength = b'\x00\x20'  # 长度
        self.ata = b'\x00\x01\x00\x02'  # 数据
