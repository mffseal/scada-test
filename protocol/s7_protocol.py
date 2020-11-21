from .basic_protocol import Protocol
from .tools import *


class TPKT(Protocol):
    def __init__(self):
        super().__init__()
        self.version = {'value': b'\x03', 'lens': 8, 'enabled': True}
        self.reserved = {'value': b'\x00', 'lens': 8, 'enabled': True}
        self.length = {'value': b'\x00\x1f', 'lens': 16, 'enabled': True}  # TPKT总长度（包含上层payload）

    def set_length(self, cotp_lens, s7_lens):
        self.length['value'] = sum_bit_to_bytes(self.length['lens'], self.bit_lens, cotp_lens, s7_lens)


class COTP(Protocol):
    def __init__(self):
        super().__init__()
        self.length = {'value': b'\x02', 'lens': 8, 'enabled': True}
        self.pdu_type = {'value': b'\xf0', 'lens': 8, 'enabled': True}  # pdu:协议数据单元
        self.destination = {'value': b'\x00\x00', 'lens': 16, 'enabled': False}
        self.source = {'value': b'\x00\x01', 'lens': 16, 'enabled': False}
        self.opt = {'value': b'\x80', 'lens': 8, 'enabled': True}
        self.parameter = {'value': b'\xc1\x02\x01\x00\xc2\x02\x03\x02\xc0\x01\x09', 'lens': 88, 'enabled': True}

    def to_connection(self):
        self.set_all_false()
        self.enable_field(self.length, self.pdu_type, self.destination, self.source, self.opt, self.parameter)

    def to_function(self):
        self.set_all_false()
        self.enable_field(self.length, self.pdu_type, self.opt)


class S7(Protocol):
    def __init__(self):
        super().__init__()
        # header 包含长度信息，PDU参考和消息类型常量
        self.protocol_id = {'value': b'\x32', 'lens': 8, 'enabled': True}  # 协议常量，固定值
        # 1job:主站请求 2ack:从站无数据确认 3ack-data:带数据确认 7userdata:协议扩展
        self.rosctr = {'value': b'\x01', 'lens': 8, 'enabled': True}  # 消息类型
        self.reserved = {'value': b'\x00\x00', 'lens': 16, 'enabled': True}  # 固定值
        self.pdu_reference = {'value': b'\x00\x00', 'lens': 16, 'enabled': True}  # 主站生成，每次新传输递增
        self.parameter_length = {'value': b'\x00\x0e', 'lens': 16, 'enabled': True}  # 参数长度
        self.total_data_length = {'value': b'\x00\x00', 'lens': 16, 'enabled': True}  # 数据长度
        self.error_class = {'value': b'\x00', 'lens': 8, 'enabled': False}  # 有无错误
        self.error_code = {'value': b'\x00', 'lens': 8, 'enabled': False}  # 错误码

        # parameter
        # | 0x04 | read
        # | 0x05 | write
        self.function = {'value': b'\x04', 'lens': 8, 'enabled': True}  # 功能码，见上表
        self.item_count = {'value': b'\x01', 'lens': 8, 'enabled': True}
        # Item
        self.variable_spec = {'value': b'\x12', 'lens': 8, 'enabled': True}
        self.lofas = {'value': b'\x0a', 'lens': 8, 'enabled': True}
        self.syntax_id = {'value': b'\x10', 'lens': 8, 'enabled': True}
        self.para_trans_size = {'value': b'\x02', 'lens': 8, 'enabled': False}
        self.request_data_length = {'value': b'\x00\x04', 'lens': 16, 'enabled': True}  # 请求数据长度
        self.db_num = {'value': b'\x00\x01', 'lens': 16, 'enabled': True}
        self.area = {'value': b'\x84', 'lens': 8, 'enabled': True}
        self.address = {'value': b'\x00\x00\x00', 'lens': 24, 'enabled': True}

        # data
        self.return_code = {'value': b'\xff', 'lens': 8, 'enabled': False}  # success
        self.data_trans_size = {'value': b'\x02', 'lens': 8, 'enabled': True}  # 传输字长
        self.pure_data_length = {'value': b'\x00\x04', 'lens': 16, 'enabled': True}  # 数据长度
        self.data = {'value': b'\x00\x01\x00\x02', 'lens': 32, 'enabled': False}  # 数据

    def to_ack_read(self, total_data_lens: bytes, para_trans_size: bytes, address: bytes):
        self.set_all_false()
        self.enable_field(self.protocol_id, self.rosctr, self.reserved, self.pdu_reference, self.parameter_length,
                          self.total_data_length, self.function, self.item_count, self.variable_spec, self.lofas,
                          self.syntax_id, self.para_trans_size, self.request_data_length, self.db_num, self.area,
                          self.address)

        self.rosctr['value'] = b'\x01'  # Job
        self.parameter_length['value'] = b'\x00\x0e'
        self.function['value'] = b'\x04'
        self.item_count['value'] = b'\x01'
        self.variable_spec['value'] = b'\x12'
        self.lofas['value'] = b'\x0a'
        self.syntax_id['value'] = b'\x10'
        self.para_trans_size['value'] = para_trans_size
        self.total_data_length['value'] = total_data_lens
        self.db_num['value'] = b'\x01'
        self.area['value'] = b'\x84'  # DB
        self.address['value'] = address

    def to_res_read(self, data_trans_size: bytes, data: bytes, pure_data_lens: bytes, total_data_lens: int):
        self.set_all_false()
        self.enable_field(self.protocol_id, self.rosctr, self.reserved, self.pdu_reference, self.parameter_length,
                          self.total_data_length, self.error_class, self.error_code, self.function, self.item_count,
                          self.return_code, self.data_trans_size, self.pure_data_length, self.data)

        self.rosctr['value'] = b'\x03'  # Ack_Data
        self.parameter_length['value'] = b'\x00\x02'
        self.function['value'] = b'\x04'
        self.item_count['value'] = b'\x01'
        self.total_data_length['value'] = int_to_bytes(total_data_lens, int(self.total_data_length['lens'] / 8))
        self.data_trans_size['value'] = data_trans_size
        self.pure_data_length['value'] = pure_data_lens
        self.data['lens'] = total_data_lens * 8
        self.data['value'] = data

    def to_ack_write(self, data_trans_size: bytes, data: bytes, total_data_lens: int, address: bytes):
        self.set_all_false()
        self.enable_field(self.protocol_id, self.rosctr, self.reserved, self.pdu_reference, self.parameter_length,
                          self.total_data_length, self.function, self.item_count, self.variable_spec, self.lofas,
                          self.syntax_id, self.para_trans_size, self.request_data_length, self.db_num, self.area,
                          self.address, self.return_code, self.data_trans_size, self.pure_data_length, self.data)

        self.rosctr['value'] = b'\x01'  # Job
        self.parameter_length['value'] = b'\x00\x0e'
        self.function['value'] = b'\x05'
        self.item_count['value'] = b'\x01'
        self.variable_spec['value'] = b'\x12'
        self.lofas['value'] = b'\x0a'
        self.syntax_id['value'] = b'\x10'
        self.para_trans_size['value'] = b'\x02'
        self.request_data_length['value'] = b'\x04'
        self.data_trans_size['value'] = data_trans_size
        self.total_data_length['value'] = int_to_bytes(total_data_lens, int(self.total_data_length['lens'] / 8))
        self.data['lens'] = total_data_lens * 8
        self.db_num['value'] = b'\x00'
        self.area['value'] = b'\x83'  # DB
        self.pure_data_length['value'] = b'\x00\x04'
        self.address['value'] = address
        self.data['value'] = data

    def to_res_write(self, total_data_lens: int):
        self.set_all_false()
        self.enable_field(self.protocol_id, self.rosctr, self.reserved, self.pdu_reference, self.parameter_length,
                          self.total_data_length, self.error_class, self.error_code, self.function, self.item_count,
                          self.return_code)

        self.rosctr['value'] = b'\x03'
        self.parameter_length['value'] = b'\x02'
        self.total_data_length['value'] = int_to_bytes(total_data_lens, int(self.total_data_length['lens'] / 8))
        self.data['lens'] = total_data_lens * 8
        self.function['value'] = b'\x05'
        self.item_count['value'] = b'\x01'
        self.return_code['value'] = b'\xff'
