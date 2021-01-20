from .basic_protocol import Protocol
from .tools import *


class Modbus(Protocol):
    def __init__(self):
        super().__init__()

        # Modbus/TCP
        self.trans_id = {'value': b'\x00\x05', 'lens': 16, 'enabled': True}
        self.protocol_id = {'value': b'\x00\x00', 'lens': 16, 'enabled': True}
        self.mt_length = {'value': b'\x00\x06', 'lens': 16, 'enabled': True}
        self.unit_id = {'value': b'\x01', 'lens': 8, 'enabled': True}

        # Modbus
        self.function_code = {'value': b'\x03', 'lens': 8, 'enabled': True}
        self.byte_code = {'value': b'\x02', 'lens': 8, 'enabled': False}
        self.reference_num = {'value': b'\x00\x64', 'lens': 16, 'enabled': True}
        self.word_count = {'value': b'\x00\x01', 'lens': 16, 'enabled': True}
        self.register = {'value': b'\x00\x01', 'lens': 16, 'enabled': False}
        self.data = {'value': b'\x00\x01', 'lens': 16, 'enabled': False}

    def to_read_ack(self, address):
        self.set_all_false()
        self.enable_field(self.trans_id, self.protocol_id, self.mt_length, self.unit_id, self.function_code,
                          self.reference_num, self.word_count)

        self.function_code['value'] = b'\x03'
        self.reference_num['value'] = address

    def to_read_res(self, data):
        self.set_all_false()
        self.enable_field(self.trans_id, self.protocol_id, self.mt_length, self.unit_id, self.function_code,
                          self.byte_code, self.register)

        self.function_code['value'] = b'\x03'
        self.mt_length['value'] = b'\x00\x05'
        self.register['value'] = data

    def to_write_ack(self, address, data):
        self.set_all_false()
        self.enable_field(self.trans_id, self.protocol_id, self.mt_length, self.unit_id, self.function_code,
                          self.reference_num, self.data)

        self.function_code['value'] = b'\x06'
        self.trans_id['value'] = b'\x00\x18'
        self.mt_length['value'] = b'\x00\x06'
        self.reference_num['value'] = address
        self.data['value'] = data

    def to_write_res(self, address, data):
        self.set_all_false()
        self.enable_field(self.trans_id, self.protocol_id, self.mt_length, self.unit_id, self.function_code,
                          self.reference_num, self.data)

        self.function_code['value'] = b'\x06'
        self.trans_id['value'] = b'\x00\x18'
        self.mt_length['value'] = b'\x00\x06'
        self.reference_num['value'] = address
        self.data['value'] = data
