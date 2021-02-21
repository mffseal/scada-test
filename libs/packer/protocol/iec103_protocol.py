from .basic_protocol import Protocol
from .tools import *


class IEC103(Protocol):
    def __init__(self):
        super().__init__()
        self.start = {'value': b'\x10', 'lens': 8, 'enabled': True}
        self.length = {'value': b'\x0e', 'lens': 8, 'enabled': True}
        self.length_repeat = {'value': b'\x0e', 'lens': 8, 'enabled': False}
        self.start_repeat = {'value': b'\x10', 'lens': 8, 'enabled': False}
        self.control_field = {'value': b'\x7a', 'lens': 8, 'enabled': True}
        self.link_addr = {'value': b'\x0a', 'lens': 8, 'enabled': True}
        self.type_id = {'value': b'\x01', 'lens': 8, 'enabled': False}  # time-tagged message
        self.vsq = {'value': b'\x81', 'lens': 8, 'enabled': False}
        self.cause_of_trans = {'value': b'\x09', 'lens': 8, 'enabled': False}
        self.common_address = {'value': b'\x0a', 'lens': 8, 'enabled': False}
        self.func_type = {'value': b'\x3c', 'lens': 8, 'enabled': False}
        self.info_num = {'value': b'\x69', 'lens': 8, 'enabled': False}
        self.dpi = {'value': b'\x01', 'lens': 8, 'enabled': False}
        self.bin_time = {'value': b'\x5c\x3b\x23\x13', 'lens': 32, 'enabled': False}
        self.sup_info = {'value': b'\x06', 'lens': 8, 'enabled': False}
        self.check_sum = {'value': b'\x84', 'lens': 8, 'enabled': True}
        self.end = {'value': b'\x16', 'lens': 8, 'enabled': True}

    def to_read_ack(self):
        self.set_all_false()
        self.enable_field(self.start, self.control_field, self.link_addr, self.check_sum, self.end)

    def to_read_res(self, data):
        self.set_all_false()
        self.enable_field(self.start, self.length, self.length_repeat, self.start_repeat, self.control_field,
                          self.link_addr, self.type_id, self.vsq, self.cause_of_trans, self.common_address,
                          self.func_type, self.info_num, self.dpi, self.bin_time, self.sup_info, self.check_sum,
                          self.end)

        self.start['value'] = b'\x68'
        self.length['value'] = b'\x0e'
        self.start_repeat['value'] = b'\x68'
        self.length_repeat['value'] = b'\x0e'
        self.control_field['value'] = b'\x28'
        self.bin_time['value'] = data
        self.check_sum['value'] = b'\x42'
        self.end['value'] = b'\x16'
