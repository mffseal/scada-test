from .basic_protocol import Protocol
from .tools import *


class Hartip(Protocol):
    def __init__(self):
        super().__init__()
        # header
        self.version = {'value': b'\x01', 'lens': 8, 'enabled': True}
        self.message_type = {'value': b'\x00', 'lens': 8, 'enabled': True}
        self.message_id = {'value': b'\x03', 'lens': 8, 'enabled': True}
        self.status = {'value': b'\x00', 'lens': 8, 'enabled': True}
        self.sequence_num = {'value': b'\x00\x01', 'lens': 16, 'enabled': True}
        self.message_lens = {'value': b'\x00\x11', 'lens': 16, 'enabled': True}

        # body
        self.frame_type = {'value': b'\x82', 'lens': 8, 'enabled': True}
        self.long_address = {'value': b'\x00\x00\x00\x00\x05', 'lens': 40, 'enabled': True}
        self.command = {'value': b'\x0c', 'lens': 8, 'enabled': True}
        self.length = {'value': b'\x00', 'lens': 8, 'enabled': True}
        self.response_code = {'value': b'\x00', 'lens': 8, 'enabled': False}
        self.device_status = {'value': b'\xd0', 'lens': 8, 'enabled': False}
        self.message = {'value': b'\x00\x01', 'lens': 32, 'enabled': False}
        self.checksum = {'value': b'\x34', 'lens': 8, 'enabled': True}

    def to_read_ack(self):
        self.set_all_false()
        self.enable_field(self.version, self.message_type, self.message_id, self.status, self.sequence_num,
                          self.message_lens, self.frame_type, self.long_address, self.command, self.length,
                          self.checksum)

    def to_read_res(self, data):
        self.set_all_false()
        self.enable_field(self.version, self.message_type, self.message_id, self.status, self.sequence_num,
                          self.message_lens, self.frame_type, self.long_address, self.command, self.length,
                          self.response_code, self.device_status, self.message, self.checksum)

        self.message_type['value'] = b'\x01'
        self.message_lens['value'] = b'\x17'
        self.frame_type['value'] = b'\x86'
        self.length['value'] = b'\x05'
        self.message['value'] = data
        self.checksum['value'] = b'\xf5'
