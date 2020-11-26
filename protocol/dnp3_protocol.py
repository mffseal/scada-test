from .basic_protocol import Protocol
from .tools import *


class DNP3(Protocol):
    def __init__(self):
        super().__init__()

        # Data Link Layer
        self.start_bytes = {'value': b'\x05\x64', 'lens': 16, 'enabled': True}  # 固定字段
        self.dlh_length = {'value': b'\x14', 'lens': 8, 'enabled': True}
        self.control = {'value': b'\xc4', 'lens': 8, 'enabled': True}
        self.destination = {'value': b'\x0a\x00', 'lens': 16, 'enabled': True}
        self.source = {'value': b'\x01\x00', 'lens': 16, 'enabled': True}
        self.dlh_checksum = {'value': b'\x8f\xed', 'lens': 16, 'enabled': True}

        # Transport Control
        self.transport_control = {'value': b'\xc0', 'lens': 8, 'enabled': True}

        # Application Layer
        # Data Chunk
        self.app_control = {'value': b'\xc0', 'lens': 8, 'enabled': True}
        self.function_code = {'value': b'\x01', 'lens': 8, 'enabled': True}
        self.internal_indications = {'value': b'\x00\x00', 'lens': 16, 'enabled': True}
        self.read_req_data_objs = {'value': b'\x3c\x02\x06\x3c\x03\x06\x3c\x04\x06\x3c\x01\x06', 'lens': 96,
                                   'enabled': True}
        self.data_chunk_checksum = {'value': b'\x8a\x51', 'lens': 16, 'enabled': True}

    def to_read_ack(self, address):
        self.set_all_false()
        self.enable_field(self.start_bytes, self.dlh_length, self.control, self.destination, self.source,
                          self.dlh_checksum, self.transport_control, self.app_control, self.function_code,
                          self.read_req_data_objs, self.data_chunk_checksum)

        self.function_code['value'] = b'\x01'  # read
        self.dlh_length['value'] = b'\x0b'
        self.destination['value'] = address
        self.read_req_data_objs['value'] = b'\x3c\x04\x06'
        self.read_req_data_objs['lens'] = 24

        self.dlh_checksum['value'] = calc_crc(self.start_bytes['value'], self.dlh_length['value'],
                                              self.control['value'], self.destination['value'], self.source['value'],
                                              pattern='crc-16-dnp')

        self.data_chunk_checksum['value'] = calc_crc(self.transport_control['value'], self.app_control['value'],
                                                     self.function_code['value'], self.read_req_data_objs['value'],
                                                     pattern='crc-16-dnp')

    def to_read_res(self):
        self.set_all_false()
        self.enable_field()
