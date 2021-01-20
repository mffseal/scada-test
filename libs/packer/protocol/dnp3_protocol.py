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
        self.transport_control = {'value': b'\xc1', 'lens': 8, 'enabled': True}

        # Application Layer
        # Data Chunk
        self.app_control = {'value': b'\xc0', 'lens': 8, 'enabled': True}
        self.function_code = {'value': b'\x01', 'lens': 8, 'enabled': True}
        self.internal_indications = {'value': b'\x00\x00', 'lens': 16, 'enabled': True}
        self.read_req_data_objs = {'value': b'\x3c\x02\x06\x3c\x03\x06\x3c\x04\x06\x3c\x01\x06', 'lens': 96,
                                   'enabled': True}
        self.write_req_data_objs = {'value': b'\x50\x01\x00\x07\x07\x00', 'lens': 48,
                                    'enabled': False}
        self.response_data_objs = {'value': b'\x01\x02\x00\x00\x09\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x03" \
                                            "\x02\x00\x00\x09\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x14\x01" \
                                            "\x00\x00\x09\x02\x00\x00\x00\x00\x02\x00\x00\x00\x00\x02\x00\x00" \
                                            "\x00\x00\x02\x00\x00\x00\x00\x02\x00\x00\x00\x00\x02\x00\x00\x00" \
                                            "\x00\x02\x00\x00\x00\x00\x02\x00\x00\x00\x00\x02\x00\x00\x00\x00" \
                                            "\x02\x00\x00\x00\x00\x15\x01\x00\x00\x09\x02\x00\x00\x00\x00\x02" \
                                            "\x00\x00\x00\x00\x02\x00\x00\x00\x00\x02\x00\x00\x00\x00\x02\x00" \
                                            "\x00\x00\x00\x02\x00\x00\x00\x00\x02\x00\x00\x00\x00\x02\x00\x00" \
                                            "\x00\x00\x02\x00\x00\x00\x00\x02\x00\x00\x00\x00\x1e\x01\x00\x00" \
                                            "\x09\x02\x00\x00\x00\x00\x02\x00\x00\x00\x00\x02\x00\x00\x00\x00" \
                                            "\x02\x00\x00\x00\x00\x02\x00\x00\x00\x00\x02\x00\x00\x00\x00\x02" \
                                            "\x00\x00\x00\x00\x02\x00\x00\x00\x00\x02\x00\x00\x00\x00\x02\x00" \
                                            "\x00\x00\x00\x0a\x02\x00\x00\x09\x02\x02\x02\x02\x02\x02\x02\x02" \
                                            "\x02\x02\x28\x01\x00\x00\x09\x02\x00\x00\x00\x00\x02\x00\x00\x00" \
                                            "\x00\x02\x00\x00\x00\x00\x02\x00\x00\x00\x00\x02\x00\x00\x00\x00" \
                                            "\x02\x00\x00\x00\x00\x02\x00\x00\x00\x00\x02\x00\x00\x00\x00\x02" \
                                            "\x00\x00\x00\x00\x02\x00\x00\x00\x00', 'lens': 269,
                                   'enabled': False}
        self.data_chunk_checksum = {'value': b'\x8a\x51', 'lens': 16, 'enabled': True}

    def to_read_ack(self, address, data):
        self.set_all_false()
        self.enable_field(self.start_bytes, self.dlh_length, self.control, self.destination, self.source,
                          self.dlh_checksum, self.transport_control, self.app_control, self.function_code,
                          self.read_req_data_objs, self.data_chunk_checksum)

        self.transport_control['value'] = b'\xc1'
        self.app_control['value'] = b'\xc2'
        self.function_code['value'] = b'\x01'  # read
        self.dlh_length['value'] = b'\x0b'
        self.destination['value'] = b'\x0a\x00'
        self.source['value'] = b'\x01\x00'
        self.read_req_data_objs['value'] = address + data + b'\x06'
        self.read_req_data_objs['lens'] = 24

        self.dlh_checksum['value'] = calc_crc(self.start_bytes['value'], self.dlh_length['value'],
                                              self.control['value'], self.destination['value'], self.source['value'],
                                              pattern='crc-16-dnp')

        self.data_chunk_checksum['value'] = calc_crc(self.transport_control['value'], self.app_control['value'],
                                                     self.function_code['value'], self.read_req_data_objs['value'],
                                                     pattern='crc-16-dnp')

    def to_read_res(self):
        self.set_all_false()
        self.enable_field(self.start_bytes, self.dlh_length, self.control, self.destination, self.source,
                          self.dlh_checksum, self.transport_control, self.app_control, self.function_code,
                          self.internal_indications, self.data_chunk_checksum)

        self.destination['value'] = b'\x01\x00'
        self.source['value'] = b'\x0a\x00'
        self.transport_control['value'] = b'\xd4'
        self.app_control['value'] = b'\xc2'
        self.function_code['value'] = b'\x81'
        self.dlh_length['value'] = b'\x0a'
        self.internal_indications['value'] = b'\x80\x00'

        self.dlh_checksum['value'] = calc_crc(self.start_bytes['value'], self.dlh_length['value'],
                                              self.control['value'], self.destination['value'], self.source['value'],
                                              pattern='crc-16-dnp')

        self.data_chunk_checksum['value'] = calc_crc(self.transport_control['value'], self.app_control['value'],
                                                     self.function_code['value'], self.internal_indications['value'],
                                                     pattern='crc-16-dnp')

    def to_write_ack(self, address, data):
        self.set_all_false()
        self.enable_field(self.start_bytes, self.dlh_length, self.control, self.destination, self.source,
                          self.dlh_checksum, self.transport_control, self.app_control, self.function_code,
                          self.write_req_data_objs, self.data_chunk_checksum)

        self.control['value'] = b'\xc4'
        self.destination['value'] = b'\x04\x00'
        self.source['value'] = b'\x03\x00'
        self.dlh_length['value'] = b'\x0e'
        self.dlh_checksum['value'] = calc_crc(self.start_bytes['value'], self.dlh_length['value'],
                                              self.control['value'], self.destination['value'], self.source['value'],
                                              pattern='crc-16-dnp')
        self.transport_control['value'] = b'\xc3'
        self.app_control['value'] = b'\xc4'
        self.function_code['value'] = b'\x02'
        self.write_req_data_objs['value'] = address + data + b'\x00\x07\x07\x00'
        self.write_req_data_objs['lens'] = 48
        self.data_chunk_checksum['value'] = calc_crc(self.transport_control['value'], self.app_control['value'],
                                                     self.function_code['value'], self.write_req_data_objs['value'],
                                                     pattern='crc-16-dnp')

    def to_write_res(self):
        self.set_all_false()
        self.enable_field(self.start_bytes, self.dlh_length, self.control, self.destination, self.source,
                          self.dlh_checksum, self.transport_control, self.app_control, self.function_code,
                          self.internal_indications, self.data_chunk_checksum)

        self.control['value'] = b'\x44'
        self.destination['value'] = b'\x03\x00'
        self.source['value'] = b'\x04\x00'
        self.dlh_length['value'] = b'\x0a'
        self.dlh_checksum['value'] = calc_crc(self.start_bytes['value'], self.dlh_length['value'],
                                              self.control['value'], self.destination['value'], self.source['value'],
                                              pattern='crc-16-dnp')
        self.transport_control['value'] = b'\xd7'
        self.app_control['value'] = b'\xc4'
        self.function_code['value'] = b'\x81'
        self.internal_indications['value'] = b'\x00\x00'
        self.data_chunk_checksum['value'] = calc_crc(self.transport_control['value'], self.app_control['value'],
                                                     self.function_code['value'], self.internal_indications['value'],
                                                     pattern='crc-16-dnp')
