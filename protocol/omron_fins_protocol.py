from .basic_protocol import Protocol
from .tools import *


class OmronFins(Protocol):
    def __init__(self):
        super().__init__()

        # FINS/TCP Header
        self.magic_bytes = {'value': b'\x46\x49\x4e\x53', 'lens': 32, 'enabled': True}  # FINS
        self.fintcp_total_lens = {'value': b'\x00\x00\x00\x1a', 'lens': 32, 'enabled': True}
        # 0:仅有Client Node Address字段, 1:Client/Server Node Address字段均出现
        self.command = {'value': b'\x00\x00\x00\x02', 'lens': 32, 'enabled': True}
        self.error_code = {'value': b'\x00\x00\x00\x00', 'lens': 32, 'enabled': True}
        self.client_node_address = {'value': b'\x00', 'lens': 32, 'enabled': False}
        self.server_node_address = {'value': b'\x00', 'lens': 32, 'enabled': False}

        # FINS Header
        self.omron_icf_field = {'value': b'\x80', 'lens': 8, 'enabled': True}
        self.reserved = {'value': b'\x00', 'lens': 8, 'enabled': True}
        self.gateway_count = {'value': b'\x02', 'lens': 8, 'enabled': True}
        self.des_network_address = {'value': b'\x00', 'lens': 8, 'enabled': True}  # local network
        self.des_node_number = {'value': b'\x03', 'lens': 8, 'enabled': True}  # sysmac net / link
        self.des_unit_address = {'value': b'\x00', 'lens': 8, 'enabled': True}  # cpu
        self.src_network_address = {'value': b'\x00', 'lens': 8, 'enabled': True}  # local network
        self.src_node_number = {'value': b'\xc0', 'lens': 8, 'enabled': True}
        self.src_unit_address = {'value': b'\x00', 'lens': 8, 'enabled': True}  # cpu
        self.service_id = {'value': b'\x00', 'lens': 8, 'enabled': True}
        self.command_code = {'value': b'\x01\x01', 'lens': 16, 'enabled': True}

        # Command Data
        self.response_code = {'value': b'\x00\x00', 'lens': 16, 'enabled': False}
        self.response_data = {'value': b'\x00\x01', 'lens': 16, 'enabled': False}
        self.memory_area_code = {'value': b'\x82', 'lens': 8, 'enabled': True}
        self.begin_address = {'value': b'\x00\x64', 'lens': 16, 'enabled': True}
        self.begin_address_bits = {'value': b'\x00', 'lens': 8, 'enabled': True}
        self.num_of_items = {'value': b'\x00\x01', 'lens': 16, 'enabled': True}
        self.fill = {'value': b'\x00', 'lens': 16, 'enabled': False}
        self.data = {'value': b'\x00\x00\x00\x08', 'lens': 16, 'enabled': False}
        self.command_data = {'value': b'\x00\x00\x00\x08', 'lens': 32, 'enabled': False}

    def to_ask_read(self, address):
        self.set_all_false()
        self.enable_field(self.magic_bytes, self.fintcp_total_lens, self.command, self.error_code, self.omron_icf_field,
                          self.reserved, self.gateway_count, self.des_network_address, self.des_node_number,
                          self.des_unit_address, self.src_network_address, self.src_node_number, self.src_unit_address,
                          self.service_id, self.command_code, self.memory_area_code, self.begin_address,
                          self.begin_address_bits, self.num_of_items)

        self.command['value'] = b'\x00\x00\x00\x02'
        self.command_code['value'] = b'\x01\x01'
        self.begin_address['value'] = address
        self.fintcp_total_lens['value'] = int_to_bytes(int(self.calc_inner_lens('fintcp_total_lens') / 8),
                                                       int(self.fintcp_total_lens['lens'] / 8))

    def to_res_read(self, data):
        self.set_all_false()
        self.enable_field(self.magic_bytes, self.fintcp_total_lens, self.command, self.error_code,
                          self.client_node_address, self.fill, self.data)

        self.command['value'] = b'\x00\x00\x00\x00'
        self.data['value'] = data
        self.fintcp_total_lens['value'] = int_to_bytes(int(self.calc_inner_lens('fintcp_total_lens') / 8),
                                                       int(self.fintcp_total_lens['lens'] / 8))

    def to_ask_write(self, address, data):
        self.set_all_false()
        self.enable_field(self.magic_bytes, self.fintcp_total_lens, self.command, self.error_code, self.omron_icf_field,
                          self.reserved, self.gateway_count, self.des_network_address, self.des_node_number,
                          self.des_unit_address, self.src_network_address, self.src_node_number, self.src_unit_address,
                          self.service_id, self.command_code, self.memory_area_code, self.begin_address,
                          self.begin_address_bits, self.num_of_items, self.command_data)

        self.command['value'] = b'\x00\x00\x00\x02'
        self.command_code['value'] = b'\x01\x02'
        self.begin_address['value'] = address
        self.command_data['value'] = data
        self.fintcp_total_lens['value'] = int_to_bytes(int(self.calc_inner_lens('fintcp_total_lens') / 8),
                                                       int(self.fintcp_total_lens['lens'] / 8))

    def to_res_write(self):
        self.set_all_false()
        self.enable_field(self.magic_bytes, self.fintcp_total_lens, self.command, self.error_code,
                          self.client_node_address)

        self.command['value'] = b'\x00\x00\x00\x00'
        self.fintcp_total_lens['value'] = int_to_bytes(int(self.calc_inner_lens('fintcp_total_lens') / 8),
                                                       int(self.fintcp_total_lens['lens'] / 8))

    def to_udp_ask_read(self, address):
        self.set_all_false()
        self.enable_field(self.omron_icf_field,
                          self.reserved, self.gateway_count, self.des_network_address, self.des_node_number,
                          self.des_unit_address, self.src_network_address, self.src_node_number, self.src_unit_address,
                          self.service_id, self.command_code, self.memory_area_code, self.begin_address,
                          self.begin_address_bits, self.num_of_items)

        self.omron_icf_field['value'] = b'\x80'
        self.des_node_number['value'] = b'\x03'
        self.src_node_number['value'] = b'\xc0'
        self.des_node_number['value'] = b'\x03'
        self.command['value'] = b'\x00\x00\x00\x02'
        self.command_code['value'] = b'\x01\x01'
        self.begin_address['value'] = address

    def to_udp_res_read(self, data):
        self.set_all_false()
        self.enable_field(self.omron_icf_field, self.reserved, self.gateway_count, self.des_network_address,
                          self.des_node_number, self.des_unit_address, self.src_network_address, self.src_node_number,
                          self.src_unit_address, self.service_id, self.command_code, self.response_code,
                          self.response_data)

        self.omron_icf_field['value'] = b'\xc0'
        self.des_node_number['value'] = b'\xc0'
        self.src_node_number['value'] = b'\x03'
        self.response_code['value'] = b'\x00\x00'
        self.response_data['value'] = data

    def to_udp_ask_write(self, address, data):
        self.set_all_false()
        self.enable_field(self.omron_icf_field, self.reserved, self.gateway_count, self.des_network_address,
                          self.des_node_number, self.des_unit_address, self.src_network_address, self.src_node_number,
                          self.src_unit_address, self.service_id, self.command_code, self.memory_area_code,
                          self.begin_address, self.begin_address_bits, self.num_of_items, self.command_data)

        self.omron_icf_field['value'] = b'\x80'
        self.des_node_number['value'] = b'\x03'
        self.src_node_number['value'] = b'\xc0'
        self.command_code['value'] = b'\x01\x02'
        self.memory_area_code['value'] = b'\x82'
        self.begin_address['value'] = address
        self.command_data['value'] = b'\x01'

    def to_udp_res_write(self):
        self.set_all_false()
        self.enable_field(self.omron_icf_field, self.reserved, self.gateway_count, self.des_network_address,
                          self.des_node_number, self.des_unit_address, self.src_network_address, self.src_node_number,
                          self.src_unit_address, self.service_id, self.command_code, self.response_code)

        self.omron_icf_field['value'] = b'\xc0'
        self.des_node_number['value'] = b'\xc0'
        self.src_node_number['value'] = b'\x03'
        self.command_code['value'] = b'\x01\x02'
        self.response_code['value'] = b'\x00\x00'

