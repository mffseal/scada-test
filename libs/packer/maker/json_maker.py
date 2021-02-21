import json


def general_process(name, process_data, key):
    with open('../out/ref/ref_check.json') as ref_chk_file:
        ref_chk_json = json.load(ref_chk_file)

    with open('../out/log/' + name + '_log.json') as log_file:
        log_json = json.load(log_file)
        print(log_json)
    with open('../out/' + name + '.json', 'w+') as json_file:
        ref_chk_json['table'] = 't_' + name[0:name.rfind('_')] + '_log'
        ref_chk_json['data'].clear()
        for i in range(1, 51):
            if i == 16:
                i = -49
            log_json[key] = process_data(51 - i)
            temp = log_json.copy()
            ref_chk_json['data'].append(temp)
        json_file.write(json.dumps(ref_chk_json, indent=4))


def s7_r():
    def data(i):
        return "\"\"{\"item\":[{\"db_number\":0,\"transport_size\":0,\"address_byte\":0,\"address_bit\":5,\"area\":\"0x84\",\"data_len\":4,\"data\":\"" + str(
            hex(i)).replace('x', '').zfill(8) + "\"}]}\"\""

    general_process('s7_r', data, 'PDU')


def modbus_w():
    def data(i):
        return "\"\"{\"address\":5,\"quantity\":1,\"value\":[" + str(i) + "]}\"\""

    general_process('modbus_w', data, 'PDU')


def omron_r():
    def data(i):
        return str(hex(i)).replace('x', '').zfill(4)

    general_process('omron_r', data, 'DATA')


def omron_w():
    def data(i):
        return str(hex(i)).replace('x', '').zfill(8)

    general_process('omron_w', data, 'DATA')


def dnp3_r():
    def data(i):
        return "\"\"{\"data\":[{\"obj\":2,\"var\":" + str(
            i) + ",\"prefix_code\":0,\"range_code\":6}],\"data_count\":1}\"\""

    general_process('dnp3_r', data, 'DATA')


def dnp3_w():
    def data(i):
        return "\"\"{\"data\":[{\"obj\":2,\"var\":" + str(
            i) + ",\"prefix_code\":0,\"range_code\":6}],\"data_count\":1}\"\"",

    general_process('dnp3_w', data, 'DATA')


def hartip_r():
    def data(i):
        return "\"\"{\"length\":5,\"data\":\"000000" + str(hex(i)).replace('x', '').zfill(8) + "f5\"}\"\""

    general_process('hartip_r', data, 'DATA')


def iec103_r():
    def data(i):
        return "\"\"{\"type_id\":1,\"SQ\":1,\"SQ_number\":1,\"COT\":9,\"addr\":10,\"FUN\":60,\"INF\":105,\"data\":[{\"DPI\":1,\"FOBTime\":{\"hour\":" + str(
            i) + ",\"min\":0,\"sec\":0},\"SIN\":6}]}\"\""

    general_process('iec103_r', data, 'DATA')


if __name__ == '__main__':
    iec103_r()
