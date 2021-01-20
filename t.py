def s7_r(s7_r_log_json):
    with open('libs/packer/out/log/s7_r_log.json') as s7_r_log_file:
        s7_r_log_json = json.load(s7_r_log_file)
        print(s7_r_log_json)

    with open('libs/packer/out/s7_r.json', 'w+') as s7_r_json_file:
        ref_chk_json['table'] = 't_s7_log'
        ref_chk_json['data'].clear()
        for i in range(1, 51):
            if i == 35:
                i = 100
            s7_r_log_json[
                'PDU'] = "\"\"{\"item\":[{\"db_number\":0,\"transport_size\":0,\"address_byte\":0,\"address_bit\":5,\"area\":\"0x84\",\"data_len\":4,\"data\":\"" + str(
                hex(i)).replace('x', '').zfill(8) + "\"}]}\"\""
            temp = s7_r_log_json.copy()
            ref_chk_json['data'].append(temp)
        s7_r_json_file.write(json.dumps(ref_chk_json, indent=4))


with open('libs/packer/out/log/modbus_w_log.json') as modbus_w_log_file:
    modbus_w_log_json = json.load(modbus_w_log_file)
    print(modbus_w_log_json)

with open('libs/packer/out/modbus_w.json', 'w+') as modbus_w_json_file:
    ref_chk_json['table'] = 't_modbus_log'
    ref_chk_json['data'].clear()
    for i in range(1, 51):
        if i == 35:
            i = 100
        s7_r_log_json['PDU'] = "\"\"{\"address\":5,\"quantity\":1,\"value\":[" + str(i) + "]}\"\""
        temp = modbus_w_log_json.copy()
        ref_chk_json['data'].append(temp)
    modbus_w_json_file.write(json.dumps(ref_chk_json, indent=4))