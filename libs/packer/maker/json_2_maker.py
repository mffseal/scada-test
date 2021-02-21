import json


def sens(name):
    fime_name = name + '_sens.json'
    with open('../out/ref/sens/' + fime_name, encoding='UTF-8') as raw_json_file:
        raw_json = json.load(raw_json_file)

        output_json = {"table": "t_sensitive_data_log", "count": 50, "sort": "OCCURRENCE_TIME", "version": 1,
                       "data": []}
        print(output_json)
        for hit in raw_json["hits"]["hits"]:
            temp = {key: hit['_source'][key] for key in
                    ["ORIGINAL_VALUE", "CONVERT_VALUE", "REGISTER_ADDRESS", "METADATA_VALUE", "LOG_TYPE"]}
            print(temp)
            output_json['data'].append(temp)

    with open('../out/' + fime_name, 'w+', encoding='UTF-8', ) as output_json_file:
        output_json_file.write(json.dumps(output_json, indent=4))


def event(name):
    fime_name = name + '_event.json'
    with open('../out/ref/event/' + fime_name, encoding='UTF-8') as raw_json_file:
        raw_json = json.load(raw_json_file)

        output_json = {"table": "t_event_log", "count": 50, "sort": "OCCURRENCE_TIME", "version": 1,
                       "data": []}
        print(output_json)
        for hit in raw_json["hits"]["hits"]:
            temp = {key: hit['_source'][key] for key in
                    ["EVENT_TYPE", "EVENT_LEVEL", "DMAC", "SMAC", "LOG_TYPE", "SPORT", "DPORT", "DIP", "EVENT_ITEM",
                     "PROTOCOL_TYPE", "REGISTER_ADDRESS", "RULE_TYPE", "SIP"]}
            print(temp)
            output_json['data'].append(temp)

    with open('../out/' + fime_name, 'w+', encoding='UTF-8', ) as output_json_file:
        output_json_file.write(json.dumps(output_json, ensure_ascii=False, indent=4))


def rw(name, rw):
    fime_name = name + rw + '.json'
    with open('../out/ref/rw/' + fime_name, encoding='UTF-8') as raw_json_file:
        raw_json = json.load(raw_json_file)

        output_json = {"table": name + "_log", "count": 50, "sort": "OCCURRENCE_TIME", "version": 1,
                       "data": []}
        print(output_json)
        for hit in raw_json["hits"]["hits"]:
            temp = {key: hit['_source'][key] for key in
                    ["EVENT_TYPE", "EVENT_LEVEL", "DMAC", "SMAC", "LOG_TYPE", "SPORT", "DPORT", "DIP", "EVENT_ITEM",
                     "PROTOCOL_TYPE", "REGISTER_ADDRESS", "RULE_TYPE", "SIP"]}
            print(temp)
            output_json['data'].append(temp)

    with open('../out/' + fime_name, 'w+', encoding='UTF-8', ) as output_json_file:
        output_json_file.write(json.dumps(output_json, ensure_ascii=False, indent=4))

if __name__ == '__main__':
    sens('modbus_r')
    event('modbus_r')
