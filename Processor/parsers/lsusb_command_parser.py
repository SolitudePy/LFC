import logging
from utils.parser import Parser

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path) 
    lines = content.split("\n")

    headers = ["bus_num", "device_num", "vendor_id","product_id", "device_info"]

    for line in lines:
        if line.strip():
            fields = line.strip().split()
            values = {
                headers[0]: fields[1],
                headers[1]: fields[3].strip(':'),
                headers[2]: fields[5].split(':')[0],
                headers[3]: fields[5].split(':')[1],
                headers[4]: ' '.join(fields[6:])
            }
            parser.data.append(values)
    json_data = parser.to_json()

    return json_data