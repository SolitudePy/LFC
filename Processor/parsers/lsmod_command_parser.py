import logging
from utils.parser import Parser

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path) 
    lines = content.splitlines()
    headers = lines[0].split()

    # Fix headers
    headers[0] = "module_name"
    headers = parser.list_to_lower(headers)

    for line in lines[1:]:
        values = line.split()

        # if module is not used by any system
        if len(values) == 3:
            values.append("")
        else:
            values[-1] = values[-1].split(',')
        module_info = dict(zip(headers, values))
        parser.data.append(module_info)
    json_data = parser.to_json()

    return json_data