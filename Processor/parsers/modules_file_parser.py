import logging
from utils.parser import Parser

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path)
    lines = content.split("\n")
    headers = ["module_name", "size_bytes", "instance_num", "dependencies",
              "load_state", "kernel_offset"]

    # Loops through passwd file lines
    for line in lines:
        if line.strip():
            values = line.split()

            # For some reason it also ends with a comma.
            values[3] = values[3].strip(',').split(',')
            module_info = dict(zip(headers, values))
            parser.data.append(module_info)
    json_data = parser.to_json()

    return json_data