import logging
from utils.parser import Parser

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path)
    lines = content.split("\n")
    headers = ["group_name", "password", "group_id", "group_members"]

    # Loops through group file lines
    for line in lines:
        if line.strip():
            values = line.split(":")
            values[-1] = values[-1].split(',')
            group_info = dict(zip(headers, values))
            parser.data.append(group_info)
    json_data = parser.to_json()

    return json_data