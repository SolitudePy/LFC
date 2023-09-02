import logging
from utils.parser import Parser

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path)
    lines = content.split("\n")
    headers = ["exe_sha256", "file_path"]

    for line in lines:
        if line.strip():
            values = line.split()
            file_info = dict(zip(headers, values))
            parser.data.append(file_info)
    json_data = parser.to_json()

    return json_data