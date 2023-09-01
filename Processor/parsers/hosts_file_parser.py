import logging
from utils.parser import Parser

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path)
    lines = content.split("\n")
    headers = ["ip_addr", "hostname", "aliases"]

    # Loops through hosts file lines
    for line in lines:
        if line.strip() and not line.startswith("#"):
            values = line.split()
            if len(values) > 2:
                values[2::] = [values[2::]]
            hosts_info = dict(zip(headers, values))
            parser.data.append(hosts_info)
    json_data = parser.to_json()

    return json_data