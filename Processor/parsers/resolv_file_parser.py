import logging
from utils.parser import Parser

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path)
    lines = content.split("\n")
    headers = ["directive", "value"]

    # Loops through resolv file lines
    for line in lines:
        if line.strip() and not line.startswith("#"):
            values = line.split(maxsplit=1)
            values[1] = values[1].split()
            dns_info = dict(zip(headers, values))
            parser.data.append(dns_info)
    json_data = parser.to_json()

    return json_data