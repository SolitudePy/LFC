from utils.parser import Parser
import logging

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    hostname_info = {}
    content = parser.read_file(file_path)
    lines = content.splitlines()
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            hostname_info[key] = value

    parser.data.append(hostname_info)
    json_data = parser.to_json()
    
    return json_data