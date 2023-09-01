from utils.parser import Parser
import logging

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    sestatus_info = {}
    content = parser.read_file(file_path)
    lines = content.splitlines()
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            sestatus_info[key] = value

    parser.data.append(sestatus_info)
    json_data = parser.to_json()
    
    return json_data