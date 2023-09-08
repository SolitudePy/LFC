import logging
from utils.parser import Parser
import re

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path) 
    lines = content.strip().split('\n')

    
    for line in lines[1:]:
        values = line.split()

        parser.data.append({
            "protocol": values[0],
            "state": values[1],
            "recv-q": values[2],
            "send-q": values[3],
            "src_socket": values[4],
            "dest_socket": values[5],
        })
    json_data = parser.to_json()

    return json_data