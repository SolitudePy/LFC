import logging
from utils.parser import Parser
import re

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path) 
    lines = content.strip().split('\n')

    for line in lines:
        values = line.split()
        
        # Checks if the device is no longer used
        if values[-1] == "STALE":
            state = "STALE"
        else:
            state = values[5]

        parser.data.append({
            "ip_addr": values[0],
            "interface": values[2],
            "mac_addr": values[4],
            "state": state,
        })
    json_data = parser.to_json()

    return json_data