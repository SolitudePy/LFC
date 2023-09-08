import logging
from utils.parser import Parser

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path) 
    lines = content.strip().split('\n')

    for line in lines:
        values = line.strip().split()

        # Ignore comments and empty lines
        if not values or values[0].startswith('#') or values[0].startswith('*'):
            continue

        # Create a dictionary to store the rule
        rule = {
            "target": values[0],  # Target (e.g., ACCEPT, DROP)
            "chain": values[1],   # Chain (e.g., INPUT, OUTPUT)
            "protocol": values[2] if values[2] != '-p' else None,  # Protocol (if specified)
            "source": values[3] if values[3] != '--source' else None,  # Source IP (if specified)
            "destination": values[5] if values[4] == '--destination' else None,  # Destination IP (if specified)
        }
        parser.data.append(rule)
    json_data = parser.to_json()

    return json_data