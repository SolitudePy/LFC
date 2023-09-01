import logging
from utils.parser import Parser
import re

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path) 
    lines = content.strip().split('\n')

    # Extract the header line and creates a list.
    header_line = lines[1]
    headers = header_line.split()

    # Fix headers with spaces
    headers[3:5] = [''.join(headers[3:5])]
    headers[4:6] = [''.join(headers[4:6])]
    headers[6:8] = [''.join(headers[6:8])]
    headers[-1] = "pid"
    headers.append("process_name")
    headers[3] = "src_socket"
    headers[4] = "dest_socket"
    headers = parser.list_to_lower(headers)
    print(headers)

    for line in lines[2:]:
        values = line.split(None, len(headers) - 2)

        # In case State is empty
        if len(values) == 6:
            values.insert(5, "")
        
        # Done to seperate pid/programname
        values[-1] = values[-1].strip()
        fixed_value_process = values[-1].split('/')
        values[-1] = fixed_value_process[0]
        values.append(fixed_value_process[1])
        
        socket_info = dict(zip(headers, values))
        parser.data.append(socket_info)
    json_data = parser.to_json()

    return json_data