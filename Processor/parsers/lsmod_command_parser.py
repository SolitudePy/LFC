import logging
from utils.parser import Parser

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path) 
    lines = content.splitlines()
    headers = lines[0].split()

    # Normalize and rename headers using the updated field mapping
    normalized_headers = []
    for header in headers:
        if header.lower() == 'uid':
            normalized_headers.append('user_name')
        elif header.lower() == 'cmd':
            normalized_headers.append('cmd_line')
        elif header.lower() == 'stime':
            normalized_headers.append('process_start_time')
        else:
            normalized_headers.append(header.lower())

    for line in lines[1:]:
        values = line.split(None, len(normalized_headers) - 1)
        process_info = dict(zip(normalized_headers, values))
        parser.data.append(process_info)
    json_data = parser.to_json()

    return json_data