import logging
from utils.parser import Parser

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path) 
    lines = content.splitlines()

    headers = ["process_name", "pid", "tid", "user_name",
              "file_descriptor", "type", "device", "size_offset",
                "inode_num", "file_path", "is_deleted"]

    for line in lines[1:]:
        fd_info = {}
        values = line.split()
        
        # Extract process name
        fd_info[headers[0]] = values[0]

        # Extract pid
        fd_info[headers[1]] = values[1]

        # Checks whether tid is blank or not
        if values[2].isdigit():
            fd_info[headers[2]] = values[2]
        else:
            fd_info[headers[2]] = ""
            values.insert(2, " ")
        
        # Extract user name
        fd_info[headers[3]] = values[3]

        # Checks if fd is DEL
        if values[4] == "DEL":
            continue
        else:
            fd_info[headers[4]] = values[4]

        # Checks whether type is unknown
        if values[5] == "unknown":
            continue
        else:
            fd_info[headers[5]] = values[5]
        
        # Checks whether device is not blank
        if ',' in values[6] or 'x' in values[6]:
            fd_info[headers[6]] = values[6]
        else:
            fd_info[headers[6]] = ""
            values.insert(6, " ")
        
        # Extract size/offset
        fd_info[headers[7]] = values[7]

        # Extract inode number
        fd_info[headers[8]] = values[8]
        
        # Extract file path
        fd_info[headers[9]] = values[9]
 
        # Checks if file has been deleted.
        if values[-1] == '(deleted)':
            fd_info[headers[10]] = True
        else:
            fd_info[headers[10]] = False
        parser.data.append(fd_info)
    json_data = parser.to_json()

    return json_data