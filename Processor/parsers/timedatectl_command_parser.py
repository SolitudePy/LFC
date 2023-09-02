from utils.parser import Parser
import logging

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    timedate_info = {}
    content = parser.read_file(file_path)
    lines = content.splitlines()

    i = 0
    while i < len(lines):
        line = lines[i]
        key_value = line.split(":", maxsplit=1)
        key = key_value[0].strip()
        value = key_value[1].strip()
        if key == "Last DST change" or key == "Next DST change":
            value += " "  + lines[i+1].strip()
            value += " " + lines[i+2].strip()
            i += 2
        i += 1
        timedate_info[key] = value
    parser.data.append(timedate_info)
    json_data = parser.to_json()
    
    return json_data