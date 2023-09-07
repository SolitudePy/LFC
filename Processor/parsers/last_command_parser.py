import logging
from utils.parser import Parser
import re

logger = logging.getLogger(__name__)


def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path) 
    lines = content.strip().split('\n')
    lines = lines[:-2]

    for line in lines:
        fields = line.split()

        # Checks if it's a reboot row.
        if fields[0:3] == ["reboot", "system", "boot"]:
            fields[1:3] = ["system_boot"]

        # Checks if it's a local connection.
        if "tty" in fields[1]:
            fields.insert(2, "")

        # Checks if session still exist.
        if fields[7] == "-":
            end_time = fields[8]
            session_length = fields[9]
        else:
            end_time = "still logged in"
            session_length = "still logged in"
        parser.data.append({
            "user_name": fields[0],
            "terminal": fields[1],
            "src_ip": fields[2],
            "start_time": " ".join(fields[3:7]),
            "end_time": end_time,
            "session_length": session_length
        })
    json_data = parser.to_json()

    return json_data