import logging
from utils.parser import Parser
import re

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path) 
    lines = content.splitlines()

    for line in lines[2:]:
        fields = line.split()
        if len(fields) >= 8:
            user_name = fields[0]
            terminal = fields[1]
            remote_src = fields[2]
            login_time = fields[3]
            idle_time = fields[4]
            system_process_time = fields[5]
            current_process_time = fields[6]
            user_current_process = fields[7:]

            session_info = {
                'user_name': user_name,
                'terminal': terminal,
                'remote_src': remote_src,
                'login_time': login_time,
                'idle_time': idle_time,
                'system_process_time': system_process_time,
                'current_process_time': current_process_time,
                'user_current_process': user_current_process
            }
            parser.data.append(session_info)
    json_data = parser.to_json()

    return json_data