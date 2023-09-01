import logging
from utils.parser import Parser

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path)
    lines = content.split("\n")
    headers = ["user_name", "password", "user_id", "group_id",
              "description", "home_dir", "shell"]

    # Loops through passwd file lines
    for line in lines:
        if line.strip():
            values = line.split(":")
            user_info = dict(zip(headers, values))
            parser.data.append(user_info)
    json_data = parser.to_json()

    return json_data