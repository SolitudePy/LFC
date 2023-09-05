import logging
from utils.parser import Parser
import os

logger = logging.getLogger(__name__)

def parse(base_dir):
    parser = Parser()

    # Loops through base dir and search for all history files
    for root, _, files in os.walk(base_dir):
        for filename in files:
            if filename.endswith('_history') or filename == '.history':
                filepath = os.path.join(root, filename)
                username = os.path.basename(root)

                enc = "utf-8"
                with open(filepath, 'r', encoding=enc) as file:
                    commands = file.read().splitlines()
                    for command in commands:

                        # Creates a json from those history files.
                        parser.data.append({
                            'cmd_line': command,
                            'user_name': username,
                            'file_name': filename
                        })
    json_data = parser.to_json()

    return json_data
