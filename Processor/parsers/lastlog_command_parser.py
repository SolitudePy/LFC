import logging
from utils.parser import Parser

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path)
    lines = content.split("\n")
    headers = ["user_name", "terminal", "src_ip", "last_login"]

    # Loops through passwd file lines
    for line in lines[1:]:
        if line.strip():
            login_info = {}
            values = line.split(maxsplit=3)
            login_info[headers[0]] = values[0]
            term = False
            if (values[1].startswith('pts') or values[1].startswith('tty')):
                login_info[headers[1]] = values[1]
                term = True
            else:
                login_info[headers[1]] = ""
            if (values[2][0]).isdigit():
                login_info[headers[2]] = values[2]
                login_info[headers[3]] = values[3]
            else:
                if term:
                    login_info[headers[2]] = ""
                    login_info[headers[3]] = ' '.join(values[2:])
                else:
                    if not values[1].startswith("*"):
                        login_info[headers[2]] = values[1]
                        login_info[headers[3]] = ' '.join(values[2:])
                    else:
                        login_info[headers[2]] = ""
                        login_info[headers[3]] = "No Logon"
            if login_info[headers[3]].startswith("*"):
                login_info[headers[3]] = "No Logon"
            parser.data.append(login_info)
    json_data = parser.to_json()

    return json_data