import logging
from utils.parser import Parser

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path)
    lines = content.strip().split('\n')[:-7]

    # Iterate through the lines and split each line into fields
    for line in lines[1:]:
        fields = line.split(maxsplit=4)

        # Check if line is empty
        if len(fields) != 0:

            # Done for services with not-found load state
            if fields[0] == "\u25cf":
                fields = line.split(maxsplit=5)[1:]
        
        # Check if line is a service schema
        if len(fields) == 5:
            service_name, load, overall_state, sub_state, description = fields[:5]
            parser.data.append({
                "service_name": service_name,
                "load": load,
                "overall_state": overall_state,
                "sub_state": sub_state,
                "description": description,
            })
    json_data = parser.to_json()

    return json_data