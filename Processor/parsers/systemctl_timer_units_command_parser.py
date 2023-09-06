import logging
from utils.parser import Parser

logger = logging.getLogger(__name__)

def parse(file_path):
    parser = Parser()
    content = parser.read_file(file_path)
    lines = content.strip().split('\n')[:-2]

    # Iterate through the lines and split each line into fields
    for line in lines[1:]:
        fields = line.split()

        non_schedule = "n/a"

        # Checks if timer has no schedule activation
        if fields[0] == non_schedule:
            next_run_time = non_schedule
            time_for_next_run = non_schedule
            last_run_time = non_schedule
            time_from_last_run = non_schedule
        else:
            next_run_time = " ".join(fields[0:4])
            time_for_next_run = " ".join(fields[4:6])
            last_run_time = " ".join(fields[6:10])
            time_from_last_run = " ".join(fields[10:12])
        timer_name = fields[-2]
        action = fields[-1]
        parser.data.append({
            "next_run_time": next_run_time,
            "time_for_next_run": time_for_next_run,
            "last_run_time": last_run_time,
            "time_from_last_run": time_from_last_run,
            "timer_name": timer_name,
            "action": action
        })
    json_data = parser.to_json()

    return json_data