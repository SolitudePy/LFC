import logging
import os
from utils.parser import Parser

logger = logging.getLogger(__name__)

def parse(proc_path):
    parser = Parser()

    for pid in os.listdir(proc_path):
        if pid.isdigit():
            pid_path = os.path.join(proc_path, pid)
            if len(os.listdir(pid_path)) == 0:
                continue
            process_info = {'pid': int(pid)}
            try:
                with open(os.path.join(pid_path, 'status')) as status_file:
                    for line in status_file:
                        if line.startswith('Name:'):
                            process_info['process_name'] = line.split(':', 1)[1].strip()
                        elif line.startswith('State:'):
                            process_info['state'] = line.split(':', 1)[1].strip()
                        elif line.startswith('Uid:'):
                            uid = line.split(':', 1)[1].split()[0]
                            process_info['user_id'] = int(uid)
                        elif line.startswith('PPid:'):
                            ppid = line.split(':', 1)[1].split()[0]
                            process_info['ppid'] = int(ppid)
            except FileNotFoundError as e:
                logger.error(f"{e}")

            try:
                with open(os.path.join(proc_path, pid, 'cmdline'), 'rb') as cmdline_file:
                    cmdline = cmdline_file.read().decode('utf-8').replace('\x00', ' ').strip()
                    process_info['cmd_line'] = cmdline
            except (FileNotFoundError, UnicodeDecodeError) as e:
                logger.error(f"{e}")

            try:
                executable_path = os.path.join(proc_path, pid, 'exe')
                executable_hash = parser.calculate_hash_sha256(executable_path)
                process_info['exe_sha256'] = executable_hash
            except FileNotFoundError:
                process_info['exe_sha256'] = ""
            parser.data.append(process_info)
    json_data = parser.to_json()

    return json_data