import json
import hashlib

class Parser:
    def __init__(self):
        self.data = []

    def read_file(self, file_path):
        with open(file_path, 'r') as file:
            content = file.read()
        return content

    def to_json(self):
        json_data = json.dumps(self.data)
        return json_data
    
    def calculate_hash_sha256(self, file_path):
        hash_object = hashlib.sha256()
        with open(file_path, 'rb') as file:
            for chunk in iter(lambda: file.read(4096), b''):
                hash_object.update(chunk)
        return hash_object.hexdigest()
    
    def list_to_lower(self, lst):
        return [i.lower() for i in lst]