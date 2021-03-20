import csv
from typing import Mapping
from os import path

# -------- init GUIDs dictionary --------
csv_path = path.dirname(path.abspath(__file__))
csv_path = path.join(csv_path,'guids.csv')

guids_dict: Mapping[str, str] = {}
with open(csv_path) as guids_file:
    guids_reader = csv.reader(guids_file)

    guids_dict = dict(tuple(entry) for entry in guids_reader)
