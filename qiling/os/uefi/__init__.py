import csv
from pathlib import Path

# -------- init GUIDs dictionary --------
csv_path = Path(__file__).parent / 'guids.csv'

guids_dict = {}
with open(csv_path) as guids_file:
    guids_reader = csv.reader(guids_file)
    for (guid, name) in guids_reader:
        guids_dict[guid] = name
