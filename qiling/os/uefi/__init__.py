import csv
from os import path

# -------- init GUIDs dictionary --------
csv_path = path.dirname(path.abspath(__file__))
csv_path = path.join(csv_path,'guids.csv')

guids_dict = {}
with open(csv_path) as guids_file:
    guids_reader = csv.reader(guids_file)
    for (guid, name) in guids_reader:
        guids_dict[guid] = name
