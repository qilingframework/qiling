import csv
from typing import Mapping
from os import path

def __init_guids_db() -> Mapping[str, str]:
    """Initialize GUIDs dictionary from a local database.
    """

    csv_path = path.dirname(path.abspath(__file__))
    csv_path = path.join(csv_path, 'guids.csv')

    with open(csv_path) as guids_file:
        guids_reader = csv.reader(guids_file)

        return dict(tuple(entry) for entry in guids_reader)

guids_db = __init_guids_db()
