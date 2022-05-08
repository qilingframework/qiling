import csv
from typing import Mapping
import inspect
from pathlib import Path

def __init_guids_db() -> Mapping[str, str]:
    """Initialize GUIDs dictionary from a local database.
    """

    csv_path = Path(inspect.getfile(inspect.currentframe())).parent / 'guids.csv'

    with csv_path.open('r') as guids_file:
        guids_reader = csv.reader(guids_file)

        return dict(tuple(entry) for entry in guids_reader)

guids_db = __init_guids_db()
