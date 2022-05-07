import csv
from typing import Mapping
import pkgutil

def __init_guids_db() -> Mapping[str, str]:
    """Initialize GUIDs dictionary from a local database.
    """

    guids_file = pkgutil.get_data(__package__, 'guids.csv').decode()
    guids_reader = csv.reader(guids_file.splitlines())

    return dict(tuple(entry) for entry in guids_reader)

guids_db = __init_guids_db()
