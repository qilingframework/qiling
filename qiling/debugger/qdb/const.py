from enum import IntEnum


class color:
    """
    class for colorful prints
    """
    DARKGRAY  = '\033[90m'
    RED       = '\033[91m'
    GREEN     = '\033[92m'
    YELLOW    = '\033[93m'
    BLUE      = '\033[94m'
    PURPLE    = '\033[95m'
    CYAN      = '\033[96m'
    WHITE     = '\033[48m'
    BLACK     = '\033[35m'
    DARKCYAN  = '\033[36m'
    UNDERLINE = '\033[4m'
    BOLD      = '\033[1m'
    END       = '\033[0m'
    RESET     = '\033[39m'


class QDB_MSG(IntEnum):
    ERROR = 10
    INFO  = 20
