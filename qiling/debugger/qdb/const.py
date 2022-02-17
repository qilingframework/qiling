from enum import IntEnum

class color:
   """
   class for colorful prints
   """
   CYAN      = '\033[96m'
   PURPLE    = '\033[95m'
   BLUE      = '\033[94m'
   YELLOW    = '\033[93m'
   GREEN     = '\033[92m'
   RED       = '\033[91m'
   DARKGRAY  = '\033[90m'
   WHITE     = '\033[48m'
   DARKCYAN  = '\033[36m'
   BLACK     = '\033[35m'
   UNDERLINE = '\033[4m'
   BOLD      = '\033[1m'
   END       = '\033[0m'
   RESET     = '\x1b[39m'

class QDB_MSG(IntEnum):
    ERROR = 10
    INFO  = 20
