# class for colorful prints
class color:
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


FORMAT_LETTER = {
        "o", # octal
        "x", # hex
        "d", # decimal
        "u", # unsigned decimal
        "t", # binary
        "f", # float
        "a", # address
        "i", # instruction
        "c", # char
        "s", # string
        "z", # hex, zero padded on the left
        }


SIZE_LETTER = {
    "b": 1, # 1-byte, byte
    "h": 2, # 2-byte, halfword
    "w": 4, # 4-byte, word
    "g": 8, # 8-byte, giant
    }
