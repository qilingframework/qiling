from enum import IntEnum

class ETYPE(IntEnum):
    UNKNOWN         = -1
    RESET           = 0
    NMI             = 1
    HARD_FAULT      = 2
    MEMMANAGE_FAULT = 3
    BUS_FAULT       = 4
    USAGE_FAULT     = 5
    SVCALL          = 6
    PENDSV          = 7
    SYSTICK         = 8
    IRQ             = 9

