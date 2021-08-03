#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class STATE(IntEnum):
    CTS = 9
    LBD = 8
    TXE = 7
    TC = 6
    RXNE = 5
    IDLE = 4
    ORE = 3
    NF = 2
    FE = 1
    PE = 0
