#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class USART_SR(IntEnum):    
    CTS  = 1 << 9
    LBD  = 1 << 8
    TXE  = 1 << 7
    TC   = 1 << 6
    RXNE = 1 << 5
    IDLE = 1 << 4
    ORE  = 1 << 3
    NF   = 1 << 2
    FE   = 1 << 1
    PE   = 1 << 0
    RESET = TXE | TC
