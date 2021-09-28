#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class SPI_SR:
    RXNE   = 1 << 0
    TXE    = 1 << 1
    CHSIDE = 1 << 2
    UDR    = 1 << 3
    CRCERR = 1 << 4
    MODF   = 1 << 5
    OVR    = 1 << 6
    BSY    = 1 << 7
    FRE    = 1 << 8
