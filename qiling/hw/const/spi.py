#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class SPI_CR2(IntEnum):
    TXEIE   = 1 << 7
    RXNEIE  = 1 << 6
    ERRIE   = 1 << 5
    FRF     = 1 << 4
    Res     = 1 << 3
    SSOE    = 1 << 2
    TXDMAEN = 1 << 1
    RXDMAEN = 1 << 0