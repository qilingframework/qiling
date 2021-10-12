#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class SYSTICK_CTRL(IntEnum):
    ENABLE    = 1 << 0
    TICKINT   = 1 << 1
    CLKSOURCE = 1 << 2
    COUNTFLAG = 1 << 16
    MASK = ENABLE | TICKINT | CLKSOURCE | COUNTFLAG
