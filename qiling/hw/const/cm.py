#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class IRQ(IntEnum):
    NMI = -14
    HARD_FAULT = -13
    MEMORY_MANAGEMENT_FAULT = -12
    BUS_FAULT = -11
    USAGE_FAULT = -10
    SVCALL = -5
    PENDSV = -2
    SYSTICK = -1
