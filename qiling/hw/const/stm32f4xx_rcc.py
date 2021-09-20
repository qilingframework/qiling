#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class RCC_CR(IntEnum):
    PLLI2SRDY = 1 << 27
    PLLI2SON  = 1 << 26
    PLLRDY    = 1 << 25
    PLLON     = 1 << 24