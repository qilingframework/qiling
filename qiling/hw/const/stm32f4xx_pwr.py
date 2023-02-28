#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class PWR_CR(IntEnum):
    LPDS   = 1 << 0
    PDDS   = 1 << 1
    CWUF   = 1 << 2
    CSBF   = 1 << 3
    PVDE   = 1 << 4
    PLS    = 0x7 << 5
    DBP    = 1 << 8
    FPDS   = 1 << 9
    LPLVDS = 1 << 10
    MRLVDS = 1 << 11
    ADCDC1 = 1 << 13
    VOS    = 0x3 << 14
    ODEN   = 1 << 16
    ODSWEN = 1 << 17
    UDEN   = 0x3 << 18

class PWR_CSR(IntEnum):
    WUF     = 1 << 0
    SBF     = 1 << 1
    PVDO    = 1 << 2
    BRR     = 1 << 3
    EWUP    = 1 << 8
    BRE     = 1 << 9
    VOSRDY  = 1 << 14
    ODRDY   = 1 << 16
    ODSWRDY = 1 << 17
    UDRDY   = 0x3 << 18
