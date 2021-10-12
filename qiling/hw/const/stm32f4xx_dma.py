#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class DMA_CR(IntEnum):
    CHSEL    = 7 << 25
    CHSEL_0  = 1 << 25
    CHSEL_1  = 2 << 25
    CHSEL_2  = 4 << 25
    MBURST_0 = 1 << 23
    MBURST_1 = 2 << 23
    MBURST   = 3 << 23
    PBURST_0 = 1 << 21
    PBURST_1 = 2 << 21
    PBURST   = 3 << 21
    CT       = 1 << 19
    DBM      = 1 << 18
    PL_0     = 1 << 16
    PL_1     = 2 << 16
    PL       = 3 << 16
    PINCOS   = 1 << 15
    MSIZE_0  = 1 << 13
    MSIZE_1  = 2 << 13
    MSIZE    = 3 << 13
    PSIZE_0  = 1 << 11
    PSIZE_1  = 2 << 11
    PSIZE    = 3 << 11
    MINC     = 1 << 10
    PINC     = 1 << 9
    CIRC     = 1 << 8
    DIR_0    = 1 << 6
    DIR_1    = 2 << 6
    DIR      = 3 << 6
    PFCTRL   = 1 << 5
    TCIE     = 1 << 4
    HTIE     = 1 << 3
    TEIE     = 1 << 2
    DMEIE    = 1 << 1
    EN       = 1 << 0

class DMA(IntEnum):
    PERIPH_TO_MEMORY = 0
    MEMORY_TO_PERIPH = DMA_CR.DIR_0
    MEMORY_TO_MEMORY = DMA_CR.DIR_1

    PDATAALIGN_BYTE     = 0
    PDATAALIGN_HALFWORD = DMA_CR.MSIZE_0
    PDATAALIGN_WORD     = DMA_CR.MSIZE_1