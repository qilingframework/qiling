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

class USART_CR1(IntEnum):    
    OVER8  = 1 << 15
    UE     = 1 << 13
    M      = 1 << 12
    WAKE   = 1 << 11
    PCE    = 1 << 10
    PS     = 1 << 9
    PEIE   = 1 << 8
    TXEIE  = 1 << 7
    TCIE   = 1 << 6
    RXNEIE = 1 << 5
    IDLEIE = 1 << 4
    TE     = 1 << 3
    RE     = 1 << 2
    RWU    = 1 << 1
    SBK    = 1 << 0
