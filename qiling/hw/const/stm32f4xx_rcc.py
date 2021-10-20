#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class RCC_CR(IntEnum):
    HSION   = 1 << 0
    HSIRDY  = 1 << 1
    HSITRIM = 0x1F << 3
    HSICAL  = 0xFF << 8
    
    HSEON  = 1 << 16
    HSERDY = 1 << 17
    HSEBYP = 1 << 18
    CSSON  = 1 << 19

    PLLI2SRDY = 1 << 27
    PLLI2SON  = 1 << 26
    PLLRDY    = 1 << 25
    PLLON     = 1 << 24

    RW_MASK = HSION | HSITRIM | HSEON | HSEBYP | CSSON | PLLON | PLLI2SON
    RO_MASK = HSIRDY | HSICAL | HSERDY | PLLRDY | PLLI2SRDY

class RCC_CFGR(IntEnum):
    SW      = 0x3 << 0
    SW_0    = 1 << 0
    SW_1    = 1 << 1
    SWS     = 0x3 << 2
    SWS_0   = 1 << 2
    SWS_1   = 1 << 3
    HPRE    = 0xF << 4
    PPRE1   = 0x7 << 10
    PPRE2   = 0x7 << 13
    RTCPRE  = 0x1F << 16
    MCO1    = 0x3 << 21
    I2SSCR  = 1 << 23
    MCO1PRE = 0x3 << 24
    MCO2PRE = 0x3 << 27
    MCO2    = 0x3 << 30

    RO_MASK = SWS
    RW_MASK = SW | HPRE | PPRE1 | PPRE2 | MCO1 | I2SSCR | MCO1PRE | MCO2PRE | MCO2
