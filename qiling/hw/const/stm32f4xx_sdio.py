#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class SDIO_CLKCR(IntEnum):
    CLKDIV  = 0xff << 0
    CLKEN   = 1 << 8
    PWRSAV  = 1 << 9
    BYPASS  = 1 << 10
    WIDBUS  = 0x3 << 11
    NEGEDGE = 1 << 13
    HWFC_EN = 1 << 14

class SDIO_CMD(IntEnum):
    CMDINDEX    = 0x3f << 0
    WAITRESP    = 0x3 << 6
    WAITINT     = 1 << 8
    WAITPEND    = 1 << 9
    CPSMEN      = 1 << 10
    SDIOSUSPEND = 1 << 11
    ENCMDCOMPL  = 1 << 12
    NIEN        = 1 << 13
    CEATACMD    = 1 << 14

class SDIO_DCTRL(IntEnum):
    DTEN       = 1 << 0
    DTDIR      = 1 << 1
    DTMODE     = 1 << 2
    DMAEN      = 1 << 3
    DBLOCKSIZE = 0xf << 4
    RWSTART    = 1 << 8
    RWSTOP     = 1 << 9
    RWMOD      = 1 << 10
    SDIOEN     = 1 << 11

class SDIO_STA(IntEnum):
    CCRCFAIL = 1 << 0
    DCRCFAIL = 1 << 1
    CTIMEOUT = 1 << 2
    DTIMEOUT = 1 << 3
    TXUNDERR = 1 << 4
    RXOVERR  = 1 << 5
    CMDREND  = 1 << 6
    CMDSENT  = 1 << 7
    DATAEND  = 1 << 8
    STBITERR = 1 << 9
    DBCKEND  = 1 << 10
    CMDACT   = 1 << 11
    TXACT    = 1 << 12
    RXACT    = 1 << 13
    TXFIFOHE = 1 << 14
    RXFIFOHF = 1 << 15
    TXFIFOF  = 1 << 16
    RXFIFOF  = 1 << 17
    TXFIFOE  = 1 << 18
    RXFIFOE  = 1 << 19
    TXDAVL   = 1 << 20
    RXDAVL   = 1 << 21
    SDIOIT   = 1 << 22
    CEATAEND = 1 << 23

class SDIO_ICR(IntEnum):
    CCRCFAILC = 1 << 0
    DCRCFAILC = 1 << 1
    CTIMEOUTC = 1 << 2
    DTIMEOUTC = 1 << 3
    TXUNDERRC = 1 << 4
    RXOVERRC  = 1 << 5
    CMDRENDC  = 1 << 6
    CMDSENTC  = 1 << 7
    DATAENDC  = 1 << 8
    STBITERRC = 1 << 9
    DBCKENDC  = 1 << 10
    SDIOITC   = 1 << 22
    CEATAENDC = 1 << 23

class SDIO_MASK(IntEnum):
    CCRCFAILIE = 1 << 0
    DCRCFAILIE = 1 << 1
    CTIMEOUTIE = 1 << 2
    DTIMEOUTIE = 1 << 3
    TXUNDERRIE = 1 << 4
    RXOVERRIE  = 1 << 5
    CMDRENDIE  = 1 << 6
    CMDSENTIE  = 1 << 7
    DATAENDIE  = 1 << 8
    STBITERRIE = 1 << 9
    DBCKENDIE  = 1 << 10
    CMDACTIE   = 1 << 11
    TXACTIE    = 1 << 12
    RXACTIE    = 1 << 13
    TXFIFOHEIE = 1 << 14
    RXFIFOHFIE = 1 << 15
    TXFIFOFIE  = 1 << 16
    RXFIFOFIE  = 1 << 17
    TXFIFOEIE  = 1 << 18
    RXFIFOEIE  = 1 << 19
    TXDAVLIE   = 1 << 20
    RXDAVLIE   = 1 << 21
    SDIOITIE   = 1 << 22
    CEATAENDIE = 1 << 23
