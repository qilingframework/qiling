#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.core import Qiling
from qiling.hw.peripheral import QlPeripheral
from qiling.hw.connectivity import QlConnectivityPeripheral
from qiling.hw.const.stm32f4xx_sdio import SDIO_CMD, SDIO_STA


class STM32F4xxSdio(QlConnectivityPeripheral):
    class Type(ctypes.Structure):
        """ the structure available in :
                stm32f401xc
                stm32f401xe
                stm32f405xx
                stm32f407xx
                stm32f411xe
                stm32f412cx
                stm32f412rx
                stm32f412vx
                stm32f412zx
                stm32f413xx
                stm32f415xx
                stm32f417xx
                stm32f423xx
                stm32f427xx
                stm32f429xx
                stm32f437xx
                stm32f439xx
                stm32f446xx
                stm32f469xx
                stm32f479xx
        """

        _fields_ = [
            ("POWER"    , ctypes.c_uint32),      #SDIO power control register,    Address offset: 0x00
            ("CLKCR"    , ctypes.c_uint32),      #SDI clock control register,     Address offset: 0x04
            ("ARG"      , ctypes.c_uint32),      #SDIO argument register,         Address offset: 0x08
            ("CMD"      , ctypes.c_uint32),      #SDIO command register,          Address offset: 0x0C
            ("RESPCMD"  , ctypes.c_uint32),      #SDIO command response register, Address offset: 0x10
            ("RESP1"    , ctypes.c_uint32),      #SDIO response 1 register,       Address offset: 0x14
            ("RESP2"    , ctypes.c_uint32),      #SDIO response 2 register,       Address offset: 0x18
            ("RESP3"    , ctypes.c_uint32),      #SDIO response 3 register,       Address offset: 0x1C
            ("RESP4"    , ctypes.c_uint32),      #SDIO response 4 register,       Address offset: 0x20
            ("DTIMER"   , ctypes.c_uint32),      #SDIO data timer register,       Address offset: 0x24
            ("DLEN"     , ctypes.c_uint32),      #SDIO data length register,      Address offset: 0x28
            ("DCTRL"    , ctypes.c_uint32),      #SDIO data control register,     Address offset: 0x2C
            ("DCOUNT"   , ctypes.c_uint32),      #SDIO data counter register,     Address offset: 0x30
            ("STA"      , ctypes.c_uint32),      #SDIO status register,           Address offset: 0x34
            ("ICR"      , ctypes.c_uint32),      #SDIO interrupt clear register,  Address offset: 0x38
            ("MASK"     , ctypes.c_uint32),      #SDIO mask register,             Address offset: 0x3C
            ("RESERVED0", ctypes.c_uint32 * 2),  #Reserved, 0x40-0x44
            ("FIFOCNT"  , ctypes.c_uint32),      #SDIO FIFO counter register,     Address offset: 0x48
            ("RESERVED1", ctypes.c_uint32 * 13), #Reserved, 0x4C-0x7C
            ("FIFO"     , ctypes.c_uint32),      #SDIO data FIFO register,        Address offset: 0x80
        ]

    def __init__(self, ql: Qiling, label: str, intn: int = None):
        super().__init__(ql, label)

        self.intn = intn
        self.instance = self.struct()
    
    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        if offset == self.struct.CMD.offset:            
            if value & SDIO_CMD.CPSMEN:
                waitresp = (value & SDIO_CMD.WAITRESP) >> 6
                if waitresp in [0b00, 0b11]:
                    self.instance.STA |= SDIO_STA.CMDSENT
                else:
                    self.instance.STA |= SDIO_STA.CMDREND
                
                self.instance.RESPCMD = value & SDIO_CMD.CMDINDEX

        self.raw_write(offset, size, value)
