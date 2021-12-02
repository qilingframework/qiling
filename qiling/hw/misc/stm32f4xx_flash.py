#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes
from qiling.core import Qiling

from qiling.hw.peripheral import QlPeripheral


class STM32F4xxFlash(QlPeripheral):
    class Type(ctypes.Structure):
        """ the structure available in :
                stm32f401xc
                stm32f401xe
                stm32f405xx
                stm32f407xx
                stm32f410cx
                stm32f410rx
                stm32f410tx
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
            ("ACR"    , ctypes.c_uint32), #FLASH access control register,   Address offset: 0x00
            ("KEYR"   , ctypes.c_uint32), #FLASH key register,              Address offset: 0x04
            ("OPTKEYR", ctypes.c_uint32), #FLASH option key register,       Address offset: 0x08
            ("SR"     , ctypes.c_uint32), #FLASH status register,           Address offset: 0x0C
            ("CR"     , ctypes.c_uint32), #FLASH control register,          Address offset: 0x10
            ("OPTCR"  , ctypes.c_uint32), #FLASH option control register ,  Address offset: 0x14
            ("OPTCR1" , ctypes.c_uint32), #FLASH option control register 1, Address offset: 0x18
        ]

    def __init__(self, ql: Qiling, label: str, intn: int = None):
        super().__init__(ql, label)

        self.intn = intn
        self.flash = self.struct()

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:		
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.flash) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')
    
    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.flash) + offset, data, size)
