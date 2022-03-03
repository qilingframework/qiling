#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes
from qiling.core import Qiling

from qiling.hw.peripheral import QlPeripheral


class STM32F1xxFlash(QlPeripheral):
    class Type(ctypes.Structure):
        """ the structure available in :
                stm32f100xb
                stm32f100xe
                stm32f101xb
                stm32f101xe
                stm32f102xb
                stm32f103xb
                stm32f103xe
                stm32f105xc
                stm32f107xc
        """

        _fields_ = [
            ("ACR"     , ctypes.c_uint32),
            ("KEYR"    , ctypes.c_uint32),
            ("OPTKEYR" , ctypes.c_uint32),
            ("SR"      , ctypes.c_uint32),
            ("CR"      , ctypes.c_uint32),
            ("AR"      , ctypes.c_uint32),
            ("RESERVED", ctypes.c_uint32),
            ("OBR"     , ctypes.c_uint32),
            ("WRPR"    , ctypes.c_uint32),
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

