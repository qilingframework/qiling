#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class STM32F1xxAdc(QlPeripheral):
    class Type(ctypes.Structure):
        """ the structure available in :
                stm32f100xb
                stm32f100xe
                stm32f101xb
                stm32f101xe
                stm32f101xg
                stm32f102xb
                stm32f103xb
                stm32f103xe
                stm32f103xg
                stm32f105xc
                stm32f107xc
        """

        _fields_ = [
            ("SR"   , ctypes.c_uint32),
            ("CR1"  , ctypes.c_uint32),
            ("CR2"  , ctypes.c_uint32),
            ("SMPR1", ctypes.c_uint32),
            ("SMPR2", ctypes.c_uint32),
            ("JOFR1", ctypes.c_uint32),
            ("JOFR2", ctypes.c_uint32),
            ("JOFR3", ctypes.c_uint32),
            ("JOFR4", ctypes.c_uint32),
            ("HTR"  , ctypes.c_uint32),
            ("LTR"  , ctypes.c_uint32),
            ("SQR1" , ctypes.c_uint32),
            ("SQR2" , ctypes.c_uint32),
            ("SQR3" , ctypes.c_uint32),
            ("JSQR" , ctypes.c_uint32),
            ("JDR1" , ctypes.c_uint32),
            ("JDR2" , ctypes.c_uint32),
            ("JDR3" , ctypes.c_uint32),
            ("JDR4" , ctypes.c_uint32),
            ("DR"   , ctypes.c_uint32),
        ]

    def __init__(self, ql, label, intn = None):
        super().__init__(ql, label)

        self.adc = self.struct()
        self.intn = intn

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.adc) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):      
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.adc) + offset, data, size)
