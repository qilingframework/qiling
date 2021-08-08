#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
import ctypes

from qiling.hw.peripheral import QlPeripheral

uint32_t = ctypes.c_uint32

class STM32F4xxRcc(QlPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ('CR', uint32_t),
            ('PLLCFGR', uint32_t),
            ('CFGR', uint32_t),
            ('CIR', uint32_t),
            ('AHB1RSTR', uint32_t),
            ('AHB2RSTR', uint32_t),
            ('AHB3RSTR', uint32_t),
            ('RESERVED0', uint32_t),
            ('APB1RSTR', uint32_t),
            ('APB2RSTR', uint32_t),
            ('RESERVED1', uint32_t * 2),
            ('AHB1ENR', uint32_t),
            ('AHB2ENR', uint32_t),
            ('AHB3ENR', uint32_t),
            ('RESERVED2', uint32_t),
            ('APB1ENR', uint32_t),
            ('APB2ENR', uint32_t),
            ('RESERVED3', uint32_t * 2),
            ('AHB1LPENR', uint32_t),
            ('AHB2LPENR', uint32_t),
            ('AHB3LPENR', uint32_t),
            ('RESERVED4', uint32_t),
            ('APB1LPENR', uint32_t),
            ('APB2LPENR', uint32_t),
            ('RESERVED5', uint32_t * 2),
            ('BDCR', uint32_t),
            ('CSR', uint32_t),
            ('RESERVED6', uint32_t * 2),
            ('SSCGR', uint32_t),
            ('PLLI2SCFGR', uint32_t),
            ('RESERVED7', uint32_t),
            ('DCKCFGR', uint32_t)
        ]

    def __init__(self, ql, tag):
        super().__init__(ql, tag)

        RCC_Type = type(self).Type
        self.rcc = RCC_Type(
            CR         = 0x00000083, # FIXME: The value may need to be update 
            PLLCFGR    = 0x24003010,
            AHB1LPENR  = 0x0061900F,
            AHB2LPENR  = 0x00000080,
            APB1LPENR  = 0x10E2C80F,
            APB2LPENR  = 0x00077930,
            CSR        = 0x0E000000,
            PLLI2SCFGR = 0x24003000,
        )

        self.mem = {}

    def read(self, offset, size):        
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.rcc) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    def write(self, offset, size, value):
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.systick) + offset, data, size)
