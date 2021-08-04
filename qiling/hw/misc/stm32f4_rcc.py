#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
import ctypes

from qiling.hw.peripheral import QlPeripheral

uint32_t = ctypes.c_uint32

class STM32F4RCC(QlPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ('CR', uint32_t)
            ('PLLCFGR', uint32_t)
            ('CFGR', uint32_t)
            ('CIR', uint32_t)
            ('AHB1RSTR', uint32_t)
            ('AHB2RSTR', uint32_t)
            ('AHB3RSTR', uint32_t)
            ('RESERVED0', uint32_t)
            ('APB1RSTR', uint32_t)
            ('APB2RSTR', uint32_t)
            ('RESERVED1', uint32_t * 2)
            ('AHB1ENR', uint32_t)
            ('AHB2ENR', uint32_t)
            ('AHB3ENR', uint32_t)
            ('RESERVED2', uint32_t)
            ('APB1ENR', uint32_t)
            ('APB2ENR', uint32_t)
            ('RESERVED3', uint32_t * 2)
            ('AHB1LPENR', uint32_t)
            ('AHB2LPENR', uint32_t)
            ('AHB3LPENR', uint32_t)
            ('RESERVED4', uint32_t)
            ('APB1LPENR', uint32_t)
            ('APB2LPENR', uint32_t)
            ('RESERVED5', uint32_t * 2)
            ('BDCR', uint32_t)
            ('CSR', uint32_t)
            ('RESERVED6', uint32_t * 2)
            ('SSCGR', uint32_t)
            ('PLLI2SCFGR', uint32_t)
            ('RESERVED7', uint32_t)
            ('DCKCFGR', uint32_t)
        ]

    def __init__(self, ql, tag):
        super().__init__(ql, tag)
        self.mem = {}

    def read(self, offset, size):
        # print('a')
        ## TODO: Temporary plan, wait for me to implement uart and then change it.
        if offset == 0:
            return 0xffff
        return 0
