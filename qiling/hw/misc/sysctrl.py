#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes

from qiling.hw.peripheral import QlPeripheral

class SCB(QlPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ('CPUID'    , ctypes.c_uint32),
            ('ICSR'     , ctypes.c_uint32),
            ('VTOR'     , ctypes.c_uint32),
            ('AIRCR'    , ctypes.c_uint32),
            ('SCR'      , ctypes.c_uint32),
            ('CCR'      , ctypes.c_uint32),
            ('SHP'      , ctypes.c_uint8 * 12),
            ('SHCSR'    , ctypes.c_uint32),
            ('CFSR'     , ctypes.c_uint32),
            ('HFSR'     , ctypes.c_uint32),
            ('DFSR'     , ctypes.c_uint32),
            ('MMFAR'    , ctypes.c_uint32),
            ('BFSR'     , ctypes.c_uint32),
            ('AFSR'     , ctypes.c_uint32),
            ('PFR'      , ctypes.c_uint32 * 2),
            ('DFR'      , ctypes.c_uint32),
            ('ADR'      , ctypes.c_uint32),
            ('MMFR'     , ctypes.c_uint32 * 4),
            ('ISAR'     , ctypes.c_uint32 * 5),
            ('RESERVED0', ctypes.c_uint32 * 5),
            ('CPACR'    , ctypes.c_uint32)
        ]

    def __init__(self, ql, tag):
        super().__init__(ql, tag)

        SCB_Type = type(self).Type
        self.scb = SCB_Type()

    def enable(self, IRQn):
        if IRQn in [-10, -11, -12]:
            self.scb.SHCSR |= 1 << (28 + IRQn)
        
    def disable(self, IRQn):
        if IRQn in [-10, -11, -12]:
            self.scb.SHCSR &= (1 << (28 + IRQn)) ^ 0xffffffff

    def get_enable(self, IRQn):
        if IRQn in [-10, -11, -12]:
            return (self.scb.SHCSR >> (28 + IRQn)) & 1
        return 1

    def set_pending(self, IRQn):
        if IRQn == -12:
            self.scb.SHCSR |= 1 << 13
        if IRQn == -11:
            self.scb.SHCSR |= 1 << 14        
        if IRQn == -10:
            self.scb.SHCSR |= 1 << 12
        if IRQn == -5:
            self.scb.SHCSR |= 1 << 15        
        if IRQn == -2:
            self.scb.ICSR  |= 1 << 28
        if IRQn == -1:
            self.scb.ICSR  |= 1 << 26

    def clear_pending(self, IRQn):
        if IRQn == -12:
            self.scb.SHCSR &= (1 << 13) ^ 0xffffffff
        if IRQn == -11:
            self.scb.SHCSR &= (1 << 14) ^ 0xffffffff
        if IRQn == -10:
            self.scb.SHCSR &= (1 << 12) ^ 0xffffffff
        if IRQn == -5:
            self.scb.SHCSR &= (1 << 15) ^ 0xffffffff
        if IRQn == -2:
            self.scb.ICSR  &= (1 << 28) ^ 0xffffffff
        if IRQn == -1:
            self.scb.ICSR  &= (1 << 26) ^ 0xffffffff

    def get_pending(self, IRQn):
        if IRQn == -12:
            return (self.scb.SHCSR >> 13) & 1
        if IRQn == -11:
            return (self.scb.SHCSR >> 14) & 1
        if IRQn == -10:
            return (self.scb.SHCSR >> 12) & 1
        if IRQn == -5:
            return (self.scb.SHCSR >> 15) & 1
        if IRQn == -2:
            return (self.scb.ICSR  >> 28) & 1
        if IRQn == -1:
            return (self.scb.ICSR  >> 26) & 1
        return 0