#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.cm import IRQ

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
        ]

    def __init__(self, ql, tag):
        super().__init__(ql, tag)

        SCB_Type = type(self).Type
        self.scb = SCB_Type(
            CPUID = 0x410FC241,
            AIRCR = 0xFA050000,
            CCR   = 0x00000200,
        )

    def enable(self, IRQn):
        if IRQn == IRQ.USAGE_FAULT:
            self.scb.SHCSR |= 1 << 18
        if IRQn == IRQ.BUS_FAULT:
            self.scb.SHCSR |= 1 << 17
        if IRQn == IRQ.MEMORY_MANAGEMENT_FAULT:
            self.scb.SHCSR |= 1 << 16
        
    def disable(self, IRQn):
        if IRQn == IRQ.USAGE_FAULT:
            self.scb.SHCSR &= (1 << 18) ^ 0xffffffff
        if IRQn == IRQ.BUS_FAULT:
            self.scb.SHCSR &= (1 << 17) ^ 0xffffffff
        if IRQn == IRQ.MEMORY_MANAGEMENT_FAULT:
            self.scb.SHCSR &= (1 << 16) ^ 0xffffffff

    def get_enable(self, IRQn):
        if IRQn == IRQ.USAGE_FAULT:
            return (self.scb.SHCSR >> 18) & 1
        if IRQn == IRQ.BUS_FAULT:
            return (self.scb.SHCSR >> 17) & 1
        if IRQn == IRQ.MEMORY_MANAGEMENT_FAULT:
            return (self.scb.SHCSR >> 16) & 1
        return 1

    def set_pending(self, IRQn):
        if IRQn == IRQ.NMI:
            self.scb.ICSR |= 1 << 31
        if IRQn == IRQ.PENDSV:
            self.scb.ICSR |= 3 << 27 # set-bit and clear-bit
        if IRQn == IRQ.SYSTICK:
            self.scb.ICSR |= 3 << 25 # set-bit and clear-bit

        if IRQn == IRQ.MEMORY_MANAGEMENT_FAULT:
            self.scb.SHCSR |= 1 << 13
        if IRQn == IRQ.BUS_FAULT:
            self.scb.SHCSR |= 1 << 14        
        if IRQn == IRQ.USAGE_FAULT:
            self.scb.SHCSR |= 1 << 12
        if IRQn == IRQ.SVCALL:
            self.scb.SHCSR |= 1 << 15

    def clear_pending(self, IRQn):
        if IRQn == IRQ.NMI:
            self.scb.ICSR &= (1 << 31) ^ 0xffffffff
        if IRQn == IRQ.PENDSV:
            self.scb.ICSR &= (3 << 27) ^ 0xffffffff
        if IRQn == IRQ.SYSTICK:
            self.scb.ICSR &= (3 << 25) ^ 0xffffffff

        if IRQn == IRQ.MEMORY_MANAGEMENT_FAULT:
            self.scb.SHCSR &= (1 << 13) ^ 0xffffffff
        if IRQn == IRQ.BUS_FAULT:
            self.scb.SHCSR &= (1 << 14) ^ 0xffffffff        
        if IRQn == IRQ.USAGE_FAULT:
            self.scb.SHCSR &= (1 << 12) ^ 0xffffffff
        if IRQn == IRQ.SVCALL:
            self.scb.SHCSR &= (1 << 15) ^ 0xffffffff

    def get_pending(self, IRQn):
        if IRQn == IRQ.NMI:
            return (self.scb.ICSR >> 31) & 1
        if IRQn == IRQ.PENDSV:
            return (self.scb.ICSR >> 28) & 1
        if IRQn == IRQ.SYSTICK:
            return (self.scb.ICSR >> 26) & 1

        if IRQn == IRQ.MEMORY_MANAGEMENT_FAULT:
            return (self.scb.SHCSR >> 13) & 1
        if IRQn == IRQ.BUS_FAULT:
            return (self.scb.SHCSR >> 14) & 1        
        if IRQn == IRQ.USAGE_FAULT:
            return (self.scb.SHCSR >> 12) & 1
        if IRQn == IRQ.SVCALL:
            return (self.scb.SHCSR >> 15) & 1
        return 0

    def read(self, offset, size):
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.scb) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    def write(self, offset, size, value):
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.scb) + offset, data, size)
