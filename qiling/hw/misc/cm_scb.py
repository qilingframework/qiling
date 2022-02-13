#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.arch.cortex_m_const import IRQ


class CortexMScb(QlPeripheral):
    def enable(self, IRQn):
        if IRQn == IRQ.USAGE_FAULT:
            self.scb.SHCSR |= 1 << 18
        if IRQn == IRQ.BUS_FAULT:
            self.scb.SHCSR |= 1 << 17
        if IRQn == IRQ.MEMORY_MANAGEMENT_FAULT:
            self.scb.SHCSR |= 1 << 16
        
    def disable(self, IRQn):
        if IRQn == IRQ.USAGE_FAULT:
            self.scb.SHCSR &= ~(1 << 18)
        if IRQn == IRQ.BUS_FAULT:
            self.scb.SHCSR &= ~(1 << 17)
        if IRQn == IRQ.MEMORY_MANAGEMENT_FAULT:
            self.scb.SHCSR &= ~(1 << 16)

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
            self.scb.ICSR &= ~(1 << 31)
        if IRQn == IRQ.PENDSV:
            self.scb.ICSR &= ~(3 << 27)
        if IRQn == IRQ.SYSTICK:
            self.scb.ICSR &= ~(3 << 25)

        if IRQn == IRQ.MEMORY_MANAGEMENT_FAULT:
            self.scb.SHCSR &= ~(1 << 13)
        if IRQn == IRQ.BUS_FAULT:
            self.scb.SHCSR &= ~(1 << 14)        
        if IRQn == IRQ.USAGE_FAULT:
            self.scb.SHCSR &= ~(1 << 12)
        if IRQn == IRQ.SVCALL:
            self.scb.SHCSR &= ~(1 << 15)

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

    def get_priority(self, IRQn):
        return self.scb.SHP[(IRQn & 0xf) - 4]

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.scb) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        if offset == self.struct.ICSR.offset:
            if (value >> 28) & 1:
                self.ql.hw.nvic.set_pending(IRQ.PENDSV)                

        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.scb) + offset, data, size)
