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
            self.instance.SHCSR |= 1 << 18
        if IRQn == IRQ.BUS_FAULT:
            self.instance.SHCSR |= 1 << 17
        if IRQn == IRQ.MEMORY_MANAGEMENT_FAULT:
            self.instance.SHCSR |= 1 << 16
        
    def disable(self, IRQn):
        if IRQn == IRQ.USAGE_FAULT:
            self.instance.SHCSR &= ~(1 << 18)
        if IRQn == IRQ.BUS_FAULT:
            self.instance.SHCSR &= ~(1 << 17)
        if IRQn == IRQ.MEMORY_MANAGEMENT_FAULT:
            self.instance.SHCSR &= ~(1 << 16)

    def get_enable(self, IRQn):
        if IRQn == IRQ.USAGE_FAULT:
            return (self.instance.SHCSR >> 18) & 1
        if IRQn == IRQ.BUS_FAULT:
            return (self.instance.SHCSR >> 17) & 1
        if IRQn == IRQ.MEMORY_MANAGEMENT_FAULT:
            return (self.instance.SHCSR >> 16) & 1
        return 1

    def set_pending(self, IRQn):
        if IRQn == IRQ.NMI:
            self.instance.ICSR |= 1 << 31
        if IRQn == IRQ.PENDSV:
            self.instance.ICSR |= 3 << 27 # set-bit and clear-bit
        if IRQn == IRQ.SYSTICK:
            self.instance.ICSR |= 3 << 25 # set-bit and clear-bit

        if IRQn == IRQ.MEMORY_MANAGEMENT_FAULT:
            self.instance.SHCSR |= 1 << 13
        if IRQn == IRQ.BUS_FAULT:
            self.instance.SHCSR |= 1 << 14        
        if IRQn == IRQ.USAGE_FAULT:
            self.instance.SHCSR |= 1 << 12
        if IRQn == IRQ.SVCALL:
            self.instance.SHCSR |= 1 << 15

    def clear_pending(self, IRQn):
        if IRQn == IRQ.NMI:
            self.instance.ICSR &= ~(1 << 31)
        if IRQn == IRQ.PENDSV:
            self.instance.ICSR &= ~(3 << 27)
        if IRQn == IRQ.SYSTICK:
            self.instance.ICSR &= ~(3 << 25)

        if IRQn == IRQ.MEMORY_MANAGEMENT_FAULT:
            self.instance.SHCSR &= ~(1 << 13)
        if IRQn == IRQ.BUS_FAULT:
            self.instance.SHCSR &= ~(1 << 14)        
        if IRQn == IRQ.USAGE_FAULT:
            self.instance.SHCSR &= ~(1 << 12)
        if IRQn == IRQ.SVCALL:
            self.instance.SHCSR &= ~(1 << 15)

    def get_pending(self, IRQn):
        if IRQn == IRQ.NMI:
            return (self.instance.ICSR >> 31) & 1
        if IRQn == IRQ.PENDSV:
            return (self.instance.ICSR >> 28) & 1
        if IRQn == IRQ.SYSTICK:
            return (self.instance.ICSR >> 26) & 1

        if IRQn == IRQ.MEMORY_MANAGEMENT_FAULT:
            return (self.instance.SHCSR >> 13) & 1
        if IRQn == IRQ.BUS_FAULT:
            return (self.instance.SHCSR >> 14) & 1        
        if IRQn == IRQ.USAGE_FAULT:
            return (self.instance.SHCSR >> 12) & 1
        if IRQn == IRQ.SVCALL:
            return (self.instance.SHCSR >> 15) & 1
        return 0

    def get_priority(self, IRQn):
        return self.instance.SHP[(IRQn & 0xf) - 4]

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.instance) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        if offset == self.struct.ICSR.offset:
            if (value >> 28) & 1:
                self.ql.hw.nvic.set_pending(IRQ.PENDSV)                

        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.instance) + offset, data, size)
