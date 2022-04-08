#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.gpio.hooks import GpioHooks


class MK64F12Gpio(QlPeripheral, GpioHooks):
    class Type(ctypes.Structure):
        """ General Purpose Input/Output """  
        _fields_ = [
            ("PDOR", ctypes.c_uint32), # Port Data Output Register
            ("PSOR", ctypes.c_uint32), # Port Set Output Register
            ("PCOR", ctypes.c_uint32), # Port Clear Output Register
            ("PTOR", ctypes.c_uint32), # Port Toggle Output Register
            ("PDIR", ctypes.c_uint32), # Port Data Input Register
            ("PDDR", ctypes.c_uint32), # Port Data Direction Register
        ]

    def __init__(self, ql, label, intn=None):
        QlPeripheral.__init__(self, ql, label)
        GpioHooks.__init__(self, ql, 32)

        self.intn = intn

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        if   offset == self.struct.PSOR.offset:
            for i in range(32):
                self.set_pin(i)   
        
        elif offset == self.struct.PCOR.offset:            
            for i in range(32):
                self.reset_pin(i)
        
        elif offset == self.struct.PTOR.offset:            
            for i in range(32):
                if self.pin(i):
                    self.reset_pin(i)
                else:
                    self.set_pin(i)

        else:
            self.raw_write(offset, size, value)

    def set_pin(self, i):
        self.ql.log.debug(f'[{self.label}] Set P{self.label[-1].upper()}{i}')
        
        self.port.send_interrupt(i, self.pin(i), 1)

        if self.instance.PDDR:
            self.instance.PDOR |= 1 << i
        else:
            self.instance.PDIR |= 1 << i
        self.call_hook_set(i)
    
    def reset_pin(self, i):
        self.ql.log.debug(f'[{self.label}] Reset P{self.label[-1].upper()}{i}')
        
        self.port.send_interrupt(i, self.pin(i), 0)

        if self.instance.PDDR:
            self.instance.PDOR &= ~(1 << i)
        else:
            self.instance.PDIR &= ~(1 << i)
        self.call_hook_reset(i)
        
    def pin(self, index):
        if self.instance.PDDR:
            return (self.instance.PDOR >> index) & 1
        else:
            return (self.instance.PDIR >> index) & 1

    @property
    def port(self):
        return getattr(self.ql.hw, 'port' + self.label[-1])
