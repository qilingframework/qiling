#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.gpio.hooks import GpioHooks


class STM32F1xxGpio(QlPeripheral, GpioHooks):
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
            ("CRL" , ctypes.c_uint32),
            ("CRH" , ctypes.c_uint32),
            ("IDR" , ctypes.c_uint32),
            ("ODR" , ctypes.c_uint32),
            ("BSRR", ctypes.c_uint32),
            ("BRR" , ctypes.c_uint32),
            ("LCKR", ctypes.c_uint32),
        ]

    def __init__(self, ql, label):
        QlPeripheral.__init__(self, ql, label)
        GpioHooks.__init__(self, ql, 16)

        self.gpio = self.struct()

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:
        if offset == self.struct.BSRR.offset:
            return 0x00
        
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.gpio) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        if offset == self.struct.IDR.offset:
            return

        if offset == self.struct.BSRR.offset:
            for i in range(32):
                if ((value >> i) & 1) == 0:
                    continue
                if i < 16:   
                    self.set_pin(i)
                else:
                    self.reset_pin(i - 16)                    
            
            return
        
        if offset == self.struct.ODR.offset:            
            for i in range(16):
                new_bit = (value >> i) & 1
                old_bit = (self.gpio.ODR >> i) & 1                

                if new_bit !=  old_bit:
                    if new_bit:
                        self.set_pin(i)                        
                    else:
                        self.reset_pin(i)                        
            
            return    
        
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.gpio) + offset, data, size) 

    def set_pin(self, i):
        self.ql.log.debug(f'[{self.label}] Set P{self.label[-1].upper()}{i}')
        
        self.gpio.ODR |= 1 << i        
        self.call_hook_set(i)
    
    def reset_pin(self, i):
        self.ql.log.debug(f'[{self.label}] Reset P{self.label[-1].upper()}{i}')
        
        self.gpio.ODR &= ~(1 << i)
        self.call_hook_reset(i)
        
    def pin(self, index):
        return (self.gpio.ODR >> index) & 1