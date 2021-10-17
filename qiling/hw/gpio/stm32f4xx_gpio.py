#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.gpio.hooks import GpioHooks


class STM32F4xxGpio(QlPeripheral, GpioHooks):
    class Type(ctypes.Structure):
        """ the structure available in :
            stm32f413xx.h
            stm32f407xx.h
            stm32f469xx.h
            stm32f446xx.h
            stm32f427xx.h
            stm32f401xc.h
            stm32f415xx.h
            stm32f412cx.h
            stm32f410rx.h
            stm32f410tx.h
            stm32f439xx.h
            stm32f412vx.h
            stm32f417xx.h
            stm32f479xx.h
            stm32f429xx.h
            stm32f412rx.h
            stm32f423xx.h
            stm32f437xx.h
            stm32f412zx.h
            stm32f401xe.h
            stm32f410cx.h
            stm32f405xx.h
            stm32f411xe.h 
		"""

        _fields_ = [
            ('MODER'  , ctypes.c_uint32),      # GPIO port mode register,               Address offset: 0x00
            ('OTYPER' , ctypes.c_uint32),      # GPIO port output type register,        Address offset: 0x04
            ('OSPEEDR', ctypes.c_uint32),      # GPIO port output speed register,       Address offset: 0x08
            ('PUPDR'  , ctypes.c_uint32),      # GPIO port pull-up/pull-down register,  Address offset: 0x0C
            ('IDR'    , ctypes.c_uint32),      # GPIO port input data register,         Address offset: 0x10
            ('ODR'    , ctypes.c_uint32),      # GPIO port output data register,        Address offset: 0x14
            ('BSRR'   , ctypes.c_uint32),      # GPIO port bit set/reset register,      Address offset: 0x18
            ('LCKR'   , ctypes.c_uint32),      # GPIO port configuration lock register, Address offset: 0x1C
            ('AFRL'   , ctypes.c_uint32),      # GPIO alternate function registers,     Address offset: 0x20-0x24
            ('AFRH'   , ctypes.c_uint32),      # GPIO alternate function registers,     Address offset: 0x20-0x24
        ]

    def __init__(self, ql, label, 
            moder_reset   = 0x00, 
            ospeedr_reset = 0x00,
            pupdr_reset    = 0x00
        ):
        QlPeripheral.__init__(self, ql, label)
        GpioHooks.__init__(self, ql, 16)

        self.gpio = self.struct(
            MODER   = moder_reset,
            OSPEEDR = ospeedr_reset,
            PUPDR   = pupdr_reset,
        )        

    def read(self, offset: int, size: int) -> int:
        if offset == self.struct.BSRR.offset:
            return 0x00
        
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.gpio) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

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
                        self.reset_pin(i - 16)                        
            
            return    
        
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.gpio) + offset, data, size) 

    def set_pin(self, i):
        self.ql.log.debug(f'[{self.label}] Set P{self.label[-1].upper()}{i}')
        
        self.gpio.ODR |= 1 << i        
        self.hook_set_func[i]()
    
    def reset_pin(self, i):
        self.ql.log.debug(f'[{self.label}] Reset P{self.label[-1].upper()}{i}')
        
        self.gpio.ODR &= ~(1 << i)
        self.hook_reset_func[i]()
        
    def pin(self, index):
        return (self.gpio.ODR >> index) & 1    
