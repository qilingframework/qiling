#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes
from qiling.hw.gpio.hooks import GpioHooks
from qiling.hw.peripheral import QlPeripheral


class GD32VF1xxGpio(QlPeripheral, GpioHooks):
    class Type(ctypes.Structure):
        """ General-purpose I/Os 
        """

        _fields_ = [
            ("CTL0" , ctypes.c_uint32), # Address offset: 0x0, port control register 0
            ("CTL1" , ctypes.c_uint32), # Address offset: 0x04, port control register 1
            ("ISTAT", ctypes.c_uint32), # Address offset: 0x08, Port input status register
            ("OCTL" , ctypes.c_uint32), # Address offset: 0x0C, Port output control register
            ("BOP"  , ctypes.c_uint32), # Address offset: 0x10, Port bit operate register
            ("BC"   , ctypes.c_uint32), # Address offset: 0x14, Port bit clear register
            ("LOCK" , ctypes.c_uint32), # Address offset: 0x18, GPIO port configuration lock register
        ]

    def __init__(self, ql, label):
        QlPeripheral.__init__(self, ql, label)
        GpioHooks.__init__(self, ql, 16)

        self.gpio = self.struct(
            CTL0  =  0x44444444,
            CTL1  =  0x44444444,
            ISTAT =  0x00000000,
            OCTL  =  0x00000000,
            BOP   =  0x00000000,
            BC    =  0x00000000,
            LOCK  =  0x00000000,
        )

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:		
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.gpio) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')
    
    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        if offset == self.struct.OCTL.offset: 
            for i in range(16):
                new_bit = (value >> i) & 1
                old_bit = (self.gpio.OCTL >> i) & 1                

                if new_bit !=  old_bit:
                    if new_bit:
                        self.set_pin(i)                        
                    else:
                        self.reset_pin(i)                        
            
            return

        if offset == self.struct.BOP.offset:
            for i in range(32):
                if ((value >> i) & 1) == 0:
                    continue
                if i < 16:   
                    self.set_pin(i)
                else:
                    self.reset_pin(i - 16)                    
            
            return

        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.gpio) + offset, data, size)

    def set_pin(self, i):
        self.ql.log.debug(f'[{self.label}] Set P{self.label[-1].upper()}{i}')
        
        self.gpio.OCTL |= 1 << i        
        self.call_hook_set(i)
    
    def reset_pin(self, i):
        self.ql.log.debug(f'[{self.label}] Reset P{self.label[-1].upper()}{i}')
        
        self.gpio.OCTL &= ~(1 << i)
        self.call_hook_reset(i)
        
    def pin(self, index):
        return (self.gpio.OCTL >> index) & 1