#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.hw.peripheral import QlPeripheral


class CortexM4SysTick(QlPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ('CTRL' , ctypes.c_uint32),
            ('LOAD' , ctypes.c_int32),
            ('VAL'  , ctypes.c_int32),
            ('CALIB', ctypes.c_uint32),
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.systick = self.struct(
            CALIB = 0xC0000000
        )        
        
        self.RATIO = 1000        

    def step(self):
        if not self.systick.CTRL & 1:
            return

        if self.systick.VAL <= 0:
            self.systick.VAL = self.systick.LOAD
            if self.systick.CTRL & 2:
                self.ql.hw.nvic.set_pending(-1)
        else:
            self.systick.VAL -= self.RATIO

    def read(self, offset, size):
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.systick) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    def write(self, offset, size, value):
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.systick) + offset, data, size)        
