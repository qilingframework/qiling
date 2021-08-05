#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.hw.peripheral import QlPeripheral


class SysTick(QlPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ('CTRL' , ctypes.c_uint32),
            ('LOAD' , ctypes.c_int32),
            ('VAL'  , ctypes.c_int32),
            ('CALIB', ctypes.c_uint32),
        ]

    def __init__(self, ql, tag):
        super().__init__(ql, tag)

        SysTick_Type = type(self).Type
        self.systick = SysTick_Type()        
        
        self.RATIO = 1000
        self.LOAD_OFFSET = SysTick_Type.LOAD.offset

    def step(self):
        if not self.systick.CTRL & 1:
            return

        if self.systick.VAL <= 0:
            self.systick.VAL = self.systick.LOAD
            if self.systick.CTRL & 2:
                self.ql.hw.intc.set_pending(-1)
        else:
            self.systick.VAL -= self.RATIO

    def read(self, offset, size):
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.systick) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    def write(self, offset, size, value):
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.systick) + offset, data, size)        
