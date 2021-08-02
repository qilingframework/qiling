#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.hw.peripheral import QlPeripheral


class USART(QlPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ('SR'  , ctypes.c_uint32),
            ('DR'  , ctypes.c_uint32),
            ('BRR' , ctypes.c_uint32),
            ('CR1' , ctypes.c_uint32),
            ('CR2' , ctypes.c_uint32),
            ('CR3' , ctypes.c_uint32),
            ('GTPR', ctypes.c_uint32),
        ]

    def __init__(self, ql, tag):
        super().__init__(ql, tag)
        
        USART_Type = type(self).Type
        self.usart = USART_Type(
            SR = 0xc0,
        )

    def read(self, offset, size):
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.usart) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little', signed=False)

    def write(self, offset, size, value):
        data = (value).to_bytes(size, byteorder='little', signed=False)
        ctypes.memmove(ctypes.addressof(self.usart) + offset, data, size)

        if offset == type(self).Type.DR.offset:
            self.ql.log.info('[%s] %s' % (self.tag, repr(chr(value))))
