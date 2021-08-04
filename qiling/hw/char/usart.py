#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.usart import STATE

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

        self.SR = USART_Type.SR.offset
        self.DR = USART_Type.DR.offset

        self.recv_buf = bytearray()
        self.send_buf = bytearray()

    def set_flag(self, offset, flag):
        if flag:
            self.usart.SR |= 1 << offset
        else:
            self.usart.SR &= (1 << offset) ^ 0xffffffff
    
    def get_flag(self, offset):
        return (self.usart.SR >> offset) & 1        

    def read(self, offset, size):
        if offset == self.DR:
            self.set_flag(STATE.RXNE, 0) # clear RXNE
            
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.usart) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    def write(self, offset, size, value):
        data = (value).to_bytes(size, byteorder='little')

        if offset == self.DR:
            self.send_buf.append(value)
        else:
            ctypes.memmove(ctypes.addressof(self.usart) + offset, data, size)

    def send(self, data: bytes):
        self.recv_buf += data

    def recv(self) -> bytes:
        data = bytes(self.send_buf)
        self.send_buf.clear()
        return data

    def step(self):
        if not self.get_flag(STATE.RXNE):
            if self.recv_buf:
                self.set_flag(STATE.RXNE, 1)
                self.usart.DR = self.recv_buf.pop(0)
