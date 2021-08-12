#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.usart import USART_SR, USART_CR1

class STM32F4xxUsart(QlPeripheral):
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

    def __init__(self, ql, tag, IRQn=None):
        super().__init__(ql, tag)
        
        self.usart = self.struct(
            SR = 0x000000c0,
        )
        
        self.IRQn = IRQn

        self.recv_buf = bytearray()
        self.send_buf = bytearray()   

    def read(self, offset, size):
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.usart) + offset, size)
        retval = int.from_bytes(buf.raw, byteorder='little')

        if offset == self.struct.DR.offset:
            self.usart.SR &= ~USART_SR.RXNE            
            retval &= 0x3ff

        return retval

    def write(self, offset, size, value):
        data = (value).to_bytes(size, byteorder='little')

        if offset == self.struct.DR.offset:
            self.send_buf.append(value)
            self.usart.SR |= USART_SR.TC            
        else:
            ctypes.memmove(ctypes.addressof(self.usart) + offset, data, size)

    def send(self, data: bytes):
        self.recv_buf += data

    def recv(self) -> bytes:
        data = bytes(self.send_buf)
        self.send_buf.clear()
        return data

    def step(self):
        if not (self.usart.SR & USART_SR.RXNE):
            if self.recv_buf:
                self.usart.SR |= USART_SR.RXNE
                self.usart.DR = self.recv_buf.pop(0)

        if self.IRQn is not None:
            if  (self.usart.CR1 & USART_CR1.PEIE   and self.usart.SR & USART_SR.PE)   or \
                (self.usart.CR1 & USART_CR1.TXEIE  and self.usart.SR & USART_SR.TXE)  or \
                (self.usart.CR1 & USART_CR1.TCIE   and self.usart.SR & USART_SR.TC)   or \
                (self.usart.CR1 & USART_CR1.RXNEIE and self.usart.SR & USART_SR.RXNE) or \
                (self.usart.CR1 & USART_CR1.IDLEIE and self.usart.SR & USART_SR.IDLE):
                self.ql.hw.intc.set_pending(self.IRQn)
