#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.stm32f4xx_usart import USART_SR, USART_CR1

class STM32F4xxUsart(QlPeripheral):
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
			('SR'  , ctypes.c_uint32),  # USART Status register,                   Address offset: 0x00
			('DR'  , ctypes.c_uint32),  # USART Data register,                     Address offset: 0x04
			('BRR' , ctypes.c_uint32),  # USART Baud rate register,                Address offset: 0x08
			('CR1' , ctypes.c_uint32),  # USART Control register 1,                Address offset: 0x0C
			('CR2' , ctypes.c_uint32),  # USART Control register 2,                Address offset: 0x10
			('CR3' , ctypes.c_uint32),  # USART Control register 3,                Address offset: 0x14
			('GTPR', ctypes.c_uint32),  # USART Guard time and prescaler register, Address offset: 0x18
		]

    
    def __init__(self, ql, label, intn=None):
        super().__init__(ql, label)
        
        self.usart = self.struct(
            SR = USART_SR.RESET,
        )
        
        self.intn = intn

        self.recv_buf = bytearray()
        self.send_buf = bytearray()

    def read(self, offset: int, size: int) -> int:
        self.ql.log.debug(f'[{self.label.upper()}] [R] {self.find_field(offset, size):10s}')

        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.usart) + offset, size)
        retval = int.from_bytes(buf.raw, byteorder='little')

        if offset == self.struct.DR.offset:
            self.usart.SR &= ~USART_SR.RXNE        

        return retval

    def write(self, offset: int, size: int, value: int):
        self.ql.log.debug(f'[{self.label.upper()}] [W] {self.find_field(offset, size):10s} = {hex(value)}')

        if offset == self.struct.SR.offset:
            self.usart.SR &= value | USART_SR.CTS | USART_SR.LBD | USART_SR.TC | USART_SR.RXNE

        elif offset == self.struct.DR.offset:
            self.usart.SR &= ~USART_SR.TXE
            self.usart.DR = value

        else:
            data = (value).to_bytes(size, byteorder='little')
            ctypes.memmove(ctypes.addressof(self.usart) + offset, data, size)

    def transfer(self):
        """ transfer data from DR to shift buffer and
            receive data from user buffer into DR
        """        

        if not (self.usart.SR & USART_SR.TXE):
            data = self.usart.DR

            self.usart.SR |= USART_SR.TXE            
            self.send_buf.append(data)            
            self.ql.log.debug(f'[{self.label}] Send {repr(chr(data))}')

        if not (self.usart.SR & USART_SR.RXNE): 
            # TXE bit must had been cleared
            if self.recv_buf:
                self.usart.SR |= USART_SR.RXNE
                self.usart.DR = self.recv_buf.pop(0)        
        

    def send(self, data: bytes):
        """ send user data into USART.

        Args:
            data (bytes): Input Data
        """        
        self.recv_buf += data

    def recv(self) -> bytes:
        """ receive data from USART.

        Returns:
            bytes: USART send buffer data
        """
        data = bytes(self.send_buf)
        self.send_buf.clear()
        return data

    def step(self):
        self.transfer()

        if self.intn is not None:
            if  (self.usart.CR1 & USART_CR1.PEIE   and self.usart.SR & USART_SR.PE)   or \
                (self.usart.CR1 & USART_CR1.TXEIE  and self.usart.SR & USART_SR.TXE)  or \
                (self.usart.CR1 & USART_CR1.TCIE   and self.usart.SR & USART_SR.TC)   or \
                (self.usart.CR1 & USART_CR1.RXNEIE and self.usart.SR & USART_SR.RXNE) or \
                (self.usart.CR1 & USART_CR1.IDLEIE and self.usart.SR & USART_SR.IDLE):
                self.ql.hw.nvic.set_pending(self.intn)
