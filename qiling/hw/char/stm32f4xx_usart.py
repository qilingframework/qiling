#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.connectivity import QlConnectivityPeripheral
from qiling.hw.const.stm32f4xx_usart import USART_SR, USART_CR1

class STM32F4xxUsart(QlConnectivityPeripheral):
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
        
        self.instance = self.struct(
            SR = USART_SR.RESET,
        )
        
        self.intn = intn

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:
        if offset == self.struct.DR.offset:
            self.instance.SR &= ~USART_SR.RXNE  
            retval = self.recv_from_user()
            self.transfer()

        else:        
            retval = self.raw_read(offset, size)
        
        return retval

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):  
        if offset == self.struct.SR.offset:
            self.instance.SR &= value | USART_SR.CTS | USART_SR.LBD | USART_SR.TC | USART_SR.RXNE | USART_SR.TXE        
        
        elif offset == self.struct.DR.offset:
            self.send_to_user(value)

        else:
            data = (value).to_bytes(size, byteorder='little')
            ctypes.memmove(ctypes.addressof(self.instance) + offset, data, size)

    def transfer(self):
        if not (self.instance.SR & USART_SR.RXNE): 
            if self.has_input():
                self.instance.SR |= USART_SR.RXNE  

    def check_interrupt(self):
        if self.intn is not None:
            if  (self.instance.CR1 & USART_CR1.PEIE   and self.instance.SR & USART_SR.PE)   or \
                (self.instance.CR1 & USART_CR1.TXEIE  and self.instance.SR & USART_SR.TXE)  or \
                (self.instance.CR1 & USART_CR1.TCIE   and self.instance.SR & USART_SR.TC)   or \
                (self.instance.CR1 & USART_CR1.RXNEIE and self.instance.SR & USART_SR.RXNE) or \
                (self.instance.CR1 & USART_CR1.IDLEIE and self.instance.SR & USART_SR.IDLE):
                self.ql.hw.nvic.set_pending(self.intn)              

    @QlConnectivityPeripheral.device_handler
    def step(self):
        self.transfer()
        self.check_interrupt()
