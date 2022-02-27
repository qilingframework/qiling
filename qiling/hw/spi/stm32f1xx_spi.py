#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.connectivity import QlConnectivityPeripheral
from qiling.hw.const.stm32f4xx_spi import SPI_SR


class STM32F1xxSpi(QlConnectivityPeripheral):
    class Type(ctypes.Structure):
        """ the structure available in :
                stm32f101xb
                stm32f102xb
                stm32f103xb
        """

        _fields_ = [
            ("CR1"    , ctypes.c_uint32),
            ("CR2"    , ctypes.c_uint32),
            ("SR"     , ctypes.c_uint32),
            ("DR"     , ctypes.c_uint32),
            ("CRCPR"  , ctypes.c_uint32),
            ("RXCRCR" , ctypes.c_uint32),
            ("TXCRCR" , ctypes.c_uint32),
            ("I2SCFGR", ctypes.c_uint32),
        ]

    def __init__(self, ql, label, intn=None):
        super().__init__(ql, label)
        self.spi = self.struct(
            CR1     = 0x00000000,
            CR2     = 0x00000000,
            SR      = 0x0000000A,
            DR      = 0x0000000C,
            CRCPR   = 0x00000007,
            RXCRCR  = 0x00000000,
            TXCRCR  = 0x00000000,
            I2SCFGR = 0x00000000,
        )

        self.intn = intn

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:        
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.spi) + offset, size)
        data = int.from_bytes(buf.raw, byteorder='little')

        if self.contain(self.struct.DR, offset, size):
            self.spi.SR &= ~SPI_SR.RXNE

        return data

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        if self.contain(self.struct.DR, offset, size):
            self.send_to_user(value)

        else:
            data = (value).to_bytes(size, 'little')
            ctypes.memmove(ctypes.addressof(self.spi) + offset, data, size)           

    def transfer(self):
        """ transfer data from DR to shift buffer and
            receive data from user buffer into DR
        """        

        if not (self.spi.SR & SPI_SR.RXNE): 
            # TXE bit must had been cleared
            if self.has_input():
                self.spi.SR |= SPI_SR.RXNE                
                self.spi.DR = self.recv_from_user()

    def send_interrupt(self):
        self.ql.hw.nvic.set_pending(self.intn)

    @QlConnectivityPeripheral.device_handler
    def step(self):
        self.transfer()
