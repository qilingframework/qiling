#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.connectivity import QlConnectivityPeripheral
from qiling.hw.const.stm32f4xx_spi import SPI_CR1, SPI_CR2, SPI_SR, SPI_CRCPR, SPI_I2SCFGR, SPI_I2SPR


class STM32F4xxSpi(QlConnectivityPeripheral):
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
            ('CR1'    , ctypes.c_uint32),  # SPI control register 1 (not used in I2S mode),      Address offset: 0x00
            ('CR2'    , ctypes.c_uint32),  # SPI control register 2,                             Address offset: 0x04
            ('SR'     , ctypes.c_uint32),  # SPI status register,                                Address offset: 0x08
            ('DR'     , ctypes.c_uint32),  # SPI data register,                                  Address offset: 0x0C
            ('CRCPR'  , ctypes.c_uint32),  # SPI CRC polynomial register (not used in I2S mode), Address offset: 0x10
            ('RXCRCR' , ctypes.c_uint32),  # SPI RX CRC register (not used in I2S mode),         Address offset: 0x14
            ('TXCRCR' , ctypes.c_uint32),  # SPI TX CRC register (not used in I2S mode),         Address offset: 0x18
            ('I2SCFGR', ctypes.c_uint32),  # SPI_I2S configuration register,                     Address offset: 0x1C
            ('I2SPR'  , ctypes.c_uint32),  # SPI_I2S prescaler register,                         Address offset: 0x20
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
            I2SPR   = 0x00000002,
        )

        self.intn = intn

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:
        if self.in_field(self.struct.DR, offset, size):
            self.spi.SR &= ~SPI_SR.RXNE

        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.spi) + offset, size)
        data = int.from_bytes(buf.raw, byteorder='little')

        return data

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        if offset in [self.struct.SR.offset, self.struct.RXCRCR.offset, self.struct.TXCRCR.offset]:
            return

        if offset == self.struct.CR1.offset:
            value &= SPI_CR1.RW_MASK

        elif offset == self.struct.CR2.offset:
            value &= SPI_CR2.RW_MASK
        
        elif offset == self.struct.CRCPR.offset:
            value &= SPI_CRCPR.CRCPOLY		

        elif offset == self.struct.I2SCFGR.offset:
            value &= SPI_I2SCFGR.RW_MASK

        elif offset == self.struct.I2SPR.offset:
            value &= SPI_I2SPR.RW_MASK

        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.spi) + offset, data, size)   

        if self.in_field(self.struct.DR, offset, size):
            self.spi.SR |= SPI_SR.RXNE
            self.send_to_user(self.spi.DR)

    def send_interrupt(self):
        self.ql.hw.nvic.set_pending(self.intn)

    @QlConnectivityPeripheral.device_handler
    def step(self):
        pass