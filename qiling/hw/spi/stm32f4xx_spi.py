#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.spi import *

class STM32F4xxSpi(QlPeripheral):
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

    def __init__(self, ql, tag, **kwargs):
        super().__init__(ql, tag, **kwargs)

        self.spi = self.struct()

        self.receive_buff = []

    def read_data(self):
        if len(self.receive_buff) > 0:
            data = self.receive_buff[0]
            self.receive_buff = self.receive_buff[1:]
            self.ql.log.debug(f'[{self.tag}] Read {hex(data)} to receive buffer')
            return data

        self.ql.log.debug(f'[{self.tag}] try to Read but no data in receive buffer')
        return 0

    def write_data(self, value):
        self.receive_buff = value + self.receive_buff
        self.ql.log.debug(f'[{self.tag}] Write {hex(value)} to receive buffer')

        # gpio.enable(self.struct.CR2 & SPI_CR2.RXDMAEN |
        #             self.struct.CR2 & SPI_CR2.TXDMAEN |
        #             self.struct.CR2 & SPI_CR2.RXNEIE  |
        #             self.struct.CR2 & SPI_CR2.TXEIE    )


    def read(self, offset, size):
        if offset == self.struct.DR.offset:
            return self.read_data()

        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.spi) + offset, size)
        data = int.from_bytes(buf.raw, byteorder='little')
        self.ql.log.debug(f'[{self.tag}] Read [{hex(self.base + offset)}] = {hex(data)}')

        return data

    def write(self, offset, size, value):
        if offset == self.struct.DR.offset:
            return self.write_data(value)

        for ofs in range(offset, offset + size):
            data = (value & 0xff).to_bytes(size, byteorder='little')
            ctypes.memmove(ctypes.addressof(self.spi) + ofs, data, 1)
            value >>= 8
        
        self.ql.log.debug(f'[{self.tag}] Write [{hex(self.base + offset)}] = {hex(value)}')

