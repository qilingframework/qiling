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
        self.instance = self.struct(
            CR1     = 0x00000000,
            CR2     = 0x00000000,
            SR      = 0x0000000B,
            DR      = 0x0000000C,
            CRCPR   = 0x00000007,
            RXCRCR  = 0x00000000,
            TXCRCR  = 0x00000000,
            I2SCFGR = 0x00000000,
        )

        self.intn = intn

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:        
        if self.contain(self.struct.DR, offset, size):
            if self.has_input():
                return self.recv_from_user()

        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.instance) + offset, size)
        data = int.from_bytes(buf.raw, byteorder='little')        

        return data

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        if self.contain(self.struct.DR, offset, size):
            self.send_to_user(value)

        else:
            data = (value).to_bytes(size, 'little')
            ctypes.memmove(ctypes.addressof(self.instance) + offset, data, size)           

    def send_interrupt(self):
        self.ql.hw.nvic.set_pending(self.intn)
