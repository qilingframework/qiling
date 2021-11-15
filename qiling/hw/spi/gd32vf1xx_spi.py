#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes

from qiling.hw.connectivity import QlConnectivityPeripheral


class GD32VF1xxSpi(QlConnectivityPeripheral):
    class Type(ctypes.Structure):
        """ Serial peripheral interface 
        """

        _fields_ = [
            ("CTL0"   , ctypes.c_uint16), # Address offset: 0x0, control register 0
            ("CTL1"   , ctypes.c_uint16), # Address offset: 0x04, control register 1
            ("STAT"   , ctypes.c_uint16), # Address offset: 0x08, status register
            ("DATA"   , ctypes.c_uint16), # Address offset: 0x0C, data register
            ("CRCPOLY", ctypes.c_uint16), # Address offset: 0x10, CRC polynomial register
            ("RCRC"   , ctypes.c_uint16), # Address offset: 0x14, RX CRC register
            ("TCRC"   , ctypes.c_uint16), # Address offset: 0x18, TX CRC register
            ("I2SCTL" , ctypes.c_uint16), # Address offset: 0x1C, I2S control register
            ("I2SPSC" , ctypes.c_uint16), # Address offset: 0x20, I2S prescaler register
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.spi = self.struct(
            CTL0    =  0x00000000,
            CTL1    =  0x00000000,
            STAT    =  0x00000002,
            DATA    =  0x00000000,
            CRCPOLY =  0x00000007,
            RCRC    =  0x00000000,
            TCRC    =  0x00000000,
            I2SCTL  =  0x00000000,
            I2SPSC  =  0x00000002,
        )

