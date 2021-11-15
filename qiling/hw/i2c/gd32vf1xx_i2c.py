#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes

from qiling.hw.connectivity import QlConnectivityPeripheral


class GD32VF1xxI2c(QlConnectivityPeripheral):
    class Type(ctypes.Structure):
        """ Inter integrated circuit 
        """

        _fields_ = [
            ("CTL0"  , ctypes.c_uint16), # Address offset: 0x0, Control register 0
            ("CTL1"  , ctypes.c_uint16), # Address offset: 0x04, Control register 1
            ("SADDR0", ctypes.c_uint16), # Address offset: 0x08, Slave address register 0
            ("SADDR1", ctypes.c_uint16), # Address offset: 0x0C, Slave address register 1
            ("DATA"  , ctypes.c_uint16), # Address offset: 0x10, Transfer buffer register
            ("STAT0" , ctypes.c_uint16), # Address offset: 0x14, Transfer status register 0
            ("STAT1" , ctypes.c_uint16), # Address offset: 0x18, Transfer status register 1
            ("CKCFG" , ctypes.c_uint16), # Address offset: 0x1C, Clock configure register
            ("RT"    , ctypes.c_uint16), # Address offset: 0x20, Rise time register
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.i2c = self.struct(
            CTL0   =  0x00000000,
            CTL1   =  0x00000000,
            SADDR0 =  0x00000000,
            SADDR1 =  0x00000000,
            DATA   =  0x00000000,
            STAT0  =  0x00000000,
            STAT1  =  0x00000000,
            CKCFG  =  0x00000000,
            RT     =  0x00000002,
        )

