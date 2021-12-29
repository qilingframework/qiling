#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.connectivity import QlConnectivityPeripheral


class GD32VF1xxUsart(QlConnectivityPeripheral):
    class Type(ctypes.Structure):
        """ Universal synchronous asynchronous receiver
      transmitter 
        """

        _fields_ = [
            ("STAT", ctypes.c_uint32), # Address offset: 0x00, Status register
            ("DATA", ctypes.c_uint32), # Address offset: 0x04, Data register
            ("BAUD", ctypes.c_uint32), # Address offset: 0x08, Baud rate register
            ("CTL0", ctypes.c_uint32), # Address offset: 0x0C, Control register 0
            ("CTL1", ctypes.c_uint32), # Address offset: 0x10, Control register 1
            ("CTL2", ctypes.c_uint32), # Address offset: 0x14, Control register 2
            ("GP"  , ctypes.c_uint32), # Address offset: 0x18, Guard time and prescaler register
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.usart = self.struct(
            STAT =  0x000000c0,
            DATA =  0x00000000,
            BAUD =  0x00000000,
            CTL0 =  0x00000000,
            CTL1 =  0x00000000,
            CTL2 =  0x00000000,
            GP   =  0x00000000,
        )

    @QlConnectivityPeripheral.device_handler
    def step(self):
        pass
