#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class MK64F12Port(QlPeripheral):
    class Type(ctypes.Structure):
        """ Pin Control and Interrupts """  
        _fields_ = [
            ("PCR" , ctypes.c_uint32 * 32), # Pin Control Register n
            ("GPCLR", ctypes.c_uint32), # Global Pin Control Low Register
            ("GPCHR", ctypes.c_uint32), # Global Pin Control High Register
            ("RESERVED0", ctypes.c_uint8 * 24),
            ("ISFR" , ctypes.c_uint32), # Interrupt Status Flag Register
            ("RESERVED1", ctypes.c_uint8 * 28),
            ("DFER" , ctypes.c_uint32), # Digital Filter Enable Register
            ("DFCR" , ctypes.c_uint32), # Digital Filter Clock Register
            ("DFWR" , ctypes.c_uint32), # Digital Filter Width Register
        ]

    def __init__(self, ql, label, intn=None):
        super().__init__(ql, label)