#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class MK64F12Gpio(QlPeripheral):
    class Type(ctypes.Structure):
        """ General Purpose Input/Output """  
        _fields_ = [
            ("PDOR", ctypes.c_uint32), # Port Data Output Register
            ("PSOR", ctypes.c_uint32), # Port Set Output Register
            ("PCOR", ctypes.c_uint32), # Port Clear Output Register
            ("PTOR", ctypes.c_uint32), # Port Toggle Output Register
            ("PDIR", ctypes.c_uint32), # Port Data Input Register
            ("PDDR", ctypes.c_uint32), # Port Data Direction Register
        ]

    def __init__(self, ql, label, intn=None):
        super().__init__(ql, label)