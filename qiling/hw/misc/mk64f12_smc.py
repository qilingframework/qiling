#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class MK64F12Smc(QlPeripheral):
    class Type(ctypes.Structure):
        """ System Mode Controller """  
        _fields_ = [
            ("PMPROT"  , ctypes.c_uint8), # Power Mode Protection register
            ("PMCTRL"  , ctypes.c_uint8), # Power Mode Control register
            ("VLLSCTRL", ctypes.c_uint8), # VLLS Control register
            ("PMSTAT"  , ctypes.c_uint8), # Power Mode Status register
        ]
