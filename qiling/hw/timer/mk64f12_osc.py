#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral

class MK64F12Osc(QlPeripheral):
    class Type(ctypes.Structure):
        """ Oscillator """  
        _fields_ = [
            ("CR", ctypes.c_uint8), # OSC Control Register
        ]
