#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class SAM3xaEfc(QlPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ("FMR", ctypes.c_uint32), # (Efc Offset: 0x00) EEFC Flash Mode Register
            ("FCR", ctypes.c_uint32), # (Efc Offset: 0x04) EEFC Flash Command Register
            ("FSR", ctypes.c_uint32), # (Efc Offset: 0x08) EEFC Flash Status Register
            ("FRR", ctypes.c_uint32), # (Efc Offset: 0x0C) EEFC Flash Result Register
        ]

    def __init__(self, ql, label, intn = None):
        super().__init__(ql, label)

        self.efc = self.struct()
        self.intn = intn
