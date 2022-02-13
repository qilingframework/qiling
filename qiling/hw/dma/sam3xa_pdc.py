#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class SAM3xaPdc(QlPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ("RPR" , ctypes.c_uint32), # (Pdc Offset: 0x0) Receive Pointer Register
            ("RCR" , ctypes.c_uint32), # (Pdc Offset: 0x4) Receive Counter Register
            ("TPR" , ctypes.c_uint32), # (Pdc Offset: 0x8) Transmit Pointer Register
            ("TCR" , ctypes.c_uint32), # (Pdc Offset: 0xC) Transmit Counter Register
            ("RNPR", ctypes.c_uint32), # (Pdc Offset: 0x10) Receive Next Pointer Register
            ("RNCR", ctypes.c_uint32), # (Pdc Offset: 0x14) Receive Next Counter Register
            ("TNPR", ctypes.c_uint32), # (Pdc Offset: 0x18) Transmit Next Pointer Register
            ("TNCR", ctypes.c_uint32), # (Pdc Offset: 0x1C) Transmit Next Counter Register
            ("PTCR", ctypes.c_uint32), # (Pdc Offset: 0x20) Transfer Control Register
            ("PTSR", ctypes.c_uint32), # (Pdc Offset: 0x24) Transfer Status Register
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.pdc = self.struct()
