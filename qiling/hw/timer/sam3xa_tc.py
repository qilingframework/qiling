#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class TcChannel(ctypes.Structure):
    _fields_ = [
        ("CCR"      , ctypes.c_uint32),     # (TcChannel Offset: 0x0) Channel Control Register
        ("CMR"      , ctypes.c_uint32),     # (TcChannel Offset: 0x4) Channel Mode Register 
        ("SMMR"     , ctypes.c_uint32),     # (TcChannel Offset: 0x8) Stepper Motor Mode Register 
        ("Reserved1", ctypes.c_uint32),     #
        ("CV"       , ctypes.c_uint32),     # (TcChannel Offset: 0x10) Counter Value 
        ("RA"       , ctypes.c_uint32),     # (TcChannel Offset: 0x14) Register A 
        ("RB"       , ctypes.c_uint32),     # (TcChannel Offset: 0x18) Register B 
        ("RC"       , ctypes.c_uint32),     # (TcChannel Offset: 0x1C) Register C 
        ("SR"       , ctypes.c_uint32),     # (TcChannel Offset: 0x20) Status Register 
        ("IER"      , ctypes.c_uint32),     # (TcChannel Offset: 0x24) Interrupt Enable Register 
        ("IDR"      , ctypes.c_uint32),     # (TcChannel Offset: 0x28) Interrupt Disable Register 
        ("IMR"      , ctypes.c_uint32),     # (TcChannel Offset: 0x2C) Interrupt Mask Register 
        ("Reserved2", ctypes.c_uint32 * 4), #
    ]

class SAM3xaTc(QlPeripheral):
    """ SAM3XA_TC Timer Counter """
    class Type(ctypes.Structure):
        _fields_ = [
            ("CHANNEL"  , TcChannel * 3),       # (Tc Offset: 0x0) channel = 0 .. 2
            ("BCR"      , ctypes.c_uint32),     # (Tc Offset: 0xC0) Block Control Register
            ("BMR"      , ctypes.c_uint32),     # (Tc Offset: 0xC4) Block Mode Register
            ("QIER"     , ctypes.c_uint32),     # (Tc Offset: 0xC8) QDEC Interrupt Enable Register
            ("QIDR"     , ctypes.c_uint32),     # (Tc Offset: 0xCC) QDEC Interrupt Disable Register
            ("QIMR"     , ctypes.c_uint32),     # (Tc Offset: 0xD0) QDEC Interrupt Mask Register
            ("QISR"     , ctypes.c_uint32),     # (Tc Offset: 0xD4) QDEC Interrupt Status Register
            ("FMR"      , ctypes.c_uint32),     # (Tc Offset: 0xD8) Fault Mode Register
            ("Reserved1", ctypes.c_uint32 * 2), # 
            ("WPMR"     , ctypes.c_uint32),     # (Tc Offset: 0xE4) Write Protect Mode Register
        ]

    def __init__(self, ql, label, intn):
        super().__init__(ql, label)

        self.instance = self.struct()
        self.intn = intn