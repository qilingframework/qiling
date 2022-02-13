#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class SAM3xaWdt(QlPeripheral):
    """
    The Watchdog Timer can be used to prevent system lock-up if the software becomes trapped in a deadlock. It
    features a 12-bit down counter that allows a watchdog period of up to 16 seconds (slow clock at 32.768 kHz). It
    can generate a general reset or a processor reset only. In addition, it can be stopped while the processor is in
    debug mode or idle mode.
    """

    class Type(ctypes.Structure):
        _fields_ = [
            ("CR", ctypes.c_uint32), # (Wdt Offset: 0x00) Control Register
            ("MR", ctypes.c_uint32), # (Wdt Offset: 0x04) Mode Register
            ("SR", ctypes.c_uint32), # (Wdt Offset: 0x08) Status Register
        ]

    def __init__(self, ql, label, intn = None):
        super().__init__(ql, label)

        self.wdt = self.struct()
        self.intn = intn
