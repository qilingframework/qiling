#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes

from qiling.hw.peripheral import QlPeripheral


class GD32VF1xxRtc(QlPeripheral):
    class Type(ctypes.Structure):
        """ Real-time clock 
        """

        _fields_ = [
            ("INTEN", ctypes.c_uint32), # Address offset: 0x0, RTC interrupt enable register
            ("CTL"  , ctypes.c_uint32), # Address offset: 0x04, control register
            ("PSCH" , ctypes.c_uint32), # Address offset: 0x08, RTC prescaler high register
            ("PSCL" , ctypes.c_uint32), # Address offset: 0x0C, RTC prescaler low register
            ("DIVH" , ctypes.c_uint32), # Address offset: 0x10, RTC divider high register
            ("DIVL" , ctypes.c_uint32), # Address offset: 0x14, RTC divider low register
            ("CNTH" , ctypes.c_uint32), # Address offset: 0x18, RTC counter high register
            ("CNTL" , ctypes.c_uint32), # Address offset: 0x1C, RTC counter low register
            ("ALRMH", ctypes.c_uint32), # Address offset: 0x20, Alarm high register
            ("ALRML", ctypes.c_uint32), # Address offset: 0x24, RTC alarm low register
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.rtc = self.struct(
            INTEN =  0x00000000,
            CTL   =  0x00000020,
            PSCH  =  0x00000000,
            PSCL  =  0x00008000,
            DIVH  =  0x00000000,
            DIVL  =  0x00008000,
            CNTH  =  0x00000000,
            CNTL  =  0x00000000,
            ALRMH =  0x0000ffff,
            ALRML =  0x0000ffff,
        )

