#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class MK64F12Rtc(QlPeripheral):
    class Type(ctypes.Structure):
        """ Secure Real Time Clock """  
        _fields_ = [
            ("TSR", ctypes.c_uint32), # RTC Time Seconds Register
            ("TPR", ctypes.c_uint32), # RTC Time Prescaler Register
            ("TAR", ctypes.c_uint32), # RTC Time Alarm Register
            ("TCR", ctypes.c_uint32), # RTC Time Compensation Register
            ("CR" , ctypes.c_uint32), # RTC Control Register
            ("SR" , ctypes.c_uint32), # RTC Status Register
            ("LR" , ctypes.c_uint32), # RTC Lock Register
            ("IER", ctypes.c_uint32), # RTC Interrupt Enable Register
            ("WAR", ctypes.c_uint32), # RTC Write Access Register
            ("RAR", ctypes.c_uint32), # RTC Read Access Register
        ]

    def __init__(self, ql, label, intn=None, seconds_intn=None):
        super().__init__(ql, label)

        self.intn = intn