#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class MK64F12Wdog(QlPeripheral):
    class Type(ctypes.Structure):
        """ Generation 2008 Watchdog Timer """  
        _fields_ = [
            ("STCTRLH", ctypes.c_uint16), # Watchdog Status and Control Register High
            ("STCTRLL", ctypes.c_uint16), # Watchdog Status and Control Register Low
            ("TOVALH" , ctypes.c_uint16), # Watchdog Time-out Value Register High
            ("TOVALL" , ctypes.c_uint16), # Watchdog Time-out Value Register Low
            ("WINH"   , ctypes.c_uint16), # Watchdog Window Register High
            ("WINL"   , ctypes.c_uint16), # Watchdog Window Register Low
            ("REFRESH", ctypes.c_uint16), # Watchdog Refresh register
            ("UNLOCK" , ctypes.c_uint16), # Watchdog Unlock register
            ("TMROUTH", ctypes.c_uint16), # Watchdog Timer Output Register High
            ("TMROUTL", ctypes.c_uint16), # Watchdog Timer Output Register Low
            ("RSTCNT" , ctypes.c_uint16), # Watchdog Reset Count register
            ("PRESC"  , ctypes.c_uint16), # Watchdog Prescaler register
        ]

    def __init__(self, ql, label, ewm_intn=None):
        super().__init__(ql, label)
