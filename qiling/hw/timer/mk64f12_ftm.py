#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes
from typing import Optional
from qiling.core import Qiling

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.timer.timer import QlTimerPeripheral
from qiling.hw.const.mk64f12_ftm import MODE, SC


class Control(ctypes.Structure):
    _fields_ = [
        ('CnSC', ctypes.c_uint32), # Channel (n) Status And Control
        ('CnV' , ctypes.c_uint32), # Channel (n) Value
    ]


class MK64F12Ftm(QlTimerPeripheral):
    class Type(ctypes.Structure):
        """ FlexTimer Module """  
        _fields_ = [
            ("SC"      , ctypes.c_uint32), # Status And Control
            ("CNT"     , ctypes.c_int32),  # Counter
            ("MOD"     , ctypes.c_uint32), # Modulo
            ("CONTROLS", Control * 8),
            ("CNTIN"   , ctypes.c_uint32), # Counter Initial Value
            ("STATUS"  , ctypes.c_uint32), # Capture And Compare Status
            ("MODE"    , ctypes.c_uint32), # Features Mode Selection
            ("SYNC"    , ctypes.c_uint32), # Synchronization
            ("OUTINIT" , ctypes.c_uint32), # Initial State For Channels Output
            ("OUTMASK" , ctypes.c_uint32), # Output Mask
            ("COMBINE" , ctypes.c_uint32), # Function For Linked Channels
            ("DEADTIME", ctypes.c_uint32), # Deadtime Insertion Control
            ("EXTTRIG" , ctypes.c_uint32), # FTM External Trigger
            ("POL"     , ctypes.c_uint32), # Channels Polarity
            ("FMS"     , ctypes.c_uint32), # Fault Mode Status
            ("FILTER"  , ctypes.c_uint32), # Input Capture Filter Control
            ("FLTCTRL" , ctypes.c_uint32), # Fault Control
            ("QDCTRL"  , ctypes.c_uint32), # Quadrature Decoder Control And Status
            ("CONF"    , ctypes.c_uint32), # Configuration
            ("FLTPOL"  , ctypes.c_uint32), # FTM Fault Input Polarity
            ("SYNCONF" , ctypes.c_uint32), # Synchronization Configuration
            ("INVCTRL" , ctypes.c_uint32), # FTM Inverting Control
            ("SWOCTRL" , ctypes.c_uint32), # FTM Software Output Control
            ("PWMLOAD" , ctypes.c_uint32), # FTM PWM Load
        ]

    def __init__(self, ql, label, intn=None):
        super().__init__(ql, label)

        self.intn = intn

    def step(self):
        if self.instance.MODE & MODE.FTMEN and self.instance.SC & SC.CLKS:
            if self.instance.CNT <= 0:
                self.instance.CNT = 1000000 // ((self.instance.SC & SC.PS) + 1)
            
            else:
                self.instance.CNT -= self.ratio
                if self.instance.CNT <= 0:                    
                    self.ql.hw.nvic.set_pending(self.intn)
