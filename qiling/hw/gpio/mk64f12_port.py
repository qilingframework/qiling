#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class MK64F12Port(QlPeripheral):
    class Type(ctypes.Structure):
        """ Pin Control and Interrupts """  
        _fields_ = [
            ("PCR0" , ctypes.c_uint32), # Pin Control Register n
            ("PCR1" , ctypes.c_uint32), # Pin Control Register n
            ("PCR2" , ctypes.c_uint32), # Pin Control Register n
            ("PCR3" , ctypes.c_uint32), # Pin Control Register n
            ("PCR4" , ctypes.c_uint32), # Pin Control Register n
            ("PCR5" , ctypes.c_uint32), # Pin Control Register n
            ("PCR6" , ctypes.c_uint32), # Pin Control Register n
            ("PCR7" , ctypes.c_uint32), # Pin Control Register n
            ("PCR8" , ctypes.c_uint32), # Pin Control Register n
            ("PCR9" , ctypes.c_uint32), # Pin Control Register n
            ("PCR10", ctypes.c_uint32), # Pin Control Register n
            ("PCR11", ctypes.c_uint32), # Pin Control Register n
            ("PCR12", ctypes.c_uint32), # Pin Control Register n
            ("PCR13", ctypes.c_uint32), # Pin Control Register n
            ("PCR14", ctypes.c_uint32), # Pin Control Register n
            ("PCR15", ctypes.c_uint32), # Pin Control Register n
            ("PCR16", ctypes.c_uint32), # Pin Control Register n
            ("PCR17", ctypes.c_uint32), # Pin Control Register n
            ("PCR18", ctypes.c_uint32), # Pin Control Register n
            ("PCR19", ctypes.c_uint32), # Pin Control Register n
            ("PCR20", ctypes.c_uint32), # Pin Control Register n
            ("PCR21", ctypes.c_uint32), # Pin Control Register n
            ("PCR22", ctypes.c_uint32), # Pin Control Register n
            ("PCR23", ctypes.c_uint32), # Pin Control Register n
            ("PCR24", ctypes.c_uint32), # Pin Control Register n
            ("PCR25", ctypes.c_uint32), # Pin Control Register n
            ("PCR26", ctypes.c_uint32), # Pin Control Register n
            ("PCR27", ctypes.c_uint32), # Pin Control Register n
            ("PCR28", ctypes.c_uint32), # Pin Control Register n
            ("PCR29", ctypes.c_uint32), # Pin Control Register n
            ("PCR30", ctypes.c_uint32), # Pin Control Register n
            ("PCR31", ctypes.c_uint32), # Pin Control Register n
            ("GPCLR", ctypes.c_uint32), # Global Pin Control Low Register
            ("GPCHR", ctypes.c_uint32), # Global Pin Control High Register
            ("ISFR" , ctypes.c_uint32), # Interrupt Status Flag Register
        ]

    def __init__(self, ql, label, intn=None):
        super().__init__(ql, label)