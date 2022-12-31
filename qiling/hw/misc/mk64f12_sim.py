#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class MK64F12Sim(QlPeripheral):
    class Type(ctypes.Structure):
        """ System Integration Module """  
        _fields_ = [
            ("SOPT1"   , ctypes.c_uint32), # System Options Register 1
            ("SOPT1CFG", ctypes.c_uint32), # SOPT1 Configuration Register
            ("RESERVED0", ctypes.c_uint8 * 4092),
            ("SOPT2"   , ctypes.c_uint32), # System Options Register 2
            ("RESERVED1", ctypes.c_uint8 * 4),
            ("SOPT4"   , ctypes.c_uint32), # System Options Register 4
            ("SOPT5"   , ctypes.c_uint32), # System Options Register 5
            ("RESERVED2", ctypes.c_uint8 * 8),
            ("SOPT7"   , ctypes.c_uint32), # System Options Register 7
            ("RESERVED3", ctypes.c_uint8 * 4),
            ("SDID"    , ctypes.c_uint32), # System Device Identification Register
            ("SCGC1"   , ctypes.c_uint32), # System Clock Gating Control Register 1
            ("SCGC2"   , ctypes.c_uint32), # System Clock Gating Control Register 2
            ("SCGC3"   , ctypes.c_uint32), # System Clock Gating Control Register 3
            ("SCGC4"   , ctypes.c_uint32), # System Clock Gating Control Register 4
            ("SCGC5"   , ctypes.c_uint32), # System Clock Gating Control Register 5
            ("SCGC6"   , ctypes.c_uint32), # System Clock Gating Control Register 6
            ("SCGC7"   , ctypes.c_uint32), # System Clock Gating Control Register 7
            ("CLKDIV1" , ctypes.c_uint32), # System Clock Divider Register 1
            ("CLKDIV2" , ctypes.c_uint32), # System Clock Divider Register 2
            ("FCFG1"   , ctypes.c_uint32), # Flash Configuration Register 1
            ("FCFG2"   , ctypes.c_uint32), # Flash Configuration Register 2
            ("UIDH"    , ctypes.c_uint32), # Unique Identification Register High
            ("UIDMH"   , ctypes.c_uint32), # Unique Identification Register Mid-High
            ("UIDML"   , ctypes.c_uint32), # Unique Identification Register Mid Low
            ("UIDL"    , ctypes.c_uint32), # Unique Identification Register Low
        ]