#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.mk64f12_mcg import C1, C5, C6, S


class MK64F12Mcg(QlPeripheral):
    class Type(ctypes.Structure):
        """ Multipurpose Clock Generator module """  
        _fields_ = [
            ("C1"   , ctypes.c_uint8), # MCG Control 1 Register
            ("C2"   , ctypes.c_uint8), # MCG Control 2 Register
            ("C3"   , ctypes.c_uint8), # MCG Control 3 Register
            ("C4"   , ctypes.c_uint8), # MCG Control 4 Register
            ("C5"   , ctypes.c_uint8), # MCG Control 5 Register
            ("C6"   , ctypes.c_uint8), # MCG Control 6 Register
            ("S"    , ctypes.c_uint8), # MCG Status Register
            ("RESERVED0", ctypes.c_uint8),
            ("SC"   , ctypes.c_uint8), # MCG Status and Control Register
            ("RESERVED1", ctypes.c_uint8),
            ("ATCVH", ctypes.c_uint8), # MCG Auto Trim Compare Value High Register
            ("ATCVL", ctypes.c_uint8), # MCG Auto Trim Compare Value Low Register
            ("C7"   , ctypes.c_uint8), # MCG Control 7 Register
            ("C8"   , ctypes.c_uint8), # MCG Control 8 Register
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)


    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        if offset == self.struct.C1.offset:
            self.instance.S &= ~(S.IREFST | S.CLKST)            

            self.instance.S |= (value & C1.IREFS) >> C1.IREFS_Pos << S.IREFST_Pos
            
            clock_source = value & C1.CLKS
            if clock_source == 0 and self.instance.S & S.PLLST:
                self.instance.S |= S.CLKST
            else:
                self.instance.S |= clock_source >> C1.CLKS_Pos << S.CLKST_Pos            

        elif offset == self.struct.C5.offset:
            if value & C5.PLLCLKEN0:
                self.instance.S |= S.LOCK0
        
        elif offset == self.struct.C6.offset:
            if value & C6.PLLS:
                self.instance.S |= S.PLLST
                self.instance.S |= S.LOCK0

        else:
            self.raw_write(offset, size, value)
