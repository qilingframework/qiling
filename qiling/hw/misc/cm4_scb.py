#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes

from qiling.hw.misc.cm_scb import CortexMScb


class CortexM4Scb(CortexMScb):
    class Type(ctypes.Structure):
        _fields_ = [
            ('CPUID'    , ctypes.c_uint32),
            ('ICSR'     , ctypes.c_uint32),
            ('VTOR'     , ctypes.c_uint32),
            ('AIRCR'    , ctypes.c_uint32),
            ('SCR'      , ctypes.c_uint32),
            ('CCR'      , ctypes.c_uint32),
            ('SHP'      , ctypes.c_uint8 * 12),
            ('SHCSR'    , ctypes.c_uint32),
            ('CFSR'     , ctypes.c_uint32),
            ('HFSR'     , ctypes.c_uint32),
            ('DFSR'     , ctypes.c_uint32),
            ('MMFAR'    , ctypes.c_uint32),
            ('BFAR'     , ctypes.c_uint32),
            ('AFSR'     , ctypes.c_uint32),
            ('PFR'      , ctypes.c_uint32 * 4),
            ('DFR'      , ctypes.c_uint32),
            ('ADR'      , ctypes.c_uint32),
            ('MMFR'     , ctypes.c_uint32 * 4),
            ('ISAR'     , ctypes.c_uint32 * 5),
            ('RESERVED0', ctypes.c_uint32 * 5),
            ('CPACR'    , ctypes.c_uint32),
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.instance = self.struct(
            CPUID = 0x410FC241,
            AIRCR = 0xFA050000,
            CCR   = 0x00000200,
        )
