#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes
from qiling.hw.gpio.hooks import GpioHooks
from qiling.hw.peripheral import QlPeripheral


class SAM3xaPio(QlPeripheral, GpioHooks):
    class Type(ctypes.Structure):
        _fields_ = [
            ("PER"       , ctypes.c_uint32),     # (Pio Offset: 0x0000) PIO Enable Register
            ("PDR"       , ctypes.c_uint32),     # (Pio Offset: 0x0004) PIO Disable Register
            ("PSR"       , ctypes.c_uint32),     # (Pio Offset: 0x0008) PIO Status Register
            ("Reserved1" , ctypes.c_uint32),     # 
            ("OER"       , ctypes.c_uint32),     # (Pio Offset: 0x0010) Output Enable Register
            ("ODR"       , ctypes.c_uint32),     # (Pio Offset: 0x0014) Output Disable Register
            ("OSR"       , ctypes.c_uint32),     # (Pio Offset: 0x0018) Output Status Register
            ("Reserved2" , ctypes.c_uint32),     # 
            ("IFER"      , ctypes.c_uint32),     # (Pio Offset: 0x0020) Glitch Input Filter Enable Register
            ("IFDR"      , ctypes.c_uint32),     # (Pio Offset: 0x0024) Glitch Input Filter Disable Register
            ("IFSR"      , ctypes.c_uint32),     # (Pio Offset: 0x0028) Glitch Input Filter Status Register
            ("Reserved3" , ctypes.c_uint32),     # 
            ("SODR"      , ctypes.c_uint32),     # (Pio Offset: 0x0030) Set Output Data Register
            ("CODR"      , ctypes.c_uint32),     # (Pio Offset: 0x0034) Clear Output Data Register
            ("ODSR"      , ctypes.c_uint32),     # (Pio Offset: 0x0038) Output Data Status Register
            ("PDSR"      , ctypes.c_uint32),     # (Pio Offset: 0x003C) Pin Data Status Register
            ("IER"       , ctypes.c_uint32),     # (Pio Offset: 0x0040) Interrupt Enable Register
            ("IDR"       , ctypes.c_uint32),     # (Pio Offset: 0x0044) Interrupt Disable Register
            ("IMR"       , ctypes.c_uint32),     # (Pio Offset: 0x0048) Interrupt Mask Register
            ("ISR"       , ctypes.c_uint32),     # (Pio Offset: 0x004C) Interrupt Status Register
            ("MDER"      , ctypes.c_uint32),     # (Pio Offset: 0x0050) Multi-driver Enable Register
            ("MDDR"      , ctypes.c_uint32),     # (Pio Offset: 0x0054) Multi-driver Disable Register
            ("MDSR"      , ctypes.c_uint32),     # (Pio Offset: 0x0058) Multi-driver Status Register
            ("Reserved4" , ctypes.c_uint32),     # 
            ("PUDR"      , ctypes.c_uint32),     # (Pio Offset: 0x0060) Pull-up Disable Register
            ("PUER"      , ctypes.c_uint32),     # (Pio Offset: 0x0064) Pull-up Enable Register
            ("PUSR"      , ctypes.c_uint32),     # (Pio Offset: 0x0068) Pad Pull-up Status Register
            ("Reserved5" , ctypes.c_uint32),     # 
            ("ABSR"      , ctypes.c_uint32),     # (Pio Offset: 0x0070) Peripheral AB Select Register
            ("Reserved6" , ctypes.c_uint32 * 3), # 
            ("SCIFSR"    , ctypes.c_uint32),     # (Pio Offset: 0x0080) System Clock Glitch Input Filter Select Register
            ("DIFSR"     , ctypes.c_uint32),     # (Pio Offset: 0x0084) Debouncing Input Filter Select Register
            ("IFDGSR"    , ctypes.c_uint32),     # (Pio Offset: 0x0088) Glitch or Debouncing Input Filter Clock Selection Status Register
            ("SCDR"      , ctypes.c_uint32),     # (Pio Offset: 0x008C) Slow Clock Divider Debouncing Register
            ("Reserved7" , ctypes.c_uint32 * 4), # 
            ("OWER"      , ctypes.c_uint32),     # (Pio Offset: 0x00A0) Output Write Enable
            ("OWDR"      , ctypes.c_uint32),     # (Pio Offset: 0x00A4) Output Write Disable
            ("OWSR"      , ctypes.c_uint32),     # (Pio Offset: 0x00A8) Output Write Status Register
            ("Reserved8" , ctypes.c_uint32),     # 
            ("AIMER"     , ctypes.c_uint32),     # (Pio Offset: 0x00B0) Additional Interrupt Modes Enable Register
            ("AIMDR"     , ctypes.c_uint32),     # (Pio Offset: 0x00B4) Additional Interrupt Modes Disables Register
            ("AIMMR"     , ctypes.c_uint32),     # (Pio Offset: 0x00B8) Additional Interrupt Modes Mask Register
            ("Reserved9" , ctypes.c_uint32),     # 
            ("ESR"       , ctypes.c_uint32),     # (Pio Offset: 0x00C0) Edge Select Register
            ("LSR"       , ctypes.c_uint32),     # (Pio Offset: 0x00C4) Level Select Register
            ("ELSR"      , ctypes.c_uint32),     # (Pio Offset: 0x00C8) Edge/Level Status Register
            ("Reserved10", ctypes.c_uint32),     # 
            ("FELLSR"    , ctypes.c_uint32),     # (Pio Offset: 0x00D0) Falling Edge/Low Level Select Register
            ("REHLSR"    , ctypes.c_uint32),     # (Pio Offset: 0x00D4) Rising Edge/ High Level Select Register
            ("FRLHSR"    , ctypes.c_uint32),     # (Pio Offset: 0x00D8) Fall/Rise - Low/High Status Register
            ("Reserved11", ctypes.c_uint32),     # 
            ("LOCKSR"    , ctypes.c_uint32),     # (Pio Offset: 0x00E0) Lock Status
            ("WPMR"      , ctypes.c_uint32),     # (Pio Offset: 0x00E4) Write Protect Mode Register
            ("WPSR"      , ctypes.c_uint32),     # (Pio Offset: 0x00E8) Write Protect Status Register
        ]

    def __init__(self, ql, label, intn = None):
        QlPeripheral.__init__(self, ql, label)
        GpioHooks.__init__(self, ql, 16)

        self.pio = self.struct()
        self.intn = intn
