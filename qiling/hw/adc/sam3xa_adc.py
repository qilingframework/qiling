#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class SAM3xaAdc(QlPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ("CR"       , ctypes.c_uint32),      # (Adc Offset: 0x00) Control Register
            ("MR"       , ctypes.c_uint32),      # (Adc Offset: 0x04) Mode Register
            ("SEQR1"    , ctypes.c_uint32),      # (Adc Offset: 0x08) Channel Sequence Register 1
            ("SEQR2"    , ctypes.c_uint32),      # (Adc Offset: 0x0C) Channel Sequence Register 2
            ("CHER"     , ctypes.c_uint32),      # (Adc Offset: 0x10) Channel Enable Register
            ("CHDR"     , ctypes.c_uint32),      # (Adc Offset: 0x14) Channel Disable Register
            ("CHSR"     , ctypes.c_uint32),      # (Adc Offset: 0x18) Channel Status Register
            ("Reserved1", ctypes.c_uint32),      # 
            ("LCDR"     , ctypes.c_uint32),      # (Adc Offset: 0x20) Last Converted Data Register
            ("IER"      , ctypes.c_uint32),      # (Adc Offset: 0x24) Interrupt Enable Register
            ("IDR"      , ctypes.c_uint32),      # (Adc Offset: 0x28) Interrupt Disable Register
            ("IMR"      , ctypes.c_uint32),      # (Adc Offset: 0x2C) Interrupt Mask Register
            ("ISR"      , ctypes.c_uint32),      # (Adc Offset: 0x30) Interrupt Status Register
            ("Reserved2", ctypes.c_uint32 * 2),  # 
            ("OVER"     , ctypes.c_uint32),      # (Adc Offset: 0x3C) Overrun Status Register
            ("EMR"      , ctypes.c_uint32),      # (Adc Offset: 0x40) Extended Mode Register
            ("CWR"      , ctypes.c_uint32),      # (Adc Offset: 0x44) Compare Window Register
            ("CGR"      , ctypes.c_uint32),      # (Adc Offset: 0x48) Channel Gain Register
            ("COR"      , ctypes.c_uint32),      # (Adc Offset: 0x4C) Channel Offset Register
            ("CDR"      , ctypes.c_uint32 * 16), # (Adc Offset: 0x50) Channel Data Register
            ("Reserved3", ctypes.c_uint32),      # 
            ("ACR"      , ctypes.c_uint32),      # (Adc Offset: 0x94) Analog Control Register
            ("Reserved4", ctypes.c_uint32 * 19), # 
            ("WPMR"     , ctypes.c_uint32),      # (Adc Offset: 0xE4) Write Protect Mode Register
            ("WPSR"     , ctypes.c_uint32),      # (Adc Offset: 0xE8) Write Protect Status Register
            ("Reserved5", ctypes.c_uint32 * 5),  # 
            ("RPR"      , ctypes.c_uint32),      # (Adc Offset: 0x100) Receive Pointer Register
            ("RCR"      , ctypes.c_uint32),      # (Adc Offset: 0x104) Receive Counter Register
            ("Reserved6", ctypes.c_uint32 * 2),  # 
            ("RNPR"     , ctypes.c_uint32),      # (Adc Offset: 0x110) Receive Next Pointer Register
            ("RNCR"     , ctypes.c_uint32),      # (Adc Offset: 0x114) Receive Next Counter Register
            ("Reserved7", ctypes.c_uint32 * 2),  # 
            ("PTCR"     , ctypes.c_uint32),      # (Adc Offset: 0x120) Transfer Control Register
            ("PTSR"     , ctypes.c_uint32),      # (Adc Offset: 0x124) Transfer Status Register
        ]

    def __init__(self, ql, label, intn = None):
        super().__init__(ql, label)

        self.adc = self.struct()
        self.intn = intn
