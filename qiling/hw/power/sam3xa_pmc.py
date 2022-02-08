#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.core import Qiling
from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.sam3xa_pmc import CKGR_MOR, SR, MCKR, CKGR_PLLAR, CKGR_UCKR

class SAM3xaPmc(QlPeripheral):
    """
    The Power Management Controller (PMC) optimizes power consumption by controlling all system and user
    peripheral clocks. The PMC enables/disables the clock inputs to many of the peripherals and the Cortex-M3
    Processor.

    The Supply Controller selects between the 32 kHz RC oscillator or the crystal oscillator. The unused oscillator is
    disabled automatically so that power consumption is optimized.

    By default, at startup the chip runs out of the Master Clock using the Fast RC oscillator running at 4 MHz.
    The user can trim the 8 and 12 MHz RC Oscillator frequencies by software.
    """

    class Type(ctypes.Structure):
        _fields_ = [
            ("SCER"      , ctypes.c_uint32),      # (Pmc Offset: 0x0000) System Clock Enable Register
            ("SCDR"      , ctypes.c_uint32),      # (Pmc Offset: 0x0004) System Clock Disable Register
            ("SCSR"      , ctypes.c_uint32),      # (Pmc Offset: 0x0008) System Clock Status Register
            ("Reserved1" , ctypes.c_uint32),      # 
            ("PCER0"     , ctypes.c_uint32),      # (Pmc Offset: 0x0010) Peripheral Clock Enable Register 0
            ("PCDR0"     , ctypes.c_uint32),      # (Pmc Offset: 0x0014) Peripheral Clock Disable Register 0
            ("PCSR0"     , ctypes.c_uint32),      # (Pmc Offset: 0x0018) Peripheral Clock Status Register 0
            ("CKGR_UCKR" , ctypes.c_uint32),      # (Pmc Offset: 0x001C) UTMI Clock Register
            ("CKGR_MOR"  , ctypes.c_uint32),      # (Pmc Offset: 0x0020) Main Oscillator Register
            ("CKGR_MCFR" , ctypes.c_uint32),      # (Pmc Offset: 0x0024) Main Clock Frequency Register
            ("CKGR_PLLAR", ctypes.c_uint32),      # (Pmc Offset: 0x0028) PLLA Register
            ("Reserved2" , ctypes.c_uint32),      # 
            ("MCKR"      , ctypes.c_uint32),      # (Pmc Offset: 0x0030) Master Clock Register
            ("Reserved3" , ctypes.c_uint32),      # 
            ("USB"       , ctypes.c_uint32),      # (Pmc Offset: 0x0038) USB Clock Register
            ("Reserved4" , ctypes.c_uint32),      # 
            ("PCK"       , ctypes.c_uint32 * 3),  # (Pmc Offset: 0x0040) Programmable Clock 0 Register
            ("Reserved5" , ctypes.c_uint32 * 5),  # 
            ("IER"       , ctypes.c_uint32),      # (Pmc Offset: 0x0060) Interrupt Enable Register
            ("IDR"       , ctypes.c_uint32),      # (Pmc Offset: 0x0064) Interrupt Disable Register
            ("SR"        , ctypes.c_uint32),      # (Pmc Offset: 0x0068) Status Register
            ("IMR"       , ctypes.c_uint32),      # (Pmc Offset: 0x006C) Interrupt Mask Register
            ("FSMR"      , ctypes.c_uint32),      # (Pmc Offset: 0x0070) Fast Startup Mode Register
            ("FSPR"      , ctypes.c_uint32),      # (Pmc Offset: 0x0074) Fast Startup Polarity Register
            ("FOCR"      , ctypes.c_uint32),      # (Pmc Offset: 0x0078) Fault Output Clear Register
            ("Reserved6" , ctypes.c_uint32 * 26), # 
            ("WPMR"      , ctypes.c_uint32),      # (Pmc Offset: 0x00E4) Write Protect Mode Register
            ("WPSR"      , ctypes.c_uint32),      # (Pmc Offset: 0x00E8) Write Protect Status Register
            ("Reserved7" , ctypes.c_uint32 * 5),  # 
            ("PCER1"     , ctypes.c_uint32),      # (Pmc Offset: 0x0100) Peripheral Clock Enable Register 1
            ("PCDR1"     , ctypes.c_uint32),      # (Pmc Offset: 0x0104) Peripheral Clock Disable Register 1
            ("PCSR1"     , ctypes.c_uint32),      # (Pmc Offset: 0x0108) Peripheral Clock Status Register 1
            ("PCR"       , ctypes.c_uint32),      # (Pmc Offset: 0x010C) Peripheral Control Register
        ]

    def __init__(self, ql: Qiling, label: str, intn = None):
        super().__init__(ql, label)

        self.pmc = self.struct()
        self.intn = intn

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:		
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.pmc) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        if offset == self.struct.CKGR_MOR.offset:
            if value & CKGR_MOR.MOSCXTEN:
                self.pmc.SR |= SR.MOSCXTS
            if value & CKGR_MOR.MOSCSEL:
                self.pmc.SR |= SR.MOSCSELS

        elif offset == self.struct.MCKR.offset:
            if value & MCKR.CSS:
                self.pmc.SR |= SR.MCKRDY

        elif offset == self.struct.CKGR_PLLAR.offset:
            if value & CKGR_PLLAR.ONE:
                self.pmc.SR |= SR.LOCKA

        elif offset == self.struct.CKGR_UCKR.offset:
            if value & CKGR_UCKR.UPLLEN:
                self.pmc.SR |= SR.LOCKU

        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.pmc) + offset, data, size)