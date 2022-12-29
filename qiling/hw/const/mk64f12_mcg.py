#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class C1(IntEnum):
    IREFSTEN = 0x1 << 0   # Internal Reference Stop Enable
    IRCLKEN  = 0x1 << 1   # Internal Reference Clock Enable
    IREFS    = 0x1 << 2   # Internal Reference Select
    FRDIV    = 0x7 << 3   # FLL External Reference Divider    
    CLKS     = 0x3 << 6   # Clock Source Select

    IREFS_Pos = 2
    CLKS_Pos  = 6

class C2(IntEnum):
    IRCS    = 0x1 << 0   # Internal Reference Clock Select
    LP      = 0x1 << 1   # Low Power Select
    EREFS   = 0x1 << 2   # External Reference Select
    HGO     = 0x1 << 3   # High Gain Oscillator Select
    RANGE   = 0x3 << 4   # Frequency Range Select
    FCFTRIM = 0x1 << 6   # Fast Internal Reference Clock Fine Trim
    LOCRE0  = 0x1 << 7   # Loss of Clock Reset Enable

class C3(IntEnum):
    SCTRIM = 0xff << 0   # Slow Internal Reference Clock Trim Setting

class C4(IntEnum):
    SCFTRIM  = 0x1 << 0   # Slow Internal Reference Clock Fine Trim
    FCTRIM   = 0xf << 1   # Fast Internal Reference Clock Trim Setting
    DRST_DRS = 0x3 << 5   # DCO Range Select
    DMX32    = 0x1 << 7   # DCO Maximum Frequency with 32.768 kHz Reference

class C5(IntEnum):
    PRDIV0    = 0x1f << 0   # PLL External Reference Divider
    PLLSTEN0  = 0x1 << 5    # PLL Stop Enable
    PLLCLKEN0 = 0x1 << 6    # PLL Clock Enable

class C6(IntEnum):
    VDIV0  = 0x1f << 0   # VCO 0 Divider
    CME0   = 0x1 << 5    # Clock Monitor Enable
    PLLS   = 0x1 << 6    # PLL Select
    LOLIE0 = 0x1 << 7    # Loss of Lock Interrrupt Enable

class S(IntEnum):
    IRCST    = 0x1 << 0   # Internal Reference Clock Status
    OSCINIT0 = 0x1 << 1   # OSC Initialization
    CLKST    = 0x3 << 2   # Clock Mode Status
    IREFST   = 0x1 << 4   # Internal Reference Status
    PLLST    = 0x1 << 5   # PLL Select Status
    LOCK0    = 0x1 << 6   # Lock Status
    LOLS0    = 0x1 << 7   # Loss of Lock Status

    IREFST_Pos = 4
    CLKST_Pos  = 2

class SC(IntEnum):
    LOCS0    = 0x1 << 0   # OSC0 Loss of Clock Status
    FCRDIV   = 0x7 << 1   # Fast Clock Internal Reference Divider
    FLTPRSRV = 0x1 << 4   # FLL Filter Preserve Enable
    ATMF     = 0x1 << 5   # Automatic Trim Machine Fail Flag
    ATMS     = 0x1 << 6   # Automatic Trim Machine Select
    ATME     = 0x1 << 7   # Automatic Trim Machine Enable

class ATCVH(IntEnum):
    ATCVH = 0xff << 0   # ATM Compare Value High

class ATCVL(IntEnum):
    ATCVL = 0xff << 0   # ATM Compare Value Low

class C7(IntEnum):
    OSCSEL = 0x3 << 0   # MCG OSC Clock Select

class C8(IntEnum):
    LOCS1  = 0x1 << 0   # RTC Loss of Clock Status
    CME1   = 0x1 << 5   # Clock Monitor Enable1
    LOLRE  = 0x1 << 6   # PLL Loss of Lock Reset Enable
    LOCRE1 = 0x1 << 7   # Loss of Clock Reset Enable

