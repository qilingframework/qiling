#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class SC(IntEnum):
    PS    = 0x7 << 0   # Prescale Factor Selection
    CLKS  = 0x3 << 3   # Clock Source Selection
    CPWMS = 0x1 << 5   # Center-Aligned PWM Select
    TOIE  = 0x1 << 6   # Timer Overflow Interrupt Enable
    TOF   = 0x1 << 7   # Timer Overflow Flag

class CSC(IntEnum):
    DMA  = 0x1 << 0   # DMA Enable
    ELSA = 0x1 << 2   # Edge or Level Select
    ELSB = 0x1 << 3   # Edge or Level Select
    MSA  = 0x1 << 4   # Channel Mode Select
    MSB  = 0x1 << 5   # Channel Mode Select
    CHIE = 0x1 << 6   # Channel Interrupt Enable
    CHF  = 0x1 << 7   # Channel Flag

class STATUS(IntEnum):
    CH0F = 0x1 << 0   # Channel 0 Flag
    CH1F = 0x1 << 1   # Channel 1 Flag
    CH2F = 0x1 << 2   # Channel 2 Flag
    CH3F = 0x1 << 3   # Channel 3 Flag
    CH4F = 0x1 << 4   # Channel 4 Flag
    CH5F = 0x1 << 5   # Channel 5 Flag
    CH6F = 0x1 << 6   # Channel 6 Flag
    CH7F = 0x1 << 7   # Channel 7 Flag

class MODE(IntEnum):
    FTMEN   = 0x1 << 0   # FTM Enable
    INIT    = 0x1 << 1   # Initialize The Channels Output
    WPDIS   = 0x1 << 2   # Write Protection Disable
    PWMSYNC = 0x1 << 3   # PWM Synchronization Mode
    CAPTEST = 0x1 << 4   # Capture Test Mode Enable
    FAULTM  = 0x3 << 5   # Fault Control Mode
    FAULTIE = 0x1 << 7   # Fault Interrupt Enable

class SYNC(IntEnum):
    CNTMIN  = 0x1 << 0   # Minimum Loading Point Enable
    CNTMAX  = 0x1 << 1   # Maximum Loading Point Enable
    REINIT  = 0x1 << 2   # FTM Counter Reinitialization By Synchronization (FTM counter synchronization)
    SYNCHOM = 0x1 << 3   # Output Mask Synchronization
    TRIG0   = 0x1 << 4   # PWM Synchronization Hardware Trigger 0
    TRIG1   = 0x1 << 5   # PWM Synchronization Hardware Trigger 1
    TRIG2   = 0x1 << 6   # PWM Synchronization Hardware Trigger 2
    SWSYNC  = 0x1 << 7   # PWM Synchronization Software Trigger

class OUTINIT(IntEnum):
    CH0OI = 0x1 << 0   # Channel 0 Output Initialization Value
    CH1OI = 0x1 << 1   # Channel 1 Output Initialization Value
    CH2OI = 0x1 << 2   # Channel 2 Output Initialization Value
    CH3OI = 0x1 << 3   # Channel 3 Output Initialization Value
    CH4OI = 0x1 << 4   # Channel 4 Output Initialization Value
    CH5OI = 0x1 << 5   # Channel 5 Output Initialization Value
    CH6OI = 0x1 << 6   # Channel 6 Output Initialization Value
    CH7OI = 0x1 << 7   # Channel 7 Output Initialization Value

class OUTMASK(IntEnum):
    CH0OM = 0x1 << 0   # Channel 0 Output Mask
    CH1OM = 0x1 << 1   # Channel 1 Output Mask
    CH2OM = 0x1 << 2   # Channel 2 Output Mask
    CH3OM = 0x1 << 3   # Channel 3 Output Mask
    CH4OM = 0x1 << 4   # Channel 4 Output Mask
    CH5OM = 0x1 << 5   # Channel 5 Output Mask
    CH6OM = 0x1 << 6   # Channel 6 Output Mask
    CH7OM = 0x1 << 7   # Channel 7 Output Mask

class COMBINE(IntEnum):
    COMBINE0 = 0x1 << 0    # Combine Channels For n = 0
    COMP0    = 0x1 << 1    # Complement Of Channel (n) For n = 0
    DECAPEN0 = 0x1 << 2    # Dual Edge Capture Mode Enable For n = 0
    DECAP0   = 0x1 << 3    # Dual Edge Capture Mode Captures For n = 0
    DTEN0    = 0x1 << 4    # Deadtime Enable For n = 0
    SYNCEN0  = 0x1 << 5    # Synchronization Enable For n = 0
    FAULTEN0 = 0x1 << 6    # Fault Control Enable For n = 0
    COMBINE1 = 0x1 << 8    # Combine Channels For n = 2
    COMP1    = 0x1 << 9    # Complement Of Channel (n) For n = 2
    DECAPEN1 = 0x1 << 10   # Dual Edge Capture Mode Enable For n = 2
    DECAP1   = 0x1 << 11   # Dual Edge Capture Mode Captures For n = 2
    DTEN1    = 0x1 << 12   # Deadtime Enable For n = 2
    SYNCEN1  = 0x1 << 13   # Synchronization Enable For n = 2
    FAULTEN1 = 0x1 << 14   # Fault Control Enable For n = 2
    COMBINE2 = 0x1 << 16   # Combine Channels For n = 4
    COMP2    = 0x1 << 17   # Complement Of Channel (n) For n = 4
    DECAPEN2 = 0x1 << 18   # Dual Edge Capture Mode Enable For n = 4
    DECAP2   = 0x1 << 19   # Dual Edge Capture Mode Captures For n = 4
    DTEN2    = 0x1 << 20   # Deadtime Enable For n = 4
    SYNCEN2  = 0x1 << 21   # Synchronization Enable For n = 4
    FAULTEN2 = 0x1 << 22   # Fault Control Enable For n = 4
    COMBINE3 = 0x1 << 24   # Combine Channels For n = 6
    COMP3    = 0x1 << 25   # Complement Of Channel (n) for n = 6
    DECAPEN3 = 0x1 << 26   # Dual Edge Capture Mode Enable For n = 6
    DECAP3   = 0x1 << 27   # Dual Edge Capture Mode Captures For n = 6
    DTEN3    = 0x1 << 28   # Deadtime Enable For n = 6
    SYNCEN3  = 0x1 << 29   # Synchronization Enable For n = 6
    FAULTEN3 = 0x1 << 30   # Fault Control Enable For n = 6

class DEADTIME(IntEnum):
    DTVAL = 0x3f << 0   # Deadtime Value
    DTPS  = 0x3 << 6    # Deadtime Prescaler Value

class EXTTRIG(IntEnum):
    CH2TRIG    = 0x1 << 0   # Channel 2 Trigger Enable
    CH3TRIG    = 0x1 << 1   # Channel 3 Trigger Enable
    CH4TRIG    = 0x1 << 2   # Channel 4 Trigger Enable
    CH5TRIG    = 0x1 << 3   # Channel 5 Trigger Enable
    CH0TRIG    = 0x1 << 4   # Channel 0 Trigger Enable
    CH1TRIG    = 0x1 << 5   # Channel 1 Trigger Enable
    INITTRIGEN = 0x1 << 6   # Initialization Trigger Enable
    TRIGF      = 0x1 << 7   # Channel Trigger Flag

class POL(IntEnum):
    POL0 = 0x1 << 0   # Channel 0 Polarity
    POL1 = 0x1 << 1   # Channel 1 Polarity
    POL2 = 0x1 << 2   # Channel 2 Polarity
    POL3 = 0x1 << 3   # Channel 3 Polarity
    POL4 = 0x1 << 4   # Channel 4 Polarity
    POL5 = 0x1 << 5   # Channel 5 Polarity
    POL6 = 0x1 << 6   # Channel 6 Polarity
    POL7 = 0x1 << 7   # Channel 7 Polarity

class FMS(IntEnum):
    FAULTF0 = 0x1 << 0   # Fault Detection Flag 0
    FAULTF1 = 0x1 << 1   # Fault Detection Flag 1
    FAULTF2 = 0x1 << 2   # Fault Detection Flag 2
    FAULTF3 = 0x1 << 3   # Fault Detection Flag 3
    FAULTIN = 0x1 << 5   # Fault Inputs
    WPEN    = 0x1 << 6   # Write Protection Enable
    FAULTF  = 0x1 << 7   # Fault Detection Flag

class FILTER(IntEnum):
    CH0FVAL = 0xf << 0    # Channel 0 Input Filter
    CH1FVAL = 0xf << 4    # Channel 1 Input Filter
    CH2FVAL = 0xf << 8    # Channel 2 Input Filter
    CH3FVAL = 0xf << 12   # Channel 3 Input Filter

class FLTCTRL(IntEnum):
    FAULT0EN = 0x1 << 0   # Fault Input 0 Enable
    FAULT1EN = 0x1 << 1   # Fault Input 1 Enable
    FAULT2EN = 0x1 << 2   # Fault Input 2 Enable
    FAULT3EN = 0x1 << 3   # Fault Input 3 Enable
    FFLTR0EN = 0x1 << 4   # Fault Input 0 Filter Enable
    FFLTR1EN = 0x1 << 5   # Fault Input 1 Filter Enable
    FFLTR2EN = 0x1 << 6   # Fault Input 2 Filter Enable
    FFLTR3EN = 0x1 << 7   # Fault Input 3 Filter Enable
    FFVAL    = 0xf << 8   # Fault Input Filter

class QDCTRL(IntEnum):
    QUADEN    = 0x1 << 0   # Quadrature Decoder Mode Enable
    TOFDIR    = 0x1 << 1   # Timer Overflow Direction In Quadrature Decoder Mode
    QUADIR    = 0x1 << 2   # FTM Counter Direction In Quadrature Decoder Mode
    QUADMODE  = 0x1 << 3   # Quadrature Decoder Mode
    PHBPOL    = 0x1 << 4   # Phase B Input Polarity
    PHAPOL    = 0x1 << 5   # Phase A Input Polarity
    PHBFLTREN = 0x1 << 6   # Phase B Input Filter Enable
    PHAFLTREN = 0x1 << 7   # Phase A Input Filter Enable

class CONF(IntEnum):
    NUMTOF  = 0x1f << 0   # TOF Frequency
    BDMMODE = 0x3 << 6    # BDM Mode
    GTBEEN  = 0x1 << 9    # Global Time Base Enable
    GTBEOUT = 0x1 << 10   # Global Time Base Output

class FLTPOL(IntEnum):
    FLT0POL = 0x1 << 0   # Fault Input 0 Polarity
    FLT1POL = 0x1 << 1   # Fault Input 1 Polarity
    FLT2POL = 0x1 << 2   # Fault Input 2 Polarity
    FLT3POL = 0x1 << 3   # Fault Input 3 Polarity

class SYNCONF(IntEnum):
    HWTRIGMODE = 0x1 << 0    # Hardware Trigger Mode
    CNTINC     = 0x1 << 2    # CNTIN Register Synchronization
    INVC       = 0x1 << 4    # INVCTRL Register Synchronization
    SWOC       = 0x1 << 5    # SWOCTRL Register Synchronization
    SYNCMODE   = 0x1 << 7    # Synchronization Mode
    SWRSTCNT   = 0x1 << 8    # FTM counter synchronization is activated by the software trigger.
    SWWRBUF    = 0x1 << 9    # MOD, CNTIN, and CV registers synchronization is activated by the software trigger.
    SWOM       = 0x1 << 10   # Output mask synchronization is activated by the software trigger.
    SWINVC     = 0x1 << 11   # Inverting control synchronization is activated by the software trigger.
    SWSOC      = 0x1 << 12   # Software output control synchronization is activated by the software trigger.
    HWRSTCNT   = 0x1 << 16   # FTM counter synchronization is activated by a hardware trigger.
    HWWRBUF    = 0x1 << 17   # MOD, CNTIN, and CV registers synchronization is activated by a hardware trigger.
    HWOM       = 0x1 << 18   # Output mask synchronization is activated by a hardware trigger.
    HWINVC     = 0x1 << 19   # Inverting control synchronization is activated by a hardware trigger.
    HWSOC      = 0x1 << 20   # Software output control synchronization is activated by a hardware trigger.

class INVCTRL(IntEnum):
    INV0EN = 0x1 << 0   # Pair Channels 0 Inverting Enable
    INV1EN = 0x1 << 1   # Pair Channels 1 Inverting Enable
    INV2EN = 0x1 << 2   # Pair Channels 2 Inverting Enable
    INV3EN = 0x1 << 3   # Pair Channels 3 Inverting Enable

class SWOCTRL(IntEnum):
    CH0OC  = 0x1 << 0    # Channel 0 Software Output Control Enable
    CH1OC  = 0x1 << 1    # Channel 1 Software Output Control Enable
    CH2OC  = 0x1 << 2    # Channel 2 Software Output Control Enable
    CH3OC  = 0x1 << 3    # Channel 3 Software Output Control Enable
    CH4OC  = 0x1 << 4    # Channel 4 Software Output Control Enable
    CH5OC  = 0x1 << 5    # Channel 5 Software Output Control Enable
    CH6OC  = 0x1 << 6    # Channel 6 Software Output Control Enable
    CH7OC  = 0x1 << 7    # Channel 7 Software Output Control Enable
    CH0OCV = 0x1 << 8    # Channel 0 Software Output Control Value
    CH1OCV = 0x1 << 9    # Channel 1 Software Output Control Value
    CH2OCV = 0x1 << 10   # Channel 2 Software Output Control Value
    CH3OCV = 0x1 << 11   # Channel 3 Software Output Control Value
    CH4OCV = 0x1 << 12   # Channel 4 Software Output Control Value
    CH5OCV = 0x1 << 13   # Channel 5 Software Output Control Value
    CH6OCV = 0x1 << 14   # Channel 6 Software Output Control Value
    CH7OCV = 0x1 << 15   # Channel 7 Software Output Control Value

class PWMLOAD(IntEnum):
    CH0SEL = 0x1 << 0   # Channel 0 Select
    CH1SEL = 0x1 << 1   # Channel 1 Select
    CH2SEL = 0x1 << 2   # Channel 2 Select
    CH3SEL = 0x1 << 3   # Channel 3 Select
    CH4SEL = 0x1 << 4   # Channel 4 Select
    CH5SEL = 0x1 << 5   # Channel 5 Select
    CH6SEL = 0x1 << 6   # Channel 6 Select
    CH7SEL = 0x1 << 7   # Channel 7 Select
    LDOK   = 0x1 << 9   # Load Enable
