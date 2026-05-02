#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class PCR(IntEnum):
    PS   = 0x1 << 0    # Pull Select
    PE   = 0x1 << 1    # Pull Enable
    SRE  = 0x1 << 2    # Slew Rate Enable
    PFE  = 0x1 << 4    # Passive Filter Enable
    ODE  = 0x1 << 5    # Open Drain Enable
    DSE  = 0x1 << 6    # Drive Strength Enable
    MUX  = 0x7 << 8    # Pin Mux Control
    LK   = 0x1 << 15   # Lock Register
    IRQC = 0xf << 16   # Interrupt Configuration
    ISF  = 0x1 << 24   # Interrupt Status Flag

class InterruptMode(IntEnum):
    InterruptOrDMADisabled = 0x0 # Interrupt/DMA request is disabled. 
    DMARisingEdge          = 0x1 # DMA request on rising edge. 
    DMAFallingEdge         = 0x2 # DMA request on falling edge. 
    DMAEitherEdge          = 0x3 # DMA request on either edge. 
    FlagRisingEdge         = 0x5 # Flag sets on rising edge. 
    FlagFallingEdge        = 0x6 # Flag sets on falling edge. 
    FlagEitherEdge         = 0x7 # Flag sets on either edge. 
    InterruptLogicZero     = 0x8 # Interrupt when logic zero. 
    InterruptRisingEdge    = 0x9 # Interrupt on rising edge. 
    InterruptFallingEdge   = 0xA # Interrupt on falling edge. 
    InterruptEitherEdge    = 0xB # Interrupt on either edge. 
    InterruptLogicOne      = 0xC # Interrupt when logic one. 
