#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class CR(IntEnum):
    SPIEN    = 0x1 << 0    # SPI Enable
    SPIDIS   = 0x1 << 1    # SPI Disable
    SWRST    = 0x1 << 7    # SPI Software Reset
    LASTXFER = 0x1 << 24   # Last Transfer

class MR(IntEnum):
    MSTR    = 0x1 << 0     # Master/Slave Mode
    PS      = 0x1 << 1     # Peripheral Select
    PCSDEC  = 0x1 << 2     # Chip Select Decode
    MODFDIS = 0x1 << 4     # Mode Fault Detection
    WDRBT   = 0x1 << 5     # Wait Data Read Before Transfer
    LLB     = 0x1 << 7     # Local Loopback Enable
    PCS     = 0xf << 16    # Peripheral Chip Select
    DLYBCS  = 0xff << 24   # Delay Between Chip Selects

class RDR(IntEnum):
    RD  = 0xffff << 0   # Receive Data
    PCS = 0xf << 16     # Peripheral Chip Select

class TDR(IntEnum):
    TD       = 0xffff << 0   # Transmit Data
    PCS      = 0xf << 16     # Peripheral Chip Select
    LASTXFER = 0x1 << 24     # Last Transfer

class SR(IntEnum):
    RDRF    = 0x1 << 0    # Receive Data Register Full
    TDRE    = 0x1 << 1    # Transmit Data Register Empty
    MODF    = 0x1 << 2    # Mode Fault Error
    OVRES   = 0x1 << 3    # Overrun Error Status
    NSSR    = 0x1 << 8    # NSS Rising
    TXEMPTY = 0x1 << 9    # Transmission Registers Empty
    UNDES   = 0x1 << 10   # Underrun Error Status (Slave Mode Only)
    SPIENS  = 0x1 << 16   # SPI Enable Status

class IER(IntEnum):
    RDRF    = 0x1 << 0    # Receive Data Register Full Interrupt Enable
    TDRE    = 0x1 << 1    # SPI Transmit Data Register Empty Interrupt Enable
    MODF    = 0x1 << 2    # Mode Fault Error Interrupt Enable
    OVRES   = 0x1 << 3    # Overrun Error Interrupt Enable
    NSSR    = 0x1 << 8    # NSS Rising Interrupt Enable
    TXEMPTY = 0x1 << 9    # Transmission Registers Empty Enable
    UNDES   = 0x1 << 10   # Underrun Error Interrupt Enable

class IDR(IntEnum):
    RDRF    = 0x1 << 0    # Receive Data Register Full Interrupt Disable
    TDRE    = 0x1 << 1    # SPI Transmit Data Register Empty Interrupt Disable
    MODF    = 0x1 << 2    # Mode Fault Error Interrupt Disable
    OVRES   = 0x1 << 3    # Overrun Error Interrupt Disable
    NSSR    = 0x1 << 8    # NSS Rising Interrupt Disable
    TXEMPTY = 0x1 << 9    # Transmission Registers Empty Disable
    UNDES   = 0x1 << 10   # Underrun Error Interrupt Disable

class IMR(IntEnum):
    RDRF    = 0x1 << 0    # Receive Data Register Full Interrupt Mask
    TDRE    = 0x1 << 1    # SPI Transmit Data Register Empty Interrupt Mask
    MODF    = 0x1 << 2    # Mode Fault Error Interrupt Mask
    OVRES   = 0x1 << 3    # Overrun Error Interrupt Mask
    NSSR    = 0x1 << 8    # NSS Rising Interrupt Mask
    TXEMPTY = 0x1 << 9    # Transmission Registers Empty Mask
    UNDES   = 0x1 << 10   # Underrun Error Interrupt Mask

class CSR(IntEnum):
    CPOL   = 0x1 << 0     # Clock Polarity
    NCPHA  = 0x1 << 1     # Clock Phase
    CSNAAT = 0x1 << 2     # Chip Select Not Active After Transfer (Ignored if CSAAT = 1)
    CSAAT  = 0x1 << 3     # Chip Select Not Active After Transfer (Ignored if CSAAT = 1)
    BITS   = 0xf << 4     # Bits Per Transfer
    SCBR   = 0xff << 8    # Serial Clock Baud Rate
    DLYBS  = 0xff << 16   # Delay Before SPCK
    DLYBCT = 0xff << 24   # Delay Between Consecutive Transfers

class WPMR(IntEnum):
    WPEN  = 0x1 << 0        # Write Protection Enable
    WPKEY = 0xffffff << 8   # Write Protection Key Password

class WPSR(IntEnum):
    WPVS   = 0x1 << 0    # Write Protection Violation Status
    WPVSRC = 0xff << 8   # Write Protection Violation Source
