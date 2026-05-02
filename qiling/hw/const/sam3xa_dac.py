#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class CR(IntEnum):
    SWRST = 0x1 << 0   # Software Reset

class MR(IntEnum):
    TRGEN    = 0x1 << 0     # Trigger Enable
    TRGSEL   = 0x7 << 1     # Trigger Selection
    WORD     = 0x1 << 4     # Word Transfer
    SLEEP    = 0x1 << 5     # Sleep Mode
    FASTWKUP = 0x1 << 6     # Fast Wake up Mode
    REFRESH  = 0xff << 8    # Refresh Period
    USER_SEL = 0x3 << 16    # User Channel Selection
    TAG      = 0x1 << 20    # Tag Selection Mode
    MAXS     = 0x1 << 21    # Max Speed Mode
    STARTUP  = 0x3f << 24   # Startup Time Selection

class CHER(IntEnum):
    CH0 = 0x1 << 0   # Channel 0 Enable
    CH1 = 0x1 << 1   # Channel 1 Enable

class CHDR(IntEnum):
    CH0 = 0x1 << 0   # Channel 0 Disable
    CH1 = 0x1 << 1   # Channel 1 Disable

class CHSR(IntEnum):
    CH0 = 0x1 << 0   # Channel 0 Status
    CH1 = 0x1 << 1   # Channel 1 Status

class IER(IntEnum):
    TXRDY  = 0x1 << 0   # Transmit Ready Interrupt Enable
    EOC    = 0x1 << 1   # End of Conversion Interrupt Enable
    ENDTX  = 0x1 << 2   # End of Transmit Buffer Interrupt Enable
    TXBUFE = 0x1 << 3   # Transmit Buffer Empty Interrupt Enable

class IDR(IntEnum):
    TXRDY  = 0x1 << 0   # Transmit Ready Interrupt Disable.
    EOC    = 0x1 << 1   # End of Conversion Interrupt Disable
    ENDTX  = 0x1 << 2   # End of Transmit Buffer Interrupt Disable
    TXBUFE = 0x1 << 3   # Transmit Buffer Empty Interrupt Disable

class IMR(IntEnum):
    TXRDY  = 0x1 << 0   # Transmit Ready Interrupt Mask
    EOC    = 0x1 << 1   # End of Conversion Interrupt Mask
    ENDTX  = 0x1 << 2   # End of Transmit Buffer Interrupt Mask
    TXBUFE = 0x1 << 3   # Transmit Buffer Empty Interrupt Mask

class ISR(IntEnum):
    TXRDY  = 0x1 << 0   # Transmit Ready Interrupt Flag
    EOC    = 0x1 << 1   # End of Conversion Interrupt Flag
    ENDTX  = 0x1 << 2   # End of DMA Interrupt Flag
    TXBUFE = 0x1 << 3   # Transmit Buffer Empty

class ACR(IntEnum):
    IBCTLCH0     = 0x3 << 0   # Analog Output Current Control
    IBCTLCH1     = 0x3 << 2   # Analog Output Current Control
    IBCTLDACCORE = 0x3 << 8   # Bias Current Control for DAC Core

class WPMR(IntEnum):
    WPEN  = 0x1 << 0        # Write Protect Enable
    WPKEY = 0xffffff << 8   # Write Protect KEY

class WPSR(IntEnum):
    WPROTERR  = 0x1 << 0    # Write protection error
    WPROTADDR = 0xff << 8   # Write protection error address

class TPR(IntEnum):
    TXPTR = 0xffffffff << 0   # Transmit Counter Register

class TCR(IntEnum):
    TXCTR = 0xffff << 0   # Transmit Counter Register

class TNPR(IntEnum):
    TXNPTR = 0xffffffff << 0   # Transmit Next Pointer

class TNCR(IntEnum):
    TXNCTR = 0xffff << 0   # Transmit Counter Next

class PTCR(IntEnum):
    RXTEN  = 0x1 << 0   # Receiver Transfer Enable
    RXTDIS = 0x1 << 1   # Receiver Transfer Disable
    TXTEN  = 0x1 << 8   # Transmitter Transfer Enable
    TXTDIS = 0x1 << 9   # Transmitter Transfer Disable

class PTSR(IntEnum):
    RXTEN = 0x1 << 0   # Receiver Transfer Enable
    TXTEN = 0x1 << 8   # Transmitter Transfer Enable
