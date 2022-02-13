#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class CR(IntEnum):
    RSTRX  = 0x1 << 2   # Reset Receiver
    RSTTX  = 0x1 << 3   # Reset Transmitter
    RXEN   = 0x1 << 4   # Receiver Enable
    RXDIS  = 0x1 << 5   # Receiver Disable
    TXEN   = 0x1 << 6   # Transmitter Enable
    TXDIS  = 0x1 << 7   # Transmitter Disable
    RSTSTA = 0x1 << 8   # Reset Status Bits

class MR(IntEnum):
    PAR    = 0x7 << 9    # Parity Type
    CHMODE = 0x3 << 14   # Channel Mode

class IER(IntEnum):
    RXRDY   = 0x1 << 0    # Enable RXRDY Interrupt
    TXRDY   = 0x1 << 1    # Enable TXRDY Interrupt
    ENDRX   = 0x1 << 3    # Enable End of Receive Transfer Interrupt
    ENDTX   = 0x1 << 4    # Enable End of Transmit Interrupt
    OVRE    = 0x1 << 5    # Enable Overrun Error Interrupt
    FRAME   = 0x1 << 6    # Enable Framing Error Interrupt
    PARE    = 0x1 << 7    # Enable Parity Error Interrupt
    TXEMPTY = 0x1 << 9    # Enable TXEMPTY Interrupt
    TXBUFE  = 0x1 << 11   # Enable Buffer Empty Interrupt
    RXBUFF  = 0x1 << 12   # Enable Buffer Full Interrupt

class IDR(IntEnum):
    RXRDY   = 0x1 << 0    # Disable RXRDY Interrupt
    TXRDY   = 0x1 << 1    # Disable TXRDY Interrupt
    ENDRX   = 0x1 << 3    # Disable End of Receive Transfer Interrupt
    ENDTX   = 0x1 << 4    # Disable End of Transmit Interrupt
    OVRE    = 0x1 << 5    # Disable Overrun Error Interrupt
    FRAME   = 0x1 << 6    # Disable Framing Error Interrupt
    PARE    = 0x1 << 7    # Disable Parity Error Interrupt
    TXEMPTY = 0x1 << 9    # Disable TXEMPTY Interrupt
    TXBUFE  = 0x1 << 11   # Disable Buffer Empty Interrupt
    RXBUFF  = 0x1 << 12   # Disable Buffer Full Interrupt

class IMR(IntEnum):
    RXRDY   = 0x1 << 0    # Mask RXRDY Interrupt
    TXRDY   = 0x1 << 1    # Disable TXRDY Interrupt
    ENDRX   = 0x1 << 3    # Mask End of Receive Transfer Interrupt
    ENDTX   = 0x1 << 4    # Mask End of Transmit Interrupt
    OVRE    = 0x1 << 5    # Mask Overrun Error Interrupt
    FRAME   = 0x1 << 6    # Mask Framing Error Interrupt
    PARE    = 0x1 << 7    # Mask Parity Error Interrupt
    TXEMPTY = 0x1 << 9    # Mask TXEMPTY Interrupt
    TXBUFE  = 0x1 << 11   # Mask TXBUFE Interrupt
    RXBUFF  = 0x1 << 12   # Mask RXBUFF Interrupt

class SR(IntEnum):
    RXRDY   = 0x1 << 0    # Receiver Ready
    TXRDY   = 0x1 << 1    # Transmitter Ready
    ENDRX   = 0x1 << 3    # End of Receiver Transfer
    ENDTX   = 0x1 << 4    # End of Transmitter Transfer
    OVRE    = 0x1 << 5    # Overrun Error
    FRAME   = 0x1 << 6    # Framing Error
    PARE    = 0x1 << 7    # Parity Error
    TXEMPTY = 0x1 << 9    # Transmitter Empty
    TXBUFE  = 0x1 << 11   # Transmission Buffer Empty
    RXBUFF  = 0x1 << 12   # Receive Buffer Full

class PTCR(IntEnum):
    RXTEN  = 0x1 << 0   # Receiver Transfer Enable
    RXTDIS = 0x1 << 1   # Receiver Transfer Disable
    TXTEN  = 0x1 << 8   # Transmitter Transfer Enable
    TXTDIS = 0x1 << 9   # Transmitter Transfer Disable

class PTSR(IntEnum):
    RXTEN = 0x1 << 0   # Receiver Transfer Enable
    TXTEN = 0x1 << 8   # Transmitter Transfer Enable
