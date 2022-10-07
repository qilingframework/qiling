#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class BDH(IntEnum):
    SBR     = 0x1f << 0   # UART Baud Rate Bits
    SBNS    = 0x1 << 5    # Stop Bit Number Select
    RXEDGIE = 0x1 << 6    # RxD Input Active Edge Interrupt Enable
    LBKDIE  = 0x1 << 7    # LIN Break Detect Interrupt or DMA Request Enable

class C1(IntEnum):
    PT       = 0x1 << 0   # Parity Type
    PE       = 0x1 << 1   # Parity Enable
    ILT      = 0x1 << 2   # Idle Line Type Select
    WAKE     = 0x1 << 3   # Receiver Wakeup Method Select
    M        = 0x1 << 4   # 9-bit or 8-bit Mode Select
    RSRC     = 0x1 << 5   # Receiver Source Select
    UARTSWAI = 0x1 << 6   # UART Stops in Wait Mode
    LOOPS    = 0x1 << 7   # Loop Mode Select

class C2(IntEnum):
    SBK  = 0x1 << 0   # Send Break
    RWU  = 0x1 << 1   # Receiver Wakeup Control
    RE   = 0x1 << 2   # Receiver Enable
    TE   = 0x1 << 3   # Transmitter Enable
    ILIE = 0x1 << 4   # Idle Line Interrupt DMA Transfer Enable
    RIE  = 0x1 << 5   # Receiver Full Interrupt or DMA Transfer Enable
    TCIE = 0x1 << 6   # Transmission Complete Interrupt or DMA Transfer Enable
    TIE  = 0x1 << 7   # Transmitter Interrupt or DMA Transfer Enable.

class S1(IntEnum):
    PF   = 0x1 << 0   # Parity Error Flag
    FE   = 0x1 << 1   # Framing Error Flag
    NF   = 0x1 << 2   # Noise Flag
    OR   = 0x1 << 3   # Receiver Overrun Flag
    IDLE = 0x1 << 4   # Idle Line Flag
    RDRF = 0x1 << 5   # Receive Data Register Full Flag
    TC   = 0x1 << 6   # Transmit Complete Flag
    TDRE = 0x1 << 7   # Transmit Data Register Empty Flag

class S2(IntEnum):
    RAF     = 0x1 << 0   # Receiver Active Flag
    LBKDE   = 0x1 << 1   # LIN Break Detection Enable
    BRK13   = 0x1 << 2   # Break Transmit Character Length
    RWUID   = 0x1 << 3   # Receive Wakeup Idle Detect
    RXINV   = 0x1 << 4   # Receive Data Inversion
    MSBF    = 0x1 << 5   # Most Significant Bit First
    RXEDGIF = 0x1 << 6   # RxD Pin Active Edge Interrupt Flag
    LBKDIF  = 0x1 << 7   # LIN Break Detect Interrupt Flag

class C3(IntEnum):
    PEIE  = 0x1 << 0   # Parity Error Interrupt Enable
    FEIE  = 0x1 << 1   # Framing Error Interrupt Enable
    NEIE  = 0x1 << 2   # Noise Error Interrupt Enable
    ORIE  = 0x1 << 3   # Overrun Error Interrupt Enable
    TXINV = 0x1 << 4   # Transmit Data Inversion.
    TXDIR = 0x1 << 5   # Transmitter Pin Data Direction in Single-Wire mode
    T8    = 0x1 << 6   # Transmit Bit 8
    R8    = 0x1 << 7   # Received Bit 8

class C4(IntEnum):
    BRFA  = 0x1f << 0   # Baud Rate Fine Adjust
    M10   = 0x1 << 5    # 10-bit Mode select
    MAEN2 = 0x1 << 6    # Match Address Mode Enable 2
    MAEN1 = 0x1 << 7    # Match Address Mode Enable 1

class C5(IntEnum):
    LBKDDMAS = 0x1 << 3   # LIN Break Detect DMA Select Bit
    ILDMAS   = 0x1 << 4   # Idle Line DMA Select
    RDMAS    = 0x1 << 5   # Receiver Full DMA Select
    TCDMAS   = 0x1 << 6   # Transmission Complete DMA Select
    TDMAS    = 0x1 << 7   # Transmitter DMA Select

class ED(IntEnum):
    PARITYE = 0x1 << 6   # The current received dataword contained in D and C3[R8] was received with a parity error.
    NOISY   = 0x1 << 7   # The current received dataword contained in D and C3[R8] was received with noise.

class MODEM(IntEnum):
    TXCTSE   = 0x1 << 0   # Transmitter clear-to-send enable
    TXRTSE   = 0x1 << 1   # Transmitter request-to-send enable
    TXRTSPOL = 0x1 << 2   # Transmitter request-to-send polarity
    RXRTSE   = 0x1 << 3   # Receiver request-to-send enable

class IR(IntEnum):
    TNP  = 0x3 << 0   # Transmitter narrow pulse
    IREN = 0x1 << 2   # Infrared enable

class PFIFO(IntEnum):
    RXFIFOSIZE = 0x7 << 0   # Receive FIFO. Buffer Depth
    RXFE       = 0x1 << 3   # Receive FIFO Enable
    TXFIFOSIZE = 0x7 << 4   # Transmit FIFO. Buffer Depth
    TXFE       = 0x1 << 7   # Transmit FIFO Enable

class CFIFO(IntEnum):
    RXUFE   = 0x1 << 0   # Receive FIFO Underflow Interrupt Enable
    TXOFE   = 0x1 << 1   # Transmit FIFO Overflow Interrupt Enable
    RXOFE   = 0x1 << 2   # Receive FIFO Overflow Interrupt Enable
    RXFLUSH = 0x1 << 6   # Receive FIFO/Buffer Flush
    TXFLUSH = 0x1 << 7   # Transmit FIFO/Buffer Flush

class SFIFO(IntEnum):
    RXUF   = 0x1 << 0   # Receiver Buffer Underflow Flag
    TXOF   = 0x1 << 1   # Transmitter Buffer Overflow Flag
    RXOF   = 0x1 << 2   # Receiver Buffer Overflow Flag
    RXEMPT = 0x1 << 6   # Receive Buffer/FIFO Empty
    TXEMPT = 0x1 << 7   # Transmit Buffer/FIFO Empty

class C7816(IntEnum):
    ISO_7816E = 0x1 << 0   # ISO-7816 Functionality Enabled
    TTYPE     = 0x1 << 1   # Transfer Type
    INIT      = 0x1 << 2   # Detect Initial Character
    ANACK     = 0x1 << 3   # Generate NACK on Error
    ONACK     = 0x1 << 4   # Generate NACK on Overflow

class IE7816(IntEnum):
    RXTE   = 0x1 << 0   # Receive Threshold Exceeded Interrupt Enable
    TXTE   = 0x1 << 1   # Transmit Threshold Exceeded Interrupt Enable
    GTVE   = 0x1 << 2   # Guard Timer Violated Interrupt Enable
    INITDE = 0x1 << 4   # Initial Character Detected Interrupt Enable
    BWTE   = 0x1 << 5   # Block Wait Timer Interrupt Enable
    CWTE   = 0x1 << 6   # Character Wait Timer Interrupt Enable
    WTE    = 0x1 << 7   # Wait Timer Interrupt Enable

class IS7816(IntEnum):
    RXT   = 0x1 << 0   # Receive Threshold Exceeded Interrupt
    TXT   = 0x1 << 1   # Transmit Threshold Exceeded Interrupt
    GTV   = 0x1 << 2   # Guard Timer Violated Interrupt
    INITD = 0x1 << 4   # Initial Character Detected Interrupt
    BWT   = 0x1 << 5   # Block Wait Timer Interrupt
    CWT   = 0x1 << 6   # Character Wait Timer Interrupt
    WT    = 0x1 << 7   # Wait Timer Interrupt

class WP7816T1(IntEnum):
    BWI = 0xf << 0   # Block Wait Time Integer(C7816[TTYPE] = 1)
    CWI = 0xf << 4   # Character Wait Time Integer (C7816[TTYPE] = 1)

class ET7816(IntEnum):
    RXTHRESHOLD = 0xf << 0   # Receive NACK Threshold
    TXTHRESHOLD = 0xf << 4   # Transmit NACK Threshold
