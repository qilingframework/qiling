#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from enum import IntEnum


class STAT(IntEnum):
    CTSF  = 0x1 << 9   # CTS change flag
    LBDF  = 0x1 << 8   # LIN break detection flag
    TBE   = 0x1 << 7   # Transmit data buffer empty
    TC    = 0x1 << 6   # Transmission complete
    RBNE  = 0x1 << 5   # Read data buffer not empty
    IDLEF = 0x1 << 4   # IDLE frame detected flag
    ORERR = 0x1 << 3   # Overrun error
    NERR  = 0x1 << 2   # Noise error flag
    FERR  = 0x1 << 1   # Frame error flag
    PERR  = 0x1 << 0   # Parity error flag

class DATA(IntEnum):
    DATA = 0x1ff << 0   # Transmit or read data value

class BAUD(IntEnum):
    INTDIV = 0xfff << 4   # Integer part of baud-rate divider
    FRADIV = 0xf << 0     # Fraction part of baud-rate divider

class CTL0(IntEnum):
    UEN    = 0x1 << 13   # USART enable
    WL     = 0x1 << 12   # Word length
    WM     = 0x1 << 11   # Wakeup method in mute mode
    PCEN   = 0x1 << 10   # Parity check function enable
    PM     = 0x1 << 9    # Parity mode
    PERRIE = 0x1 << 8    # Parity error interrupt enable
    TBEIE  = 0x1 << 7    # Transmitter buffer empty interrupt enable
    TCIE   = 0x1 << 6    # Transmission complete interrupt enable
    RBNEIE = 0x1 << 5    # Read data buffer not empty interrupt and overrun error interrupt enable
    IDLEIE = 0x1 << 4    # IDLE line detected interrupt enable
    TEN    = 0x1 << 3    # Transmitter enable
    REN    = 0x1 << 2    # Receiver enable
    RWU    = 0x1 << 1    # Receiver wakeup from mute mode
    SBKCMD = 0x1 << 0    # Send break command

class CTL1(IntEnum):
    LMEN  = 0x1 << 14   # LIN mode enable
    STB   = 0x3 << 12   # STOP bits length
    CKEN  = 0x1 << 11   # CK pin enable
    CPL   = 0x1 << 10   # Clock polarity
    CPH   = 0x1 << 9    # Clock phase
    CLEN  = 0x1 << 8    # CK Length
    LBDIE = 0x1 << 6    # LIN break detection interrupt enable
    LBLEN = 0x1 << 5    # LIN break frame length
    ADDR  = 0xf << 0    # Address of the USART

class CTL2(IntEnum):
    CTSIE = 0x1 << 10   # CTS interrupt enable
    CTSEN = 0x1 << 9    # CTS enable
    RTSEN = 0x1 << 8    # RTS enable
    DENT  = 0x1 << 7    # DMA request enable for transmission
    DENR  = 0x1 << 6    # DMA request enable for reception
    SCEN  = 0x1 << 5    # Smartcard mode enable
    NKEN  = 0x1 << 4    # Smartcard NACK enable
    HDEN  = 0x1 << 3    # Half-duplex selection
    IRLP  = 0x1 << 2    # IrDA low-power
    IREN  = 0x1 << 1    # IrDA mode enable
    ERRIE = 0x1 << 0    # Error interrupt enable

class GP(IntEnum):
    GUAT = 0xff << 8   # Guard time value in Smartcard mode
    PSC  = 0xff << 0   # Prescaler value

