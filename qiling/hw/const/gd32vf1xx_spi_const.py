#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from enum import IntEnum


class CTL0(IntEnum):
    BDEN    = 0x1 << 15   # Bidirectional enable
    BDOEN   = 0x1 << 14   # Bidirectional Transmit output enable
    CRCEN   = 0x1 << 13   # CRC Calculation Enable
    CRCNT   = 0x1 << 12   # CRC Next Transfer
    FF16    = 0x1 << 11   # Data frame format
    RO      = 0x1 << 10   # Receive only
    SWNSSEN = 0x1 << 9    # NSS Software Mode Selection
    SWNSS   = 0x1 << 8    # NSS Pin Selection In NSS Software Mode
    LF      = 0x1 << 7    # LSB First Mode
    SPIEN   = 0x1 << 6    # SPI enable
    PSC     = 0x7 << 3    # Master Clock Prescaler Selection
    MSTMOD  = 0x1 << 2    # Master Mode Enable
    CKPL    = 0x1 << 1    # Clock polarity Selection
    CKPH    = 0x1 << 0    # Clock Phase Selection

class CTL1(IntEnum):
    TBEIE  = 0x1 << 7   # Tx buffer empty interrupt enable
    RBNEIE = 0x1 << 6   # RX buffer not empty interrupt enable
    ERRIE  = 0x1 << 5   # Error interrupt enable
    TMOD   = 0x1 << 4   # SPI TI mode enable
    NSSP   = 0x1 << 3   # SPI NSS pulse mode enable
    NSSDRV = 0x1 << 2   # Drive NSS Output
    DMATEN = 0x1 << 1   # Transmit Buffer DMA Enable
    DMAREN = 0x1 << 0   # Rx buffer DMA enable

class STAT(IntEnum):
    FERR    = 0x1 << 8   # Format error
    TRANS   = 0x1 << 7   # Transmitting On-going Bit
    RXORERR = 0x1 << 6   # Reception Overrun Error Bit
    CONFERR = 0x1 << 5   # SPI Configuration error
    CRCERR  = 0x1 << 4   # SPI CRC Error Bit
    TXURERR = 0x1 << 3   # Transmission underrun error bit
    I2SCH   = 0x1 << 2   # I2S channel side
    TBE     = 0x1 << 1   # Transmit Buffer Empty
    RBNE    = 0x1 << 0   # Receive Buffer Not Empty

class DATA(IntEnum):
    SPI_DATA = 0xffff << 0   # Data transfer register

class CRCPOLY(IntEnum):
    CRCPOLY = 0xffff << 0   # CRC polynomial value

class RCRC(IntEnum):
    RCRC = 0xffff << 0   # RX CRC value

class TCRC(IntEnum):
    TCRC = 0xffff << 0   # Tx CRC value

class I2SCTL(IntEnum):
    I2SSEL   = 0x1 << 11   # I2S mode selection
    I2SEN    = 0x1 << 10   # I2S Enable
    I2SOPMOD = 0x3 << 8    # I2S operation mode
    PCMSMOD  = 0x1 << 7    # PCM frame synchronization mode
    I2SSTD   = 0x3 << 4    # I2S standard selection
    CKPL     = 0x1 << 3    # Idle state clock polarity
    DTLEN    = 0x3 << 1    # Data length
    CHLEN    = 0x1 << 0    # Channel length (number of bits per audio channel)

class I2SPSC(IntEnum):
    MCKOEN = 0x1 << 9    # I2S_MCK output enable
    OF     = 0x1 << 8    # Odd factor for the prescaler
    DIV    = 0xff << 0   # Dividing factor for the prescaler

