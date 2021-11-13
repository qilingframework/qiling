#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from enum import IntEnum


class CTL0(IntEnum):
    SRESET   = 0x1 << 15   # Software reset
    SALT     = 0x1 << 13   # SMBus alert
    PECTRANS = 0x1 << 12   # PEC Transfer
    POAP     = 0x1 << 11   # Position of ACK and PEC when receiving
    ACKEN    = 0x1 << 10   # Whether or not to send an ACK
    STOP     = 0x1 << 9    # Generate a STOP condition on I2C bus
    START    = 0x1 << 8    # Generate a START condition on I2C bus
    SS       = 0x1 << 7    # Whether to stretch SCL low when data is not ready in slave mode
    GCEN     = 0x1 << 6    # Whether or not to response to a General Call (0x00)
    PECEN    = 0x1 << 5    # PEC Calculation Switch
    ARPEN    = 0x1 << 4    # ARP protocol in SMBus switch
    SMBSEL   = 0x1 << 3    # SMBusType Selection
    SMBEN    = 0x1 << 1    # SMBus/I2C mode switch
    I2CEN    = 0x1 << 0    # I2C peripheral enable

class CTL1(IntEnum):
    DMALST = 0x1 << 12   # Flag indicating DMA last transfer
    DMAON  = 0x1 << 11   # DMA mode switch
    BUFIE  = 0x1 << 10   # Buffer interrupt enable
    EVIE   = 0x1 << 9    # Event interrupt enable
    ERRIE  = 0x1 << 8    # Error interrupt enable
    I2CCLK = 0x3f << 0   # I2C Peripheral clock frequency

class SADDR0(IntEnum):
    ADDFORMAT  = 0x1 << 15   # Address mode for the I2C slave
    ADDRESS9_8 = 0x3 << 8    # Highest two bits of a 10-bit address
    ADDRESS7_1 = 0x7f << 1   # 7-bit address or bits 7:1 of a 10-bit address
    ADDRESS0   = 0x1 << 0    # Bit 0 of a 10-bit address

class SADDR1(IntEnum):
    ADDRESS2 = 0x7f << 1   # Second I2C address for the slave in Dual-Address mode
    DUADEN   = 0x1 << 0    # Dual-Address mode switch

class DATA(IntEnum):
    TRB = 0xff << 0   # Transmission or reception data buffer register

class STAT0(IntEnum):
    SMBALT    = 0x1 << 15   # SMBus Alert status
    SMBTO     = 0x1 << 14   # Timeout signal in SMBus mode
    PECERR    = 0x1 << 12   # PEC error when receiving data
    OUERR     = 0x1 << 11   # Over-run or under-run situation occurs in slave mode
    AERR      = 0x1 << 10   # Acknowledge error
    LOSTARB   = 0x1 << 9    # Arbitration Lost in master mode
    BERR      = 0x1 << 8    # A bus error occurs indication a unexpected START or STOP condition on I2C bus
    TBE       = 0x1 << 7    # I2C_DATA is Empty during transmitting
    RBNE      = 0x1 << 6    # I2C_DATA is not Empty during receiving
    STPDET    = 0x1 << 4    # STOP condition detected in slave mode
    ADD10SEND = 0x1 << 3    # Header of 10-bit address is sent in master mode
    BTC       = 0x1 << 2    # Byte transmission completed
    ADDSEND   = 0x1 << 1    # Address is sent in master mode or received and matches in slave mode
    SBSEND    = 0x1 << 0    # START condition sent out in master mode

class STAT1(IntEnum):
    PECV   = 0xff << 8   # Packet Error Checking Value that calculated by hardware when PEC is enabled
    DUMODF = 0x1 << 7    # Dual Flag in slave mode
    HSTSMB = 0x1 << 6    # SMBus Host Header detected in slave mode
    DEFSMB = 0x1 << 5    # Default address of SMBusDevice
    RXGC   = 0x1 << 4    # General call address (00h) received
    TR     = 0x1 << 2    # Whether the I2C is a transmitter or a receiver
    I2CBSY = 0x1 << 1    # Busy flag
    MASTER = 0x1 << 0    # A flag indicating whether I2C block is in master or slave mode

class CKCFG(IntEnum):
    FAST = 0x1 << 15    # I2C speed selection in master mode
    DTCY = 0x1 << 14    # Duty cycle in fast mode
    CLKC = 0xfff << 0   # I2C Clock control in master mode

class RT(IntEnum):
    RISETIME = 0x3f << 0   # Maximum rise time in master mode

