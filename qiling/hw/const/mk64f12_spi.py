#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class MCR(IntEnum):
    HALT      = 0x1 << 0    # Halt
    SMPL_PT   = 0x3 << 8    # Sample Point
    CLR_RXF   = 0x1 << 10   # Flushes the RX FIFO
    CLR_TXF   = 0x1 << 11   # Clear TX FIFO
    DIS_RXF   = 0x1 << 12   # Disable Receive FIFO
    DIS_TXF   = 0x1 << 13   # Disable Transmit FIFO
    MDIS      = 0x1 << 14   # Module Disable
    DOZE      = 0x1 << 15   # Doze Enable
    PCSIS0    = 0x1 << 16   # Peripheral Chip Select x Inactive State
    PCSIS1    = 0x1 << 17   # Peripheral Chip Select x Inactive State
    PCSIS2    = 0x1 << 18   # Peripheral Chip Select x Inactive State
    PCSIS3    = 0x1 << 19   # Peripheral Chip Select x Inactive State
    PCSIS4    = 0x1 << 20   # Peripheral Chip Select x Inactive State
    PCSIS5    = 0x1 << 21   # Peripheral Chip Select x Inactive State
    ROOE      = 0x1 << 24   # Receive FIFO Overflow Overwrite Enable
    PCSSE     = 0x1 << 25   # Peripheral Chip Select Strobe Enable
    MTFE      = 0x1 << 26   # Modified Timing Format Enable
    FRZ       = 0x1 << 27   # Freeze
    DCONF     = 0x3 << 28   # SPI Configuration.
    CONT_SCKE = 0x1 << 30   # Continuous SCK Enable
    MSTR      = 0x1 << 31   # Master/Slave Mode Select

class CTAR(IntEnum):
    BR     = 0xf << 0    # Baud Rate Scaler
    DT     = 0xf << 4    # Delay After Transfer Scaler
    ASC    = 0xf << 8    # After SCK Delay Scaler
    CSSCK  = 0xf << 12   # PCS to SCK Delay Scaler
    PBR    = 0x3 << 16   # Baud Rate Prescaler
    PDT    = 0x3 << 18   # Delay after Transfer Prescaler
    PASC   = 0x3 << 20   # After SCK Delay Prescaler
    PCSSCK = 0x3 << 22   # PCS to SCK Delay Prescaler
    LSBFE  = 0x1 << 24   # LSB First
    CPHA   = 0x1 << 25   # Clock Phase
    CPOL   = 0x1 << 26   # Clock Polarity
    FMSZ   = 0xf << 27   # Frame Size
    DBR    = 0x1 << 31   # Double Baud Rate

class SR(IntEnum):
    POPNXTPTR = 0xf << 0    # Pop Next Pointer
    RXCTR     = 0xf << 4    # RX FIFO Counter
    TXNXTPTR  = 0xf << 8    # Transmit Next Pointer
    TXCTR     = 0xf << 12   # TX FIFO Counter
    RFDF      = 0x1 << 17   # Receive FIFO Drain Flag
    RFOF      = 0x1 << 19   # Receive FIFO Overflow Flag
    TFFF      = 0x1 << 25   # Transmit FIFO Fill Flag
    TFUF      = 0x1 << 27   # Transmit FIFO Underflow Flag
    EOQF      = 0x1 << 28   # End of Queue Flag
    TXRXS     = 0x1 << 30   # TX and RX Status
    TCF       = 0x1 << 31   # Transfer Complete Flag

class RSER(IntEnum):
    RFDF_DIRS = 0x1 << 16   # Receive FIFO Drain DMA or Interrupt Request Select
    RFDF_RE   = 0x1 << 17   # Receive FIFO Drain Request Enable
    RFOF_RE   = 0x1 << 19   # Receive FIFO Overflow Request Enable
    TFFF_DIRS = 0x1 << 24   # Transmit FIFO Fill DMA or Interrupt Request Select
    TFFF_RE   = 0x1 << 25   # Transmit FIFO Fill Request Enable
    TFUF_RE   = 0x1 << 27   # Transmit FIFO Underflow Request Enable
    EOQF_RE   = 0x1 << 28   # Finished Request Enable
    TCF_RE    = 0x1 << 31   # Transmission Complete Request Enable

class PUSHR(IntEnum):
    TXDATA = 0xffff << 0   # Transmit Data
    PCS0   = 0x1 << 16     # Select which PCS signals are to be asserted for the transfer
    PCS1   = 0x1 << 17     # Select which PCS signals are to be asserted for the transfer
    PCS2   = 0x1 << 18     # Select which PCS signals are to be asserted for the transfer
    PCS3   = 0x1 << 19     # Select which PCS signals are to be asserted for the transfer
    PCS4   = 0x1 << 20     # Select which PCS signals are to be asserted for the transfer
    PCS5   = 0x1 << 21     # Select which PCS signals are to be asserted for the transfer
    CTCNT  = 0x1 << 26     # Clear Transfer Counter
    EOQ    = 0x1 << 27     # End Of Queue
    CTAS   = 0x7 << 28     # Clock and Transfer Attributes Select
    CONT   = 0x1 << 31     # Continuous Peripheral Chip Select Enable

class TXFR(IntEnum):
    TXDATA       = 0xffff << 0    # Transmit Data
    TXCMD_TXDATA = 0xffff << 16   # Transmit Command or Transmit Data
