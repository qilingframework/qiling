#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class CR(IntEnum):
    SWRST = 0x1 << 0   # Software Reset
    START = 0x1 << 1   # Start Conversion

class MR(IntEnum):
    TRGEN    = 0x1 << 0    # Trigger Enable
    TRGSEL   = 0x7 << 1    # Trigger Selection
    LOWRES   = 0x1 << 4    # Resolution
    SLEEP    = 0x1 << 5    # Sleep Mode
    FWUP     = 0x1 << 6    # Fast Wake Up
    FREERUN  = 0x1 << 7    # Free Run Mode
    PRESCAL  = 0xff << 8   # Prescaler Rate Selection
    STARTUP  = 0xf << 16   # Start Up Time
    SETTLING = 0x3 << 20   # Analog Settling Time
    ANACH    = 0x1 << 23   # Analog Change
    TRACKTIM = 0xf << 24   # Tracking Time
    TRANSFER = 0x3 << 28   # Transfer Period
    USEQ     = 0x1 << 31   # Use Sequence Enable

class SEQR1(IntEnum):
    USCH1 = 0xf << 0    # User Sequence Number 1
    USCH2 = 0xf << 4    # User Sequence Number 2
    USCH3 = 0xf << 8    # User Sequence Number 3
    USCH4 = 0xf << 12   # User Sequence Number 4
    USCH5 = 0xf << 16   # User Sequence Number 5
    USCH6 = 0xf << 20   # User Sequence Number 6
    USCH7 = 0xf << 24   # User Sequence Number 7
    USCH8 = 0xf << 28   # User Sequence Number 8

class SEQR2(IntEnum):
    USCH9  = 0xf << 0    # User Sequence Number 9
    USCH10 = 0xf << 4    # User Sequence Number 10
    USCH11 = 0xf << 8    # User Sequence Number 11
    USCH12 = 0xf << 12   # User Sequence Number 12
    USCH13 = 0xf << 16   # User Sequence Number 13
    USCH14 = 0xf << 20   # User Sequence Number 14
    USCH15 = 0xf << 24   # User Sequence Number 15
    USCH16 = 0xf << 28   # User Sequence Number 16

class CHER(IntEnum):
    CH0  = 0x1 << 0    # Channel 0 Enable
    CH1  = 0x1 << 1    # Channel 1 Enable
    CH2  = 0x1 << 2    # Channel 2 Enable
    CH3  = 0x1 << 3    # Channel 3 Enable
    CH4  = 0x1 << 4    # Channel 4 Enable
    CH5  = 0x1 << 5    # Channel 5 Enable
    CH6  = 0x1 << 6    # Channel 6 Enable
    CH7  = 0x1 << 7    # Channel 7 Enable
    CH8  = 0x1 << 8    # Channel 8 Enable
    CH9  = 0x1 << 9    # Channel 9 Enable
    CH10 = 0x1 << 10   # Channel 10 Enable
    CH11 = 0x1 << 11   # Channel 11 Enable
    CH12 = 0x1 << 12   # Channel 12 Enable
    CH13 = 0x1 << 13   # Channel 13 Enable
    CH14 = 0x1 << 14   # Channel 14 Enable
    CH15 = 0x1 << 15   # Channel 15 Enable

class CHDR(IntEnum):
    CH0  = 0x1 << 0    # Channel 0 Disable
    CH1  = 0x1 << 1    # Channel 1 Disable
    CH2  = 0x1 << 2    # Channel 2 Disable
    CH3  = 0x1 << 3    # Channel 3 Disable
    CH4  = 0x1 << 4    # Channel 4 Disable
    CH5  = 0x1 << 5    # Channel 5 Disable
    CH6  = 0x1 << 6    # Channel 6 Disable
    CH7  = 0x1 << 7    # Channel 7 Disable
    CH8  = 0x1 << 8    # Channel 8 Disable
    CH9  = 0x1 << 9    # Channel 9 Disable
    CH10 = 0x1 << 10   # Channel 10 Disable
    CH11 = 0x1 << 11   # Channel 11 Disable
    CH12 = 0x1 << 12   # Channel 12 Disable
    CH13 = 0x1 << 13   # Channel 13 Disable
    CH14 = 0x1 << 14   # Channel 14 Disable
    CH15 = 0x1 << 15   # Channel 15 Disable

class CHSR(IntEnum):
    CH0  = 0x1 << 0    # Channel 0 Status
    CH1  = 0x1 << 1    # Channel 1 Status
    CH2  = 0x1 << 2    # Channel 2 Status
    CH3  = 0x1 << 3    # Channel 3 Status
    CH4  = 0x1 << 4    # Channel 4 Status
    CH5  = 0x1 << 5    # Channel 5 Status
    CH6  = 0x1 << 6    # Channel 6 Status
    CH7  = 0x1 << 7    # Channel 7 Status
    CH8  = 0x1 << 8    # Channel 8 Status
    CH9  = 0x1 << 9    # Channel 9 Status
    CH10 = 0x1 << 10   # Channel 10 Status
    CH11 = 0x1 << 11   # Channel 11 Status
    CH12 = 0x1 << 12   # Channel 12 Status
    CH13 = 0x1 << 13   # Channel 13 Status
    CH14 = 0x1 << 14   # Channel 14 Status
    CH15 = 0x1 << 15   # Channel 15 Status

class LCDR(IntEnum):
    LDATA = 0xfff << 0   # Last Data Converted
    CHNB  = 0xf << 12    # Channel Number

class IER(IntEnum):
    EOC0   = 0x1 << 0    # End of Conversion Interrupt Enable 0
    EOC1   = 0x1 << 1    # End of Conversion Interrupt Enable 1
    EOC2   = 0x1 << 2    # End of Conversion Interrupt Enable 2
    EOC3   = 0x1 << 3    # End of Conversion Interrupt Enable 3
    EOC4   = 0x1 << 4    # End of Conversion Interrupt Enable 4
    EOC5   = 0x1 << 5    # End of Conversion Interrupt Enable 5
    EOC6   = 0x1 << 6    # End of Conversion Interrupt Enable 6
    EOC7   = 0x1 << 7    # End of Conversion Interrupt Enable 7
    EOC8   = 0x1 << 8    # End of Conversion Interrupt Enable 8
    EOC9   = 0x1 << 9    # End of Conversion Interrupt Enable 9
    EOC10  = 0x1 << 10   # End of Conversion Interrupt Enable 10
    EOC11  = 0x1 << 11   # End of Conversion Interrupt Enable 11
    EOC12  = 0x1 << 12   # End of Conversion Interrupt Enable 12
    EOC13  = 0x1 << 13   # End of Conversion Interrupt Enable 13
    EOC14  = 0x1 << 14   # End of Conversion Interrupt Enable 14
    EOC15  = 0x1 << 15   # End of Conversion Interrupt Enable 15
    DRDY   = 0x1 << 24   # Data Ready Interrupt Enable
    GOVRE  = 0x1 << 25   # General Overrun Error Interrupt Enable
    COMPE  = 0x1 << 26   # Comparison Event Interrupt Enable
    ENDRX  = 0x1 << 27   # End of Receive Buffer Interrupt Enable
    RXBUFF = 0x1 << 28   # Receive Buffer Full Interrupt Enable

class IDR(IntEnum):
    EOC0   = 0x1 << 0    # End of Conversion Interrupt Disable 0
    EOC1   = 0x1 << 1    # End of Conversion Interrupt Disable 1
    EOC2   = 0x1 << 2    # End of Conversion Interrupt Disable 2
    EOC3   = 0x1 << 3    # End of Conversion Interrupt Disable 3
    EOC4   = 0x1 << 4    # End of Conversion Interrupt Disable 4
    EOC5   = 0x1 << 5    # End of Conversion Interrupt Disable 5
    EOC6   = 0x1 << 6    # End of Conversion Interrupt Disable 6
    EOC7   = 0x1 << 7    # End of Conversion Interrupt Disable 7
    EOC8   = 0x1 << 8    # End of Conversion Interrupt Disable 8
    EOC9   = 0x1 << 9    # End of Conversion Interrupt Disable 9
    EOC10  = 0x1 << 10   # End of Conversion Interrupt Disable 10
    EOC11  = 0x1 << 11   # End of Conversion Interrupt Disable 11
    EOC12  = 0x1 << 12   # End of Conversion Interrupt Disable 12
    EOC13  = 0x1 << 13   # End of Conversion Interrupt Disable 13
    EOC14  = 0x1 << 14   # End of Conversion Interrupt Disable 14
    EOC15  = 0x1 << 15   # End of Conversion Interrupt Disable 15
    DRDY   = 0x1 << 24   # Data Ready Interrupt Disable
    GOVRE  = 0x1 << 25   # General Overrun Error Interrupt Disable
    COMPE  = 0x1 << 26   # Comparison Event Interrupt Disable
    ENDRX  = 0x1 << 27   # End of Receive Buffer Interrupt Disable
    RXBUFF = 0x1 << 28   # Receive Buffer Full Interrupt Disable

class IMR(IntEnum):
    EOC0   = 0x1 << 0    # End of Conversion Interrupt Mask 0
    EOC1   = 0x1 << 1    # End of Conversion Interrupt Mask 1
    EOC2   = 0x1 << 2    # End of Conversion Interrupt Mask 2
    EOC3   = 0x1 << 3    # End of Conversion Interrupt Mask 3
    EOC4   = 0x1 << 4    # End of Conversion Interrupt Mask 4
    EOC5   = 0x1 << 5    # End of Conversion Interrupt Mask 5
    EOC6   = 0x1 << 6    # End of Conversion Interrupt Mask 6
    EOC7   = 0x1 << 7    # End of Conversion Interrupt Mask 7
    EOC8   = 0x1 << 8    # End of Conversion Interrupt Mask 8
    EOC9   = 0x1 << 9    # End of Conversion Interrupt Mask 9
    EOC10  = 0x1 << 10   # End of Conversion Interrupt Mask 10
    EOC11  = 0x1 << 11   # End of Conversion Interrupt Mask 11
    EOC12  = 0x1 << 12   # End of Conversion Interrupt Mask 12
    EOC13  = 0x1 << 13   # End of Conversion Interrupt Mask 13
    EOC14  = 0x1 << 14   # End of Conversion Interrupt Mask 14
    EOC15  = 0x1 << 15   # End of Conversion Interrupt Mask 15
    DRDY   = 0x1 << 24   # Data Ready Interrupt Mask
    GOVRE  = 0x1 << 25   # General Overrun Error Interrupt Mask
    COMPE  = 0x1 << 26   # Comparison Event Interrupt Mask
    ENDRX  = 0x1 << 27   # End of Receive Buffer Interrupt Mask
    RXBUFF = 0x1 << 28   # Receive Buffer Full Interrupt Mask

class ISR(IntEnum):
    EOC0   = 0x1 << 0    # End of Conversion 0
    EOC1   = 0x1 << 1    # End of Conversion 1
    EOC2   = 0x1 << 2    # End of Conversion 2
    EOC3   = 0x1 << 3    # End of Conversion 3
    EOC4   = 0x1 << 4    # End of Conversion 4
    EOC5   = 0x1 << 5    # End of Conversion 5
    EOC6   = 0x1 << 6    # End of Conversion 6
    EOC7   = 0x1 << 7    # End of Conversion 7
    EOC8   = 0x1 << 8    # End of Conversion 8
    EOC9   = 0x1 << 9    # End of Conversion 9
    EOC10  = 0x1 << 10   # End of Conversion 10
    EOC11  = 0x1 << 11   # End of Conversion 11
    EOC12  = 0x1 << 12   # End of Conversion 12
    EOC13  = 0x1 << 13   # End of Conversion 13
    EOC14  = 0x1 << 14   # End of Conversion 14
    EOC15  = 0x1 << 15   # End of Conversion 15
    DRDY   = 0x1 << 24   # Data Ready
    GOVRE  = 0x1 << 25   # General Overrun Error
    COMPE  = 0x1 << 26   # Comparison Error
    ENDRX  = 0x1 << 27   # End of RX Buffer
    RXBUFF = 0x1 << 28   # RX Buffer Full

class OVER(IntEnum):
    OVRE0  = 0x1 << 0    # Overrun Error 0
    OVRE1  = 0x1 << 1    # Overrun Error 1
    OVRE2  = 0x1 << 2    # Overrun Error 2
    OVRE3  = 0x1 << 3    # Overrun Error 3
    OVRE4  = 0x1 << 4    # Overrun Error 4
    OVRE5  = 0x1 << 5    # Overrun Error 5
    OVRE6  = 0x1 << 6    # Overrun Error 6
    OVRE7  = 0x1 << 7    # Overrun Error 7
    OVRE8  = 0x1 << 8    # Overrun Error 8
    OVRE9  = 0x1 << 9    # Overrun Error 9
    OVRE10 = 0x1 << 10   # Overrun Error 10
    OVRE11 = 0x1 << 11   # Overrun Error 11
    OVRE12 = 0x1 << 12   # Overrun Error 12
    OVRE13 = 0x1 << 13   # Overrun Error 13
    OVRE14 = 0x1 << 14   # Overrun Error 14
    OVRE15 = 0x1 << 15   # Overrun Error 15

class EMR(IntEnum):
    CMPMODE   = 0x3 << 0    # Comparison Mode
    CMPSEL    = 0xf << 4    # Comparison Selected Channel
    CMPALL    = 0x1 << 9    # Compare All Channels
    CMPFILTER = 0x3 << 12   # Compare Event Filtering
    TAG       = 0x1 << 24   # TAG of ADC_LDCR register

class CWR(IntEnum):
    LOWTHRES  = 0xfff << 0    # Low Threshold
    HIGHTHRES = 0xfff << 16   # High Threshold

class CGR(IntEnum):
    GAIN0  = 0x3 << 0    # Gain for channel 0
    GAIN1  = 0x3 << 2    # Gain for channel 1
    GAIN2  = 0x3 << 4    # Gain for channel 2
    GAIN3  = 0x3 << 6    # Gain for channel 3
    GAIN4  = 0x3 << 8    # Gain for channel 4
    GAIN5  = 0x3 << 10   # Gain for channel 5
    GAIN6  = 0x3 << 12   # Gain for channel 6
    GAIN7  = 0x3 << 14   # Gain for channel 7
    GAIN8  = 0x3 << 16   # Gain for channel 8
    GAIN9  = 0x3 << 18   # Gain for channel 9
    GAIN10 = 0x3 << 20   # Gain for channel 10
    GAIN11 = 0x3 << 22   # Gain for channel 11
    GAIN12 = 0x3 << 24   # Gain for channel 12
    GAIN13 = 0x3 << 26   # Gain for channel 13
    GAIN14 = 0x3 << 28   # Gain for channel 14
    GAIN15 = 0x3 << 30   # Gain for channel 15

class COR(IntEnum):
    OFF0   = 0x1 << 0    # Offset for channel 0
    OFF1   = 0x1 << 1    # Offset for channel 1
    OFF2   = 0x1 << 2    # Offset for channel 2
    OFF3   = 0x1 << 3    # Offset for channel 3
    OFF4   = 0x1 << 4    # Offset for channel 4
    OFF5   = 0x1 << 5    # Offset for channel 5
    OFF6   = 0x1 << 6    # Offset for channel 6
    OFF7   = 0x1 << 7    # Offset for channel 7
    OFF8   = 0x1 << 8    # Offset for channel 8
    OFF9   = 0x1 << 9    # Offset for channel 9
    OFF10  = 0x1 << 10   # Offset for channel 10
    OFF11  = 0x1 << 11   # Offset for channel 11
    OFF12  = 0x1 << 12   # Offset for channel 12
    OFF13  = 0x1 << 13   # Offset for channel 13
    OFF14  = 0x1 << 14   # Offset for channel 14
    OFF15  = 0x1 << 15   # Offset for channel 15
    DIFF0  = 0x1 << 16   # Differential inputs for channel 0
    DIFF1  = 0x1 << 17   # Differential inputs for channel 1
    DIFF2  = 0x1 << 18   # Differential inputs for channel 2
    DIFF3  = 0x1 << 19   # Differential inputs for channel 3
    DIFF4  = 0x1 << 20   # Differential inputs for channel 4
    DIFF5  = 0x1 << 21   # Differential inputs for channel 5
    DIFF6  = 0x1 << 22   # Differential inputs for channel 6
    DIFF7  = 0x1 << 23   # Differential inputs for channel 7
    DIFF8  = 0x1 << 24   # Differential inputs for channel 8
    DIFF9  = 0x1 << 25   # Differential inputs for channel 9
    DIFF10 = 0x1 << 26   # Differential inputs for channel 10
    DIFF11 = 0x1 << 27   # Differential inputs for channel 11
    DIFF12 = 0x1 << 28   # Differential inputs for channel 12
    DIFF13 = 0x1 << 29   # Differential inputs for channel 13
    DIFF14 = 0x1 << 30   # Differential inputs for channel 14
    DIFF15 = 0x1 << 31   # Differential inputs for channel 15

class CDR(IntEnum):
    DATA = 0xfff << 0   # Converted Data

class ACR(IntEnum):
    TSON  = 0x1 << 4   # Temperature Sensor On
    IBCTL = 0x3 << 8   # ADC Bias Current Control

class WPMR(IntEnum):
    WPEN  = 0x1 << 0        # Write Protect Enable
    WPKEY = 0xffffff << 8   # Write Protect KEY

class WPSR(IntEnum):
    WPVS   = 0x1 << 0      # Write Protect Violation Status
    WPVSRC = 0xffff << 8   # Write Protect Violation Source

class RPR(IntEnum):
    RXPTR = 0xffffffff << 0   # Receive Pointer Register

class RCR(IntEnum):
    RXCTR = 0xffff << 0   # Receive Counter Register

class RNPR(IntEnum):
    RXNPTR = 0xffffffff << 0   # Receive Next Pointer

class RNCR(IntEnum):
    RXNCTR = 0xffff << 0   # Receive Next Counter

class PTCR(IntEnum):
    RXTEN  = 0x1 << 0   # Receiver Transfer Enable
    RXTDIS = 0x1 << 1   # Receiver Transfer Disable
    TXTEN  = 0x1 << 8   # Transmitter Transfer Enable
    TXTDIS = 0x1 << 9   # Transmitter Transfer Disable

class PTSR(IntEnum):
    RXTEN = 0x1 << 0   # Receiver Transfer Enable
    TXTEN = 0x1 << 8   # Transmitter Transfer Enable
