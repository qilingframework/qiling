#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class DEVCTRL(IntEnum):
    UADD    = 0x7f << 0   # USB Address
    ADDEN   = 0x1 << 7    # Address Enable
    DETACH  = 0x1 << 8    # Detach
    RMWKUP  = 0x1 << 9    # Remote Wake-Up
    SPDCONF = 0x3 << 10   # Mode Configuration
    LS      = 0x1 << 12   # Low-Speed Mode Force
    TSTJ    = 0x1 << 13   # Test mode J
    TSTK    = 0x1 << 14   # Test mode K
    TSTPCKT = 0x1 << 15   # Test packet mode
    OPMODE2 = 0x1 << 16   # Specific Operational mode

class DEVISR(IntEnum):
    SUSP   = 0x1 << 0    # Suspend Interrupt
    MSOF   = 0x1 << 1    # Micro Start of Frame Interrupt
    SOF    = 0x1 << 2    # Start of Frame Interrupt
    EORST  = 0x1 << 3    # End of Reset Interrupt
    WAKEUP = 0x1 << 4    # Wake-Up Interrupt
    EORSM  = 0x1 << 5    # End of Resume Interrupt
    UPRSM  = 0x1 << 6    # Upstream Resume Interrupt
    PEP_0  = 0x1 << 12   # Endpoint 0 Interrupt
    PEP_1  = 0x1 << 13   # Endpoint 1 Interrupt
    PEP_2  = 0x1 << 14   # Endpoint 2 Interrupt
    PEP_3  = 0x1 << 15   # Endpoint 3 Interrupt
    PEP_4  = 0x1 << 16   # Endpoint 4 Interrupt
    PEP_5  = 0x1 << 17   # Endpoint 5 Interrupt
    PEP_6  = 0x1 << 18   # Endpoint 6 Interrupt
    PEP_7  = 0x1 << 19   # Endpoint 7 Interrupt
    PEP_8  = 0x1 << 20   # Endpoint 8 Interrupt
    PEP_9  = 0x1 << 21   # Endpoint 9 Interrupt
    DMA_1  = 0x1 << 25   # DMA Channel 1 Interrupt
    DMA_2  = 0x1 << 26   # DMA Channel 2 Interrupt
    DMA_3  = 0x1 << 27   # DMA Channel 3 Interrupt
    DMA_4  = 0x1 << 28   # DMA Channel 4 Interrupt
    DMA_5  = 0x1 << 29   # DMA Channel 5 Interrupt
    DMA_6  = 0x1 << 30   # DMA Channel 6 Interrupt

class DEVICR(IntEnum):
    SUSPC   = 0x1 << 0   # Suspend Interrupt Clear
    MSOFC   = 0x1 << 1   # Micro Start of Frame Interrupt Clear
    SOFC    = 0x1 << 2   # Start of Frame Interrupt Clear
    EORSTC  = 0x1 << 3   # End of Reset Interrupt Clear
    WAKEUPC = 0x1 << 4   # Wake-Up Interrupt Clear
    EORSMC  = 0x1 << 5   # End of Resume Interrupt Clear
    UPRSMC  = 0x1 << 6   # Upstream Resume Interrupt Clear

class DEVIFR(IntEnum):
    SUSPS   = 0x1 << 0    # Suspend Interrupt Set
    MSOFS   = 0x1 << 1    # Micro Start of Frame Interrupt Set
    SOFS    = 0x1 << 2    # Start of Frame Interrupt Set
    EORSTS  = 0x1 << 3    # End of Reset Interrupt Set
    WAKEUPS = 0x1 << 4    # Wake-Up Interrupt Set
    EORSMS  = 0x1 << 5    # End of Resume Interrupt Set
    UPRSMS  = 0x1 << 6    # Upstream Resume Interrupt Set
    DMA_1   = 0x1 << 25   # DMA Channel 1 Interrupt Set
    DMA_2   = 0x1 << 26   # DMA Channel 2 Interrupt Set
    DMA_3   = 0x1 << 27   # DMA Channel 3 Interrupt Set
    DMA_4   = 0x1 << 28   # DMA Channel 4 Interrupt Set
    DMA_5   = 0x1 << 29   # DMA Channel 5 Interrupt Set
    DMA_6   = 0x1 << 30   # DMA Channel 6 Interrupt Set

class DEVIMR(IntEnum):
    SUSPE   = 0x1 << 0    # Suspend Interrupt Mask
    MSOFE   = 0x1 << 1    # Micro Start of Frame Interrupt Mask
    SOFE    = 0x1 << 2    # Start of Frame Interrupt Mask
    EORSTE  = 0x1 << 3    # End of Reset Interrupt Mask
    WAKEUPE = 0x1 << 4    # Wake-Up Interrupt Mask
    EORSME  = 0x1 << 5    # End of Resume Interrupt Mask
    UPRSME  = 0x1 << 6    # Upstream Resume Interrupt Mask
    PEP_0   = 0x1 << 12   # Endpoint 0 Interrupt Mask
    PEP_1   = 0x1 << 13   # Endpoint 1 Interrupt Mask
    PEP_2   = 0x1 << 14   # Endpoint 2 Interrupt Mask
    PEP_3   = 0x1 << 15   # Endpoint 3 Interrupt Mask
    PEP_4   = 0x1 << 16   # Endpoint 4 Interrupt Mask
    PEP_5   = 0x1 << 17   # Endpoint 5 Interrupt Mask
    PEP_6   = 0x1 << 18   # Endpoint 6 Interrupt Mask
    PEP_7   = 0x1 << 19   # Endpoint 7 Interrupt Mask
    PEP_8   = 0x1 << 20   # Endpoint 8 Interrupt Mask
    PEP_9   = 0x1 << 21   # Endpoint 9 Interrupt Mask
    DMA_1   = 0x1 << 25   # DMA Channel 1 Interrupt Mask
    DMA_2   = 0x1 << 26   # DMA Channel 2 Interrupt Mask
    DMA_3   = 0x1 << 27   # DMA Channel 3 Interrupt Mask
    DMA_4   = 0x1 << 28   # DMA Channel 4 Interrupt Mask
    DMA_5   = 0x1 << 29   # DMA Channel 5 Interrupt Mask
    DMA_6   = 0x1 << 30   # DMA Channel 6 Interrupt Mask

class DEVIDR(IntEnum):
    SUSPEC   = 0x1 << 0    # Suspend Interrupt Disable
    MSOFEC   = 0x1 << 1    # Micro Start of Frame Interrupt Disable
    SOFEC    = 0x1 << 2    # Start of Frame Interrupt Disable
    EORSTEC  = 0x1 << 3    # End of Reset Interrupt Disable
    WAKEUPEC = 0x1 << 4    # Wake-Up Interrupt Disable
    EORSMEC  = 0x1 << 5    # End of Resume Interrupt Disable
    UPRSMEC  = 0x1 << 6    # Upstream Resume Interrupt Disable
    PEP_0    = 0x1 << 12   # Endpoint 0 Interrupt Disable
    PEP_1    = 0x1 << 13   # Endpoint 1 Interrupt Disable
    PEP_2    = 0x1 << 14   # Endpoint 2 Interrupt Disable
    PEP_3    = 0x1 << 15   # Endpoint 3 Interrupt Disable
    PEP_4    = 0x1 << 16   # Endpoint 4 Interrupt Disable
    PEP_5    = 0x1 << 17   # Endpoint 5 Interrupt Disable
    PEP_6    = 0x1 << 18   # Endpoint 6 Interrupt Disable
    PEP_7    = 0x1 << 19   # Endpoint 7 Interrupt Disable
    PEP_8    = 0x1 << 20   # Endpoint 8 Interrupt Disable
    PEP_9    = 0x1 << 21   # Endpoint 9 Interrupt Disable
    DMA_1    = 0x1 << 25   # DMA Channel 1 Interrupt Disable
    DMA_2    = 0x1 << 26   # DMA Channel 2 Interrupt Disable
    DMA_3    = 0x1 << 27   # DMA Channel 3 Interrupt Disable
    DMA_4    = 0x1 << 28   # DMA Channel 4 Interrupt Disable
    DMA_5    = 0x1 << 29   # DMA Channel 5 Interrupt Disable
    DMA_6    = 0x1 << 30   # DMA Channel 6 Interrupt Disable

class DEVIER(IntEnum):
    SUSPES   = 0x1 << 0    # Suspend Interrupt Enable
    MSOFES   = 0x1 << 1    # Micro Start of Frame Interrupt Enable
    SOFES    = 0x1 << 2    # Start of Frame Interrupt Enable
    EORSTES  = 0x1 << 3    # End of Reset Interrupt Enable
    WAKEUPES = 0x1 << 4    # Wake-Up Interrupt Enable
    EORSMES  = 0x1 << 5    # End of Resume Interrupt Enable
    UPRSMES  = 0x1 << 6    # Upstream Resume Interrupt Enable
    PEP_0    = 0x1 << 12   # Endpoint 0 Interrupt Enable
    PEP_1    = 0x1 << 13   # Endpoint 1 Interrupt Enable
    PEP_2    = 0x1 << 14   # Endpoint 2 Interrupt Enable
    PEP_3    = 0x1 << 15   # Endpoint 3 Interrupt Enable
    PEP_4    = 0x1 << 16   # Endpoint 4 Interrupt Enable
    PEP_5    = 0x1 << 17   # Endpoint 5 Interrupt Enable
    PEP_6    = 0x1 << 18   # Endpoint 6 Interrupt Enable
    PEP_7    = 0x1 << 19   # Endpoint 7 Interrupt Enable
    PEP_8    = 0x1 << 20   # Endpoint 8 Interrupt Enable
    PEP_9    = 0x1 << 21   # Endpoint 9 Interrupt Enable
    DMA_1    = 0x1 << 25   # DMA Channel 1 Interrupt Enable
    DMA_2    = 0x1 << 26   # DMA Channel 2 Interrupt Enable
    DMA_3    = 0x1 << 27   # DMA Channel 3 Interrupt Enable
    DMA_4    = 0x1 << 28   # DMA Channel 4 Interrupt Enable
    DMA_5    = 0x1 << 29   # DMA Channel 5 Interrupt Enable
    DMA_6    = 0x1 << 30   # DMA Channel 6 Interrupt Enable

class DEVEPT(IntEnum):
    EPEN0  = 0x1 << 0    # Endpoint 0 Enable
    EPEN1  = 0x1 << 1    # Endpoint 1 Enable
    EPEN2  = 0x1 << 2    # Endpoint 2 Enable
    EPEN3  = 0x1 << 3    # Endpoint 3 Enable
    EPEN4  = 0x1 << 4    # Endpoint 4 Enable
    EPEN5  = 0x1 << 5    # Endpoint 5 Enable
    EPEN6  = 0x1 << 6    # Endpoint 6 Enable
    EPEN7  = 0x1 << 7    # Endpoint 7 Enable
    EPEN8  = 0x1 << 8    # Endpoint 8 Enable
    EPRST0 = 0x1 << 16   # Endpoint 0 Reset
    EPRST1 = 0x1 << 17   # Endpoint 1 Reset
    EPRST2 = 0x1 << 18   # Endpoint 2 Reset
    EPRST3 = 0x1 << 19   # Endpoint 3 Reset
    EPRST4 = 0x1 << 20   # Endpoint 4 Reset
    EPRST5 = 0x1 << 21   # Endpoint 5 Reset
    EPRST6 = 0x1 << 22   # Endpoint 6 Reset
    EPRST7 = 0x1 << 23   # Endpoint 7 Reset
    EPRST8 = 0x1 << 24   # Endpoint 8 Reset

class DEVFNUM(IntEnum):
    MFNUM  = 0x7 << 0     # Micro Frame Number
    FNUM   = 0x7ff << 3   # Frame Number
    FNCERR = 0x1 << 15    # Frame Number CRC Error

class DEVEPTCFG(IntEnum):
    ALLOC   = 0x1 << 1    # Endpoint Memory Allocate
    EPBK    = 0x3 << 2    # Endpoint Banks
    EPSIZE  = 0x7 << 4    # Endpoint Size
    EPDIR   = 0x1 << 8    # Endpoint Direction
    AUTOSW  = 0x1 << 9    # Automatic Switch
    EPTYPE  = 0x3 << 11   # Endpoint Type
    NBTRANS = 0x3 << 13   # Number of transaction per microframe for isochronous endpoint

class DEVEPTISR(IntEnum):
    TXINI       = 0x1 << 0      # Transmitted IN Data Interrupt
    RXOUTI      = 0x1 << 1      # Received OUT Data Interrupt
    RXSTPI      = 0x1 << 2      # Received SETUP Interrupt
    UNDERFI     = 0x1 << 2      # Underflow Interrupt
    NAKOUTI     = 0x1 << 3      # NAKed OUT Interrupt
    HBISOINERRI = 0x1 << 3      # High bandwidth isochronous IN Underflow Error Interrupt
    NAKINI      = 0x1 << 4      # NAKed IN Interrupt
    HBISOFLUSHI = 0x1 << 4      # High Bandwidth Isochronous IN Flush Interrupt
    OVERFI      = 0x1 << 5      # Overflow Interrupt
    STALLEDI    = 0x1 << 6      # STALLed Interrupt
    CRCERRI     = 0x1 << 6      # CRC Error Interrupt
    SHORTPACKET = 0x1 << 7      # Short Packet Interrupt
    DTSEQ       = 0x3 << 8      # Data Toggle Sequence
    ERRORTRANS  = 0x1 << 10     # High-bandwidth isochronous OUT endpoint transaction error Interrupt
    NBUSYBK     = 0x3 << 12     # Number of Busy Banks
    CURRBK      = 0x3 << 14     # Current Bank
    RWALL       = 0x1 << 16     # Read-write Allowed
    CTRLDIR     = 0x1 << 17     # Control Direction
    CFGOK       = 0x1 << 18     # Configuration OK Status
    BYCT        = 0x7ff << 20   # Byte Count

class DEVEPTICR(IntEnum):
    TXINIC       = 0x1 << 0   # Transmitted IN Data Interrupt Clear
    RXOUTIC      = 0x1 << 1   # Received OUT Data Interrupt Clear
    RXSTPIC      = 0x1 << 2   # Received SETUP Interrupt Clear
    UNDERFIC     = 0x1 << 2   # Underflow Interrupt Clear
    NAKOUTIC     = 0x1 << 3   # NAKed OUT Interrupt Clear
    HBISOINERRIC = 0x1 << 3   # High bandwidth isochronous IN Underflow Error Interrupt Clear
    NAKINIC      = 0x1 << 4   # NAKed IN Interrupt Clear
    HBISOFLUSHIC = 0x1 << 4   # High Bandwidth Isochronous IN Flush Interrupt Clear
    OVERFIC      = 0x1 << 5   # Overflow Interrupt Clear
    STALLEDIC    = 0x1 << 6   # STALLed Interrupt Clear
    CRCERRIC     = 0x1 << 6   # CRC Error Interrupt Clear
    SHORTPACKETC = 0x1 << 7   # Short Packet Interrupt Clear

class DEVEPTIFR(IntEnum):
    TXINIS       = 0x1 << 0    # Transmitted IN Data Interrupt Set
    RXOUTIS      = 0x1 << 1    # Received OUT Data Interrupt Set
    RXSTPIS      = 0x1 << 2    # Received SETUP Interrupt Set
    UNDERFIS     = 0x1 << 2    # Underflow Interrupt Set
    NAKOUTIS     = 0x1 << 3    # NAKed OUT Interrupt Set
    HBISOINERRIS = 0x1 << 3    # High bandwidth isochronous IN Underflow Error Interrupt Set
    NAKINIS      = 0x1 << 4    # NAKed IN Interrupt Set
    HBISOFLUSHIS = 0x1 << 4    # High Bandwidth Isochronous IN Flush Interrupt Set
    OVERFIS      = 0x1 << 5    # Overflow Interrupt Set
    STALLEDIS    = 0x1 << 6    # STALLed Interrupt Set
    CRCERRIS     = 0x1 << 6    # CRC Error Interrupt Set
    SHORTPACKETS = 0x1 << 7    # Short Packet Interrupt Set
    NBUSYBKS     = 0x1 << 12   # Number of Busy Banks Interrupt Set

class DEVEPTIMR(IntEnum):
    TXINE        = 0x1 << 0    # Transmitted IN Data Interrupt
    RXOUTE       = 0x1 << 1    # Received OUT Data Interrupt
    RXSTPE       = 0x1 << 2    # Received SETUP Interrupt
    UNDERFE      = 0x1 << 2    # Underflow Interrupt
    NAKOUTE      = 0x1 << 3    # NAKed OUT Interrupt
    HBISOINERRE  = 0x1 << 3    # High Bandwidth Isochronous IN Error Interrupt
    NAKINE       = 0x1 << 4    # NAKed IN Interrupt
    HBISOFLUSHE  = 0x1 << 4    # High Bandwidth Isochronous IN Flush Interrupt
    OVERFE       = 0x1 << 5    # Overflow Interrupt
    STALLEDE     = 0x1 << 6    # STALLed Interrupt
    CRCERRE      = 0x1 << 6    # CRC Error Interrupt
    SHORTPACKETE = 0x1 << 7    # Short Packet Interrupt
    MDATAE       = 0x1 << 8    # MData Interrupt
    DATAXE       = 0x1 << 9    # DataX Interrupt
    ERRORTRANSE  = 0x1 << 10   # Transaction Error Interrupt
    NBUSYBKE     = 0x1 << 12   # Number of Busy Banks Interrupt
    KILLBK       = 0x1 << 13   # Kill IN Bank
    FIFOCON      = 0x1 << 14   # FIFO Control
    EPDISHDMA    = 0x1 << 16   # Endpoint Interrupts Disable HDMA Request
    NYETDIS      = 0x1 << 17   # NYET Token Disable
    RSTDT        = 0x1 << 18   # Reset Data Toggle
    STALLRQ      = 0x1 << 19   # STALL Request

class DEVEPTIER(IntEnum):
    TXINES        = 0x1 << 0    # Transmitted IN Data Interrupt Enable
    RXOUTES       = 0x1 << 1    # Received OUT Data Interrupt Enable
    RXSTPES       = 0x1 << 2    # Received SETUP Interrupt Enable
    UNDERFES      = 0x1 << 2    # Underflow Interrupt Enable
    NAKOUTES      = 0x1 << 3    # NAKed OUT Interrupt Enable
    HBISOINERRES  = 0x1 << 3    # High Bandwidth Isochronous IN Error Interrupt Enable
    NAKINES       = 0x1 << 4    # NAKed IN Interrupt Enable
    HBISOFLUSHES  = 0x1 << 4    # High Bandwidth Isochronous IN Flush Interrupt Enable
    OVERFES       = 0x1 << 5    # Overflow Interrupt Enable
    STALLEDES     = 0x1 << 6    # STALLed Interrupt Enable
    CRCERRES      = 0x1 << 6    # CRC Error Interrupt Enable
    SHORTPACKETES = 0x1 << 7    # Short Packet Interrupt Enable
    MDATAES       = 0x1 << 8    # MData Interrupt Enable
    DATAXES       = 0x1 << 9    # DataX Interrupt Enable
    ERRORTRANSES  = 0x1 << 10   # Transaction Error Interrupt Enable
    NBUSYBKES     = 0x1 << 12   # Number of Busy Banks Interrupt Enable
    KILLBKS       = 0x1 << 13   # Kill IN Bank
    EPDISHDMAS    = 0x1 << 16   # Endpoint Interrupts Disable HDMA Request Enable
    NYETDISS      = 0x1 << 17   # NYET Token Disable Enable
    RSTDTS        = 0x1 << 18   # Reset Data Toggle Enable
    STALLRQS      = 0x1 << 19   # STALL Request Enable

class DEVEPTIDR(IntEnum):
    TXINEC        = 0x1 << 0    # Transmitted IN Interrupt Clear
    RXOUTEC       = 0x1 << 1    # Received OUT Data Interrupt Clear
    RXSTPEC       = 0x1 << 2    # Received SETUP Interrupt Clear
    UNDERFEC      = 0x1 << 2    # Underflow Interrupt Clear
    NAKOUTEC      = 0x1 << 3    # NAKed OUT Interrupt Clear
    HBISOINERREC  = 0x1 << 3    # High Bandwidth Isochronous IN Error Interrupt Clear
    NAKINEC       = 0x1 << 4    # NAKed IN Interrupt Clear
    HBISOFLUSHEC  = 0x1 << 4    # High Bandwidth Isochronous IN Flush Interrupt Clear
    OVERFEC       = 0x1 << 5    # Overflow Interrupt Clear
    STALLEDEC     = 0x1 << 6    # STALLed Interrupt Clear
    CRCERREC      = 0x1 << 6    # CRC Error Interrupt Clear
    SHORTPACKETEC = 0x1 << 7    # Shortpacket Interrupt Clear
    MDATEC        = 0x1 << 8    # MData Interrupt Clear
    DATAXEC       = 0x1 << 9    # DataX Interrupt Clear
    ERRORTRANSEC  = 0x1 << 10   # Transaction Error Interrupt Clear
    NBUSYBKEC     = 0x1 << 12   # Number of Busy Banks Interrupt Clear
    FIFOCONC      = 0x1 << 14   # FIFO Control Clear
    EPDISHDMAC    = 0x1 << 16   # Endpoint Interrupts Disable HDMA Request Clear
    NYETDISC      = 0x1 << 17   # NYET Token Disable Clear
    STALLRQC      = 0x1 << 19   # STALL Request Clear

class DEVDMANXTDSC1(IntEnum):
    NXT_DSC_ADD = 0xffffffff << 0   # Next Descriptor Address

class DEVDMAADDRESS1(IntEnum):
    BUFF_ADD = 0xffffffff << 0   # Buffer Address

class DEVDMACONTROL1(IntEnum):
    CHANN_ENB   = 0x1 << 0       # Channel Enable Command
    LDNXT_DSC   = 0x1 << 1       # Load Next Channel Transfer Descriptor Enable Command
    END_TR_EN   = 0x1 << 2       # End of Transfer Enable Control
    END_B_EN    = 0x1 << 3       # End of Buffer Enable Control
    END_TR_IT   = 0x1 << 4       # End of Transfer Interrupt Enable
    END_BUFFIT  = 0x1 << 5       # End of Buffer Interrupt Enable
    DESC_LD_IT  = 0x1 << 6       # Descriptor Loaded Interrupt Enable
    BURST_LCK   = 0x1 << 7       # Burst Lock Enable
    BUFF_LENGTH = 0xffff << 16   # Buffer Byte Length (Write-only)

class DEVDMASTATUS1(IntEnum):
    CHANN_ENB  = 0x1 << 0       # Channel Enable Status
    CHANN_ACT  = 0x1 << 1       # Channel Active Status
    END_TR_ST  = 0x1 << 4       # End of Channel Transfer Status
    END_BF_ST  = 0x1 << 5       # End of Channel Buffer Status
    DESC_LDST  = 0x1 << 6       # Descriptor Loaded Status
    BUFF_COUNT = 0xffff << 16   # Buffer Byte Count

class DEVDMANXTDSC2(IntEnum):
    NXT_DSC_ADD = 0xffffffff << 0   # Next Descriptor Address

class DEVDMAADDRESS2(IntEnum):
    BUFF_ADD = 0xffffffff << 0   # Buffer Address

class DEVDMACONTROL2(IntEnum):
    CHANN_ENB   = 0x1 << 0       # Channel Enable Command
    LDNXT_DSC   = 0x1 << 1       # Load Next Channel Transfer Descriptor Enable Command
    END_TR_EN   = 0x1 << 2       # End of Transfer Enable Control
    END_B_EN    = 0x1 << 3       # End of Buffer Enable Control
    END_TR_IT   = 0x1 << 4       # End of Transfer Interrupt Enable
    END_BUFFIT  = 0x1 << 5       # End of Buffer Interrupt Enable
    DESC_LD_IT  = 0x1 << 6       # Descriptor Loaded Interrupt Enable
    BURST_LCK   = 0x1 << 7       # Burst Lock Enable
    BUFF_LENGTH = 0xffff << 16   # Buffer Byte Length (Write-only)

class DEVDMASTATUS2(IntEnum):
    CHANN_ENB  = 0x1 << 0       # Channel Enable Status
    CHANN_ACT  = 0x1 << 1       # Channel Active Status
    END_TR_ST  = 0x1 << 4       # End of Channel Transfer Status
    END_BF_ST  = 0x1 << 5       # End of Channel Buffer Status
    DESC_LDST  = 0x1 << 6       # Descriptor Loaded Status
    BUFF_COUNT = 0xffff << 16   # Buffer Byte Count

class DEVDMANXTDSC3(IntEnum):
    NXT_DSC_ADD = 0xffffffff << 0   # Next Descriptor Address

class DEVDMAADDRESS3(IntEnum):
    BUFF_ADD = 0xffffffff << 0   # Buffer Address

class DEVDMACONTROL3(IntEnum):
    CHANN_ENB   = 0x1 << 0       # Channel Enable Command
    LDNXT_DSC   = 0x1 << 1       # Load Next Channel Transfer Descriptor Enable Command
    END_TR_EN   = 0x1 << 2       # End of Transfer Enable Control
    END_B_EN    = 0x1 << 3       # End of Buffer Enable Control
    END_TR_IT   = 0x1 << 4       # End of Transfer Interrupt Enable
    END_BUFFIT  = 0x1 << 5       # End of Buffer Interrupt Enable
    DESC_LD_IT  = 0x1 << 6       # Descriptor Loaded Interrupt Enable
    BURST_LCK   = 0x1 << 7       # Burst Lock Enable
    BUFF_LENGTH = 0xffff << 16   # Buffer Byte Length (Write-only)

class DEVDMASTATUS3(IntEnum):
    CHANN_ENB  = 0x1 << 0       # Channel Enable Status
    CHANN_ACT  = 0x1 << 1       # Channel Active Status
    END_TR_ST  = 0x1 << 4       # End of Channel Transfer Status
    END_BF_ST  = 0x1 << 5       # End of Channel Buffer Status
    DESC_LDST  = 0x1 << 6       # Descriptor Loaded Status
    BUFF_COUNT = 0xffff << 16   # Buffer Byte Count

class DEVDMANXTDSC4(IntEnum):
    NXT_DSC_ADD = 0xffffffff << 0   # Next Descriptor Address

class DEVDMAADDRESS4(IntEnum):
    BUFF_ADD = 0xffffffff << 0   # Buffer Address

class DEVDMACONTROL4(IntEnum):
    CHANN_ENB   = 0x1 << 0       # Channel Enable Command
    LDNXT_DSC   = 0x1 << 1       # Load Next Channel Transfer Descriptor Enable Command
    END_TR_EN   = 0x1 << 2       # End of Transfer Enable Control
    END_B_EN    = 0x1 << 3       # End of Buffer Enable Control
    END_TR_IT   = 0x1 << 4       # End of Transfer Interrupt Enable
    END_BUFFIT  = 0x1 << 5       # End of Buffer Interrupt Enable
    DESC_LD_IT  = 0x1 << 6       # Descriptor Loaded Interrupt Enable
    BURST_LCK   = 0x1 << 7       # Burst Lock Enable
    BUFF_LENGTH = 0xffff << 16   # Buffer Byte Length (Write-only)

class DEVDMASTATUS4(IntEnum):
    CHANN_ENB  = 0x1 << 0       # Channel Enable Status
    CHANN_ACT  = 0x1 << 1       # Channel Active Status
    END_TR_ST  = 0x1 << 4       # End of Channel Transfer Status
    END_BF_ST  = 0x1 << 5       # End of Channel Buffer Status
    DESC_LDST  = 0x1 << 6       # Descriptor Loaded Status
    BUFF_COUNT = 0xffff << 16   # Buffer Byte Count

class DEVDMANXTDSC5(IntEnum):
    NXT_DSC_ADD = 0xffffffff << 0   # Next Descriptor Address

class DEVDMAADDRESS5(IntEnum):
    BUFF_ADD = 0xffffffff << 0   # Buffer Address

class DEVDMACONTROL5(IntEnum):
    CHANN_ENB   = 0x1 << 0       # Channel Enable Command
    LDNXT_DSC   = 0x1 << 1       # Load Next Channel Transfer Descriptor Enable Command
    END_TR_EN   = 0x1 << 2       # End of Transfer Enable Control
    END_B_EN    = 0x1 << 3       # End of Buffer Enable Control
    END_TR_IT   = 0x1 << 4       # End of Transfer Interrupt Enable
    END_BUFFIT  = 0x1 << 5       # End of Buffer Interrupt Enable
    DESC_LD_IT  = 0x1 << 6       # Descriptor Loaded Interrupt Enable
    BURST_LCK   = 0x1 << 7       # Burst Lock Enable
    BUFF_LENGTH = 0xffff << 16   # Buffer Byte Length (Write-only)

class DEVDMASTATUS5(IntEnum):
    CHANN_ENB  = 0x1 << 0       # Channel Enable Status
    CHANN_ACT  = 0x1 << 1       # Channel Active Status
    END_TR_ST  = 0x1 << 4       # End of Channel Transfer Status
    END_BF_ST  = 0x1 << 5       # End of Channel Buffer Status
    DESC_LDST  = 0x1 << 6       # Descriptor Loaded Status
    BUFF_COUNT = 0xffff << 16   # Buffer Byte Count

class DEVDMANXTDSC6(IntEnum):
    NXT_DSC_ADD = 0xffffffff << 0   # Next Descriptor Address

class DEVDMAADDRESS6(IntEnum):
    BUFF_ADD = 0xffffffff << 0   # Buffer Address

class DEVDMACONTROL6(IntEnum):
    CHANN_ENB   = 0x1 << 0       # Channel Enable Command
    LDNXT_DSC   = 0x1 << 1       # Load Next Channel Transfer Descriptor Enable Command
    END_TR_EN   = 0x1 << 2       # End of Transfer Enable Control
    END_B_EN    = 0x1 << 3       # End of Buffer Enable Control
    END_TR_IT   = 0x1 << 4       # End of Transfer Interrupt Enable
    END_BUFFIT  = 0x1 << 5       # End of Buffer Interrupt Enable
    DESC_LD_IT  = 0x1 << 6       # Descriptor Loaded Interrupt Enable
    BURST_LCK   = 0x1 << 7       # Burst Lock Enable
    BUFF_LENGTH = 0xffff << 16   # Buffer Byte Length (Write-only)

class DEVDMASTATUS6(IntEnum):
    CHANN_ENB  = 0x1 << 0       # Channel Enable Status
    CHANN_ACT  = 0x1 << 1       # Channel Active Status
    END_TR_ST  = 0x1 << 4       # End of Channel Transfer Status
    END_BF_ST  = 0x1 << 5       # End of Channel Buffer Status
    DESC_LDST  = 0x1 << 6       # Descriptor Loaded Status
    BUFF_COUNT = 0xffff << 16   # Buffer Byte Count

class DEVDMANXTDSC7(IntEnum):
    NXT_DSC_ADD = 0xffffffff << 0   # Next Descriptor Address

class DEVDMAADDRESS7(IntEnum):
    BUFF_ADD = 0xffffffff << 0   # Buffer Address

class DEVDMACONTROL7(IntEnum):
    CHANN_ENB   = 0x1 << 0       # Channel Enable Command
    LDNXT_DSC   = 0x1 << 1       # Load Next Channel Transfer Descriptor Enable Command
    END_TR_EN   = 0x1 << 2       # End of Transfer Enable Control
    END_B_EN    = 0x1 << 3       # End of Buffer Enable Control
    END_TR_IT   = 0x1 << 4       # End of Transfer Interrupt Enable
    END_BUFFIT  = 0x1 << 5       # End of Buffer Interrupt Enable
    DESC_LD_IT  = 0x1 << 6       # Descriptor Loaded Interrupt Enable
    BURST_LCK   = 0x1 << 7       # Burst Lock Enable
    BUFF_LENGTH = 0xffff << 16   # Buffer Byte Length (Write-only)

class DEVDMASTATUS7(IntEnum):
    CHANN_ENB  = 0x1 << 0       # Channel Enable Status
    CHANN_ACT  = 0x1 << 1       # Channel Active Status
    END_TR_ST  = 0x1 << 4       # End of Channel Transfer Status
    END_BF_ST  = 0x1 << 5       # End of Channel Buffer Status
    DESC_LDST  = 0x1 << 6       # Descriptor Loaded Status
    BUFF_COUNT = 0xffff << 16   # Buffer Byte Count

class HSTCTRL(IntEnum):
    SOFE    = 0x1 << 8    # Start of Frame Generation Enable
    RESET   = 0x1 << 9    # Send USB Reset
    RESUME  = 0x1 << 10   # Send USB Resume
    SPDCONF = 0x3 << 12   # Mode Configuration

class HSTISR(IntEnum):
    DCONNI = 0x1 << 0    # Device Connection Interrupt
    DDISCI = 0x1 << 1    # Device Disconnection Interrupt
    RSTI   = 0x1 << 2    # USB Reset Sent Interrupt
    RSMEDI = 0x1 << 3    # Downstream Resume Sent Interrupt
    RXRSMI = 0x1 << 4    # Upstream Resume Received Interrupt
    HSOFI  = 0x1 << 5    # Host Start of Frame Interrupt
    HWUPI  = 0x1 << 6    # Host Wake-Up Interrupt
    PEP_0  = 0x1 << 8    # Pipe 0 Interrupt
    PEP_1  = 0x1 << 9    # Pipe 1 Interrupt
    PEP_2  = 0x1 << 10   # Pipe 2 Interrupt
    PEP_3  = 0x1 << 11   # Pipe 3 Interrupt
    PEP_4  = 0x1 << 12   # Pipe 4 Interrupt
    PEP_5  = 0x1 << 13   # Pipe 5 Interrupt
    PEP_6  = 0x1 << 14   # Pipe 6 Interrupt
    PEP_7  = 0x1 << 15   # Pipe 7 Interrupt
    PEP_8  = 0x1 << 16   # Pipe 8 Interrupt
    PEP_9  = 0x1 << 17   # Pipe 9 Interrupt
    DMA_1  = 0x1 << 25   # DMA Channel 1 Interrupt
    DMA_2  = 0x1 << 26   # DMA Channel 2 Interrupt
    DMA_3  = 0x1 << 27   # DMA Channel 3 Interrupt
    DMA_4  = 0x1 << 28   # DMA Channel 4 Interrupt
    DMA_5  = 0x1 << 29   # DMA Channel 5 Interrupt
    DMA_6  = 0x1 << 30   # DMA Channel 6 Interrupt

class HSTICR(IntEnum):
    DCONNIC = 0x1 << 0   # Device Connection Interrupt Clear
    DDISCIC = 0x1 << 1   # Device Disconnection Interrupt Clear
    RSTIC   = 0x1 << 2   # USB Reset Sent Interrupt Clear
    RSMEDIC = 0x1 << 3   # Downstream Resume Sent Interrupt Clear
    RXRSMIC = 0x1 << 4   # Upstream Resume Received Interrupt Clear
    HSOFIC  = 0x1 << 5   # Host Start of Frame Interrupt Clear
    HWUPIC  = 0x1 << 6   # Host Wake-Up Interrupt Clear

class HSTIFR(IntEnum):
    DCONNIS = 0x1 << 0    # Device Connection Interrupt Set
    DDISCIS = 0x1 << 1    # Device Disconnection Interrupt Set
    RSTIS   = 0x1 << 2    # USB Reset Sent Interrupt Set
    RSMEDIS = 0x1 << 3    # Downstream Resume Sent Interrupt Set
    RXRSMIS = 0x1 << 4    # Upstream Resume Received Interrupt Set
    HSOFIS  = 0x1 << 5    # Host Start of Frame Interrupt Set
    HWUPIS  = 0x1 << 6    # Host Wake-Up Interrupt Set
    DMA_1   = 0x1 << 25   # DMA Channel 1 Interrupt Set
    DMA_2   = 0x1 << 26   # DMA Channel 2 Interrupt Set
    DMA_3   = 0x1 << 27   # DMA Channel 3 Interrupt Set
    DMA_4   = 0x1 << 28   # DMA Channel 4 Interrupt Set
    DMA_5   = 0x1 << 29   # DMA Channel 5 Interrupt Set
    DMA_6   = 0x1 << 30   # DMA Channel 6 Interrupt Set

class HSTIMR(IntEnum):
    DCONNIE = 0x1 << 0    # Device Connection Interrupt Enable
    DDISCIE = 0x1 << 1    # Device Disconnection Interrupt Enable
    RSTIE   = 0x1 << 2    # USB Reset Sent Interrupt Enable
    RSMEDIE = 0x1 << 3    # Downstream Resume Sent Interrupt Enable
    RXRSMIE = 0x1 << 4    # Upstream Resume Received Interrupt Enable
    HSOFIE  = 0x1 << 5    # Host Start of Frame Interrupt Enable
    HWUPIE  = 0x1 << 6    # Host Wake-Up Interrupt Enable
    PEP_0   = 0x1 << 8    # Pipe 0 Interrupt Enable
    PEP_1   = 0x1 << 9    # Pipe 1 Interrupt Enable
    PEP_2   = 0x1 << 10   # Pipe 2 Interrupt Enable
    PEP_3   = 0x1 << 11   # Pipe 3 Interrupt Enable
    PEP_4   = 0x1 << 12   # Pipe 4 Interrupt Enable
    PEP_5   = 0x1 << 13   # Pipe 5 Interrupt Enable
    PEP_6   = 0x1 << 14   # Pipe 6 Interrupt Enable
    PEP_7   = 0x1 << 15   # Pipe 7 Interrupt Enable
    PEP_8   = 0x1 << 16   # Pipe 8 Interrupt Enable
    PEP_9   = 0x1 << 17   # Pipe 9 Interrupt Enable
    DMA_1   = 0x1 << 25   # DMA Channel 1 Interrupt Enable
    DMA_2   = 0x1 << 26   # DMA Channel 2 Interrupt Enable
    DMA_3   = 0x1 << 27   # DMA Channel 3 Interrupt Enable
    DMA_4   = 0x1 << 28   # DMA Channel 4 Interrupt Enable
    DMA_5   = 0x1 << 29   # DMA Channel 5 Interrupt Enable
    DMA_6   = 0x1 << 30   # DMA Channel 6 Interrupt Enable

class HSTIDR(IntEnum):
    DCONNIEC = 0x1 << 0    # Device Connection Interrupt Disable
    DDISCIEC = 0x1 << 1    # Device Disconnection Interrupt Disable
    RSTIEC   = 0x1 << 2    # USB Reset Sent Interrupt Disable
    RSMEDIEC = 0x1 << 3    # Downstream Resume Sent Interrupt Disable
    RXRSMIEC = 0x1 << 4    # Upstream Resume Received Interrupt Disable
    HSOFIEC  = 0x1 << 5    # Host Start of Frame Interrupt Disable
    HWUPIEC  = 0x1 << 6    # Host Wake-Up Interrupt Disable
    PEP_0    = 0x1 << 8    # Pipe 0 Interrupt Disable
    PEP_1    = 0x1 << 9    # Pipe 1 Interrupt Disable
    PEP_2    = 0x1 << 10   # Pipe 2 Interrupt Disable
    PEP_3    = 0x1 << 11   # Pipe 3 Interrupt Disable
    PEP_4    = 0x1 << 12   # Pipe 4 Interrupt Disable
    PEP_5    = 0x1 << 13   # Pipe 5 Interrupt Disable
    PEP_6    = 0x1 << 14   # Pipe 6 Interrupt Disable
    PEP_7    = 0x1 << 15   # Pipe 7 Interrupt Disable
    PEP_8    = 0x1 << 16   # Pipe 8 Interrupt Disable
    PEP_9    = 0x1 << 17   # Pipe 9 Interrupt Disable
    DMA_1    = 0x1 << 25   # DMA Channel 1 Interrupt Disable
    DMA_2    = 0x1 << 26   # DMA Channel 2 Interrupt Disable
    DMA_3    = 0x1 << 27   # DMA Channel 3 Interrupt Disable
    DMA_4    = 0x1 << 28   # DMA Channel 4 Interrupt Disable
    DMA_5    = 0x1 << 29   # DMA Channel 5 Interrupt Disable
    DMA_6    = 0x1 << 30   # DMA Channel 6 Interrupt Disable

class HSTIER(IntEnum):
    DCONNIES = 0x1 << 0    # Device Connection Interrupt Enable
    DDISCIES = 0x1 << 1    # Device Disconnection Interrupt Enable
    RSTIES   = 0x1 << 2    # USB Reset Sent Interrupt Enable
    RSMEDIES = 0x1 << 3    # Downstream Resume Sent Interrupt Enable
    RXRSMIES = 0x1 << 4    # Upstream Resume Received Interrupt Enable
    HSOFIES  = 0x1 << 5    # Host Start of Frame Interrupt Enable
    HWUPIES  = 0x1 << 6    # Host Wake-Up Interrupt Enable
    PEP_0    = 0x1 << 8    # Pipe 0 Interrupt Enable
    PEP_1    = 0x1 << 9    # Pipe 1 Interrupt Enable
    PEP_2    = 0x1 << 10   # Pipe 2 Interrupt Enable
    PEP_3    = 0x1 << 11   # Pipe 3 Interrupt Enable
    PEP_4    = 0x1 << 12   # Pipe 4 Interrupt Enable
    PEP_5    = 0x1 << 13   # Pipe 5 Interrupt Enable
    PEP_6    = 0x1 << 14   # Pipe 6 Interrupt Enable
    PEP_7    = 0x1 << 15   # Pipe 7 Interrupt Enable
    PEP_8    = 0x1 << 16   # Pipe 8 Interrupt Enable
    PEP_9    = 0x1 << 17   # Pipe 9 Interrupt Enable
    DMA_1    = 0x1 << 25   # DMA Channel 1 Interrupt Enable
    DMA_2    = 0x1 << 26   # DMA Channel 2 Interrupt Enable
    DMA_3    = 0x1 << 27   # DMA Channel 3 Interrupt Enable
    DMA_4    = 0x1 << 28   # DMA Channel 4 Interrupt Enable
    DMA_5    = 0x1 << 29   # DMA Channel 5 Interrupt Enable
    DMA_6    = 0x1 << 30   # DMA Channel 6 Interrupt Enable

class HSTPIP(IntEnum):
    PEN0  = 0x1 << 0    # Pipe 0 Enable
    PEN1  = 0x1 << 1    # Pipe 1 Enable
    PEN2  = 0x1 << 2    # Pipe 2 Enable
    PEN3  = 0x1 << 3    # Pipe 3 Enable
    PEN4  = 0x1 << 4    # Pipe 4 Enable
    PEN5  = 0x1 << 5    # Pipe 5 Enable
    PEN6  = 0x1 << 6    # Pipe 6 Enable
    PEN7  = 0x1 << 7    # Pipe 7 Enable
    PEN8  = 0x1 << 8    # Pipe 8 Enable
    PRST0 = 0x1 << 16   # Pipe 0 Reset
    PRST1 = 0x1 << 17   # Pipe 1 Reset
    PRST2 = 0x1 << 18   # Pipe 2 Reset
    PRST3 = 0x1 << 19   # Pipe 3 Reset
    PRST4 = 0x1 << 20   # Pipe 4 Reset
    PRST5 = 0x1 << 21   # Pipe 5 Reset
    PRST6 = 0x1 << 22   # Pipe 6 Reset
    PRST7 = 0x1 << 23   # Pipe 7 Reset
    PRST8 = 0x1 << 24   # Pipe 8 Reset

class HSTFNUM(IntEnum):
    MFNUM    = 0x7 << 0     # Micro Frame Number
    FNUM     = 0x7ff << 3   # Frame Number
    FLENHIGH = 0xff << 16   # Frame Length

class HSTADDR1(IntEnum):
    HSTADDRP0 = 0x7f << 0    # USB Host Address
    HSTADDRP1 = 0x7f << 8    # USB Host Address
    HSTADDRP2 = 0x7f << 16   # USB Host Address
    HSTADDRP3 = 0x7f << 24   # USB Host Address

class HSTADDR2(IntEnum):
    HSTADDRP4 = 0x7f << 0    # USB Host Address
    HSTADDRP5 = 0x7f << 8    # USB Host Address
    HSTADDRP6 = 0x7f << 16   # USB Host Address
    HSTADDRP7 = 0x7f << 24   # USB Host Address

class HSTADDR3(IntEnum):
    HSTADDRP8 = 0x7f << 0   # USB Host Address
    HSTADDRP9 = 0x7f << 8   # USB Host Address

class HSTPIPCFG(IntEnum):
    ALLOC     = 0x1 << 1     # Pipe Memory Allocate
    PBK       = 0x3 << 2     # Pipe Banks
    PSIZE     = 0x7 << 4     # Pipe Size
    PTOKEN    = 0x3 << 8     # Pipe Token
    AUTOSW    = 0x1 << 10    # Automatic Switch
    PTYPE     = 0x3 << 12    # Pipe Type
    PEPNUM    = 0xf << 16    # Pipe Endpoint Number
    PINGEN    = 0x1 << 20    # Ping Enable
    INTFRQ    = 0xff << 24   # Pipe Interrupt Request Frequency
    BINTERVAL = 0xff << 24   # bInterval parameter for the Bulk-Out/Ping transaction

class HSTPIPISR(IntEnum):
    RXINI        = 0x1 << 0      # Received IN Data Interrupt
    TXOUTI       = 0x1 << 1      # Transmitted OUT Data Interrupt
    TXSTPI       = 0x1 << 2      # Transmitted SETUP Interrupt
    UNDERFI      = 0x1 << 2      # Underflow Interrupt
    PERRI        = 0x1 << 3      # Pipe Error Interrupt
    NAKEDI       = 0x1 << 4      # NAKed Interrupt
    OVERFI       = 0x1 << 5      # Overflow Interrupt
    RXSTALLDI    = 0x1 << 6      # Received STALLed Interrupt
    CRCERRI      = 0x1 << 6      # CRC Error Interrupt
    SHORTPACKETI = 0x1 << 7      # Short Packet Interrupt
    DTSEQ        = 0x3 << 8      # Data Toggle Sequence
    NBUSYBK      = 0x3 << 12     # Number of Busy Banks
    CURRBK       = 0x3 << 14     # Current Bank
    RWALL        = 0x1 << 16     # Read-write Allowed
    CFGOK        = 0x1 << 18     # Configuration OK Status
    PBYCT        = 0x7ff << 20   # Pipe Byte Count

class HSTPIPICR(IntEnum):
    RXINIC        = 0x1 << 0   # Received IN Data Interrupt Clear
    TXOUTIC       = 0x1 << 1   # Transmitted OUT Data Interrupt Clear
    TXSTPIC       = 0x1 << 2   # Transmitted SETUP Interrupt Clear
    UNDERFIC      = 0x1 << 2   # Underflow Interrupt Clear
    NAKEDIC       = 0x1 << 4   # NAKed Interrupt Clear
    OVERFIC       = 0x1 << 5   # Overflow Interrupt Clear
    RXSTALLDIC    = 0x1 << 6   # Received STALLed Interrupt Clear
    CRCERRIC      = 0x1 << 6   # CRC Error Interrupt Clear
    SHORTPACKETIC = 0x1 << 7   # Short Packet Interrupt Clear

class HSTPIPIFR(IntEnum):
    RXINIS        = 0x1 << 0    # Received IN Data Interrupt Set
    TXOUTIS       = 0x1 << 1    # Transmitted OUT Data Interrupt Set
    TXSTPIS       = 0x1 << 2    # Transmitted SETUP Interrupt Set
    UNDERFIS      = 0x1 << 2    # Underflow Interrupt Set
    PERRIS        = 0x1 << 3    # Pipe Error Interrupt Set
    NAKEDIS       = 0x1 << 4    # NAKed Interrupt Set
    OVERFIS       = 0x1 << 5    # Overflow Interrupt Set
    RXSTALLDIS    = 0x1 << 6    # Received STALLed Interrupt Set
    CRCERRIS      = 0x1 << 6    # CRC Error Interrupt Set
    SHORTPACKETIS = 0x1 << 7    # Short Packet Interrupt Set
    NBUSYBKS      = 0x1 << 12   # Number of Busy Banks Set

class HSTPIPIMR(IntEnum):
    RXINE         = 0x1 << 0    # Received IN Data Interrupt Enable
    TXOUTE        = 0x1 << 1    # Transmitted OUT Data Interrupt Enable
    TXSTPE        = 0x1 << 2    # Transmitted SETUP Interrupt Enable
    UNDERFIE      = 0x1 << 2    # Underflow Interrupt Enable
    PERRE         = 0x1 << 3    # Pipe Error Interrupt Enable
    NAKEDE        = 0x1 << 4    # NAKed Interrupt Enable
    OVERFIE       = 0x1 << 5    # Overflow Interrupt Enable
    RXSTALLDE     = 0x1 << 6    # Received STALLed Interrupt Enable
    CRCERRE       = 0x1 << 6    # CRC Error Interrupt Enable
    SHORTPACKETIE = 0x1 << 7    # Short Packet Interrupt Enable
    NBUSYBKE      = 0x1 << 12   # Number of Busy Banks Interrupt Enable
    FIFOCON       = 0x1 << 14   # FIFO Control
    PDISHDMA      = 0x1 << 16   # Pipe Interrupts Disable HDMA Request Enable
    PFREEZE       = 0x1 << 17   # Pipe Freeze
    RSTDT         = 0x1 << 18   # Reset Data Toggle

class HSTPIPIER(IntEnum):
    RXINES         = 0x1 << 0    # Received IN Data Interrupt Enable
    TXOUTES        = 0x1 << 1    # Transmitted OUT Data Interrupt Enable
    TXSTPES        = 0x1 << 2    # Transmitted SETUP Interrupt Enable
    UNDERFIES      = 0x1 << 2    # Underflow Interrupt Enable
    PERRES         = 0x1 << 3    # Pipe Error Interrupt Enable
    NAKEDES        = 0x1 << 4    # NAKed Interrupt Enable
    OVERFIES       = 0x1 << 5    # Overflow Interrupt Enable
    RXSTALLDES     = 0x1 << 6    # Received STALLed Interrupt Enable
    CRCERRES       = 0x1 << 6    # CRC Error Interrupt Enable
    SHORTPACKETIES = 0x1 << 7    # Short Packet Interrupt Enable
    NBUSYBKES      = 0x1 << 12   # Number of Busy Banks Enable
    PDISHDMAS      = 0x1 << 16   # Pipe Interrupts Disable HDMA Request Enable
    PFREEZES       = 0x1 << 17   # Pipe Freeze Enable
    RSTDTS         = 0x1 << 18   # Reset Data Toggle Enable

class HSTPIPIDR(IntEnum):
    RXINEC         = 0x1 << 0    # Received IN Data Interrupt Disable
    TXOUTEC        = 0x1 << 1    # Transmitted OUT Data Interrupt Disable
    TXSTPEC        = 0x1 << 2    # Transmitted SETUP Interrupt Disable
    UNDERFIEC      = 0x1 << 2    # Underflow Interrupt Disable
    PERREC         = 0x1 << 3    # Pipe Error Interrupt Disable
    NAKEDEC        = 0x1 << 4    # NAKed Interrupt Disable
    OVERFIEC       = 0x1 << 5    # Overflow Interrupt Disable
    RXSTALLDEC     = 0x1 << 6    # Received STALLed Interrupt Disable
    CRCERREC       = 0x1 << 6    # CRC Error Interrupt Disable
    SHORTPACKETIEC = 0x1 << 7    # Short Packet Interrupt Disable
    NBUSYBKEC      = 0x1 << 12   # Number of Busy Banks Disable
    FIFOCONC       = 0x1 << 14   # FIFO Control Disable
    PDISHDMAC      = 0x1 << 16   # Pipe Interrupts Disable HDMA Request Disable
    PFREEZEC       = 0x1 << 17   # Pipe Freeze Disable

class HSTPIPINRQ(IntEnum):
    INRQ   = 0xff << 0   # IN Request Number before Freeze
    INMODE = 0x1 << 8    # IN Request Mode

class HSTPIPERR(IntEnum):
    DATATGL = 0x1 << 0   # Data Toggle Error
    DATAPID = 0x1 << 1   # Data PID Error
    PID     = 0x1 << 2   # PID Error
    TIMEOUT = 0x1 << 3   # Time-Out Error
    CRC16   = 0x1 << 4   # CRC16 Error
    COUNTER = 0x3 << 5   # Error Counter

class HSTDMANXTDSC1(IntEnum):
    NXT_DSC_ADD = 0xffffffff << 0   # Next Descriptor Address

class HSTDMAADDRESS1(IntEnum):
    BUFF_ADD = 0xffffffff << 0   # Buffer Address

class HSTDMACONTROL1(IntEnum):
    CHANN_ENB   = 0x1 << 0       # Channel Enable Command
    LDNXT_DSC   = 0x1 << 1       # Load Next Channel Transfer Descriptor Enable Command
    END_TR_EN   = 0x1 << 2       # End of Transfer Enable (Control)
    END_B_EN    = 0x1 << 3       # End of Buffer Enable Control
    END_TR_IT   = 0x1 << 4       # End of Transfer Interrupt Enable
    END_BUFFIT  = 0x1 << 5       # End of Buffer Interrupt Enable
    DESC_LD_IT  = 0x1 << 6       # Descriptor Loaded Interrupt Enable
    BURST_LCK   = 0x1 << 7       # Burst Lock Enable
    BUFF_LENGTH = 0xffff << 16   # Buffer Byte Length (Write-only)

class HSTDMASTATUS1(IntEnum):
    CHANN_ENB  = 0x1 << 0       # Channel Enable Status
    CHANN_ACT  = 0x1 << 1       # Channel Active Status
    END_TR_ST  = 0x1 << 4       # End of Channel Transfer Status
    END_BF_ST  = 0x1 << 5       # End of Channel Buffer Status
    DESC_LDST  = 0x1 << 6       # Descriptor Loaded Status
    BUFF_COUNT = 0xffff << 16   # Buffer Byte Count

class HSTDMANXTDSC2(IntEnum):
    NXT_DSC_ADD = 0xffffffff << 0   # Next Descriptor Address

class HSTDMAADDRESS2(IntEnum):
    BUFF_ADD = 0xffffffff << 0   # Buffer Address

class HSTDMACONTROL2(IntEnum):
    CHANN_ENB   = 0x1 << 0       # Channel Enable Command
    LDNXT_DSC   = 0x1 << 1       # Load Next Channel Transfer Descriptor Enable Command
    END_TR_EN   = 0x1 << 2       # End of Transfer Enable (Control)
    END_B_EN    = 0x1 << 3       # End of Buffer Enable Control
    END_TR_IT   = 0x1 << 4       # End of Transfer Interrupt Enable
    END_BUFFIT  = 0x1 << 5       # End of Buffer Interrupt Enable
    DESC_LD_IT  = 0x1 << 6       # Descriptor Loaded Interrupt Enable
    BURST_LCK   = 0x1 << 7       # Burst Lock Enable
    BUFF_LENGTH = 0xffff << 16   # Buffer Byte Length (Write-only)

class HSTDMASTATUS2(IntEnum):
    CHANN_ENB  = 0x1 << 0       # Channel Enable Status
    CHANN_ACT  = 0x1 << 1       # Channel Active Status
    END_TR_ST  = 0x1 << 4       # End of Channel Transfer Status
    END_BF_ST  = 0x1 << 5       # End of Channel Buffer Status
    DESC_LDST  = 0x1 << 6       # Descriptor Loaded Status
    BUFF_COUNT = 0xffff << 16   # Buffer Byte Count

class HSTDMANXTDSC3(IntEnum):
    NXT_DSC_ADD = 0xffffffff << 0   # Next Descriptor Address

class HSTDMAADDRESS3(IntEnum):
    BUFF_ADD = 0xffffffff << 0   # Buffer Address

class HSTDMACONTROL3(IntEnum):
    CHANN_ENB   = 0x1 << 0       # Channel Enable Command
    LDNXT_DSC   = 0x1 << 1       # Load Next Channel Transfer Descriptor Enable Command
    END_TR_EN   = 0x1 << 2       # End of Transfer Enable (Control)
    END_B_EN    = 0x1 << 3       # End of Buffer Enable Control
    END_TR_IT   = 0x1 << 4       # End of Transfer Interrupt Enable
    END_BUFFIT  = 0x1 << 5       # End of Buffer Interrupt Enable
    DESC_LD_IT  = 0x1 << 6       # Descriptor Loaded Interrupt Enable
    BURST_LCK   = 0x1 << 7       # Burst Lock Enable
    BUFF_LENGTH = 0xffff << 16   # Buffer Byte Length (Write-only)

class HSTDMASTATUS3(IntEnum):
    CHANN_ENB  = 0x1 << 0       # Channel Enable Status
    CHANN_ACT  = 0x1 << 1       # Channel Active Status
    END_TR_ST  = 0x1 << 4       # End of Channel Transfer Status
    END_BF_ST  = 0x1 << 5       # End of Channel Buffer Status
    DESC_LDST  = 0x1 << 6       # Descriptor Loaded Status
    BUFF_COUNT = 0xffff << 16   # Buffer Byte Count

class HSTDMANXTDSC4(IntEnum):
    NXT_DSC_ADD = 0xffffffff << 0   # Next Descriptor Address

class HSTDMAADDRESS4(IntEnum):
    BUFF_ADD = 0xffffffff << 0   # Buffer Address

class HSTDMACONTROL4(IntEnum):
    CHANN_ENB   = 0x1 << 0       # Channel Enable Command
    LDNXT_DSC   = 0x1 << 1       # Load Next Channel Transfer Descriptor Enable Command
    END_TR_EN   = 0x1 << 2       # End of Transfer Enable (Control)
    END_B_EN    = 0x1 << 3       # End of Buffer Enable Control
    END_TR_IT   = 0x1 << 4       # End of Transfer Interrupt Enable
    END_BUFFIT  = 0x1 << 5       # End of Buffer Interrupt Enable
    DESC_LD_IT  = 0x1 << 6       # Descriptor Loaded Interrupt Enable
    BURST_LCK   = 0x1 << 7       # Burst Lock Enable
    BUFF_LENGTH = 0xffff << 16   # Buffer Byte Length (Write-only)

class HSTDMASTATUS4(IntEnum):
    CHANN_ENB  = 0x1 << 0       # Channel Enable Status
    CHANN_ACT  = 0x1 << 1       # Channel Active Status
    END_TR_ST  = 0x1 << 4       # End of Channel Transfer Status
    END_BF_ST  = 0x1 << 5       # End of Channel Buffer Status
    DESC_LDST  = 0x1 << 6       # Descriptor Loaded Status
    BUFF_COUNT = 0xffff << 16   # Buffer Byte Count

class HSTDMANXTDSC5(IntEnum):
    NXT_DSC_ADD = 0xffffffff << 0   # Next Descriptor Address

class HSTDMAADDRESS5(IntEnum):
    BUFF_ADD = 0xffffffff << 0   # Buffer Address

class HSTDMACONTROL5(IntEnum):
    CHANN_ENB   = 0x1 << 0       # Channel Enable Command
    LDNXT_DSC   = 0x1 << 1       # Load Next Channel Transfer Descriptor Enable Command
    END_TR_EN   = 0x1 << 2       # End of Transfer Enable (Control)
    END_B_EN    = 0x1 << 3       # End of Buffer Enable Control
    END_TR_IT   = 0x1 << 4       # End of Transfer Interrupt Enable
    END_BUFFIT  = 0x1 << 5       # End of Buffer Interrupt Enable
    DESC_LD_IT  = 0x1 << 6       # Descriptor Loaded Interrupt Enable
    BURST_LCK   = 0x1 << 7       # Burst Lock Enable
    BUFF_LENGTH = 0xffff << 16   # Buffer Byte Length (Write-only)

class HSTDMASTATUS5(IntEnum):
    CHANN_ENB  = 0x1 << 0       # Channel Enable Status
    CHANN_ACT  = 0x1 << 1       # Channel Active Status
    END_TR_ST  = 0x1 << 4       # End of Channel Transfer Status
    END_BF_ST  = 0x1 << 5       # End of Channel Buffer Status
    DESC_LDST  = 0x1 << 6       # Descriptor Loaded Status
    BUFF_COUNT = 0xffff << 16   # Buffer Byte Count

class HSTDMANXTDSC6(IntEnum):
    NXT_DSC_ADD = 0xffffffff << 0   # Next Descriptor Address

class HSTDMAADDRESS6(IntEnum):
    BUFF_ADD = 0xffffffff << 0   # Buffer Address

class HSTDMACONTROL6(IntEnum):
    CHANN_ENB   = 0x1 << 0       # Channel Enable Command
    LDNXT_DSC   = 0x1 << 1       # Load Next Channel Transfer Descriptor Enable Command
    END_TR_EN   = 0x1 << 2       # End of Transfer Enable (Control)
    END_B_EN    = 0x1 << 3       # End of Buffer Enable Control
    END_TR_IT   = 0x1 << 4       # End of Transfer Interrupt Enable
    END_BUFFIT  = 0x1 << 5       # End of Buffer Interrupt Enable
    DESC_LD_IT  = 0x1 << 6       # Descriptor Loaded Interrupt Enable
    BURST_LCK   = 0x1 << 7       # Burst Lock Enable
    BUFF_LENGTH = 0xffff << 16   # Buffer Byte Length (Write-only)

class HSTDMASTATUS6(IntEnum):
    CHANN_ENB  = 0x1 << 0       # Channel Enable Status
    CHANN_ACT  = 0x1 << 1       # Channel Active Status
    END_TR_ST  = 0x1 << 4       # End of Channel Transfer Status
    END_BF_ST  = 0x1 << 5       # End of Channel Buffer Status
    DESC_LDST  = 0x1 << 6       # Descriptor Loaded Status
    BUFF_COUNT = 0xffff << 16   # Buffer Byte Count

class HSTDMANXTDSC7(IntEnum):
    NXT_DSC_ADD = 0xffffffff << 0   # Next Descriptor Address

class HSTDMAADDRESS7(IntEnum):
    BUFF_ADD = 0xffffffff << 0   # Buffer Address

class HSTDMACONTROL7(IntEnum):
    CHANN_ENB   = 0x1 << 0       # Channel Enable Command
    LDNXT_DSC   = 0x1 << 1       # Load Next Channel Transfer Descriptor Enable Command
    END_TR_EN   = 0x1 << 2       # End of Transfer Enable (Control)
    END_B_EN    = 0x1 << 3       # End of Buffer Enable Control
    END_TR_IT   = 0x1 << 4       # End of Transfer Interrupt Enable
    END_BUFFIT  = 0x1 << 5       # End of Buffer Interrupt Enable
    DESC_LD_IT  = 0x1 << 6       # Descriptor Loaded Interrupt Enable
    BURST_LCK   = 0x1 << 7       # Burst Lock Enable
    BUFF_LENGTH = 0xffff << 16   # Buffer Byte Length (Write-only)

class HSTDMASTATUS7(IntEnum):
    CHANN_ENB  = 0x1 << 0       # Channel Enable Status
    CHANN_ACT  = 0x1 << 1       # Channel Active Status
    END_TR_ST  = 0x1 << 4       # End of Channel Transfer Status
    END_BF_ST  = 0x1 << 5       # End of Channel Buffer Status
    DESC_LDST  = 0x1 << 6       # Descriptor Loaded Status
    BUFF_COUNT = 0xffff << 16   # Buffer Byte Count

class CTRL(IntEnum):
    IDTE     = 0x1 << 0    # ID Transition Interrupt Enable
    VBUSTE   = 0x1 << 1    # VBus Transition Interrupt Enable
    SRPE     = 0x1 << 2    # SRP Interrupt Enable
    VBERRE   = 0x1 << 3    # VBus Error Interrupt Enable
    BCERRE   = 0x1 << 4    # B-Connection Error Interrupt Enable
    ROLEEXE  = 0x1 << 5    # Role Exchange Interrupt Enable
    HNPERRE  = 0x1 << 6    # HNP Error Interrupt Enable
    STOE     = 0x1 << 7    # Suspend Time-Out Interrupt Enable
    VBUSHWC  = 0x1 << 8    # VBus Hardware Control
    SRPSEL   = 0x1 << 9    # SRP Selection
    SRPREQ   = 0x1 << 10   # SRP Request
    HNPREQ   = 0x1 << 11   # HNP Request
    OTGPADE  = 0x1 << 12   # OTG Pad Enable
    VBUSPO   = 0x1 << 13   # VBus Polarity Off
    FRZCLK   = 0x1 << 14   # Freeze USB Clock
    USBE     = 0x1 << 15   # UOTGHS Enable
    TIMVALUE = 0x3 << 16   # Timer Value
    TIMPAGE  = 0x3 << 20   # Timer Page
    UNLOCK   = 0x1 << 22   # Timer Access Unlock
    UIDE     = 0x1 << 24   # UOTGID Pin Enable
    UIMOD    = 0x1 << 25   # UOTGHS Mode

class SR(IntEnum):
    IDTI      = 0x1 << 0    # ID Transition Interrupt
    VBUSTI    = 0x1 << 1    # VBus Transition Interrupt
    SRPI      = 0x1 << 2    # SRP Interrupt
    VBERRI    = 0x1 << 3    # VBus Error Interrupt
    BCERRI    = 0x1 << 4    # B-Connection Error Interrupt
    ROLEEXI   = 0x1 << 5    # Role Exchange Interrupt
    HNPERRI   = 0x1 << 6    # HNP Error Interrupt
    STOI      = 0x1 << 7    # Suspend Time-Out Interrupt
    VBUSRQ    = 0x1 << 9    # VBus Request
    ID        = 0x1 << 10   # UOTGID Pin State
    VBUS      = 0x1 << 11   # VBus Level
    SPEED     = 0x3 << 12   # Speed Status
    CLKUSABLE = 0x1 << 14   # UTMI Clock Usable

class SCR(IntEnum):
    IDTIC    = 0x1 << 0   # ID Transition Interrupt Clear
    VBUSTIC  = 0x1 << 1   # VBus Transition Interrupt Clear
    SRPIC    = 0x1 << 2   # SRP Interrupt Clear
    VBERRIC  = 0x1 << 3   # VBus Error Interrupt Clear
    BCERRIC  = 0x1 << 4   # B-Connection Error Interrupt Clear
    ROLEEXIC = 0x1 << 5   # Role Exchange Interrupt Clear
    HNPERRIC = 0x1 << 6   # HNP Error Interrupt Clear
    STOIC    = 0x1 << 7   # Suspend Time-Out Interrupt Clear
    VBUSRQC  = 0x1 << 9   # VBus Request Clear

class SFR(IntEnum):
    IDTIS    = 0x1 << 0   # ID Transition Interrupt Set
    VBUSTIS  = 0x1 << 1   # VBus Transition Interrupt Set
    SRPIS    = 0x1 << 2   # SRP Interrupt Set
    VBERRIS  = 0x1 << 3   # VBus Error Interrupt Set
    BCERRIS  = 0x1 << 4   # B-Connection Error Interrupt Set
    ROLEEXIS = 0x1 << 5   # Role Exchange Interrupt Set
    HNPERRIS = 0x1 << 6   # HNP Error Interrupt Set
    STOIS    = 0x1 << 7   # Suspend Time-Out Interrupt Set
    VBUSRQS  = 0x1 << 9   # VBus Request Set

class FSM(IntEnum):
    DRDSTATE = 0xf << 0   # 

