#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from enum import IntEnum


class INTF(IntEnum):
    GIF0   = 0x1 << 0    # Global interrupt flag of channel 0
    FTFIF0 = 0x1 << 1    # Full Transfer finish flag of channe 0
    HTFIF0 = 0x1 << 2    # Half transfer finish flag of channel 0
    ERRIF0 = 0x1 << 3    # Error flag of channel 0
    GIF1   = 0x1 << 4    # Global interrupt flag of channel 1
    FTFIF1 = 0x1 << 5    # Full Transfer finish flag of channe 1
    HTFIF1 = 0x1 << 6    # Half transfer finish flag of channel 1
    ERRIF1 = 0x1 << 7    # Error flag of channel 1
    GIF2   = 0x1 << 8    # Global interrupt flag of channel 2
    FTFIF2 = 0x1 << 9    # Full Transfer finish flag of channe 2
    HTFIF2 = 0x1 << 10   # Half transfer finish flag of channel 2
    ERRIF2 = 0x1 << 11   # Error flag of channel 2
    GIF3   = 0x1 << 12   # Global interrupt flag of channel 3
    FTFIF3 = 0x1 << 13   # Full Transfer finish flag of channe 3
    HTFIF3 = 0x1 << 14   # Half transfer finish flag of channel 3
    ERRIF3 = 0x1 << 15   # Error flag of channel 3
    GIF4   = 0x1 << 16   # Global interrupt flag of channel 4
    FTFIF4 = 0x1 << 17   # Full Transfer finish flag of channe 4
    HTFIF4 = 0x1 << 18   # Half transfer finish flag of channel 4
    ERRIF4 = 0x1 << 19   # Error flag of channel 4
    GIF5   = 0x1 << 20   # Global interrupt flag of channel 5
    FTFIF5 = 0x1 << 21   # Full Transfer finish flag of channe 5
    HTFIF5 = 0x1 << 22   # Half transfer finish flag of channel 5
    ERRIF5 = 0x1 << 23   # Error flag of channel 5
    GIF6   = 0x1 << 24   # Global interrupt flag of channel 6
    FTFIF6 = 0x1 << 25   # Full Transfer finish flag of channe 6
    HTFIF6 = 0x1 << 26   # Half transfer finish flag of channel 6
    ERRIF6 = 0x1 << 27   # Error flag of channel 6

class INTC(IntEnum):
    GIFC0   = 0x1 << 0    # Clear global interrupt flag of channel 0
    FTFIFC0 = 0x1 << 1    # Clear bit for full transfer finish flag of channel 0
    HTFIFC0 = 0x1 << 2    # Clear bit for half transfer finish flag of channel 0
    ERRIFC0 = 0x1 << 3    # Clear bit for error flag of channel 0
    GIFC1   = 0x1 << 4    # Clear global interrupt flag of channel 1
    FTFIFC1 = 0x1 << 5    # Clear bit for full transfer finish flag of channel 1
    HTFIFC1 = 0x1 << 6    # Clear bit for half transfer finish flag of channel 1
    ERRIFC1 = 0x1 << 7    # Clear bit for error flag of channel 1
    GIFC2   = 0x1 << 8    # Clear global interrupt flag of channel 2
    FTFIFC2 = 0x1 << 9    # Clear bit for full transfer finish flag of channel 2
    HTFIFC2 = 0x1 << 10   # Clear bit for half transfer finish flag of channel 2
    ERRIFC2 = 0x1 << 11   # Clear bit for error flag of channel 2
    GIFC3   = 0x1 << 12   # Clear global interrupt flag of channel 3
    FTFIFC3 = 0x1 << 13   # Clear bit for full transfer finish flag of channel 3
    HTFIFC3 = 0x1 << 14   # Clear bit for half transfer finish flag of channel 3
    ERRIFC3 = 0x1 << 15   # Clear bit for error flag of channel 3
    GIFC4   = 0x1 << 16   # Clear global interrupt flag of channel 4
    FTFIFC4 = 0x1 << 17   # Clear bit for full transfer finish flag of channel 4
    HTFIFC4 = 0x1 << 18   # Clear bit for half transfer finish flag of channel 4
    ERRIFC4 = 0x1 << 19   # Clear bit for error flag of channel 4
    GIFC5   = 0x1 << 20   # Clear global interrupt flag of channel 5
    FTFIFC5 = 0x1 << 21   # Clear bit for full transfer finish flag of channel 5
    HTFIFC5 = 0x1 << 22   # Clear bit for half transfer finish flag of channel 5
    ERRIFC5 = 0x1 << 23   # Clear bit for error flag of channel 5
    GIFC6   = 0x1 << 24   # Clear global interrupt flag of channel 6
    FTFIFC6 = 0x1 << 25   # Clear bit for full transfer finish flag of channel 6
    HTFIFC6 = 0x1 << 26   # Clear bit for half transfer finish flag of channel 6
    ERRIFC6 = 0x1 << 27   # Clear bit for error flag of channel 6

class CH0CTL(IntEnum):
    CHEN   = 0x1 << 0    # Channel enable
    FTFIE  = 0x1 << 1    # Enable bit for channel full transfer finish interrupt
    HTFIE  = 0x1 << 2    # Enable bit for channel half transfer finish interrupt
    ERRIE  = 0x1 << 3    # Enable bit for channel error interrupt
    DIR    = 0x1 << 4    # Transfer direction
    CMEN   = 0x1 << 5    # Circular mode enable
    PNAGA  = 0x1 << 6    # Next address generation algorithm of peripheral
    MNAGA  = 0x1 << 7    # Next address generation algorithm of memory
    PWIDTH = 0x3 << 8    # Transfer data size of peripheral
    MWIDTH = 0x3 << 10   # Transfer data size of memory
    PRIO   = 0x3 << 12   # Priority level
    M2M    = 0x1 << 14   # Memory to Memory Mode

class CH0CNT(IntEnum):
    CNT = 0xffff << 0   # Transfer counter

class CH0PADDR(IntEnum):
    PADDR = 0xffffffff << 0   # Peripheral base address

class CH0MADDR(IntEnum):
    MADDR = 0xffffffff << 0   # Memory base address

class CH1CTL(IntEnum):
    CHEN   = 0x1 << 0    # Channel enable
    FTFIE  = 0x1 << 1    # Enable bit for channel full transfer finish interrupt
    HTFIE  = 0x1 << 2    # Enable bit for channel half transfer finish interrupt
    ERRIE  = 0x1 << 3    # Enable bit for channel error interrupt
    DIR    = 0x1 << 4    # Transfer direction
    CMEN   = 0x1 << 5    # Circular mode enable
    PNAGA  = 0x1 << 6    # Next address generation algorithm of peripheral
    MNAGA  = 0x1 << 7    # Next address generation algorithm of memory
    PWIDTH = 0x3 << 8    # Transfer data size of peripheral
    MWIDTH = 0x3 << 10   # Transfer data size of memory
    PRIO   = 0x3 << 12   # Priority level
    M2M    = 0x1 << 14   # Memory to Memory Mode

class CH1CNT(IntEnum):
    CNT = 0xffff << 0   # Transfer counter

class CH1PADDR(IntEnum):
    PADDR = 0xffffffff << 0   # Peripheral base address

class CH1MADDR(IntEnum):
    MADDR = 0xffffffff << 0   # Memory base address

class CH2CTL(IntEnum):
    CHEN   = 0x1 << 0    # Channel enable
    FTFIE  = 0x1 << 1    # Enable bit for channel full transfer finish interrupt
    HTFIE  = 0x1 << 2    # Enable bit for channel half transfer finish interrupt
    ERRIE  = 0x1 << 3    # Enable bit for channel error interrupt
    DIR    = 0x1 << 4    # Transfer direction
    CMEN   = 0x1 << 5    # Circular mode enable
    PNAGA  = 0x1 << 6    # Next address generation algorithm of peripheral
    MNAGA  = 0x1 << 7    # Next address generation algorithm of memory
    PWIDTH = 0x3 << 8    # Transfer data size of peripheral
    MWIDTH = 0x3 << 10   # Transfer data size of memory
    PRIO   = 0x3 << 12   # Priority level
    M2M    = 0x1 << 14   # Memory to Memory Mode

class CH2CNT(IntEnum):
    CNT = 0xffff << 0   # Transfer counter

class CH2PADDR(IntEnum):
    PADDR = 0xffffffff << 0   # Peripheral base address

class CH2MADDR(IntEnum):
    MADDR = 0xffffffff << 0   # Memory base address

class CH3CTL(IntEnum):
    CHEN   = 0x1 << 0    # Channel enable
    FTFIE  = 0x1 << 1    # Enable bit for channel full transfer finish interrupt
    HTFIE  = 0x1 << 2    # Enable bit for channel half transfer finish interrupt
    ERRIE  = 0x1 << 3    # Enable bit for channel error interrupt
    DIR    = 0x1 << 4    # Transfer direction
    CMEN   = 0x1 << 5    # Circular mode enable
    PNAGA  = 0x1 << 6    # Next address generation algorithm of peripheral
    MNAGA  = 0x1 << 7    # Next address generation algorithm of memory
    PWIDTH = 0x3 << 8    # Transfer data size of peripheral
    MWIDTH = 0x3 << 10   # Transfer data size of memory
    PRIO   = 0x3 << 12   # Priority level
    M2M    = 0x1 << 14   # Memory to Memory Mode

class CH3CNT(IntEnum):
    CNT = 0xffff << 0   # Transfer counter

class CH3PADDR(IntEnum):
    PADDR = 0xffffffff << 0   # Peripheral base address

class CH3MADDR(IntEnum):
    MADDR = 0xffffffff << 0   # Memory base address

class CH4CTL(IntEnum):
    CHEN   = 0x1 << 0    # Channel enable
    FTFIE  = 0x1 << 1    # Enable bit for channel full transfer finish interrupt
    HTFIE  = 0x1 << 2    # Enable bit for channel half transfer finish interrupt
    ERRIE  = 0x1 << 3    # Enable bit for channel error interrupt
    DIR    = 0x1 << 4    # Transfer direction
    CMEN   = 0x1 << 5    # Circular mode enable
    PNAGA  = 0x1 << 6    # Next address generation algorithm of peripheral
    MNAGA  = 0x1 << 7    # Next address generation algorithm of memory
    PWIDTH = 0x3 << 8    # Transfer data size of peripheral
    MWIDTH = 0x3 << 10   # Transfer data size of memory
    PRIO   = 0x3 << 12   # Priority level
    M2M    = 0x1 << 14   # Memory to Memory Mode

class CH4CNT(IntEnum):
    CNT = 0xffff << 0   # Transfer counter

class CH4PADDR(IntEnum):
    PADDR = 0xffffffff << 0   # Peripheral base address

class CH4MADDR(IntEnum):
    MADDR = 0xffffffff << 0   # Memory base address

class CH5CTL(IntEnum):
    CHEN   = 0x1 << 0    # Channel enable
    FTFIE  = 0x1 << 1    # Enable bit for channel full transfer finish interrupt
    HTFIE  = 0x1 << 2    # Enable bit for channel half transfer finish interrupt
    ERRIE  = 0x1 << 3    # Enable bit for channel error interrupt
    DIR    = 0x1 << 4    # Transfer direction
    CMEN   = 0x1 << 5    # Circular mode enable
    PNAGA  = 0x1 << 6    # Next address generation algorithm of peripheral
    MNAGA  = 0x1 << 7    # Next address generation algorithm of memory
    PWIDTH = 0x3 << 8    # Transfer data size of peripheral
    MWIDTH = 0x3 << 10   # Transfer data size of memory
    PRIO   = 0x3 << 12   # Priority level
    M2M    = 0x1 << 14   # Memory to Memory Mode

class CH5CNT(IntEnum):
    CNT = 0xffff << 0   # Transfer counter

class CH5PADDR(IntEnum):
    PADDR = 0xffffffff << 0   # Peripheral base address

class CH5MADDR(IntEnum):
    MADDR = 0xffffffff << 0   # Memory base address

class CH6CTL(IntEnum):
    CHEN   = 0x1 << 0    # Channel enable
    FTFIE  = 0x1 << 1    # Enable bit for channel full transfer finish interrupt
    HTFIE  = 0x1 << 2    # Enable bit for channel half transfer finish interrupt
    ERRIE  = 0x1 << 3    # Enable bit for channel error interrupt
    DIR    = 0x1 << 4    # Transfer direction
    CMEN   = 0x1 << 5    # Circular mode enable
    PNAGA  = 0x1 << 6    # Next address generation algorithm of peripheral
    MNAGA  = 0x1 << 7    # Next address generation algorithm of memory
    PWIDTH = 0x3 << 8    # Transfer data size of peripheral
    MWIDTH = 0x3 << 10   # Transfer data size of memory
    PRIO   = 0x3 << 12   # Priority level
    M2M    = 0x1 << 14   # Memory to Memory Mode

class CH6CNT(IntEnum):
    CNT = 0xffff << 0   # Transfer counter

class CH6PADDR(IntEnum):
    PADDR = 0xffffffff << 0   # Peripheral base address

class CH6MADDR(IntEnum):
    MADDR = 0xffffffff << 0   # Memory base address

