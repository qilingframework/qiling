#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class DMA_SxCR(IntEnum):
    CHSEL    = 7 << 25
    CHSEL_0  = 1 << 25
    CHSEL_1  = 2 << 25
    CHSEL_2  = 4 << 25
    MBURST_0 = 1 << 23
    MBURST_1 = 2 << 23
    MBURST   = 3 << 23
    PBURST_0 = 1 << 21
    PBURST_1 = 2 << 21
    PBURST   = 3 << 21
    CT       = 1 << 19
    DBM      = 1 << 18
    PL_0     = 1 << 16
    PL_1     = 2 << 16
    PL       = 3 << 16
    PINCOS   = 1 << 15
    MSIZE_0  = 1 << 13
    MSIZE_1  = 2 << 13
    MSIZE    = 3 << 13
    PSIZE_0  = 1 << 11
    PSIZE_1  = 2 << 11
    PSIZE    = 3 << 11
    MINC     = 1 << 10
    PINC     = 1 << 9
    CIRC     = 1 << 8
    DIR_0    = 1 << 6
    DIR_1    = 2 << 6
    DIR      = 3 << 6
    PFCTRL   = 1 << 5
    TCIE     = 1 << 4
    HTIE     = 1 << 3
    TEIE     = 1 << 2
    DMEIE    = 1 << 1
    EN       = 1 << 0

class DMA_SxFCR(IntEnum):
	FEIE  = 1 << 7
	FS    = 0x7 << 3
	DMDIS = 1 << 2
	FTH   = 0x3 << 0

class DMA_LISR(IntEnum):
	TCIF3  = 1 << 27
	HTIF3  = 1 << 26
	TEIF3  = 1 << 25
	DMEIF3 = 1 << 24
	FEIF3  = 1 << 22
	TCIF2  = 1 << 21
	HTIF2  = 1 << 20
	TEIF2  = 1 << 19
	DMEIF2 = 1 << 18
	FEIF2  = 1 << 16
	TCIF1  = 1 << 11
	HTIF1  = 1 << 10
	TEIF1  = 1 << 9
	DMEIF1 = 1 << 8
	FEIF1  = 1 << 6
	TCIF0  = 1 << 5
	HTIF0  = 1 << 4
	TEIF0  = 1 << 3
	DMEIF0 = 1 << 2
	FEIF0  = 1 << 0

class DMA_HISR(IntEnum):
	TCIF7  = 1 << 27
	HTIF7  = 1 << 26
	TEIF7  = 1 << 25
	DMEIF7 = 1 << 24
	FEIF7  = 1 << 22
	TCIF6  = 1 << 21
	HTIF6  = 1 << 20
	TEIF6  = 1 << 19
	DMEIF6 = 1 << 18
	FEIF6  = 1 << 16
	TCIF5  = 1 << 11
	HTIF5  = 1 << 10
	TEIF5  = 1 << 9
	DMEIF5 = 1 << 8
	FEIF5  = 1 << 6
	TCIF4  = 1 << 5
	HTIF4  = 1 << 4
	TEIF4  = 1 << 3
	DMEIF4 = 1 << 2
	FEIF4  = 1 << 0

class DMA_LIFCR(IntEnum):
	CTCIF3  = 1 << 27
	CHTIF3  = 1 << 26
	CTEIF3  = 1 << 25
	CDMEIF3 = 1 << 24
	CFEIF3  = 1 << 22
	CTCIF2  = 1 << 21
	CHTIF2  = 1 << 20
	CTEIF2  = 1 << 19
	CDMEIF2 = 1 << 18
	CFEIF2  = 1 << 16
	CTCIF1  = 1 << 11
	CHTIF1  = 1 << 10
	CTEIF1  = 1 << 9
	CDMEIF1 = 1 << 8
	CFEIF1  = 1 << 6
	CTCIF0  = 1 << 5
	CHTIF0  = 1 << 4
	CTEIF0  = 1 << 3
	CDMEIF0 = 1 << 2
	CFEIF0  = 1 << 0

class DMA_HIFCR(IntEnum):
	CTCIF7  = 1 << 27
	CHTIF7  = 1 << 26
	CTEIF7  = 1 << 25
	CDMEIF7 = 1 << 24
	CFEIF7  = 1 << 22
	CTCIF6  = 1 << 21
	CHTIF6  = 1 << 20
	CTEIF6  = 1 << 19
	CDMEIF6 = 1 << 18
	CFEIF6  = 1 << 16
	CTCIF5  = 1 << 11
	CHTIF5  = 1 << 10
	CTEIF5  = 1 << 9
	CDMEIF5 = 1 << 8
	CFEIF5  = 1 << 6
	CTCIF4  = 1 << 5
	CHTIF4  = 1 << 4
	CTEIF4  = 1 << 3
	CDMEIF4 = 1 << 2
	CFEIF4  = 1 << 0

class DMA_SxPAR(IntEnum):
	PA = 0xffffffff << 0

class DMA_SxM0AR(IntEnum):
	M0A = 0xffffffff << 0

class DMA_SxM1AR(IntEnum):
	M1A = 0xffffffff << 0

class DMA(IntEnum):
	PERIPH_TO_MEMORY = 0
	MEMORY_TO_PERIPH = DMA_SxCR.DIR_0
	MEMORY_TO_MEMORY = DMA_SxCR.DIR_1

	PDATAALIGN_BYTE     = 0
	PDATAALIGN_HALFWORD = DMA_SxCR.PSIZE_0
	PDATAALIGN_WORD     = DMA_SxCR.PSIZE_1

	MDATAALIGN_BYTE     = 0
	MDATAALIGN_HALFWORD = DMA_SxCR.MSIZE_0
	MDATAALIGN_WORD     = DMA_SxCR.MSIZE_1
