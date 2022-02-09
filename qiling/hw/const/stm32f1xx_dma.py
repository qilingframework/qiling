#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class DMA_ISR(IntEnum):
	GIF1  = 1 << 0
	TCIF1 = 1 << 1
	HTIF1 = 1 << 2
	TEIF1 = 1 << 3
	GIF2  = 1 << 4
	TCIF2 = 1 << 5
	HTIF2 = 1 << 6
	TEIF2 = 1 << 7
	GIF3  = 1 << 8
	TCIF3 = 1 << 9
	HTIF3 = 1 << 10
	TEIF3 = 1 << 11
	GIF4  = 1 << 12
	TCIF4 = 1 << 13
	HTIF4 = 1 << 14
	TEIF4 = 1 << 15
	GIF5  = 1 << 16
	TCIF5 = 1 << 17
	HTIF5 = 1 << 18
	TEIF5 = 1 << 19
	GIF6  = 1 << 20
	TCIF6 = 1 << 21
	HTIF6 = 1 << 22
	TEIF6 = 1 << 23
	GIF7  = 1 << 24
	TCIF7 = 1 << 25
	HTIF7 = 1 << 26
	TEIF7 = 1 << 27

class DMA_IFCR(IntEnum):
	CGIF1  = 1 << 0
	CTCIF1 = 1 << 1
	CHTIF1 = 1 << 2
	CTEIF1 = 1 << 3
	CGIF2  = 1 << 4
	CTCIF2 = 1 << 5
	CHTIF2 = 1 << 6
	CTEIF2 = 1 << 7
	CGIF3  = 1 << 8
	CTCIF3 = 1 << 9
	CHTIF3 = 1 << 10
	CTEIF3 = 1 << 11
	CGIF4  = 1 << 12
	CTCIF4 = 1 << 13
	CHTIF4 = 1 << 14
	CTEIF4 = 1 << 15
	CGIF5  = 1 << 16
	CTCIF5 = 1 << 17
	CHTIF5 = 1 << 18
	CTEIF5 = 1 << 19
	CGIF6  = 1 << 20
	CTCIF6 = 1 << 21
	CHTIF6 = 1 << 22
	CTEIF6 = 1 << 23
	CGIF7  = 1 << 24
	CTCIF7 = 1 << 25
	CHTIF7 = 1 << 26
	CTEIF7 = 1 << 27

class DMA_CR(IntEnum):
    EN      = 1 << 0
    TCIE    = 1 << 1
    HTIE    = 1 << 2
    TEIE    = 1 << 3
    DIR     = 1 << 4
    CIRC    = 1 << 5
    PINC    = 1 << 6
    MINC    = 1 << 7
    PSIZE_0 = 1 << 8
    PSIZE_1 = 2 << 8
    PSIZE   = 0x3 << 8  
    MSIZE_0 = 1 << 10
    MSIZE_1 = 2 << 10
    MSIZE   = 0x3 << 10
    PL      = 0x3 << 12
    MEM2MEM = 1 << 14

class DMA(IntEnum):
	PERIPH_TO_MEMORY = 0
	MEMORY_TO_PERIPH = DMA_CR.DIR

	PDATAALIGN_BYTE     = 0
	PDATAALIGN_HALFWORD = DMA_CR.PSIZE_0
	PDATAALIGN_WORD     = DMA_CR.PSIZE_1

	MDATAALIGN_BYTE     = 0
	MDATAALIGN_HALFWORD = DMA_CR.MSIZE_0
	MDATAALIGN_WORD     = DMA_CR.MSIZE_1
