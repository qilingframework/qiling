#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class SPI_CR1(IntEnum):
	CPHA     = 1 << 0
	CPOL     = 1 << 1
	MSTR     = 1 << 2
	BR       = 0x7 << 3
	SPE      = 1 << 6
	LSBFIRST = 1 << 7
	SSI      = 1 << 8
	SSM      = 1 << 9
	RXONLY   = 1 << 10
	DFF      = 1 << 11
	CRCNEXT  = 1 << 12
	CRCEN    = 1 << 13
	BIDIOE   = 1 << 14
	BIDIMODE = 1 << 15

	RW_MASK = 0xffff

class SPI_CR2(IntEnum):
	RXDMAEN = 1 << 0
	TXDMAEN = 1 << 1
	SSOE    = 1 << 2
	FRF     = 1 << 4
	ERRIE   = 1 << 5
	RXNEIE  = 1 << 6
	TXEIE   = 1 << 7

	RW_MASK = RXDMAEN|TXDMAEN|SSOE|FRF|ERRIE|RXNEIE|TXEIE

class SPI_SR(IntEnum):
	RXNE   = 1 << 0
	TXE    = 1 << 1
	CHSIDE = 1 << 2
	UDR    = 1 << 3
	CRCERR = 1 << 4
	MODF   = 1 << 5
	OVR    = 1 << 6
	BSY    = 1 << 7
	FRE    = 1 << 8

class SPI_CRCPR(IntEnum):
	CRCPOLY = 0xffff

class SPI_I2SCFGR(IntEnum):
	CHLEN   = 1 << 0
	DATLEN  = 0x3 << 1
	CKPOL   = 1 << 3
	I2SSTD  = 0x3 << 4
	PCMSYNC = 1 << 7
	I2SCFG  = 0x3 << 8
	I2SE    = 1 << 10
	I2SMOD  = 1 << 11

	RW_MASK = CHLEN|DATLEN|CKPOL|I2SSTD|PCMSYNC|I2SCFG|I2SE|I2SMOD

class SPI_I2SPR(IntEnum):
	I2SDIV = 0xff << 0
	ODD    = 1 << 8
	MCKOE  = 1 << 9

	RW_MASK = I2SDIV|ODD|MCKOE
