#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class I2C_CR1(IntEnum):
	PE        = 1 << 0
	SMBUS     = 1 << 1
	SMBTYPE   = 1 << 3
	ENARP     = 1 << 4
	ENPEC     = 1 << 5
	ENGC      = 1 << 6
	NOSTRETCH = 1 << 7
	START     = 1 << 8
	STOP      = 1 << 9
	ACK       = 1 << 10
	POS       = 1 << 11
	PEC       = 1 << 12
	ALERT     = 1 << 13
	SWRST     = 1 << 15

	RW_MASK = PE|SMBUS|SMBTYPE|ENARP|ENPEC|ENGC|NOSTRETCH|START|STOP|ACK|POS|ALERT|SWRST

class I2C_CR2(IntEnum):
	FREQ    = 0x3f << 0
	ITERREN = 1 << 8
	ITEVTEN = 1 << 9
	ITBUFEN = 1 << 10
	DMAEN   = 1 << 11
	LAST    = 1 << 12

class I2C_OAR1(IntEnum):
	ADD0    = 1 << 0
	ADD1    = 1 << 1
	ADD2    = 1 << 2
	ADD3    = 1 << 3
	ADD4    = 1 << 4
	ADD5    = 1 << 5
	ADD6    = 1 << 6
	ADD7    = 1 << 7
	ADD8    = 1 << 8
	ADD9    = 1 << 9
	ADDMODE = 1 << 15

	ADDR1_7B = 0x7f << 1
	ADDR1_10B = 0x3ff

class I2C_OAR2(IntEnum):
	ENDUAL = 1 << 0
	ADDR2   = 0x7f << 1

class I2C_DR(IntEnum):
	DR = 0xff << 0

class I2C_SR1(IntEnum):
	SB       = 1 << 0
	ADDR     = 1 << 1
	BTF      = 1 << 2
	ADD10    = 1 << 3
	STOPF    = 1 << 4
	RXNE     = 1 << 6
	TXE      = 1 << 7
	BERR     = 1 << 8
	ARLO     = 1 << 9
	AF       = 1 << 10
	OVR      = 1 << 11
	PECERR   = 1 << 12
	TIMEOUT  = 1 << 14
	SMBALERT = 1 << 15

class I2C_SR2(IntEnum):
	MSL        = 1 << 0
	BSY        = 1 << 1
	TRA        = 1 << 2
	GENCALL    = 1 << 4
	SMBDEFAULT = 1 << 5
	SMBHOST    = 1 << 6
	DALF       = 1 << 7
	PEC        = 0xff << 8

class I2C_CCR(IntEnum):
	CCR = 0xfff << 0
	DTY = 1 << 14
	FS  = 1 << 15

class I2C_TRISE(IntEnum):
	TRISE = 0x3f << 0

class I2C_FLTR(IntEnum):
	DNF   = 0xf << 0
	ANOFF = 1 << 4
