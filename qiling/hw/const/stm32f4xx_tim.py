#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import IntEnum


class TIM_CR1(IntEnum):
	CEN  = 1 << 0
	UDIS = 1 << 1
	URS  = 1 << 2
	OPM  = 1 << 3
	DIR  = 1 << 4
	CMS  = 0x3 << 5
	ARPE = 1 << 7
	CKD  = 0x3 << 8

class TIM_CR2(IntEnum):
	CCPC  = 1 << 0
	CCS   = 1 << 2
	CCDS  = 1 << 3
	MMS   = 0x7 << 4
	TI1S  = 1 << 7
	OIS1  = 1 << 8
	OIS1N = 1 << 9
	OIS2  = 1 << 10
	OIS2N = 1 << 11
	OIS3  = 1 << 12
	OIS3N = 1 << 13
	OIS4  = 1 << 14

class TIM_SMCR(IntEnum):
	SMS  = 0x7 << 0
	TS   = 0x7 << 4
	MSM  = 1 << 7
	ETF  = 0xf << 8
	ETPS = 0x3 << 12
	ECE  = 1 << 14
	ETP  = 1 << 15

class TIM_DIER(IntEnum):
	UIE   = 1 << 0
	CC1IE = 1 << 1
	CC2IE = 1 << 2
	CC3IE = 1 << 3
	CC4IE = 1 << 4
	COMIE = 1 << 5
	TIE   = 1 << 6
	BIE   = 1 << 7
	UDE   = 1 << 8
	CC1DE = 1 << 9
	CC2DE = 1 << 10
	CC3DE = 1 << 11
	CC4DE = 1 << 12
	COMDE = 1 << 13
	TDE   = 1 << 14

class TIM_SR(IntEnum):
	UIF   = 1 << 0
	CC1IF = 1 << 1
	CC2IF = 1 << 2
	CC3IF = 1 << 3
	CC4IF = 1 << 4
	COMIF = 1 << 5
	TIF   = 1 << 6
	BIF   = 1 << 7
	CC1OF = 1 << 9
	CC2OF = 1 << 10
	CC3OF = 1 << 11
	CC4OF = 1 << 12

class TIM_EGR(IntEnum):
	UG   = 1 << 0
	CC1G = 1 << 1
	CC2G = 1 << 2
	CC3G = 1 << 3
	CC4G = 1 << 4
	COMG = 1 << 5
	TG   = 1 << 6
	BG   = 1 << 7

class TIM_CCMR1(IntEnum):
	CC1S   = 0x3 << 0
	OC1FE  = 1 << 2
	OC1PE  = 1 << 3
	OC1M   = 0x7 << 4
	OC1CE  = 1 << 7
	CC2S   = 0x3 << 8
	OC2FE  = 1 << 10
	OC2PE  = 1 << 11
	OC2M   = 0x7 << 12
	OC2CE  = 1 << 15
	IC1PSC = 0x3 << 2
	IC1F   = 0xf << 4
	IC2PSC = 0x3 << 10
	IC2F   = 0xf << 12

class TIM_CCMR2(IntEnum):
	CC3S   = 0x3 << 0
	OC3FE  = 1 << 2
	OC3PE  = 1 << 3
	OC3M   = 0x7 << 4
	OC3CE  = 1 << 7
	CC4S   = 0x3 << 8
	OC4FE  = 1 << 10
	OC4PE  = 1 << 11
	OC4M   = 0x7 << 12
	OC4CE  = 1 << 15
	IC3PSC = 0x3 << 2
	IC3F   = 0xf << 4
	IC4PSC = 0x3 << 10
	IC4F   = 0xf << 12

class TIM_CCER(IntEnum):
	CC1E  = 1 << 0
	CC1P  = 1 << 1
	CC1NE = 1 << 2
	CC1NP = 1 << 3
	CC2E  = 1 << 4
	CC2P  = 1 << 5
	CC2NE = 1 << 6
	CC2NP = 1 << 7
	CC3E  = 1 << 8
	CC3P  = 1 << 9
	CC3NE = 1 << 10
	CC3NP = 1 << 11
	CC4E  = 1 << 12
	CC4P  = 1 << 13
	CC4NP = 1 << 15

class TIM_CNT(IntEnum):
	CNT = 0xffffffff << 0

class TIM_PSC(IntEnum):
	PSC = 0xffff << 0

class TIM_ARR(IntEnum):
	ARR = 0xffffffff << 0

class TIM_RCR(IntEnum):
	REP = 0xff << 0

class TIM_CCR1(IntEnum):
	CCR1 = 0xffff << 0

class TIM_CCR2(IntEnum):
	CCR2 = 0xffff << 0

class TIM_CCR3(IntEnum):
	CCR3 = 0xffff << 0

class TIM_CCR4(IntEnum):
	CCR4 = 0xffff << 0

class TIM_BDTR(IntEnum):
	DTG  = 0xff << 0
	LOCK = 0x3 << 8
	OSSI = 1 << 10
	OSSR = 1 << 11
	BKE  = 1 << 12
	BKP  = 1 << 13
	AOE  = 1 << 14
	MOE  = 1 << 15

class TIM_DCR(IntEnum):
	DBA = 0x1f << 0
	DBL = 0x1f << 8

class TIM_DMAR(IntEnum):
	DMAB = 0xffff << 0

class TIM_OR(IntEnum):
	TI1_RMP  = 0x3 << 0
	TI4_RMP  = 0x3 << 6
	ITR1_RMP = 0x3 << 10
