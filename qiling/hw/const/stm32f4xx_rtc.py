#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from enum import IntEnum


class RTC_TR(IntEnum):
	PM  = 1 << 22
	HT  = 0x3 << 20
	HU  = 0xf << 16
	MNT = 0x7 << 12
	MNU = 0xf << 8
	ST  = 0x7 << 4
	SU  = 0xf << 0

class RTC_DR(IntEnum):
	YT  = 0xf << 20
	YU  = 0xf << 16
	WDU = 0x7 << 13
	MT  = 1 << 12
	MU  = 0xf << 8
	DT  = 0x3 << 4
	D   = 0xf << 0

class RTC_CR(IntEnum):
	COE     = 1 << 23
	OSEL    = 0x3 << 21
	POL     = 1 << 20
	COSEL   = 1 << 19
	BKP     = 1 << 18
	SUB1H   = 1 << 17
	ADD1H   = 1 << 16
	TSIE    = 1 << 15
	WUTIE   = 1 << 14
	ALRBIE  = 1 << 13
	ALRAIE  = 1 << 12
	TSE     = 1 << 11
	WUTE    = 1 << 10
	ALRBE   = 1 << 9
	ALRAE   = 1 << 8
	DCE     = 1 << 7
	FMT     = 1 << 6
	BYPSHAD = 1 << 5
	REFCKON = 1 << 4
	TSEDGE  = 1 << 3
	WUCKSEL = 0x7 << 0

class RTC_ISR(IntEnum):
	RECALPF = 1 << 16
	TAMP1F  = 1 << 13
	TAMP2F  = 1 << 14
	TSOVF   = 1 << 12
	TSF     = 1 << 11
	WUTF    = 1 << 10
	ALRBF   = 1 << 9
	ALRAF   = 1 << 8
	INIT    = 1 << 7
	INITF   = 1 << 6
	RSF     = 1 << 5
	INITS   = 1 << 4
	SHPF    = 1 << 3
	WUTWF   = 1 << 2
	ALRBWF  = 1 << 1
	ALRAWF  = 1 << 0

class RTC_PRER(IntEnum):
	PREDIV_A = 0x7f << 16
	PREDIV_S = 0x7fff << 0

class RTC_WUTR(IntEnum):
	WUT = 0xffff << 0

class RTC_CALIBR(IntEnum):
	DCS = 1 << 7
	DC  = 0x1f << 0

class RTC_ALRMAR(IntEnum):
	MSK4  = 1 << 31
	WDSEL = 1 << 30
	DT    = 0x3 << 28
	D     = 0xf << 24
	MSK3  = 1 << 23
	PM    = 1 << 22
	HT    = 0x3 << 20
	HU    = 0xf << 16
	MSK2  = 1 << 15
	MNT   = 0x7 << 12
	MNU   = 0xf << 8
	MSK1  = 1 << 7
	ST    = 0x7 << 4
	SU    = 0xf << 0

class RTC_ALRMBR(IntEnum):
	MSK4  = 1 << 31
	WDSEL = 1 << 30
	DT    = 0x3 << 28
	D     = 0xf << 24
	MSK3  = 1 << 23
	PM    = 1 << 22
	HT    = 0x3 << 20
	HU    = 0xf << 16
	MSK2  = 1 << 15
	MNT   = 0x7 << 12
	MNU   = 0xf << 8
	MSK1  = 1 << 7
	ST    = 0x7 << 4
	SU    = 0xf << 0

class RTC_WPR(IntEnum):
	KEY = 0xff << 0

class RTC_SSR(IntEnum):
	SS = 0xffff << 0

class RTC_SHIFTR(IntEnum):
	SUBFS = 0x7fff << 0
	ADD1S = 1 << 31

class RTC_TSTR(IntEnum):
	PM  = 1 << 22
	HT  = 0x3 << 20
	HU  = 0xf << 16
	MNT = 0x7 << 12
	MNU = 0xf << 8
	ST  = 0x7 << 4
	SU  = 0xf << 0

class RTC_TSDR(IntEnum):
	WDU = 0x7 << 13
	MT  = 1 << 12
	MU  = 0xf << 8
	DT  = 0x3 << 4
	D   = 0xf << 0

class RTC_TSSSR(IntEnum):
	SS = 0xffff << 0

class RTC_CALR(IntEnum):
	CALP   = 1 << 15
	CALW8  = 1 << 14
	CALW16 = 1 << 13
	CALM   = 0x1ff << 0

class RTC_TAFCR(IntEnum):
	ALARMOUTTYPE = 1 << 18
	TSINSEL      = 1 << 17
	TAMP1INSEL   = 1 << 16
	TAMPPUDIS    = 1 << 15
	TAMPPRCH     = 0x3 << 13
	TAMPFLT      = 0x3 << 11
	TAMPFREQ     = 0x7 << 8
	TAMPTS       = 1 << 7
	TAMP2TRG     = 1 << 4
	TAMP2E       = 1 << 3
	TAMPIE       = 1 << 2
	TAMP1TRG     = 1 << 1
	TAMP1E       = 1 << 0

class RTC_ALRMASSR(IntEnum):
	MASKSS = 0xf << 24
	SS     = 0x7fff << 0

class RTC_ALRMBSSR(IntEnum):
	MASKSS = 0xf << 24
	SS     = 0x7fff << 0
