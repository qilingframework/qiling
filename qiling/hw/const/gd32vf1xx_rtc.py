#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from enum import IntEnum


class INTEN(IntEnum):
    OVIE   = 0x1 << 2   # Overflow interrupt enable
    ALRMIE = 0x1 << 1   # Alarm interrupt enable
    SCIE   = 0x1 << 0   # Second interrupt

class CTL(IntEnum):
    LWOFF  = 0x1 << 5   # Last write operation finished flag
    CMF    = 0x1 << 4   # Configuration mode flag
    RSYNF  = 0x1 << 3   # Registers synchronized flag
    OVIF   = 0x1 << 2   # Overflow interrupt flag
    ALRMIF = 0x1 << 1   # Alarm interrupt flag
    SCIF   = 0x1 << 0   # Sencond interrupt flag

class PSCH(IntEnum):
    PSC = 0xf << 0   # RTC prescaler value high

class PSCL(IntEnum):
    PSC = 0xffff << 0   # RTC prescaler value low

class DIVH(IntEnum):
    DIV = 0xf << 0   # RTC divider value high

class DIVL(IntEnum):
    DIV = 0xffff << 0   # RTC divider value low

class CNTH(IntEnum):
    CNT = 0xffff << 0   # RTC counter value high

class CNTL(IntEnum):
    CNT = 0xffff << 0   # RTC counter value low

class ALRMH(IntEnum):
    ALRM = 0xffff << 0   # Alarm value high

class ALRML(IntEnum):
    ALRM = 0xffff << 0   # alarm value low

