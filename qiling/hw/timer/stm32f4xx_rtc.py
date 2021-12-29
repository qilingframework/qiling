#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import time
import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.stm32f4xx_rtc import RTC_TR, RTC_ISR


class STM32F4xxRtc(QlPeripheral):
    class Type(ctypes.Structure):
        """ the structure is available in :
		        stm32f423xx.h
		        stm32f469xx.h
		        stm32f427xx.h
		        stm32f479xx.h
		        stm32f413xx.h
		        stm32f429xx.h
		        stm32f439xx.h
		        stm32f415xx.h
		        stm32f412cx.h
		        stm32f412rx.h
		        stm32f410tx.h
		        stm32f410cx.h
		        stm32f412zx.h
		        stm32f405xx.h
		        stm32f407xx.h
		        stm32f417xx.h
		        stm32f446xx.h
		        stm32f401xc.h
		        stm32f437xx.h
		        stm32f401xe.h
		        stm32f412vx.h
		        stm32f410rx.h
		        stm32f411xe.h 
		"""

        _fields_ = [
            ('TR'          , ctypes.c_uint32),  # RTC time register,                                        Address offset: 0x00
            ('DR'          , ctypes.c_uint32),  # RTC date register,                                        Address offset: 0x04
            ('CR'          , ctypes.c_uint32),  # RTC control register,                                     Address offset: 0x08
            ('ISR'         , ctypes.c_uint32),  # RTC initialization and status register,                   Address offset: 0x0C
            ('PRER'        , ctypes.c_uint32),  # RTC prescaler register,                                   Address offset: 0x10
            ('WUTR'        , ctypes.c_uint32),  # RTC wakeup timer register,                                Address offset: 0x14
            ('CALIBR'      , ctypes.c_uint32),  # RTC calibration register,                                 Address offset: 0x18
            ('ALRMAR'      , ctypes.c_uint32),  # RTC alarm A register,                                     Address offset: 0x1C
            ('ALRMBR'      , ctypes.c_uint32),  # RTC alarm B register,                                     Address offset: 0x20
            ('WPR'         , ctypes.c_uint32),  # RTC write protection register,                            Address offset: 0x24
            ('SSR'         , ctypes.c_uint32),  # RTC sub second register,                                  Address offset: 0x28
            ('SHIFTR'      , ctypes.c_uint32),  # RTC shift control register,                               Address offset: 0x2C
            ('TSTR'        , ctypes.c_uint32),  # RTC time stamp time register,                             Address offset: 0x30
            ('TSDR'        , ctypes.c_uint32),  # RTC time stamp date register,                             Address offset: 0x34
            ('TSSSR'       , ctypes.c_uint32),  # RTC time-stamp sub second register,                       Address offset: 0x38
            ('CALR'        , ctypes.c_uint32),  # RTC calibration register,                                 Address offset: 0x3C
            ('TAFCR'       , ctypes.c_uint32),  # RTC tamper and alternate function configuration register, Address offset: 0x40
            ('ALRMASSR'    , ctypes.c_uint32),  # RTC alarm A sub second register,                          Address offset: 0x44
            ('ALRMBSSR'    , ctypes.c_uint32),  # RTC alarm B sub second register,                          Address offset: 0x48
            ('RESERVED7'   , ctypes.c_uint32),  # Reserved, 0x4C
            ('BKP0R'       , ctypes.c_uint32),  # RTC backup register 1,                                    Address offset: 0x50
            ('BKP1R'       , ctypes.c_uint32),  # RTC backup register 1,                                    Address offset: 0x54
            ('BKP2R'       , ctypes.c_uint32),  # RTC backup register 2,                                    Address offset: 0x58
            ('BKP3R'       , ctypes.c_uint32),  # RTC backup register 3,                                    Address offset: 0x5C
            ('BKP4R'       , ctypes.c_uint32),  # RTC backup register 4,                                    Address offset: 0x60
            ('BKP5R'       , ctypes.c_uint32),  # RTC backup register 5,                                    Address offset: 0x64
            ('BKP6R'       , ctypes.c_uint32),  # RTC backup register 6,                                    Address offset: 0x68
            ('BKP7R'       , ctypes.c_uint32),  # RTC backup register 7,                                    Address offset: 0x6C
            ('BKP8R'       , ctypes.c_uint32),  # RTC backup register 8,                                    Address offset: 0x70
            ('BKP9R'       , ctypes.c_uint32),  # RTC backup register 9,                                    Address offset: 0x74
            ('BKP10R'      , ctypes.c_uint32),  # RTC backup register 10,                                   Address offset: 0x78
            ('BKP11R'      , ctypes.c_uint32),  # RTC backup register 11,                                   Address offset: 0x7C
            ('BKP12R'      , ctypes.c_uint32),  # RTC backup register 12,                                   Address offset: 0x80
            ('BKP13R'      , ctypes.c_uint32),  # RTC backup register 13,                                   Address offset: 0x84
            ('BKP14R'      , ctypes.c_uint32),  # RTC backup register 14,                                   Address offset: 0x88
            ('BKP15R'      , ctypes.c_uint32),  # RTC backup register 15,                                   Address offset: 0x8C
            ('BKP16R'      , ctypes.c_uint32),  # RTC backup register 16,                                   Address offset: 0x90
            ('BKP17R'      , ctypes.c_uint32),  # RTC backup register 17,                                   Address offset: 0x94
            ('BKP18R'      , ctypes.c_uint32),  # RTC backup register 18,                                   Address offset: 0x98
            ('BKP19R'      , ctypes.c_uint32),  # RTC backup register 19,                                   Address offset: 0x9C
        ]

    def __init__(self, ql, label, wkup_intn=None, alarm_intn=None):
        super().__init__(ql, label)

        self.rtc = self.struct(
            DR   = 0x00002101,
            ISR  = 0x00000007,
            PRER = 0x007F00FF,
            WUTR = 0x0000FFFF,            
        )

        self.wkup_intn = wkup_intn
        self.alarm_intn = alarm_intn

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.rtc) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        if offset == self.struct.ISR.offset:
            for bitmask in [
                RTC_ISR.TAMP1F, 
                RTC_ISR.TSOVF, 
                RTC_ISR.TSF, 
                RTC_ISR.WUTF, 
                RTC_ISR.ALRBF, 
                RTC_ISR.ALRAF, 
                RTC_ISR.RSF
            ]:
                if value & bitmask == 0:
                    self.rtc.ISR &= ~bitmask

            self.rtc.ISR = (self.rtc.ISR & ~RTC_ISR.INIT) | (value & RTC_ISR.INIT)            
            return

        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.rtc) + offset, data, size)    

    def step(self):
        if self.rtc.ISR & RTC_ISR.INIT:
            self.rtc.ISR |= RTC_ISR.INITF

        self.rtc.ISR |= RTC_ISR.RSF
