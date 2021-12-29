#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes
from typing import Optional
from qiling.core import Qiling

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.timer.timer import QlTimerPeripheral
from qiling.hw.const.stm32f4xx_tim import TIM_DIER, TIM_SR, TIM_CR1


class STM32F4xxTim(QlTimerPeripheral):
    class Type(ctypes.Structure):
        """ the structure available in :
                stm32f401xc
                stm32f401xe
                stm32f405xx
                stm32f407xx
                stm32f410cx
                stm32f410rx
                stm32f410tx
                stm32f411xe
                stm32f412cx
                stm32f412rx
                stm32f412vx
                stm32f412zx
                stm32f413xx
                stm32f415xx
                stm32f417xx
                stm32f423xx
                stm32f427xx
                stm32f429xx
                stm32f437xx
                stm32f439xx
                stm32f446xx
                stm32f469xx
                stm32f479xx
        """

        _fields_ = [
            ("CR1"  , ctypes.c_uint32), #TIM control register 1,              Address offset: 0x00
            ("CR2"  , ctypes.c_uint32), #TIM control register 2,              Address offset: 0x04
            ("SMCR" , ctypes.c_uint32), #TIM slave mode control register,     Address offset: 0x08
            ("DIER" , ctypes.c_uint32), #TIM DMA/interrupt enable register,   Address offset: 0x0C
            ("SR"   , ctypes.c_uint32), #TIM status register,                 Address offset: 0x10
            ("EGR"  , ctypes.c_uint32), #TIM event generation register,       Address offset: 0x14
            ("CCMR1", ctypes.c_uint32), #TIM capture/compare mode register 1, Address offset: 0x18
            ("CCMR2", ctypes.c_uint32), #TIM capture/compare mode register 2, Address offset: 0x1C
            ("CCER" , ctypes.c_uint32), #TIM capture/compare enable register, Address offset: 0x20
            ("CNT"  , ctypes.c_uint32), #TIM counter register,                Address offset: 0x24
            ("PSC"  , ctypes.c_uint32), #TIM prescaler,                       Address offset: 0x28
            ("ARR"  , ctypes.c_uint32), #TIM auto-reload register,            Address offset: 0x2C
            ("RCR"  , ctypes.c_uint32), #TIM repetition counter register,     Address offset: 0x30
            ("CCR1" , ctypes.c_uint32), #TIM capture/compare register 1,      Address offset: 0x34
            ("CCR2" , ctypes.c_uint32), #TIM capture/compare register 2,      Address offset: 0x38
            ("CCR3" , ctypes.c_uint32), #TIM capture/compare register 3,      Address offset: 0x3C
            ("CCR4" , ctypes.c_uint32), #TIM capture/compare register 4,      Address offset: 0x40
            ("BDTR" , ctypes.c_uint32), #TIM break and dead-time register,    Address offset: 0x44
            ("DCR"  , ctypes.c_uint32), #TIM DMA control register,            Address offset: 0x48
            ("DMAR" , ctypes.c_uint32), #TIM DMA address for full transfer,   Address offset: 0x4C
            ("OR"   , ctypes.c_uint32), #TIM option register,                 Address offset: 0x50
        ]

    def __init__(self, ql: Qiling, label: str, 
            brk_tim9_intn: Optional[int] = None, 
            cc_intn: Optional[int] = None,
            trg_com_tim11_intn: Optional[int] = None,
            up_tim10_intn: Optional[int] = None):

        super().__init__(ql, label)

        self.brk_tim9_intn = brk_tim9_intn
        self.cc_intn = cc_intn
        self.trg_com_tim11_intn = trg_com_tim11_intn
        self.up_tim10_intn = up_tim10_intn
        
        self.prescale_count = 0
        self.tim = self.struct()

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.tim) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.tim) + offset, data, size)

    def send_update_interrupt(self):
        if self.up_tim10_intn is None:
            return

        if not self.tim.DIER & TIM_DIER.UIE:
            return

        self.tim.SR |= TIM_SR.UIF
        self.ql.hw.nvic.set_pending(self.up_tim10_intn)

    def set_ratio(self, ratio):
        self.tim.CNT = 0
        self.prescale_count = 0

        self._ratio = ratio

    @property
    def ratio(self):
        return max(round(self._ratio / (self.tim.PSC + 1)), 1)

    @property
    def prescale(self):
        return max(round((self.tim.PSC + 1) / self._ratio) - 1, 0)

    def step(self):
        if self.tim.CR1 & TIM_CR1.CEN:
            if self.tim.CNT >= self.tim.ARR:
                self.tim.CNT = 0
                self.prescale_count = 0
                self.send_update_interrupt()

            elif self.prescale_count == self.prescale:
                self.prescale_count = 0
                self.tim.CNT += self.ratio

            else:
                self.prescale_count += 1
