#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import *

from qiling.const import *
from qiling.dev.peripheral.systick_timer import SysTickTimer
from qiling.dev.mcu.exceptions.nvic import NVIC

from .arm import QlArchARM

class QlArchCORTEX_M(QlArchARM):
    def __init__(self, ql):
        super().__init__(ql)

        ## Exception Model
        self.nvic = NVIC(self.ql)

        ## Memory Model
        self.BOOT = [0, 0]
        self.boot_space = 0
        
        self.peripherals = [
            SysTickTimer(ql)
        ]

    def get_init_uc(self):
        return Uc(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_MCLASS)

    def step(self):
        self.nvic.interrupt()
        self.ql.emu_start(self.get_pc(), 0, count=1)
        for perip in self.peripherals:
            perip.step()

    def run(self, count=-1):        
        while count != 0:
            self.step()
            count -= 1

    def check_thumb(self):
        return UC_MODE_THUMB
