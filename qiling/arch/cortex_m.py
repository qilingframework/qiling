#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import *
from qiling.const import *
from .arm import QlArchARM


class QlArchCORTEX_M(QlArchARM):
    def __init__(self, ql):
        super().__init__(ql)

        ## Core Hardwares
        self.ql.hw.create('NVIC'   , 'intc'   , [(0xE000E100, 0xE000E4F0), (0xE000EF00, 0xE000EF04)])
        self.ql.hw.create('SCB'    , 'sysctrl', (0xE000ED00, 0xE000ED3F))
        self.ql.hw.create('SysTick', 'systick', (0xE000E010, 0xE000E020))

        ## Memory Model
        self.BOOT = [0, 0]
        self.boot_space = 0
        
        ## load from profile
        self.mapinfo = {}
        self.perip_region = {}

    def get_init_uc(self):
        return Uc(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_MCLASS)

    def step(self):
        self.ql.emu_start(self.get_pc(), 0, count=1)
        self.ql.hw.step()

    def run(self, count=-1, end=None):        
        while count != 0 and self.get_pc() != end:
            self.step()
            count -= 1

    def check_thumb(self):
        return UC_MODE_THUMB
