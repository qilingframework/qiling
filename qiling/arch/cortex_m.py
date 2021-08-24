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

        ## Memory Model
        self.boot_space = 0

    def get_init_uc(self):
        return Uc(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_MCLASS)

    def step(self):
        self.ql.emu_start(self.get_pc(), 0, count=1)
        self.ql.hw.step()

    def run(self, count=-1, end=None):        
        while count != 0 and self.get_pc() != end:
            self.step()
            count -= 1
    
    def debug_run(self, count):
        self.ql.emu_start(self.get_pc(), 0, count=count)

    def check_thumb(self):
        return UC_MODE_THUMB
