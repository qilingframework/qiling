#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import *

from qiling.const import *
from qiling.mcu.peripheral.systick_timer import SysTickTimer
from qiling.mcu.exceptions.manager import ExceptionManager
from .arm import QlArchARM

class QlArchCORTEX_M(QlArchARM):
    def __init__(self, ql):
        super().__init__(ql)

        #self.ql.create_disassembler()

        ## Exception Model
        self.emgr = ExceptionManager(self)

        ## Memory Model
        self.BOOT = [0, 0]
        self.boot_space = 0
        
        self.peripherals = [
            SysTickTimer(self)
        ]

    def get_init_uc(self):
        return Uc(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_MCLASS)
        
    def step(self):
        self.emgr.interrupt()
        self.ql.emu_start(self.get_pc(), 0, count=1)
        for perip in self.peripherals:
            perip.step()

    def run(self, count=-1):        
        while count != 0:
            self.step()
            count -= 1

    def check_thumb(self):
        ## FIXME: unicorn do not implement epsr
        return UC_MODE_THUMB

    @property
    def reg(self):
        return self.ql.reg
    
    @property
    def mem(self):
        return self.ql.mem