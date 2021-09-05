#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_MCLASS, UC_MODE_THUMB
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_MCLASS, CS_MODE_THUMB
from keystone import Ks, KS_ARCH_ARM, KS_MODE_ARM, KS_MODE_THUMB

from .arm import QlArchARM
from .arm_const import IRQ, CONTROL

class QlArchCORTEX_M(QlArchARM):
    def __init__(self, ql):
        super().__init__(ql)

        ## something strange thing happened
        def intr_cb(ql, intno):
            if self.is_handler_mode():
                if intno == 8:
                    ql.emu_stop()
            
            else:
                if intno == 2:
                    ql.hw.nvic.set_pending(IRQ.SVCALL)                    
                else:
                    print(intno)
                    exit(0)

        self.intr_cb = intr_cb

    def get_init_uc(self):
        return Uc(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_MCLASS + UC_MODE_THUMB)

    def create_disassembler(self) -> Cs:
        return Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_MCLASS + CS_MODE_THUMB)

    def create_assembler(self) -> Ks:
        return Ks(KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_THUMB)
    
    def check_thumb(self):
        return UC_MODE_THUMB

    def step(self):
        self.ql.emu_start(self.get_pc(), 0, count=1)
        self.ql.hw.step()

    def run(self, count=-1, end=None):
        if type(end) is int:
            end |= 1
        
        while count != 0:
            if self.get_pc() == end:
                break

            self.step()
            count -= 1

    def is_handler_mode(self):
        return self.ql.reg.read('ipsr') > 1

    def using_psp(self):
        return not self.is_handler_mode() and (self.ql.reg.read('control') & CONTROL.SPSEL) > 0
