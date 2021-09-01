#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_MCLASS, UC_MODE_THUMB
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_MCLASS, CS_MODE_THUMB
from keystone import Ks, KS_ARCH_ARM, KS_MODE_ARM, KS_MODE_THUMB

from .arm import QlArchARM
from .arm_const import reg_map
from .cm_const import IRQ, MODE

class QlArchCORTEX_M(QlArchARM):
    def __init__(self, ql):
        super().__init__(ql)

        self.mode = MODE.THREAD
        self.register_msp()

        ## something strange thing happened
        def intr_cb(ql, intno):
            if ql.arch.mode == MODE.HANDLER:
                if intno == 8:
                    ql.emu_stop()
            
            elif ql.arch.mode == MODE.THREAD:
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
        while count != 0:
            if self.get_pc() == end:
                break

            self.step()
            count -= 1

    def exc_return(self):
        if self.ql.reg.uc_sp == reg_map['msp']:
            return 0xFFFFFFF9
        
        elif self.ql.reg.uc_sp == reg_map['psp']:
            return 0xFFFFFFFD

    def register_msp(self):
        self.ql.reg.register_sp(reg_map['msp'])

    def register_psp(self):
        self.ql.reg.register_sp(reg_map['psp'])
