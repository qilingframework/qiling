#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_MCLASS, UC_MODE_THUMB
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_MCLASS, CS_MODE_THUMB
from keystone import Ks, KS_ARCH_ARM, KS_MODE_ARM, KS_MODE_THUMB

from qiling.const import QL_VERBOSE
from qiling.exception import QlErrorNotImplemented

from .arm import QlArchARM
from .arm_const import IRQ, EXC_RETURN, CONTROL, EXCP


class QlArchCORTEX_M(QlArchARM):
    def __init__(self, ql):
        super().__init__(ql)

        self.reg_context = ['xpsr', 'pc', 'lr', 'r12', 'r3', 'r2', 'r1', 'r0']

        def intr_cb(ql, intno):
            if intno == EXCP.SWI:
                ql.hw.nvic.set_pending(IRQ.SVCALL)                    

            elif intno == EXCP.EXCEPTION_EXIT:
                ql.emu_stop()            
            
            else:
                raise QlErrorNotImplemented(f'Unhandled interrupt number ({intno})')

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

    def enter_intr(self):
        # Save Stack
        for reg in self.reg_context:
            val = self.ql.reg.read(reg)
            self.ql.arch.stack_push(val)
        
        if self.ql.verbose >= QL_VERBOSE.DISASM:
            self.ql.log.info(f'Enter into interrupt')

    def exit_intr(self):
        # Exit handler mode
        self.ql.reg.write('ipsr', 0)

        # switch the stack accroding exc_return
        old_ctrl = self.ql.reg.read('control')
        if self.ql.arch.get_pc() & EXC_RETURN.RETURN_SP:
            self.ql.reg.write('control', old_ctrl |  CONTROL.SPSEL)            
        else:
            self.ql.reg.write('control', old_ctrl & ~CONTROL.SPSEL)

        # Restore stack
        for reg in reversed(self.reg_context):
            val = self.ql.arch.stack_pop()
            if reg == 'xpsr':                
                self.ql.reg.write('XPSR_NZCVQG', val)
            else:
                self.ql.reg.write(reg, val)        

        if self.ql.verbose >= QL_VERBOSE.DISASM:
            self.ql.log.info('Exit from interrupt')

    def handle_interupt(self, IRQn):
        if IRQn > IRQ.HARD_FAULT and (self.ql.reg.read('primask') & 0x1):
            return
            
        if IRQn != IRQ.NMI and (self.ql.reg.read('faultmask') & 0x1):
            return

        basepri = self.ql.reg.read('basepri') & 0xf0
        if basepri != 0 and basepri <= self.ql.hw.nvic.get_priority(IRQn):
            return

        if self.ql.verbose >= QL_VERBOSE.DISASM:
            self.ql.log.info(f'Handle the IRQn: {IRQn}')

        isr = IRQn + 16
        offset = isr << 2

        entry = self.ql.mem.read_ptr(offset)
        exc_return = 0xFFFFFFFD if self.ql.arch.using_psp() else 0xFFFFFFF9        

        # Enter handler mode
        self.ql.reg.write('ipsr', isr)                

        self.ql.reg.write('pc', entry)
        self.ql.reg.write('lr', exc_return) 

        self.ql.emu_start(self.ql.arch.get_pc(), 0)
