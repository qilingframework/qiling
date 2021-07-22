#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from sys import intern
from unicorn.unicorn import UcError

from .manager import ExceptionManager

class NVIC(ExceptionManager):    
    def __init__(self, ql):
        super().__init__(ql)
        
        # reference:
        # https://www.youtube.com/watch?v=uFBNf7F3l60
        # https://developer.arm.com/documentation/ddi0439/b/Nested-Vectored-Interrupt-Controller
        
        self.INTR_NUM = 256
        self.enable   = [0] * self.INTR_NUM
        self.pending  = [0] * self.INTR_NUM
        self.active   = [0] * self.INTR_NUM
        self.priority = [0] * self.INTR_NUM

        default_config = [
            # (Number, Priority)
            (1, -3), # Reset
            (2, -2), # NMI
            (3, -1), # Hard fault
            (4,  0), # Memory management fault
            (5,  0), # Bus fault
            (6,  0), # Usage fault
            (11, 0), # SVCall
            (14, 0), # PendSV
            (15, 0), # SysTick
        ]
        for intrn, pri in default_config:
            self.enable[intrn] = 1
            self.priority[intrn] = pri        
        
        self.reg_context = ['xpsr', 'pc', 'lr', 'r12', 'r3', 'r2', 'r1', 'r0']

    def send_interrupt(self, isr_number):
        self.pending[isr_number] = 1

    def handle_interupt(self, offset):
        self.ql.log.debug('Enter Interrupt')
        address = self.ql.arch.boot_space + offset
        entry = self.ql.mem.read_ptr(address)

        ## TODO: handle other exceptionreturn behavior
        self.EXC_RETURN = 0xFFFFFFF9

        self.ql.reg.write('pc', entry)
        self.ql.reg.write('lr', self.EXC_RETURN)

        try:
            self.ql.emu_start(self.ql.arch.get_pc(), self.EXC_RETURN)
        ## TODO: Delete after fixing unicorn bug        
        except UcError:
            pass

        self.ql.log.debug('Exit Interrupt')

    def save_regs(self):
        for reg in self.reg_context:
            if reg == 'xpsr':
                ipsr = self.ql.reg.read('ipsr')
                apsr = self.ql.reg.read('apsr')
                epsr = 0x01000000
                val = ipsr | apsr | epsr
            else:
                val = self.ql.reg.read(reg)

            self.ql.arch.stack_push(val)

    def restore_regs(self):
        for reg in reversed(self.reg_context):
            val = self.ql.arch.stack_pop()
            if reg == 'xpsr':
                self.ql.reg.write('ipsr', val & 0x000001ff)
                self.ql.reg.write('apsr', val & 0xf80f0000)
                # self.ql.reg.write('epsr', val & 0x0600fc00)
            else:
                self.ql.reg.write(reg, val)

    def interrupt(self):
        self.save_regs()

        intrs = [i for i in range(self.INTR_NUM) if (self.pending[i] == 1 and self.enable[i])]
        intrs.sort(key=lambda x: self.priority[x])
                
        for isr_number in intrs:
            self.pending[isr_number] = 0
            self.active[isr_number] = 1
            self.ql.reg.write('ipsr', isr_number)
            self.handle_interupt(isr_number << 2)
            self.active[isr_number] = 0

        self.restore_regs()
