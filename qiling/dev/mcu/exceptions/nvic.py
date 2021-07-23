#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import struct
from unicorn.unicorn import UcError

from .manager import ExceptionManager

class NVIC(ExceptionManager):    
    def __init__(self, ql):
        super().__init__(ql)
        
        # reference:
        # https://www.youtube.com/watch?v=uFBNf7F3l60
        # https://developer.arm.com/documentation/ddi0439/b/Nested-Vectored-Interrupt-Controller
        
        self.INTR_NUM = 256
        self.IRQN_OFFSET = 16

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

    def writeDoubleWord(self, offset, value):
        def wrapper(list, value):
            def function(offset, index):
                for i in range(32):
                    if index >> i & 1:
                        list[offset + i + self.IRQN_OFFSET] = value
            return function

        set_enable    = wrapper(self.enable , 1)
        clear_enable  = wrapper(self.enable , 0)
        set_pending   = wrapper(self.pending, 1)
        clear_pending = wrapper(self.pending, 0)

        # active bits is read only
        
        if   0x000 <= offset <= 0x01C:
            set_enable((offset - 0x000) * 32, value)

        elif 0x080 <= offset <= 0x09C:
            clear_enable((offset - 0x080) * 32, value)

        elif 0x100 <= offset <= 0x11C:
            set_pending((offset - 0x100) * 32, value)

        elif 0x180 <= offset <= 0x19C:
            clear_pending((offset - 0x180) * 32, value)

        elif 0x300 <= offset <= 0x3EC:
            offset -= 0x300
            for i in range(4):
                index = offset + i + self.IRQN_OFFSET
                prior = struct.unpack('b', struct.pack('B', (value >> i) & 255))[0]
                self.priority[index] = prior
