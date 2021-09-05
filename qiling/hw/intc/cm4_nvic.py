#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.arch.arm_const import IRQ, EXC_RETURN
from qiling.const import QL_VERBOSE


class CortexM4Nvic(QlPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ('ISER'     , ctypes.c_uint32 * 8),
            ('RESERVED0', ctypes.c_uint32 * 24),
            ('ICER'     , ctypes.c_uint32 * 8),
            ('RESERVED1', ctypes.c_uint32 * 24),
            ('ISPR'     , ctypes.c_uint32 * 8),
            ('RESERVED2', ctypes.c_uint32 * 24),
            ('ICPR'     , ctypes.c_uint32 * 8),
            ('RESERVED3', ctypes.c_uint32 * 24),
            ('IABR'     , ctypes.c_uint32 * 8),
            ('RESERVED4', ctypes.c_uint32 * 56),
            ('IPR'      , ctypes.c_uint8  * 240),
            ('RESERVED5', ctypes.c_uint32 * 644),
            ('STIR'     , ctypes.c_uint32 * 8),
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)
        
        # reference:
        # https://www.youtube.com/watch?v=uFBNf7F3l60
        # https://developer.arm.com/documentation/ddi0439/b/Nested-Vectored-Interrupt-Controller 
        
        self.nvic = self.struct()

        ## The max number of interrupt request
        self.IRQN_MAX = self.struct.ISER.size * 8

        ## The ISER unit size
        self.MASK     = self.IRQN_MAX // len(self.nvic.ISER) - 1
        self.OFFSET   = self.MASK.bit_length()

        ## special write behavior
        self.triggers = [
            (self.struct.ISER, self.enable),
            (self.struct.ICER, self.disable),
            (self.struct.ISPR, self.set_pending),
            (self.struct.ICPR, self.clear_pending),
        ]

        self.intrs = []
        self.reg_context = ['xpsr', 'pc', 'lr', 'r12', 'r3', 'r2', 'r1', 'r0']

    def enable(self, IRQn):
        if IRQn >= 0:
            self.nvic.ISER[IRQn >> self.OFFSET] |= 1 << (IRQn & self.MASK)
            self.nvic.ICER[IRQn >> self.OFFSET] |= 1 << (IRQn & self.MASK)
        else:
            self.ql.hw.scb.enable(IRQn)

    def disable(self, IRQn):
        if IRQn >= 0:
            self.nvic.ISER[IRQn >> self.OFFSET] &= self.MASK ^ (1 << (IRQn & self.MASK))
            self.nvic.ICER[IRQn >> self.OFFSET] &= self.MASK ^ (1 << (IRQn & self.MASK))
        else:
            self.ql.hw.scb.disable(IRQn)

    def get_enable(self, IRQn):
        if IRQn >= 0:
            return (self.nvic.ISER[IRQn >> self.OFFSET] >> (IRQn & self.MASK)) & 1
        else:
            return self.ql.hw.scb.get_enable(IRQn)

    def set_pending(self, IRQn):
        if IRQn >= 0:
            self.nvic.ISPR[IRQn >> self.OFFSET] |= 1 << (IRQn & self.MASK)
            self.nvic.ICPR[IRQn >> self.OFFSET] |= 1 << (IRQn & self.MASK)
        else:
            self.ql.hw.scb.set_pending(IRQn)
        
        if self.get_enable(IRQn):
            if self.is_configurable(IRQn) and (self.ql.reg.read('primask') & 0x1):
                return
            
            if IRQn != IRQ.NMI and (self.ql.reg.read('faultmask') & 0x1):
                return

            basepri = self.ql.reg.read('basepri') & 0xf0
            if basepri != 0 and basepri >= self.get_priority(IRQn):
                return

            self.intrs.append(IRQn)

    def clear_pending(self, IRQn):
        if IRQn >= 0:
            self.nvic.ISPR[IRQn >> self.OFFSET] &= self.MASK ^ (1 << (IRQn & self.MASK))
            self.nvic.ICPR[IRQn >> self.OFFSET] &= self.MASK ^ (1 << (IRQn & self.MASK))
        else:
            self.ql.hw.scb.clear_pending(IRQn)

    def get_pending(self, IRQn):
        if IRQn >= 0:
            return (self.nvic.ISER[IRQn >> self.OFFSET] >> (IRQn & self.MASK)) & 1
        else:
            return self.ql.hw.scb.get_pending(IRQn)

    def get_priority(self, IRQn):
        if IRQn >= 0:
            return self.nvic.IPR[IRQn]
        else:
            return self.ql.hw.scb.get_priority(IRQn)

    def is_configurable(self, IRQn):
        return IRQn > IRQ.HARD_FAULT

    def enter_intr(self):
        for reg in self.reg_context:
            val = self.ql.reg.read(reg)
            self.ql.arch.stack_push(val)
        
        if self.ql.verbose >= QL_VERBOSE.DISASM:
            self.ql.log.info(f'Enter into interrupt {self.intrs}')

    def exit_intr(self):
        if self.ql.arch.get_pc() & EXC_RETURN.RETURN_SP:
            self.ql.reg.write('control', 0b010)            
        else:
            self.ql.reg.write('control', 0b000)

        self.ql.reg.write('ipsr', 0)

        for reg in reversed(self.reg_context):
            val = self.ql.arch.stack_pop()
            if reg == 'xpsr':                
                self.ql.reg.write('xpsr_cond', val)                
            else:
                self.ql.reg.write(reg, val)

        self.intrs.clear()        

        if self.ql.verbose >= QL_VERBOSE.DISASM:
            self.ql.log.info('Exit from interrupt')

    def handle_interupt(self, IRQn):

        isr = IRQn + 16
        offset = isr << 2
        entry = self.ql.mem.read_ptr(offset)
        exc_return = 0xFFFFFFFD if self.ql.arch.using_psp() else 0xFFFFFFF9

        self.clear_pending(IRQn)
        self.ql.reg.write('ipsr', isr)                

        self.ql.reg.write('pc', entry)
        self.ql.reg.write('lr', exc_return) 

        self.ql.emu_start(self.ql.arch.get_pc(), 0)
        
    def step(self):
        if not self.intrs:
            return
        
        self.intrs.sort(key=lambda x: self.get_priority(x))
        self.enter_intr()
                        
        for IRQn in self.intrs:            
            self.handle_interupt(IRQn)            

        self.exit_intr()

    def read(self, offset, size):
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.nvic) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    def write(self, offset, size, value):
        def write_byte(ofs, byte):
            for var, func in self.triggers:
                if var.offset <= ofs < var.offset + var.size:
                    for i in range(8):
                        if (byte >> i) & 1:
                            func(i + (ofs - var.offset) * 8)
                    break
            else:
                ipr = self.struct.IPR
                if ipr.offset <= ofs < ipr.offset + ipr.size:
                    byte &= 0xf0 # IPR[3: 0] reserved
                
                ctypes.memmove(ctypes.addressof(self.nvic) + ofs, bytes([byte]), 1)                

        for ofs in range(offset, offset + size):
            write_byte(ofs, value & 0xff)
            value >>= 8

    @property
    def region(self):
        return [(0, self.struct.RESERVED5.offset), (self.struct.STIR.offset, ctypes.sizeof(self.struct))]