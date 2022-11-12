#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from functools import cached_property
from contextlib import ContextDecorator

from unicorn import UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_MCLASS, UC_MODE_THUMB
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_MCLASS, CS_MODE_THUMB
from keystone import Ks, KS_ARCH_ARM, KS_MODE_ARM, KS_MODE_THUMB

from qiling import Qiling
from qiling.arch.arm import QlArchARM
from qiling.arch import cortex_m_const
from qiling.arch.register import QlRegisterManager
from qiling.arch.cortex_m_const import IRQ, EXC_RETURN, CONTROL, EXCP
from qiling.const import QL_ARCH, QL_ENDIAN, QL_VERBOSE
from qiling.exception import QlErrorNotImplemented
from qiling.extensions.multitask import MultiTaskUnicorn


class QlInterruptContext(ContextDecorator):
    def __init__(self, ql: Qiling):
        self.ql = ql
        self.reg_context = ['xpsr', 'pc', 'lr', 'r12', 'r3', 'r2', 'r1', 'r0']

    def __enter__(self):
        for reg in self.reg_context:
            val = self.ql.arch.regs.read(reg)
            self.ql.arch.stack_push(val)

        if self.ql.verbose >= QL_VERBOSE.DISASM:
            self.ql.log.info(f'Enter into interrupt')

    def __exit__(self, *exc):
        retval = self.ql.arch.effective_pc
        if retval & EXC_RETURN.MASK != EXC_RETURN.MASK:
            self.ql.log.warning('Interrupt Crash')
            self.ql.stop()

        else:
            # Exit handler mode
            self.ql.arch.regs.write('ipsr', 0)

            # switch the stack accroding exc_return
            old_ctrl = self.ql.arch.regs.read('control')
            if retval & EXC_RETURN.RETURN_SP:
                self.ql.arch.regs.write('control', old_ctrl | CONTROL.SPSEL)
            else:
                self.ql.arch.regs.write('control', old_ctrl & ~CONTROL.SPSEL)

            # Restore stack
            for reg in reversed(self.reg_context):
                val = self.ql.arch.stack_pop()
                if reg == 'xpsr':
                    self.ql.arch.regs.write('XPSR_NZCVQG', val)
                else:
                    self.ql.arch.regs.write(reg, val)

        if self.ql.verbose >= QL_VERBOSE.DISASM:
            self.ql.log.info('Exit from interrupt')


class QlArchCORTEX_M(QlArchARM):
    type = QL_ARCH.CORTEX_M
    bits = 32

    def __init__(self, ql: Qiling):
        super().__init__(ql, endian=QL_ENDIAN.EL, thumb=True)

    @cached_property
    def uc(self):
        return MultiTaskUnicorn(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_MCLASS + UC_MODE_THUMB, 10)

    @cached_property
    def regs(self) -> QlRegisterManager:
        regs_map = cortex_m_const.reg_map
        pc_reg = 'pc'
        sp_reg = 'sp'

        return QlRegisterManager(self.uc, regs_map, pc_reg, sp_reg)

    @cached_property
    def disassembler(self) -> Cs:
        return Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_MCLASS + CS_MODE_THUMB)

    @cached_property
    def assembler(self) -> Ks:
        return Ks(KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_THUMB)

    @property
    def is_thumb(self) -> bool:
        return True

    @property
    def endian(self) -> QL_ENDIAN:
        return QL_ENDIAN.EL

    def is_handler_mode(self):
        return self.regs.ipsr > 1

    def using_psp(self):
        return not self.is_handler_mode() and (self.regs.control & CONTROL.SPSEL) > 0

    def init_context(self):
        self.regs.lr = 0xffffffff
        self.regs.msp = self.ql.mem.read_ptr(0x0)
        self.regs.pc = self.ql.mem.read_ptr(0x4)

    def unicorn_exception_handler(self, ql, intno):
        forward_mapper = {
            EXCP.UDEF           : IRQ.HARD_FAULT,    # undefined instruction
            EXCP.SWI            : IRQ.SVCALL,        # software interrupt
            EXCP.PREFETCH_ABORT : IRQ.HARD_FAULT,
            EXCP.DATA_ABORT     : IRQ.HARD_FAULT,
            EXCP.EXCEPTION_EXIT : IRQ.NOTHING,
            # EXCP.KERNEL_TRAP    : IRQ.NOTHING,
            # EXCP.HVC            : IRQ.NOTHING,
            # EXCP.HYP_TRAP       : IRQ.NOTHING,
            # EXCP.SMC            : IRQ.NOTHING,
            # EXCP.VIRQ           : IRQ.NOTHING,
            # EXCP.VFIQ           : IRQ.NOTHING,
            # EXCP.SEMIHOST       : IRQ.NOTHING,
            EXCP.NOCP           : IRQ.USAGE_FAULT,   # v7M NOCP UsageFault
            EXCP.INVSTATE       : IRQ.USAGE_FAULT,   # v7M INVSTATE UsageFault
            EXCP.STKOF          : IRQ.USAGE_FAULT,   # v8M STKOF UsageFault
            # EXCP.LAZYFP         : IRQ.NOTHING,
            # EXCP.LSERR          : IRQ.NOTHING,
            EXCP.UNALIGNED      : IRQ.USAGE_FAULT,   # v7M UNALIGNED UsageFault
        }

        ql.emu_stop()

        try:
            handle = forward_mapper.get(intno)
            if handle != IRQ.NOTHING:
                ql.hw.nvic.set_pending(handle)
        except IndexError:
            raise QlErrorNotImplemented(f'Unhandled interrupt number ({intno})')

    def interrupt_handler(self, ql, intno):
        basepri = self.regs.basepri & 0xf0
        if basepri and basepri <= ql.hw.nvic.get_priority(intno):
            return

        if intno > IRQ.HARD_FAULT and (self.regs.primask & 0x1):
            return

        if intno != IRQ.NMI and (self.regs.faultmask & 0x1):
            return

        if ql.verbose >= QL_VERBOSE.DISASM:
            ql.log.debug(f'Handle the intno: {intno}')

        with QlInterruptContext(ql):
            isr = intno + 16
            offset = isr * 4

            entry = ql.mem.read_ptr(offset)
            exc_return = 0xFFFFFFFD if self.using_psp() else 0xFFFFFFF9

            self.regs.write('ipsr', isr)
            self.regs.write('pc', entry)
            self.regs.write('lr', exc_return)

            self.uc.emu_start(self.effective_pc, 0, 0, 0xffffff)
