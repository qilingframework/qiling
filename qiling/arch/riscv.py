#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from functools import cached_property

from unicorn import Uc, UC_ARCH_RISCV, UC_MODE_RISCV32
from capstone import Cs
from keystone import Ks

from qiling import Qiling
from qiling.arch.arch import QlArch
from qiling.arch.riscv_const import *
from qiling.exception import QlErrorNotImplemented


class QlArchRISCV(QlArch):
    def __init__(self, ql: Qiling):
        super().__init__(ql)

        reg_maps = (
            reg_map,
            reg_csr_map,
            reg_float_map,
        )

        for reg_maper in reg_maps:
            self.ql.arch.regs.expand_mapping(reg_maper)
        self.ql.arch.regs.register_sp(reg_map["sp"])
        self.ql.arch.regs.register_pc(reg_map["pc"])

    @cached_property
    def uc(self) -> Uc:
        return Uc(UC_ARCH_RISCV, UC_MODE_RISCV32)

    @cached_property
    def disassembler(self) -> Cs:
        try:
            from capstone import CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC
        except ImportError:
            raise QlErrorNotImplemented("Capstone does not yet support riscv, upgrade to capstone 5.0")
        else:
            return Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 + CS_MODE_RISCVC)

    @cached_property
    def assembler(self) -> Ks:
        raise QlErrorNotImplemented("Keystone does not yet support riscv")

    def enable_float(self):
        self.ql.arch.regs.mstatus = self.ql.arch.regs.mstatus | MSTATUS.FS_DIRTY

    def init_context(self):
        self.ql.arch.regs.pc = 0x08000000
        
    def soft_interrupt_handler(self, ql, intno):
        if intno == 2:            
            try:
                address, size = ql.arch.regs.pc - 4, 4
                tmp = ql.mem.read(address, size)
                qd = ql.arch.disassembler

                insn = '\n> '.join(f'{insn.mnemonic} {insn.op_str}' for insn in qd.disasm(tmp, address))
            except QlErrorNotImplemented:
                insn = ''
                
            ql.log.warning(f'[{hex(address)}] Illegal instruction ({insn})')
        else:
            raise QlErrorNotImplemented(f'Unhandled interrupt number ({intno})')
    
    def step(self):
        self.ql.emu_start(self.ql.arch.regs.arch_pc, 0, count=1)
        self.ql.hw.step()

    def stop(self):
        self.runable = False

    def run(self, count=-1, end=None):
        self.runable = True

        while self.runable and count != 0:
            if self.ql.arch.regs.arch_pc == end:
                break

            self.step()
            count -= 1
