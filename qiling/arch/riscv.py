#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from functools import cached_property
from typing import Optional

from unicorn import Uc, UC_ARCH_RISCV, UC_MODE_RISCV32
from capstone import Cs
from keystone import Ks

from qiling import Qiling
from qiling.arch.arch import QlArch
from qiling.arch.models import RISCV_CPU_MODEL
from qiling.arch.register import QlRegisterManager
from qiling.arch import riscv_const
from qiling.arch.riscv_const import *
from qiling.const import QL_ARCH, QL_ENDIAN
from qiling.exception import QlErrorNotImplemented


class QlArchRISCV(QlArch):
    type = QL_ARCH.RISCV
    bits = 32

    def __init__(self, ql: Qiling, *, cputype: Optional[RISCV_CPU_MODEL] = None):
        super().__init__(ql, cputype=cputype)

    @cached_property
    def uc(self) -> Uc:
        obj = Uc(UC_ARCH_RISCV, UC_MODE_RISCV32)

        if self.cpu is not None:
            obj.ctl_set_cpu_model(self.cpu.value)

        return obj

    @cached_property
    def regs(self) -> QlRegisterManager:
        regs_map = dict(
            **riscv_const.reg_map,
            **riscv_const.reg_csr_map,
            **riscv_const.reg_float_map,
        )

        pc_reg = 'pc'
        sp_reg = 'sp'

        return QlRegisterManager(self.uc, regs_map, pc_reg, sp_reg)

    @property
    def endian(self) -> QL_ENDIAN:
        return QL_ENDIAN.EL

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
        self.regs.mstatus = self.regs.mstatus | MSTATUS.FS_DIRTY

    def init_context(self):
        self.regs.pc = 0x08000000

    def unicorn_exception_handler(self, ql: Qiling, intno: int):
        if intno == 2:
            ql.log.warning(f'[{hex(self.regs.arch_pc)}] Illegal instruction')

        else:
            raise QlErrorNotImplemented(f'Unhandled interrupt number ({intno})')
