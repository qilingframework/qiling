#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from functools import cached_property
from typing import Optional

from unicorn import Uc, UC_ARCH_PPC, UC_MODE_PPC32, UC_MODE_BIG_ENDIAN
from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN
from keystone import Ks, KS_ARCH_PPC, KS_MODE_PPC32, KS_MODE_BIG_ENDIAN

from qiling import Qiling
from qiling.arch.arch import QlArch
from qiling.arch import ppc_const
from qiling.arch.models import PPC_CPU_MODEL
from qiling.arch.register import QlRegisterManager
from qiling.const import QL_ARCH, QL_ENDIAN


class QlArchPPC(QlArch):
    type = QL_ARCH.PPC
    bits = 32

    def __init__(self, ql: Qiling, *, cputype: Optional[PPC_CPU_MODEL] = None):
        super().__init__(ql, cputype=cputype)

    @cached_property
    def uc(self) -> Uc:
        obj = Uc(UC_ARCH_PPC, UC_MODE_PPC32 + UC_MODE_BIG_ENDIAN)

        if self.cpu is not None:
            obj.ctl_set_cpu_model(self.cpu.value)

        return obj

    @cached_property
    def regs(self) -> QlRegisterManager:
        regs_map = dict(
            **ppc_const.reg_map,
            **ppc_const.reg_float_map
        )

        pc_reg = 'pc'
        sp_reg = 'r1'

        return QlRegisterManager(self.uc, regs_map, pc_reg, sp_reg)

    @cached_property
    def disassembler(self) -> Cs:
        return Cs(CS_ARCH_PPC, CS_MODE_32 + CS_MODE_BIG_ENDIAN)

    @cached_property
    def assembler(self) -> Ks:
        return Ks(KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN)

    @property
    def endian(self) -> QL_ENDIAN:
        return QL_ENDIAN.EB

    def enable_float(self):
        self.regs.msr = self.regs.msr | ppc_const.MSR.FP
