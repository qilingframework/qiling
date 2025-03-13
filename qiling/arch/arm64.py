#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from functools import cached_property
from typing import Optional

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_ARM

from qiling import Qiling
from qiling.arch.arch import QlArch
from qiling.arch import arm64_const
from qiling.arch.cpr64 import QlCpr64Manager
from qiling.arch.models import ARM64_CPU_MODEL
from qiling.arch.register import QlRegisterManager
from qiling.const import QL_ARCH, QL_ENDIAN


class QlArchARM64(QlArch):
    type = QL_ARCH.ARM64
    bits = 64

    def __init__(self, ql: Qiling, *, cputype: Optional[ARM64_CPU_MODEL] = None):
        super().__init__(ql, cputype=cputype)

    @cached_property
    def uc(self) -> Uc:
        obj = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

        if self.cpu is not None:
            obj.ctl_set_cpu_model(self.cpu.value)

        return obj

    @cached_property
    def regs(self) -> QlRegisterManager:
        regs_map = dict(
            **arm64_const.reg_map,
            **arm64_const.reg_map_b,
            **arm64_const.reg_map_d,
            **arm64_const.reg_map_h,
            **arm64_const.reg_map_q,
            **arm64_const.reg_map_s,
            **arm64_const.reg_map_w,
            **arm64_const.reg_map_v,
            **arm64_const.reg_map_fp
        )

        pc_reg = 'pc'
        sp_reg = 'sp'

        return QlRegisterManager(self.uc, regs_map, pc_reg, sp_reg)

    @property
    def endian(self) -> QL_ENDIAN:
        return QL_ENDIAN.EL

    @cached_property
    def cpr(self) -> QlCpr64Manager:
        """Coprocessor Registers.
        """

        regs_map = dict(
            **arm64_const.reg_cpr
        )

        return QlCpr64Manager(self.uc, regs_map)

    @cached_property
    def disassembler(self) -> Cs:
        return Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    @cached_property
    def assembler(self) -> Ks:
        return Ks(KS_ARCH_ARM64, KS_MODE_ARM)

    def enable_vfp(self):
        self.regs.cpacr_el1 |= (0b11 << 20)
