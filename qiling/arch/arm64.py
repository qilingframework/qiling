#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from functools import cached_property

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN

from qiling.arch.arch import QlArch
from qiling.arch import arm64_const
from qiling.arch.register import QlRegisterManager

class QlArchARM64(QlArch):
    bits = 64

    @cached_property
    def uc(self) -> Uc:
        return Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    @cached_property
    def regs(self) -> QlRegisterManager:
        regs_map = dict(
            **arm64_const.reg_map,
            **arm64_const.reg_map_w
        )

        pc_reg = 'pc'
        sp_reg = 'sp'

        return QlRegisterManager(self.uc, regs_map, pc_reg, sp_reg)

    @cached_property
    def disassembler(self) -> Cs:
        return Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    @cached_property
    def assembler(self) -> Ks:
        return Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

    def enable_vfp(self):
        self.ql.arch.regs.cpacr_el1 = self.ql.arch.regs.cpacr_el1 | 0x300000
