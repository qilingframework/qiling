#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from functools import cached_property

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_THUMB, UC_MODE_BIG_ENDIAN
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_BIG_ENDIAN
from keystone import Ks, KS_ARCH_ARM, KS_MODE_ARM, KS_MODE_THUMB, KS_MODE_BIG_ENDIAN

from qiling import Qiling
from qiling.arch.arch import QlArch
from qiling.arch import arm_const
from qiling.arch.register import QlRegisterManager
from qiling.const import QL_ARCH, QL_ENDIAN

class QlArchARM(QlArch):
    type = QL_ARCH.ARM
    bits = 32

    def __init__(self, ql: Qiling, endian: QL_ENDIAN, thumb: bool):
        super().__init__(ql)

        self._init_endian = endian
        self._init_thumb = thumb

        self.arm_get_tls_addr = 0xFFFF0FE0

    @cached_property
    def uc(self) -> Uc:
        mode = UC_MODE_ARM

        if self._init_endian == QL_ENDIAN.EB:
            mode += UC_MODE_BIG_ENDIAN

        if self._init_thumb:
            mode += UC_MODE_THUMB

        return Uc(UC_ARCH_ARM, mode)

    @cached_property
    def regs(self) -> QlRegisterManager:
        regs_map = dict(
            **arm_const.reg_map,
            **arm_const.reg_vfp
        )

        pc_reg = 'pc'
        sp_reg = 'sp'

        return QlRegisterManager(self.uc, regs_map, pc_reg, sp_reg)

    @property
    def is_thumb(self) -> bool:
        return bool(self.regs.cpsr & (1 << 5))

    @property
    def endian(self) -> QL_ENDIAN:
        return QL_ENDIAN.EB if self.regs.cpsr & (1 << 9) else QL_ENDIAN.EL

    @property
    def effective_pc(self) -> int:
        """Get effective PC value, taking Thumb mode into account.
        """

        # append 1 to pc if in thumb mode, or 0 otherwise
        return self.regs.pc + int(self.is_thumb)

    @property
    def disassembler(self) -> Cs:
        # note: we do not cache the disassembler instance; rather we refresh it
        # each time to make sure current endianess and thumb mode are taken into
        # account

        mode = CS_MODE_ARM

        if self.endian == QL_ENDIAN.EB:
            mode += CS_MODE_BIG_ENDIAN

        if self.is_thumb:
            mode += CS_MODE_THUMB

        return Cs(CS_ARCH_ARM, mode)

    @property
    def assembler(self) -> Ks:
        # note: we do not cache the assembler instance; rather we refresh it
        # each time to make sure current endianess and thumb mode are taken into
        # account

        mode = KS_MODE_ARM

        if self.endian == QL_ENDIAN.EB:
            mode += KS_MODE_BIG_ENDIAN

        if self.is_thumb:
            mode += KS_MODE_THUMB

        return Ks(KS_ARCH_ARM, mode)

    def enable_vfp(self) -> None:
        # set full access to cp10 and cp11
        self.regs.c1_c0_2 = self.regs.c1_c0_2 | (0b11 << 20) | (0b11 << 22)

        self.regs.fpexc = (1 << 30)
