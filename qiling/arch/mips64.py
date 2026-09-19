#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from functools import cached_property
from typing import Optional

from unicorn import (
    Uc, UC_ARCH_MIPS, UC_MODE_MIPS64, UC_MODE_BIG_ENDIAN, UC_MODE_LITTLE_ENDIAN,
    UC_HOOK_TLB_FILL, UC_TLB_VIRTUAL, UC_PROT_ALL
)
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS64, CS_MODE_BIG_ENDIAN, CS_MODE_LITTLE_ENDIAN
from keystone import Ks, KS_ARCH_MIPS, KS_MODE_MIPS64, KS_MODE_BIG_ENDIAN, KS_MODE_LITTLE_ENDIAN

from qiling import Qiling
from qiling.arch.arch import QlArch
from qiling.arch import mips_const
from qiling.arch.models import MIPS64_CPU_MODEL
from qiling.arch.register import QlRegisterManager
from qiling.const import QL_ARCH, QL_ENDIAN


class QlArchMIPS64(QlArch):
    type = QL_ARCH.MIPS64
    bits = 64

    def __init__(self, ql: Qiling, *, cputype: Optional[MIPS64_CPU_MODEL], endian: QL_ENDIAN):
        # unicorn's default MIPS64 core is an old MIPS III (R4000-class) that lacks
        # MIPS IV / MIPS64 instructions such as movn/movz, which glibc emits freely;
        # executing them traps as a reserved instruction. default to a generic
        # MIPS64 Release 2 core (what mips64/mips64r2 toolchains target) so the full
        # ISA is available.
        if cputype is None:
            cputype = MIPS64_CPU_MODEL.MIPS64_MIPS64R2_GENERIC

        super().__init__(ql, cputype=cputype)

        self._init_endian = endian

    @cached_property
    def uc(self) -> Uc:
        endian = {
            QL_ENDIAN.EB: UC_MODE_BIG_ENDIAN,
            QL_ENDIAN.EL: UC_MODE_LITTLE_ENDIAN
        }[self.endian]

        uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS64 + endian)

        if self.cpu is not None:
            uc.ctl_set_cpu_model(self.cpu.value)

        # unicorn's MIPS64 CPU-MMU only executes within the low 2GB (useg); any
        # access at or above 0x80000000 raises an address exception. MIPS64 ELFs
        # link at 0x120000000 and Qiling lays the stack/mmap out well above 4GB,
        # so we switch to unicorn's virtual-TLB mode and supply an identity
        # mapping (paddr == vaddr). that bypasses the CPU-MMU segment checks while
        # keeping virtual == physical, so the rest of Qiling's flat memory model
        # (mem.map/read/write, loader, syscall pointer reads) keeps working as-is.
        uc.ctl_set_tlb_mode(UC_TLB_VIRTUAL)
        uc.hook_add(UC_HOOK_TLB_FILL, self.__tlb_fill_identity)

        return uc

    @staticmethod
    def __tlb_fill_identity(uc: Uc, vaddr: int, access: int, entry, user_data) -> bool:
        # identity-map every page to itself (paddr == vaddr); accesses to pages
        # that are not actually backed still fault, since there is no physical
        # memory behind them
        entry.paddr = vaddr & ~0xfff
        entry.perms = UC_PROT_ALL

        return True

    @cached_property
    def regs(self) -> QlRegisterManager:
        # the register names are shared with MIPS32; unicorn widens them to
        # 64 bits under UC_MODE_MIPS64
        regs_map = dict(
            **mips_const.reg_map
        )

        pc_reg = 'pc'
        sp_reg = 'sp'

        return QlRegisterManager(self.uc, regs_map, pc_reg, sp_reg)

    @cached_property
    def disassembler(self) -> Cs:
        endian = {
            QL_ENDIAN.EL: CS_MODE_LITTLE_ENDIAN,
            QL_ENDIAN.EB: CS_MODE_BIG_ENDIAN
        }[self.endian]

        return Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + endian)

    @cached_property
    def assembler(self) -> Ks:
        endian = {
            QL_ENDIAN.EL: KS_MODE_LITTLE_ENDIAN,
            QL_ENDIAN.EB: KS_MODE_BIG_ENDIAN
        }[self.endian]

        return Ks(KS_ARCH_MIPS, KS_MODE_MIPS64 + endian)

    @property
    def endian(self) -> QL_ENDIAN:
        return self._init_endian
