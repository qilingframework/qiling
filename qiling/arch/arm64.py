#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN

from qiling import Qiling
from qiling.arch.arch import QlArch
from qiling.arch.arm64_const import *

class QlArchARM64(QlArch):
    def __init__(self, ql: Qiling):
        super().__init__(ql)

        reg_maps = (
            reg_map,
            reg_map_w
        )

        for reg_maper in reg_maps:
            self.ql.reg.expand_mapping(reg_maper)

        self.ql.reg.register_sp(reg_map["sp"])
        self.ql.reg.register_pc(reg_map["pc"])

    # get initialized unicorn engine
    def get_init_uc(self) -> Uc:
        return Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    def create_disassembler(self) -> Cs:
        if self._disasm is None:
            self._disasm = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

        return self._disasm

    def create_assembler(self) -> Ks:
        if self._asm is None:
            self._asm = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

        return self._asm

    def enable_vfp(self):
        self.ql.reg.cpacr_el1 = self.ql.reg.cpacr_el1 | 0x300000
