#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import Uc, UC_ARCH_RISCV, UC_MODE_RISCV32
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32
from keystone import Ks

from qiling import Qiling
from qiling.arch.arch import QlArch
from qiling.arch.riscv_const import *
from qiling.exception import QlErrorNotImplemented


class QlArchRISCV(QlArch):
    def __init__(self, ql: Qiling):
        super().__init__(ql)

        self.ql.reg.expand_mapping(reg_map)
        self.ql.reg.register_sp(reg_map["sp"])
        self.ql.reg.register_pc(reg_map["pc"])

    # get initialized unicorn engine
    def get_init_uc(self) -> Uc:
        return Uc(UC_ARCH_RISCV, UC_MODE_RISCV32)

    def create_disassembler(self) -> Cs:
        # raise QlErrorNotImplemented("Capstone does not yet support riscv")
        return Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)

    def create_assembler(self) -> Ks:
        raise QlErrorNotImplemented("Keystone does not yet support riscv")
