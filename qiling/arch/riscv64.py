#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from functools import cached_property

from unicorn import Uc, UC_ARCH_RISCV, UC_MODE_RISCV64
from capstone import Cs
from keystone import Ks

from qiling import Qiling
from qiling.arch.riscv_const import *
from qiling.exception import QlErrorNotImplemented

from .riscv import QlArchRISCV

class QlArchRISCV64(QlArchRISCV):
    def __init__(self, ql: Qiling):
        super().__init__(ql)

    @cached_property
    def uc(self) -> Uc:
        return Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)

    @cached_property
    def disassembler(self) -> Cs:
        try:
            from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC
        except ImportError:
            raise QlErrorNotImplemented("Capstone does not yet support riscv, upgrade to capstone 5.0")
        else:
            return Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 + CS_MODE_RISCVC)

    def create_assembler(self) -> Ks:
        raise QlErrorNotImplemented("Keystone does not yet support riscv")
