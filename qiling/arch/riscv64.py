#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from functools import cached_property
from typing import Optional

from unicorn import Uc, UC_ARCH_RISCV, UC_MODE_RISCV64
from capstone import Cs
from keystone import Ks

from qiling import Qiling
from qiling.arch.models import RISCV64_CPU_MODEL
from qiling.arch.riscv_const import *
from qiling.const import QL_ARCH
from qiling.exception import QlErrorNotImplemented

from .riscv import QlArchRISCV


class QlArchRISCV64(QlArchRISCV):
    type = QL_ARCH.RISCV64
    bits = 64

    def __init__(self, ql: Qiling, *, cputype: Optional[RISCV64_CPU_MODEL] = None):
        super().__init__(ql, cputype=cputype)

    @cached_property
    def uc(self) -> Uc:
        obj = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)

        if self.cpu is not None:
            obj.ctl_set_cpu_model(self.cpu.value)

        return obj

    @cached_property
    def disassembler(self) -> Cs:
        try:
            from capstone import CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCVC
        except ImportError:
            raise QlErrorNotImplemented("Capstone does not yet support riscv, upgrade to capstone 5.0")
        else:
            return Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 + CS_MODE_RISCVC)

    @cached_property
    def assembler(self) -> Ks:
        raise QlErrorNotImplemented("Keystone does not yet support riscv")
