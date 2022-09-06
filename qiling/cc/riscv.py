#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from qiling import Qiling
from . import QlCommonBaseCC

from unicorn.riscv_const import (
    UC_RISCV_REG_A0, UC_RISCV_REG_A1, UC_RISCV_REG_A2, 
    UC_RISCV_REG_A3, UC_RISCV_REG_A4, UC_RISCV_REG_A5, 
)


class riscv(QlCommonBaseCC):
    """Default calling convention for RISCV
        First 6 arguments are passed in regs, the rest are passed on the stack.
    """

    _argregs = (UC_RISCV_REG_A0, UC_RISCV_REG_A1, UC_RISCV_REG_A2, UC_RISCV_REG_A3, UC_RISCV_REG_A4, UC_RISCV_REG_A5) + (None, ) * 10

    def __init__(self, ql: Qiling):
        super().__init__(ql, UC_RISCV_REG_A0)

    @staticmethod
    def getNumSlots(argbits: int):
        return 1