#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from unicorn.riscv_const import (
    UC_RISCV_REG_A0, UC_RISCV_REG_A1, UC_RISCV_REG_A2,
    UC_RISCV_REG_A3, UC_RISCV_REG_A4, UC_RISCV_REG_A5
)

from qiling.cc import QlCommonBaseCC, make_arg_list


class riscv(QlCommonBaseCC):
    """Default calling convention for RISCV
    First 6 arguments are passed in regs, the rest are passed on the stack.
    """

    _retreg = UC_RISCV_REG_A0
    _argregs = make_arg_list(UC_RISCV_REG_A0, UC_RISCV_REG_A1, UC_RISCV_REG_A2, UC_RISCV_REG_A3, UC_RISCV_REG_A4, UC_RISCV_REG_A5)

    @staticmethod
    def getNumSlots(argbits: int):
        return 1

    def setReturnAddress(self, addr: int):
        self.arch.regs.ra = addr
