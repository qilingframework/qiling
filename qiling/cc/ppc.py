#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from unicorn.ppc_const import (
    UC_PPC_REG_3, UC_PPC_REG_4, UC_PPC_REG_5,
    UC_PPC_REG_6, UC_PPC_REG_7, UC_PPC_REG_8,
)

from qiling.cc import QlCommonBaseCC, make_arg_list


class ppc(QlCommonBaseCC):
    """Default calling convention for PPC
    First 6 arguments are passed in regs, the rest are passed on the stack.
    """

    _retreg = UC_PPC_REG_3
    _argregs = make_arg_list(UC_PPC_REG_3, UC_PPC_REG_4, UC_PPC_REG_5, UC_PPC_REG_6, UC_PPC_REG_7, UC_PPC_REG_8)

    @staticmethod
    def getNumSlots(argbits: int):
        return 1

    def setReturnAddress(self, addr: int):
        self.arch.regs.lr = addr
