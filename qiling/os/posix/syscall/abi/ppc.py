#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from unicorn.ppc_const import (
    UC_PPC_REG_0, UC_PPC_REG_3, UC_PPC_REG_4, UC_PPC_REG_5,
    UC_PPC_REG_6, UC_PPC_REG_7, UC_PPC_REG_8
)

from qiling.os.posix.syscall.abi import QlSyscallABI


class QlPPC(QlSyscallABI):
    """System call ABI for PowerPC systems.
    """

    _idreg = UC_PPC_REG_0
    _argregs = (UC_PPC_REG_3, UC_PPC_REG_4, UC_PPC_REG_5, UC_PPC_REG_6, UC_PPC_REG_7, UC_PPC_REG_8)
    _retreg = UC_PPC_REG_3
