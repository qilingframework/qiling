#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from unicorn.riscv_const import (
    UC_RISCV_REG_A0, UC_RISCV_REG_A1, UC_RISCV_REG_A2, UC_RISCV_REG_A3,
    UC_RISCV_REG_A4, UC_RISCV_REG_A5, UC_RISCV_REG_A7
)

from qiling.os.posix.syscall.abi import QlSyscallABI


class QlRiscV32(QlSyscallABI):
    """System call ABI for RISCV systems.
    """

    _idreg = UC_RISCV_REG_A7
    _argregs = (UC_RISCV_REG_A0, UC_RISCV_REG_A1, UC_RISCV_REG_A2, UC_RISCV_REG_A3, UC_RISCV_REG_A4, UC_RISCV_REG_A5)
    _retreg = UC_RISCV_REG_A0


QlRiscV64 = QlRiscV32
