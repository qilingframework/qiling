#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from typing import Tuple
from unicorn.mips_const import (
    UC_MIPS_REG_V0, UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3,
    UC_MIPS_REG_T0, UC_MIPS_REG_T1, UC_MIPS_REG_T2, UC_MIPS_REG_T3
)

from qiling.os.posix.syscall.abi import QlSyscallABI


class QlMipsO32(QlSyscallABI):
    """System call ABI for MIPS O32 systems.

    See: https://www.linux-mips.org/wiki/Syscall
    """

    _idreg = UC_MIPS_REG_V0
    _argregs = (UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3)
    _retreg = UC_MIPS_REG_V0

    def __get_stack_params(self, count: int) -> Tuple[int, ...]:
        """Get system call parameters passed on stack.
        """

        shadowed = len(self._argregs)

        return tuple(self.arch.stack_read(self.arch.pointersize * (i + shadowed)) for i in range(count))

    def get_params(self, count: int) -> Tuple[int, ...]:
        num_reg_args = len(self._argregs)

        stack_args = self.__get_stack_params(count - num_reg_args)
        reg_args = super().get_params(min(count, num_reg_args))

        return reg_args + stack_args

    def set_return_value(self, value: int) -> None:
        a3, v0 = (1, -value) if -1134 < value < 0 else (0, value)

        self.arch.regs.v0 = v0
        self.arch.regs.a3 = a3


class QlMips64N64(QlMipsO32):
    """System call ABI for MIPS64 n64 systems.

    n64 passes the first 8 arguments in registers (a0-a3 followed by a4-a7,
    which are the physical registers $8-$11) and, unlike o32, reserves no
    shadow space for them on the stack.

    See: https://www.linux-mips.org/wiki/Syscall
    """

    _idreg = UC_MIPS_REG_V0
    _argregs = (
        UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3,
        UC_MIPS_REG_T0, UC_MIPS_REG_T1, UC_MIPS_REG_T2, UC_MIPS_REG_T3
    )
    _retreg = UC_MIPS_REG_V0

    def get_params(self, count: int) -> Tuple[int, ...]:
        num_reg_args = len(self._argregs)

        reg_args = QlSyscallABI.get_params(self, min(count, num_reg_args))
        stack_args = tuple(
            self.arch.stack_read(self.arch.pointersize * i) for i in range(max(0, count - num_reg_args))
        )

        return reg_args + stack_args
