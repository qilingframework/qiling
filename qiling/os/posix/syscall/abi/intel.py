#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from typing import Tuple

from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_RDI,
    UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_R8,
    UC_X86_REG_R9, UC_X86_REG_RAX
)

from qiling.os.posix.syscall.abi import QlSyscallABI


class QlIntel32(QlSyscallABI):
    """System call ABI for Intel-based 32-bit systems.
    """

    _idreg = UC_X86_REG_EAX
    _argregs = (UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP)
    _retreg = UC_X86_REG_EAX


class QlIntel32MacOS(QlIntel32):
    """System call ABI for Intel-based 32-bit MacOS.
    Unlike Linux, MacOS follows the BSD calling convention in which syscall
    arguments are passed on the stack rather than in registers. The syscall
    number is still held in eax and the return value is set in eax.
    """

    def get_params(self, count: int) -> Tuple[int, ...]:
        # the '__sysenter_trap' trampoline pops the return address into edx and
        # points ecx (= esp) to the caller return address. the syscall arguments
        # are laid out on the stack right after that return address slot.
        return tuple(self.arch.stack_read((i + 1) * self.arch.pointersize) for i in range(count))


class QlIntel64(QlSyscallABI):
    """System call ABI for Intel-based 64-bit systems.
    """

    _idreg = UC_X86_REG_RAX
    _argregs = (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9)
    _retreg = UC_X86_REG_RAX
