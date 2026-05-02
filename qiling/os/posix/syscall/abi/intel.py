#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

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


class QlIntel64(QlSyscallABI):
    """System call ABI for Intel-based 64-bit systems.
    """

    _idreg = UC_X86_REG_RAX
    _argregs = (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9)
    _retreg = UC_X86_REG_RAX
