#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Collection, Dict

from .arch import Arch


class ArchIntel(Arch):
    """Arch base class for Intel architecture.
    """

    def __init__(self, regs: Collection[str], asize: int) -> None:
        super().__init__(regs, {}, asize, 15)

    @staticmethod
    def get_flags(bits: int) -> Dict[str, bool]:
        return {
            'CF' : bits & (0b1 <<  0) != 0,  # carry
            'PF' : bits & (0b1 <<  2) != 0,  # parity
            'AF' : bits & (0b1 <<  4) != 0,  # adjust
            'ZF' : bits & (0b1 <<  6) != 0,  # zero
            'SF' : bits & (0b1 <<  7) != 0,  # sign
            'IF' : bits & (0b1 <<  9) != 0,  # interrupt enable
            'DF' : bits & (0b1 << 10) != 0,  # direction
            'OF' : bits & (0b1 << 11) != 0   # overflow
        }

    @staticmethod
    def get_iopl(bits: int) -> int:
        return bits & (0b11 << 12)


class ArchX86(ArchIntel):
    def __init__(self) -> None:
        regs = (
            'eax', 'ebx', 'ecx', 'edx',
            'ebp', 'esp', 'esi', 'edi',
            'eip', 'eflags' ,'ss', 'cs',
            'ds', 'es', 'fs', 'gs'
        )

        super().__init__(regs, 4)


class ArchX64(ArchIntel):
    def __init__(self) -> None:
        regs = (
            'rax', 'rbx', 'rcx', 'rdx',
            'rbp', 'rsp', 'rsi', 'rdi',
            'r8', 'r9', 'r10', 'r11',
            'r12', 'r13', 'r14', 'r15',
            'rip', 'eflags', 'ss', 'cs',
            'ds', 'es', 'fs', 'gs'
        )

        super().__init__(regs, 8)
