#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Mapping

from .arch import Arch

class ArchX86(Arch):
    def __init__(self):
        super().__init__()

    @property
    def arch_insn_size(self):
        return 15

    @property
    def regs(self):
        return (
                "eax", "ebx", "ecx", "edx",
                "esp", "ebp", "esi", "edi",
                "eip", "ss", "cs", "ds", "es",
                "fs", "gs", "eflags",
                )

    def read_insn(self, address: int) -> bytes:
        # due to the variadic lengh of x86 instructions ( 1~15 )
        # always assume the maxium size for disassembler to tell
        # what is it exactly.

        return self.read_mem(address, self.arch_insn_size)

    @staticmethod
    def get_flags(bits: int) -> Mapping[str, bool]:
        """
        get flags from ql.reg.eflags
        """

        return {
                "CF" : bits & 0x0001 != 0, # CF, carry flag
                "PF" : bits & 0x0004 != 0, # PF, parity flag
                "AF" : bits & 0x0010 != 0, # AF, adjust flag
                "ZF" : bits & 0x0040 != 0, # ZF, zero flag
                "SF" : bits & 0x0080 != 0, # SF, sign flag
                "OF" : bits & 0x0800 != 0, # OF, overflow flag
                }
