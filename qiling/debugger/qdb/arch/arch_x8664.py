#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Mapping

from .arch import Arch

class ArchX8664(Arch):
    '''
    This is currently mostly just a copy of x86 - other than the size of archbits. Some of this may be wrong.
    '''

    def __init__(self):
        super().__init__()
    
    @property
    def arch_insn_size(self):
        '''
        Architecture maximum instruction size. x86_64 instructions are a maximum size of 15 bytes.

        @returns bytes
        '''

        return 15
    
    @property
    def regs(self):
        return (
                "rax", "rbx", "rcx", "rdx",
                "rsp", "rbp", "rsi", "rdi",
                "rip", "r8", "r9", "r10",
                "r11", "r12", "r13", "r14",
                "r15", "ss", "cs", "ds", "es",
                "fs", "gs", "eflags"
                )
    
    @property
    def archbit(self):
        '''
        Architecture maximum register size. x86 is a maximum of 4 bytes.

        @returns bytes
        '''
        
        return 8

    def read_insn(self, address: int) -> bytes:
        # Due to the variadicc length of x86 instructions
        # always assume the maximum size for disassembler to tell
        # what it is.

        return self.read_mem(address, self.arch_insn_size)
    
    @staticmethod
    def get_flags(bits: int) -> Mapping[str, bool]:

        return {
                "CF" : bits & 0x0001 != 0, # CF, carry flag
                "PF" : bits & 0x0004 != 0, # PF, parity flag
                "AF" : bits & 0x0010 != 0, # AF, adjust flag
                "ZF" : bits & 0x0040 != 0, # ZF, zero flag
                "SF" : bits & 0x0080 != 0, # SF, sign flag
                "OF" : bits & 0x0800 != 0, # OF, overflow flag
                }
