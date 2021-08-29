#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from abc import ABC, abstractmethod
from typing import Optional

from capstone import Cs
from keystone import Ks

from qiling import Qiling
from .utils import QlArchUtils, ql_create_disassembler, ql_create_assembler
from qiling.const import QL_ARCH

class QlArch(ABC):
    def __init__(self, ql: Qiling):
        self.ql = ql
        self.utils = QlArchUtils(ql)

        self._disasm: Optional[Cs] = None
        self._asm: Optional[Ks] = None

    # ql.init_Uc - initialized unicorn engine
    @property
    def init_uc(self):
        return self.get_init_uc()


    def stack_push(self, value: int) -> int:
        """Push a value onto the architectural stack.

        Args:
            value: a numeric value to push

        Returns: the top of stack after pushing the value
        """

        self.ql.reg.arch_sp -= self.ql.pointersize
        self.ql.mem.write(self.ql.reg.arch_sp, self.ql.pack(value))

        return self.ql.reg.arch_sp


    def stack_pop(self) -> int:
        """Pop a value from the architectural stack.

        Returns: the value at the top of stack
        """

        data = self.ql.unpack(self.ql.mem.read(self.ql.reg.arch_sp, self.ql.pointersize))
        self.ql.reg.arch_sp += self.ql.pointersize

        return data


    def stack_read(self, offset: int) -> int:
        """Peek the architectural stack at a specified offset from its top, without affecting
        the top of the stack.

        Note that this operation violates the FIFO property of the stack and may be used cautiously.

        Args:
            offset: offset in bytes from the top of the stack, not necessarily aligned to the
                    native stack item size. the offset may be either positive or netagive, where
                    a 0 value means overwriting the value at the top of the stack

        Returns: the value at the specified address
        """

        return self.ql.unpack(self.ql.mem.read(self.ql.reg.arch_sp + offset, self.ql.pointersize))


    def stack_write(self, offset: int, value: int) -> None:
        """Write a value to the architectural stack at a specified offset from its top, without
        affecting the top of the stack.

        Note that this operation violates the FIFO property of the stack and may be used cautiously.

        Args:
            offset: offset in bytes from the top of the stack, not necessarily aligned to the
                    native stack item size. the offset may be either positive or netagive, where
                    a 0 value means overwriting the value at the top of the stack
        """

        self.ql.mem.write(self.ql.reg.arch_sp + offset, self.ql.pack(value))


       # set PC
    def set_pc(self, address: int):
        self.ql.reg.arch_pc = address


    # get PC
    def get_pc(self) -> int:
        return self.ql.reg.arch_pc


    # set stack pointer
    def set_sp(self, address: int):
        self.ql.reg.arch_sp = address


    # get stack pointer
    def get_sp(self) -> int:
        return self.ql.reg.arch_sp 


    # Unicorn's CPU state save
    def context_save(self):
        return self.ql.uc.context_save()


    # Unicorn's CPU state restore method
    def context_restore(self, saved_context):
        self.ql.uc.context_restore(saved_context)


    def create_disassembler(self) -> Cs:
        if self.ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB):
            reg_cpsr = self.ql.reg.cpsr
        else:
            reg_cpsr = None
        return ql_create_disassembler(self.ql.archtype, self.ql.archendian, reg_cpsr)


    def create_assembler(self) -> Ks:
        if self.ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB):
            reg_cpsr = self.ql.reg.cpsr
        else:
            reg_cpsr = None
        return ql_create_assembler(self.ql.archtype, self.ql.archendian, reg_cpsr)
