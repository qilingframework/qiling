#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from abc import abstractmethod

from unicorn import Uc
from unicorn.unicorn import UcContext
from capstone import Cs
from keystone import Ks

from qiling import Qiling
from qiling.const import QL_ARCH, QL_ENDIAN
from .register import QlRegisterManager
from .utils import QlArchUtils

class QlArch:
    type: QL_ARCH
    bits: int

    def __init__(self, ql: Qiling):
        self.ql = ql
        self.utils = QlArchUtils(ql)

    @property
    @abstractmethod
    def uc(self) -> Uc:
        """Get unicorn instance bound to arch.
        """

        pass

    @property
    @abstractmethod
    def regs(self) -> QlRegisterManager:
        """Architectural registers.
        """

        pass

    @property
    def pointersize(self) -> int:
        return self.bits // 8

    def stack_push(self, value: int) -> int:
        """Push a value onto the architectural stack.

        Args:
            value: a numeric value to push

        Returns: the top of stack after pushing the value
        """

        self.regs.arch_sp -= self.pointersize
        self.ql.mem.write_ptr(self.regs.arch_sp, value)

        return self.regs.arch_sp


    def stack_pop(self) -> int:
        """Pop a value from the architectural stack.

        Returns: the value at the top of stack
        """

        data = self.ql.mem.read_ptr(self.regs.arch_sp)
        self.regs.arch_sp += self.pointersize

        return data


    def stack_read(self, offset: int) -> int:
        """Peek the architectural stack at a specified offset from its top, without affecting
        the top of the stack.

        Note that this operation violates the FIFO property of the stack and may be used cautiously.

        Args:
            offset: offset in bytes from the top of the stack, not necessarily aligned to the
                    native stack item size. the offset may be either positive or netagive, where
                    a 0 value means retrieving the value at the top of the stack

        Returns: the value at the specified address
        """

        return self.ql.mem.read_ptr(self.regs.arch_sp + offset)


    def stack_write(self, offset: int, value: int) -> None:
        """Write a value to the architectural stack at a specified offset from its top, without
        affecting the top of the stack.

        Note that this operation violates the FIFO property of the stack and may be used cautiously.

        Args:
            offset: offset in bytes from the top of the stack, not necessarily aligned to the
                    native stack item size. the offset may be either positive or netagive, where
                    a 0 value means overwriting the value at the top of the stack
        """

        self.ql.mem.write_ptr(self.regs.arch_sp + offset, value)


    # Unicorn's CPU state save
    def save(self) -> UcContext:
        return self.uc.context_save()


    # Unicorn's CPU state restore method
    def restore(self, saved_context: UcContext):
        self.uc.context_restore(saved_context)


    @property
    @abstractmethod
    def disassembler(self) -> Cs:
        """Get disassembler instance bound to arch.
        """

        pass


    @property
    @abstractmethod
    def assembler(self) -> Ks:
        """Get assembler instance bound to arch.
        """

        pass

    @property
    @abstractmethod
    def endian(self) -> QL_ENDIAN:
        """Get processor endianess.
        """

        pass