#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, Tuple, Union
from unicorn import UcError

from .misc import InvalidInsn


if TYPE_CHECKING:
    from qiling import Qiling
    from .misc import InsnLike


class Context:
    """Emulation context accessor.
    """

    def __init__(self, ql: Qiling):
        # make sure mixin classes are properly initialized
        super().__init__()

        self.ql = ql
        self.pointersize = self.ql.arch.pointersize

    @property
    def cur_addr(self) -> int:
        """Read current program counter register.
        """

        return self.ql.arch.regs.arch_pc

    @property
    def cur_sp(self) -> int:
        """Read current stack pointer register.
        """

        return self.ql.arch.regs.arch_sp

    def read_reg(self, reg: Union[str, int]) -> int:
        """Get register value.
        """

        return self.ql.arch.regs.read(reg)

    def write_reg(self, reg: Union[str, int], value: int) -> None:
        """Set register value.
        """

        self.ql.arch.regs.write(reg, value)

    def disasm(self, address: int, detail: bool = False) -> InsnLike:
        """Helper function for disassembling.
        """

        insn_bytes = self.read_insn(address) or b''
        insn = None

        if insn_bytes:
            md = self.ql.arch.disassembler
            md.detail = detail

            insn = next(md.disasm(insn_bytes, address, 1), None)

        return insn or InvalidInsn(insn_bytes, address)

    def disasm_lite(self, address: int) -> Tuple[int, int, str, str]:
        """Helper function for light disassembling, when details are not required.

        Returns:
            A tuple of: instruction address, size, mnemonic and operands
        """

        insn_bytes = self.read_insn(address) or b''
        insn = None

        if insn_bytes:
            md = self.ql.arch.disassembler

            insn = next(md.disasm_lite(insn_bytes, address, 1), None)

        return insn or tuple()

    def read_mem(self, address: int, size: int) -> bytearray:
        """Read data of a certain size from specified memory location.
        """

        return self.ql.mem.read(address, size)

    def try_read_mem(self, address: int, size: int) -> Optional[bytearray]:
        """Attempt to read data from memory.
        """

        try:
            data = self.read_mem(address, size)
        except UcError:
            data = None

        return data

    def read_pointer(self, address: int, size: int = 0, *, signed: bool = False) -> int:
        """Attempt to read a native-size integer from memory.
        """

        return self.ql.mem.read_ptr(address, size, signed=signed)

    def try_read_pointer(self, address: int, size: int = 0, *, signed: bool = False) -> Optional[int]:
        """Attempt to read a native-size integer from memory.
        """

        try:
            value = self.read_pointer(address, size, signed=signed)
        except UcError:
            value = None

        return value

    def read_string(self, address: int) -> Optional[str]:
        """Read string from memory.
        """

        return self.ql.mem.string(address)

    def try_read_string(self, address: int) -> Optional[str]:
        """Attempt to read a string from memory.
        """

        try:
            s = self.read_string(address)
        except UcError:
            s = None

        return s

    def get_deref(self, ptr: int) -> Union[int, str, None]:
        """Get content referenced by a pointer.

        If dereferenced data is printable, a string will be returned. Otherwise
        an integer value is retgurned. If the specified address is not reachable
        None is returned.
        """

        val = self.try_read_string(ptr)

        return val if val and val.isprintable() else self.try_read_pointer(ptr)
