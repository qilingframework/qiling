#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Optional

from .render import Render, ContextRender
from ..arch import ArchIntel, ArchX86, ArchX64


class ContextRenderIntel(ContextRender):
    """Context renderer base class for Intel architecture.
    """

    def print_mode_info(self) -> None:
        eflags = self.read_reg('eflags')

        flags = ArchIntel.get_flags(eflags)
        iopl = ArchIntel.get_iopl(eflags)

        self.render_flags(flags, f'iopl: {iopl}')

    @Render.divider_printer("[ DISASM ]", footer=True)
    def context_asm(self) -> None:
        """Disassemble srrounding instructions.
        """

        address = self.cur_addr
        prediction = self.predictor.predict()

        ptr = address
        listing = []

        # since intel architecture has instructions with varying sizes, it is
        # difficult to tell what were the preceding instructions. for that reason
        # we display instructions only from current address and on.

        for _ in range(9):
            insn = self.disasm(ptr)
            listing.append(insn)

            ptr += insn.size

        self.render_assembly(listing, address, prediction)


class ContextRenderX86(ContextRenderIntel, ArchX86):
    """Context renderer for x86 architecture.
    """


class ContextRenderX64(ContextRenderIntel, ArchX64):
    """Context renderer for x86-64 architecture.
    """
