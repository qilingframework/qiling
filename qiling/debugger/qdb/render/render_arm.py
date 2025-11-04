#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Iterator

from .render import Render, ContextRender
from ..arch import ArchARM, ArchCORTEX_M
from ..misc import InsnLike


class ContextRenderARM(ContextRender, ArchARM):
    """Context renderer for ARM architecture.
    """

    def print_mode_info(self) -> None:
        cpsr = self.read_reg(self._flags_reg)

        flags = ArchARM.get_flags(cpsr)
        mode = ArchARM.get_mode(cpsr)

        self.render_flags(flags, f'{mode} mode')

    def __disasm_all(self, rng: range) -> Iterator[InsnLike]:
        addr = rng.start

        while addr in rng:
            insn = self.disasm(addr)
            yield insn

            addr += insn.size

    @Render.divider_printer("[ DISASM ]", footer=True)
    def context_asm(self) -> None:
        """Disassemble srrounding instructions.
        """

        address = self.cur_addr
        prediction = self.predictor.predict()

        # arm thumb may mix narrow and wide instructions so we can never know for
        # sure where we need to start reading instructions from. to work around
        # that we assume all instructions are wide, and then take the most recent
        # ones into consideration.

        listing = []

        begin = address - self.asize * self.disasm_num
        end = address

        # disassemble all instructions in range, but keep only the last ones
        listing.extend(self.__disasm_all(range(begin, end)))
        listing = listing[-self.disasm_num:]

        begin = address
        end = address + self.asize * (self.disasm_num + 1)

        # disassemble all instructions in range, but keep only the first ones
        listing.extend(self.__disasm_all(range(begin, end)))
        listing = listing[:self.disasm_num * 2 + 1]

        self.render_assembly(listing, address, prediction)


class ContextRenderCORTEX_M(ContextRenderARM, ArchCORTEX_M):
    """Context renderer for ARM Cortex-M architecture.
    """
