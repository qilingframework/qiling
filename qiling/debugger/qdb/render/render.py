#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""Context Render for rendering UI
"""


from __future__ import annotations

import os

from typing import TYPE_CHECKING, Callable, Collection, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

from ..context import Context
from ..const import color


if TYPE_CHECKING:
    from qiling.core import Qiling
    from ..branch_predictor.branch_predictor import BranchPredictor, Prophecy
    from ..misc import InsnLike


COLORS = (
    color.DARKCYAN,
    color.BLUE,
    color.RED,
    color.YELLOW,
    color.GREEN,
    color.PURPLE,
    color.CYAN,
    color.WHITE
)

RARROW = '\u2192'
RULER = '\u2500'

CURSOR   = '\u25ba'  # current instruction cursor
GOING_DN = '\u2ba6'  # branching downward to a higher address
GOING_UP = '\u2ba4'  # branching upward to a lower address


class Render:
    """Base class for graphical rendering functionality.

    Render objects are agnostic to current emulation state.
    """

    def __init__(self):
        # make sure mixin classes are properly initialized
        super().__init__()

        self.regs_a_row = 4  # number of regs to display per row
        self.stack_num = 8   # number of stack entries to display in context
        self.disasm_num = 4  # number of instructions to display in context before and after current pc

    @staticmethod
    def divider_printer(header: str, footer: bool = False):
        """
        decorator function for printing divider and field name
        """

        def decorator(wrapped: Callable):
            def wrapper(*args, **kwargs):
                try:
                    width, _ = os.get_terminal_size()
                except OSError:
                    width = 130

                print(header.center(width, RULER))
                wrapped(*args, **kwargs)

                if footer:
                    print(RULER * width)

            return wrapper
        return decorator

    def reg_diff(self, curr: Mapping[str, int], prev: Mapping[str, int]) -> List[str]:
        """
        helper function for highlighting register changed during execution
        """

        return [k for k in curr if curr[k] != prev[k]] if prev else []

    def render_regs_dump(self, regs: Mapping[str, int], diff_reg: Collection[str]) -> None:
        """Helper function for rendering registers dump.
        """

        # find the length of the longest reg name to have all regs aligned in columns
        longest = max(len(name) for name in regs)

        def __render_regs_line() -> Iterator[str]:
            elements = []

            for idx, (name, value) in enumerate(regs.items()):
                line_color = f'{COLORS[idx // self.regs_a_row]}'

                if name in diff_reg:
                    line_color = f'{color.UNDERLINE}{color.BOLD}{line_color}'

                elements.append(f'{line_color}{name:{longest}s}: {value:#010x}{color.END}')

                if (idx + 1) % self.regs_a_row == 0:
                    yield '\t'.join(elements)

                    elements.clear()

        for line in __render_regs_line():
            print(line)

    def render_flags(self, flags: Mapping[str, int], before: str = ''):
        def __set(f: str) -> str:
            return f'{color.BLUE}{f.upper()}{color.END}'

        def __cleared(f: str) -> str:
            return f'{color.GREEN}{f.lower()}{color.END}'

        s_before = f"[{before}] " if before else ""
        s_flags = " ".join(__set(f) if val else __cleared(f) for f, val in flags.items())

        print(f'{s_before}[flags: {s_flags}]')

    def render_stack_dump(self, sp: int, dump: Sequence[Tuple[int, int, Union[int, str, None]]]) -> None:
        """Helper function for rendering stack dump.
        """

        # number of hexadecimal nibbles to display per value
        nibbles = self.pointersize * 2

        for address, value, deref in dump:
            offset = address - sp

            value_str = '(unreachable)' if value is None else f'{value:#0{nibbles + 2}x}'

            if isinstance(deref, int):
                deref_str = f'{deref:#0{nibbles + 2}x}'

            elif isinstance(deref, str):
                deref_str = f'"{deref}"'

            else:
                deref_str = ''

            print(f'SP + {offset:#04x} │ {address:#010x} : {value_str}{f" {RARROW} {deref_str}" if deref_str else ""}')

    def render_assembly(self, listing: Sequence[InsnLike], pc: int, prediction: Prophecy) -> None:
        """Helper function for rendering assembly.
        """

        def __render_asm_line(insn: InsnLike) -> str:
            """Helper function for rendering assembly instructions, indicates where we are and
            the branch prediction provided by branch predictor
            """

            trace_line = f"{insn.address:#010x} │ {insn.bytes.hex():18s} {insn.mnemonic:12} {insn.op_str:35s}"

            cursor = ''  # current instruction cursor
            brmark = ''  # branching mark

            if insn.address == pc:
                cursor = CURSOR

                if prediction.going:
                    # branch target might be None in case it should have been
                    # read from memory but that memory could not be reached
                    bmark = '?' if prediction.where is None else (GOING_DN if prediction.where > pc else GOING_UP)

                    # apply some colors
                    brmark = f'{color.RED}{bmark}{color.RESET}'

                # <DEBUG>
                where = '?' if prediction.where is None else f'{prediction.where:#010x}'

                print(f'prediction: {f"taken, {where}" if prediction.going else "not taken"}')
                # </DEBUG>

            return f"{brmark:1s}  {cursor:1s}   {color.DARKGRAY}{trace_line}{color.RESET}"

        for insn in listing:
            print(__render_asm_line(insn))


class ContextRender(Context, Render):
    """
    base class for context render
    """

    def __init__(self, ql: Qiling, predictor: BranchPredictor):
        super().__init__(ql)

        self.predictor = predictor
        self.prev_regs: Dict[str, int] = {}

    def get_regs(self) -> Dict[str, int]:
        """Save current registers state.
        """

        return {reg_name: self.read_reg(reg_name) for reg_name in self.regs}

    @Render.divider_printer("[ STACK ]")
    def context_stack(self) -> None:
        """
        display context stack dump
        """

        sp = self.cur_sp
        stack_dump = []

        for i in range(self.stack_num):
            address = sp + i * self.asize

            # attempt to read current stack entry
            value = self.try_read_pointer(address)

            # treat stack entry as a pointer and attempt to dereference it
            deref = None if value is None else self.get_deref(value)

            stack_dump.append((address, value, deref))

        self.render_stack_dump(sp, stack_dump)

    @Render.divider_printer("[ REGISTERS ]")
    def context_reg(self) -> None:
        """Rendering registers context.
        """

        curr = self.get_regs()
        prev = self.prev_regs

        curr = self.swap_regs(curr)
        prev = self.swap_regs(prev)

        diff_reg = self.reg_diff(curr, prev)
        self.render_regs_dump(curr, diff_reg)
        self.print_mode_info()

    @Render.divider_printer("[ DISASM ]", footer=True)
    def context_asm(self) -> None:
        """Disassemble srrounding instructions.
        """

        address = self.cur_addr
        prediction = self.predictor.predict()

        # assuming a single instruction is in the same size of a native pointer.
        # this is not true for all architectures.
        ptr = address - self.pointersize * self.disasm_num
        listing = []

        # taking disasm_num instructions before, current, and disasm_num instructions after
        for _ in range(self.disasm_num * 2 + 1):
            insn = self.disasm(ptr)
            listing.append(insn)

            ptr += insn.size

        self.render_assembly(listing, address, prediction)
