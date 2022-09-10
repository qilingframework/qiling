#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#



from capstone import CsInsn
from typing import Mapping
import os, copy

from ..context import Context
from ..const import color



"""

    Context Render for rendering UI

"""

COLORS = (color.DARKCYAN, color.BLUE, color.RED, color.YELLOW, color.GREEN, color.PURPLE, color.CYAN, color.WHITE)

class Render:
    """
    base class for rendering related functions
    """

    def divider_printer(field_name, ruler="─"):
        """
        decorator function for printing divider and field name
        """

        def decorator(context_dumper):
            def wrapper(*args, **kwargs):
                try:
                    width, _ = os.get_terminal_size()
                except OSError:
                    width = 130

                bar = (width - len(field_name)) // 2 - 1
                print(ruler * bar, field_name, ruler * bar)
                context_dumper(*args, **kwargs)
                if "DISASM" in field_name:
                    print(ruler * width)

            return wrapper
        return decorator

    def __init__(self):
        self.regs_a_row = 4
        self.stack_num = 10
        self.color = color

    def reg_diff(self, cur_regs, saved_reg_dump):
        """
        helper function for highlighting register changed during execution
        """

        if saved_reg_dump:
            reg_dump = copy.deepcopy(saved_reg_dump)
            if getattr(self, "regs_need_swapped", None):
                reg_dump = self.swap_reg_name(reg_dump)

            return [k for k in cur_regs if cur_regs[k] != reg_dump[k]]

    def render_regs_dump(self, regs, diff_reg=None):
        """
        helper function for redering registers dump
        """

        lines = ""
        for idx, r in enumerate(regs, 1):
            line = "{}{}: 0x{{:08x}}  {}\t".format(COLORS[(idx-1) // self.regs_a_row], r, color.END)

            if diff_reg and r in diff_reg:
                line = f"{color.UNDERLINE}{color.BOLD}{line}"

            if idx % self.regs_a_row == 0 and idx != 32:
                line += "\n"

            lines += line

        print(lines.format(*regs.values()))

    def render_stack_dump(self, arch_sp: int) -> None:
        """
        helper function for redering stack dump
        """

        for idx in range(self.stack_num):
            addr = arch_sp + idx * self.pointersize
            if (val := self.try_read_pointer(addr)[0]):
                print(f"$sp+0x{idx*self.pointersize:02x}│ [0x{addr:08x}] —▸ 0x{self.unpack(val):08x}", end="")

            # try to dereference wether it's a pointer
            if (buf := self.try_read_pointer(addr))[0] is not None:

                if (addr := self.unpack(buf[0])):

                    # try to dereference again
                    if (buf := self.try_read_pointer(addr))[0] is not None:
                        s = self.try_read_string(addr)

                        if s and s.isprintable():
                            print(f" ◂— {self.read_string(addr)}", end="")
                        else:
                            print(f" ◂— 0x{self.unpack(buf[0]):08x}", end="")
            print()

    def render_assembly(self, lines) -> None:
        """
        helper function for rendering assembly
        """

        # assembly before current location
        if (backward := lines.get("backward", None)):
            for line in backward:
                self.print_asm(line)

        # assembly for current location
        if (cur_insn := lines.get("current", None)):
            prophecy = self.predictor.predict()
            self.print_asm(cur_insn, to_jump=prophecy.going)

        # assembly after current location
        if (forward := lines.get("forward", None)):
            for line in forward:
                self.print_asm(line)

    def swap_reg_name(self, cur_regs: Mapping[str, int], extra_dict=None) -> Mapping[str, int]:
        """
        swap register name with more readable register name
        """

        target_items = extra_dict.items() if extra_dict else self.regs_need_swapped.items()

        for old_reg, new_reg in target_items:
            cur_regs.update({old_reg: cur_regs.pop(new_reg)})

        return cur_regs 

    def print_asm(self, insn: CsInsn, to_jump: bool = False) -> None:
        """
        helper function for printing assembly instructions, indicates where we are and the branch prediction
        provided by BranchPredictor
        """

        opcode = "".join(f"{b:02x}" for b in insn.bytes)
        trace_line = f"0x{insn.address:08x} │ {opcode:15s} {insn.mnemonic:10} {insn.op_str:35s}"

        cursor = "►" if self.cur_addr == insn.address else " "

        jump_sign = f"{color.RED}✓{color.END}" if to_jump else " "

        print(f"{jump_sign}  {cursor}   {color.DARKGRAY}{trace_line}{color.END}")


class ContextRender(Context, Render):
    """
    base class for context render
    """

    def __init__(self, ql, predictor):
        super().__init__(ql)
        Render.__init__(self)
        self.predictor = predictor

    def dump_regs(self) -> Mapping[str, int]:
        """
        dump all registers
        """

        return {reg_name: self.ql.arch.regs.read(reg_name) for reg_name in self.regs}

    @Render.divider_printer("[ STACK ]")
    def context_stack(self) -> None:
        """
        display context stack dump
        """

        self.render_stack_dump(self.ql.arch.regs.arch_sp)

    @Render.divider_printer("[ REGISTERS ]")
    def context_reg(self, saved_states: Mapping["str", int]) -> None:
        """
        display context registers dump
        """

        return NotImplementedError

    @Render.divider_printer("[ DISASM ]")
    def context_asm(self) -> None:
        """
        read context assembly and render with render_assembly
        """

        lines = {}
        past_list = []
        from_addr = self.cur_addr - 0x10
        to_addr = self.cur_addr + 0x10

        cur_addr = from_addr
        while cur_addr != to_addr:
            insn = self.disasm(cur_addr)
            cur_addr += self.arch_insn_size
            if not insn:
                continue
            past_list.append(insn)

        bk_list = []
        fd_list = []
        cur_insn = None
        for each in past_list:
            if each.address < self.cur_addr:
                bk_list.append(each)

            elif each.address > self.cur_addr:
                fd_list.append(each)

            elif each.address == self.cur_addr:
                cur_insn = each 

        lines.update({
            "backward": bk_list,
            "forward": fd_list,
            "current": cur_insn,
            })

        self.render_assembly(lines)
