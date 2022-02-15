#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import Optional, Mapping, Iterable, Union
import copy

from .misc import try_read, get_terminal_size, disasm
from .arch import ArchARM, ArchMIPS, ArchCORTEX_M, ArchX86
from .const import color


"""

    Context Render for rendering UI

"""

COLORS = (color.DARKCYAN, color.BLUE, color.RED, color.YELLOW, color.GREEN, color.PURPLE, color.CYAN, color.WHITE)

class Render(object):
    """
    base class for rendering related functions
    """

    def divider_printer(field_name, ruler="─"):
        """
        decorator function for printing divider and field name
        """

        def decorator(context_dumper):
            def wrapper(*args, **kwargs):
                height, width = get_terminal_size()
                bar = (width - len(field_name)) // 2 - 1
                print(ruler * bar, field_name, ruler * bar)
                context_dumper(*args, **kwargs)
                if "DISASM" in field_name:
                    print(ruler * width)
            return wrapper
        return decorator

    def __init__(self) -> Render:
        self.regs_a_row = 4

    def reg_diff(self, cur_regs, saved_reg_dump):
        """
        helper function for highlighting register changed during execution
        """

        if saved_reg_dump:
            reg_dump = copy.deepcopy(saved_reg_dump)
            if getattr(self, "regs_need_swaped", None):
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

    def swap_reg_name(self, cur_regs: Mapping["str", int], extra_dict=None):
        """
        swap register name with more readable register name
        """

        target_items = extra_dict.items() if extra_dict else self.regs_need_swaped.items()

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

        cursor = "►" if self.ql.reg.arch_pc == insn.address else " "

        jump_sign = f"{color.RED}✓{color.END}" if to_jump else " "

        print(f"{jump_sign}  {cursor}   {color.DARKGRAY}{trace_line}{color.END}")

    def context_reg(self, saved_states) -> None:
        """
        display context registers
        """

        return NotImplementedError

    @divider_printer("[ STACK ]")
    def context_stack(self) -> None:
        """
        display context stack
        """

        for idx in range(10):
            addr = self.ql.reg.arch_sp + idx * self.ql.pointersize
            if (val := try_read(self.ql, addr, self.ql.pointersize)[0]):
                print(f"$sp+0x{idx*self.ql.pointersize:02x}│ [0x{addr:08x}] —▸ 0x{self.ql.unpack(val):08x}", end="")

            # try to dereference wether it's a pointer
            if (buf := try_read(self.ql, addr, self.ql.pointersize))[0] is not None:

                if (addr := self.ql.unpack(buf[0])):

                    # try to dereference again
                    if (buf := try_read(self.ql, addr, self.ql.pointersize))[0] is not None:
                        try:
                            s = self.ql.mem.string(addr)
                        except:
                            s = None

                        if s and s.isprintable():
                            print(f" ◂— {self.ql.mem.string(addr)}", end="")
                        else:
                            print(f" ◂— 0x{self.ql.unpack(buf[0]):08x}", end="")
            print()

    @divider_printer("[ DISASM ]")
    def context_asm(self) -> None:
        """
        display context assembly
        """

        # assembly before current location
        past_list = []
        cur_addr = self.ql.reg.arch_pc

        line = disasm(self.ql, cur_addr-0x10)

        while line:
            if line.address == cur_addr:
                break

            addr = line.address + line.size
            line = disasm(self.ql, addr)

            if not line:
                break

            past_list.append(line)

        # print four insns before current location
        for line in past_list[:-1]:
            self.print_asm(line)

        # assembly for current location

        cur_insn = disasm(self.ql, cur_addr)
        prophecy = self.predictor.predict()
        self.print_asm(cur_insn, to_jump=prophecy.going)

        # assembly after current location

        forward_insn_size = cur_insn.size
        for _ in range(5):
            forward_insn = disasm(self.ql, cur_addr+forward_insn_size)
            if forward_insn:
                self.print_asm(forward_insn)
                forward_insn_size += forward_insn.size


class Context(object):
    """
    base class for accessing context of running qiling instance
    """

    def __init__(self, ql) -> Context:
        self.ql = ql

    def dump_regs(self) -> Mapping[str, int]:
        """
        dump all registers
        """

        return {reg_name: getattr(self.ql.reg, reg_name) for reg_name in self.regs}


class ContextRender(Context, Render):
    """
    base class for context render
    """

    def __init__(self, ql: Qiling, predictor: BranchPredictor):
        super().__init__(ql)
        Render.__init__(self)
        self.predictor = predictor


class ContextRenderARM(ContextRender, ArchARM):
    """
    context render for ARM
    """

    def __init__(self, ql: Qiling, predictor: BranchPredictor):
        super().__init__(ql, predictor)
        ArchARM.__init__(self)

    @staticmethod
    def print_mode_info(bits):
        print(color.GREEN, "[{cpsr[mode]} mode], Thumb: {cpsr[thumb]}, FIQ: {cpsr[fiq]}, IRQ: {cpsr[irq]}, NEG: {cpsr[neg]}, ZERO: {cpsr[zero]}, Carry: {cpsr[carry]}, Overflow: {cpsr[overflow]}".format(cpsr=ArchARM.get_flags(bits)), color.END, sep="")

    @Render.divider_printer("[ REGISTERS ]")
    def context_reg(self, saved_reg_dump):
        """
        redering context registers
        """

        cur_regs = self.dump_regs()
        cur_regs = self.swap_reg_name(cur_regs)
        diff_reg = self.reg_diff(cur_regs, saved_reg_dump)
        self.render_regs_dump(cur_regs, diff_reg=diff_reg)
        self.print_mode_info(self.ql.reg.cpsr)


class ContextRenderMIPS(ContextRender, ArchMIPS):
    """
    context render for MIPS
    """

    def __init__(self, ql: Qiling, predictor: BranchPredictor):
        super().__init__(ql, predictor)
        ArchMIPS.__init__(self)

    @Render.divider_printer("[ REGISTERS ]")
    def context_reg(self, saved_reg_dump):
        """
        redering context registers
        """

        cur_regs = self.dump_regs()
        cur_regs = self.swap_reg_name(cur_regs)
        diff_reg = self.reg_diff(cur_regs, saved_reg_dump)
        self.render_regs_dump(cur_regs, diff_reg=diff_reg)


class ContextRenderX86(ContextRender, ArchX86):
    """
    context render for X86
    """

    def __init__(self, ql: Qiling, predictor: BranchPredictor):
        super().__init__(ql, predictor)
        ArchX86.__init__(self)


    @Render.divider_printer("[ REGISTERS ]")
    def context_reg(self, saved_reg_dump):
        cur_regs = self.dump_regs()
        diff_reg = self.reg_diff(cur_regs, saved_reg_dump)
        self.render_regs_dump(cur_regs, diff_reg=diff_reg)
        print(color.GREEN, "EFLAGS: [CF: {flags[CF]}, PF: {flags[PF]}, AF: {flags[AF]}, ZF: {flags[ZF]}, SF: {flags[SF]}, OF: {flags[OF]}]".format(flags=self.get_flags(self.ql.reg.ef)), color.END, sep="")

    @Render.divider_printer("[ DISASM ]")
    def context_asm(self):
        past_list = []
        cur_addr = self.ql.reg.arch_pc

        cur_insn = disasm(self.ql, cur_addr)
        prophecy = self.predictor.predict()
        self.print_asm(cur_insn, to_jump=prophecy.going)

        # assembly before current location

        line = disasm(self.ql, cur_addr+cur_insn.size)
        acc_size = line.size + cur_insn.size

        while line and len(past_list) != 8:
            past_list.append(line)
            next_start = cur_addr + acc_size
            line = disasm(self.ql, next_start)
            acc_size += line.size

        # print four insns before current location
        for line in past_list[:-1]:
            self.print_asm(line)


class ContextRenderCORTEX_M(ContextRenderARM, ArchCORTEX_M):
    """
    context render for cortex_m
    """

    def __init__(self, ql: Qiling, predictor: BranchPredictor):
        super().__init__(ql, predictor)
        ArchCORTEX_M.__init__(self)
        self.regs_a_row = 3

    @Render.divider_printer("[ REGISTERS ]")
    def context_reg(self, saved_reg_dump):
        cur_regs = self.dump_regs()
        cur_regs = self.swap_reg_name(cur_regs)

        # for re-order
        extra_dict = {
                "xpsr": "xpsr",
                "control": "control",
                "primask": "primask",
                "faultmask": "faultmask",
                "basepri": "basepri",
                }

        cur_regs = self.swap_reg_name(cur_regs, extra_dict=extra_dict)
        diff_reg = self.reg_diff(cur_regs, saved_reg_dump)
        self.render_regs_dump(cur_regs, diff_reg=diff_reg)
        self.print_mode_info(self.ql.reg.cpsr)



if __name__ == "__main__":
    pass
