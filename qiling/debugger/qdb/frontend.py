#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import Optional, Mapping, Iterable, Union
import copy

from qiling.const import QL_ARCH

from .utils import setup_branch_predictor
from .misc import try_read, read_int, get_terminal_size, disasm, get_x86_eflags
from .const import color


"""

    Context Render for rendering UI

"""

COLORS = (color.DARKCYAN, color.BLUE, color.RED, color.YELLOW, color.GREEN, color.PURPLE, color.CYAN, color.WHITE)


def setup_context_render(ql: Qiling) -> ContextRender:
    """
    setup context render for corresponding archtype
    """

    return {
            QL_ARCH.X86: ContextRenderX86,
            QL_ARCH.ARM: ContextRenderARM,
            QL_ARCH.ARM_THUMB: ContextRenderARM,
            QL_ARCH.CORTEX_M: ContextRenderCORTEX_M,
            QL_ARCH.MIPS: ContextRenderMIPS,
            }.get(ql.archtype)(ql)


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

    def __init__(self):
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
            line = "{}{}: 0x{{:08x}} {}\t".format(COLORS[(idx-1) // self.regs_a_row], r, color.END)

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

class ArchMIPS(object):
    def __init__(self):

        self.archtype = QL_ARCH.MIPS

        self.regs = (
                "gp", "at", "v0", "v1",
                "a0", "a1", "a2", "a3",
                "t0", "t1", "t2", "t3",
                "t4", "t5", "t6", "t7",
                "t8", "t9", "sp", "s8",
                "s0", "s1", "s2", "s3",
                "s4", "s5", "s6", "s7",
                "ra", "k0", "k1", "pc",
                )

        self.regs_need_swaped = {
                "fp": "s8",
                }

class ArchARM():
    def __init__(self):
        self.archtype = QL_ARCH.ARM
        self.regs = (
                "r0", "r1", "r2", "r3",
                "r4", "r5", "r6", "r7",
                "r8", "r9", "r10", "r11",
                "r12", "sp", "lr", "pc",
                )

        self.regs_need_swaped = {
                "sl": "r10",
                "ip": "r12",
                "fp": "r11",
                }

    @staticmethod
    def get_flags(bits: int) -> Mapping[str, int]:
        """
        get flags for ARM
        """

        def get_mode(bits):
            """
            get operating mode for ARM
            """
            return {
                    0b10000: "User",
                    0b10001: "FIQ",
                    0b10010: "IRQ",
                    0b10011: "Supervisor",
                    0b10110: "Monitor",
                    0b10111: "Abort",
                    0b11010: "Hypervisor",
                    0b11011: "Undefined",
                    0b11111: "System",
                    }.get(bits & 0x00001f)

        return {
                "mode":     get_mode(bits),
                "thumb":    bits & 0x00000020 != 0,
                "fiq":      bits & 0x00000040 != 0,
                "irq":      bits & 0x00000080 != 0,
                "neg":      bits & 0x80000000 != 0,
                "zero":     bits & 0x40000000 != 0,
                "carry":    bits & 0x20000000 != 0,
                "overflow": bits & 0x10000000 != 0,
                }

    @staticmethod
    def print_mode_info(bits):
        print(color.GREEN, "[{cpsr[mode]} mode], Thumb: {cpsr[thumb]}, FIQ: {cpsr[fiq]}, IRQ: {cpsr[irq]}, NEG: {cpsr[neg]}, ZERO: {cpsr[zero]}, Carry: {cpsr[carry]}, Overflow: {cpsr[overflow]}".format(cpsr=ArchARM.get_flags(bits)), color.END, sep="")

class ArchCORTEX_M(ArchARM):
    def __init__(self):
        super().__init__()
        self.archtype = QL_ARCH.CORTEX_M
        self.regs += ("xpsr", "control", "primask", "basepri", "faultmask")

class ArchX86():
    def __init__(self):
        self.regs = (
                "eax", "ebx", "ecx", "edx",
                "esp", "ebp", "esi", "edi",
                "eip", "ss", "cs", "ds", "es",
                "fs", "gs", "ef",
                )


class Context(object):
    """
    base class for accessing context of running qiling instance
    """

    def __init__(self, ql):
        self.ql = ql

    def dump_regs(self) -> Mapping[str, int]:
        """
        dump all registers
        """

        return {reg_name: getattr(self.ql.reg, reg_name) for reg_name in self.regs}


class ContextRender(Context, Render):
    def __init__(self, ql: Qiling):
        super().__init__(ql)
        Render.__init__(self)
        self.predictor = setup_branch_predictor(ql)


class ContextRenderARM(ContextRender, ArchARM):
    """
    context render for ARM
    """

    def __init__(self, ql: Qiling):
        super().__init__(ql)
        ArchARM.__init__(self)

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

    def __init__(self, ql):
        super().__init__(ql)
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

    def __init__(self, ql):
        super().__init__(ql)
        ArchX86.__init__(self)


    @Render.divider_printer("[ REGISTERS ]")
    def context_reg(self, saved_reg_dump):
        cur_regs = self.dump_regs()
        diff_reg = self.reg_diff(cur_regs, saved_reg_dump)
        self.render_regs_dump(cur_regs, diff_reg=diff_reg)
        print(color.GREEN, "EFLAGS: [CF: {flags[CF]}, PF: {flags[PF]}, AF: {flags[AF]}, ZF: {flags[ZF]}, SF: {flags[SF]}, OF: {flags[OF]}]".format(flags=get_x86_eflags(self.ql.reg.ef)), color.END, sep="")

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


class ContextRenderCORTEX_M(ContextRender, ArchCORTEX_M):
    """
    context render for cortex_m
    """

    def __init__(self, ql):
        super().__init__(ql)
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

