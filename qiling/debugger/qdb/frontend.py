#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import Optional, Mapping, Iterable, Union
import copy, math, os

import unicorn

from qiling.const import QL_ARCH

from .utils import disasm, get_x86_eflags, setup_branch_predictor
from .const import color, SIZE_LETTER, FORMAT_LETTER


# read data from memory of qiling instance
def examine_mem(ql: Qiling, line: str) -> Union[bool, (str, int, int)]:

    _args = line.split()
    DEFAULT_FMT = ('x', 4, 1)

    if line.startswith("/"):  # followed by format letter and size letter

        def get_fmt(text):
            def extract_count(t):
                return "".join([s for s in t if s.isdigit()])

            f, s, c = DEFAULT_FMT
            if extract_count(text):
                c = int(extract_count(text))

            for char in text.strip(str(c)):
                if char in SIZE_LETTER.keys():
                    s = SIZE_LETTER.get(char)

                elif char in FORMAT_LETTER:
                    f = char

            return (f, s, c)


        fmt, *rest = line.strip("/").split()

        rest = "".join(rest)

        fmt = get_fmt(fmt)

    elif len(_args) == 1:  # only address
        rest = _args[0]
        fmt = DEFAULT_FMT

    else:
        rest = _args

    if ql.arch.type == QL_ARCH.ARM:
        rest = rest.replace("fp", "r11")

    elif ql.arch.type == QL_ARCH.MIPS:
        rest = rest.replace("fp", "s8")

    # for supporting addition of register with constant value
    elems = rest.split("+")
    elems = [elem.strip("$") for elem in elems]

    items = []
    for elem in elems:
        if elem in ql.arch.regs.register_mapping.keys():
            items.append(getattr(ql.arch.regs, elem, None))
        else:
            items.append(read_int(elem))

    addr = sum(items)

    def unpack(bs, sz):
        return {
                1: lambda x: x[0],
                2: ql.unpack16,
                4: ql.unpack32,
                8: ql.unpack64,
                }.get(sz)(bs)

    ft, sz, ct = fmt

    if ft == "i":

        for offset in range(addr, addr+ct*4, 4):
            line = disasm(ql, offset)
            if line:
                print(f"0x{line.address:x}: {line.mnemonic}\t{line.op_str}")

        print()

    else:
        lines = 1 if ct <= 4 else math.ceil(ct / 4)

        mem_read = []
        for offset in range(ct):
            # append data if read successfully, otherwise return error message
            if (data := _try_read(ql, addr+(offset*sz), sz))[0] is not None:
                mem_read.append(data[0])

            else:
                return data[1]

        for line in range(lines):
            offset = line * sz * 4
            print(f"0x{addr+offset:x}:\t", end="")

            idx = line * ql.arch.pointersize
            for each in mem_read[idx:idx+ql.arch.pointersize]:
                data = unpack(each, sz)
                prefix = "0x" if ft in ("x", "a") else ""
                pad = '0' + str(sz*2) if ft in ('x', 'a', 't') else ''
                ft = ft.lower() if ft in ("x", "o", "b", "d") else ft.lower().replace("t", "b").replace("a", "x")
                print(f"{prefix}{data:{pad}{ft}}\t", end="")

            print()

    return True


# try to read data from ql memory
def _try_read(ql: Qiling, address: int, size: int) -> Optional[bytes]:

    result = None
    err_msg = ""
    try:
        result = ql.mem.read(address, size)

    except unicorn.unicorn.UcError as err:
        if err.errno == 6: # Invalid memory read (UC_ERR_READ_UNMAPPED)
            err_msg = f"Can not access memory at address 0x{address:08x}"

    except:
        pass

    return (result, err_msg)


"""
    Context Manager for rendering UI
"""

COLORS = (color.DARKCYAN, color.BLUE, color.RED, color.YELLOW, color.GREEN, color.PURPLE, color.CYAN, color.WHITE)

# decorator function for printing divider
def context_printer(title: str, *, footer: bool = False, ruler="─"):
    def decorator(context_dumper):
        def wrapper(*args, **kwargs):
            cols, _ = os.get_terminal_size()

            print(title.center(cols, ruler))
            context_dumper(*args, **kwargs)

            if footer:
                print(ruler * cols)

        return wrapper
    return decorator


def setup_ctx_manager(ql: Qiling) -> CtxManager:
    return {
            QL_ARCH.X86: CtxManager_X86,
            QL_ARCH.ARM: CtxManager_ARM,
            QL_ARCH.CORTEX_M: CtxManager_ARM,
            QL_ARCH.MIPS: CtxManager_MIPS,
            }.get(ql.arch.type)(ql)


class CtxManager(object):
    def __init__(self, ql):
        self.ql = ql
        self.predictor = setup_branch_predictor(ql)

    def print_asm(self, insn: CsInsn, to_jump: Optional[bool] = None, address: int = None) -> None:

        opcode = "".join(f"{b:02x}" for b in insn.bytes)
        if self.ql.arch.type in (QL_ARCH.X86, QL_ARCH.X8664):
            trace_line = f"0x{insn.address:08x} │ {opcode:20s} {insn.mnemonic:10} {insn.op_str:35s}"
        else:
            trace_line = f"0x{insn.address:08x} │ {opcode:10s} {insn.mnemonic:10} {insn.op_str:35s}"

        cursor = " "
        if self.ql.arch.regs.arch_pc == insn.address:
            cursor = "►"

        jump_sign = " "
        if to_jump:
            jump_sign = f"{color.RED}✓{color.END}"

        print(f"{jump_sign}  {cursor}   {color.DARKGRAY}{trace_line}{color.END}")

    def dump_regs(self):
        return {reg_name: getattr(self.ql.arch.regs, reg_name) for reg_name in self.regs}

    def context_reg(self, saved_states):
        return NotImplementedError

    @context_printer("[ STACK ]")
    def context_stack(self):

        for idx in range(10):
            addr = self.ql.arch.regs.arch_sp + idx * self.ql.arch.pointersize
            if (val := _try_read(self.ql, addr, self.ql.arch.pointersize)[0]):
                print(f"$sp+0x{idx*self.ql.arch.pointersize:02x}│ [0x{addr:08x}] —▸ 0x{self.ql.unpack(val):08x}", end="")

            # try to dereference wether it's a pointer
            if (buf := _try_read(self.ql, addr, self.ql.arch.pointersize))[0] is not None:

                if (addr := self.ql.unpack(buf[0])):

                    # try to dereference again
                    if (buf := _try_read(self.ql, addr, self.ql.pointersize))[0] is not None:
                        try:
                            s = self.ql.mem.string(addr)
                        except:
                            s = None

                        if s and s.isprintable():
                            print(f" ◂— {self.ql.mem.string(addr)}", end="")
                        else:
                            print(f" ◂— 0x{self.ql.unpack(buf[0]):08x}", end="")
            print()

    @context_printer("[ DISASM ]", footer=True)
    def context_asm(self):
        # assembly before current location
        past_list = []
        cur_addr = self.ql.arch.regs.arch_pc

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


class CtxManager_ARM(CtxManager):
    def __init__(self, ql):
        super().__init__(ql)

        self.regs = (
                "r0", "r1", "r2", "r3",
                "r4", "r5", "r6", "r7",
                "r8", "r9", "r10", "r11",
                "r12", "sp", "lr", "pc",
                )

    @staticmethod
    def get_flags(bits: int) -> Mapping[str, int]:

        def _get_mode(bits):
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
                "mode":     _get_mode(bits),
                "thumb":    bits & 0x00000020 != 0,
                "fiq":      bits & 0x00000040 != 0,
                "irq":      bits & 0x00000080 != 0,
                "neg":      bits & 0x80000000 != 0,
                "zero":     bits & 0x40000000 != 0,
                "carry":    bits & 0x20000000 != 0,
                "overflow": bits & 0x10000000 != 0,
                }

    @context_printer("[ REGISTERS ]")
    def context_reg(self, saved_reg_dump):
        cur_regs = self.dump_regs()

        cur_regs.update({"sl": cur_regs.pop("r10")})
        cur_regs.update({"ip": cur_regs.pop("r12")})
        cur_regs.update({"fp": cur_regs.pop("r11")})

        regs_in_row = 4

        diff = None
        if saved_reg_dump is not None:
            reg_dump = copy.deepcopy(saved_reg_dump)
            reg_dump.update({"sl": reg_dump.pop("r10")})
            reg_dump.update({"ip": reg_dump.pop("r12")})
            reg_dump.update({"fp": reg_dump.pop("r11")})
            diff = [k for k in cur_regs if cur_regs[k] != reg_dump[k]]

        lines = ""
        for idx, r in enumerate(cur_regs, 1):

            line = "{}{:}: 0x{{:08x}} {}  ".format(COLORS[(idx-1) // regs_in_row], r, color.END)

            if diff and r in diff:
                line = f"{color.UNDERLINE}{color.BOLD}{line}"

            if idx % regs_in_row == 0:
                line += "\n"

            lines += line

        print(lines.format(*cur_regs.values()))
        print(color.GREEN, "[{cpsr[mode]} mode], Thumb: {cpsr[thumb]}, FIQ: {cpsr[fiq]}, IRQ: {cpsr[irq]}, NEG: {cpsr[neg]}, ZERO: {cpsr[zero]}, Carry: {cpsr[carry]}, Overflow: {cpsr[overflow]}".format(cpsr=self.get_flags(self.ql.arch.regs.cpsr)), color.END, sep="")


class CtxManager_MIPS(CtxManager):
    def __init__(self, ql):
        super().__init__(ql)

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

    @context_printer("[ REGISTERS ]")
    def context_reg(self, saved_reg_dump):

        cur_regs = self.dump_regs()

        cur_regs.update({"fp": cur_regs.pop("s8")})

        diff = None
        if saved_reg_dump is not None:
            reg_dump = copy.deepcopy(saved_reg_dump)
            reg_dump.update({"fp": saved_reg_dump.pop("s8")})
            diff = [k for k in cur_regs if cur_regs[k] != reg_dump[k]]

        lines = ""
        for idx, r in enumerate(cur_regs, 1):
            line = "{}{}: 0x{{:08x}} {}\t".format(COLORS[(idx-1) // 4], r, color.END)

            if diff and r in diff:
                line = f"{color.UNDERLINE}{color.BOLD}{line}"

            if idx % 4 == 0 and idx != 32:
                line += "\n"

            lines += line

        print(lines.format(*cur_regs.values()))


class CtxManager_X86(CtxManager):
    def __init__(self, ql):
        super().__init__(ql)

        self.regs = (
                "eax", "ebx", "ecx", "edx",
                "esp", "ebp", "esi", "edi",
                "eip", "ss", "cs", "ds", "es",
                "fs", "gs", "eflags",
                )
    @context_printer("[ REGISTERS ]")
    def context_reg(self, saved_reg_dump):
        cur_regs = self.dump_regs()

        diff = None
        if saved_reg_dump is not None:
            reg_dump = copy.deepcopy(saved_reg_dump)
            diff = [k for k in cur_regs if cur_regs[k] != saved_reg_dump[k]]

        lines = ""
        for idx, r in enumerate(cur_regs, 1):
            if len(r) == 2:
                line = "{}{}: 0x{{:08x}} {}\t\t".format(COLORS[(idx-1) // 4], r, color.END)
            else:
                line = "{}{}: 0x{{:08x}} {}\t".format(COLORS[(idx-1) // 4], r, color.END)

            if diff and r in diff:
                line = f"{color.UNDERLINE}{color.BOLD}{line}"

            if idx % 4 == 0 and idx != 32:
                line += "\n"

            lines += line

        print(lines.format(*cur_regs.values()))
        print(color.GREEN, "EFLAGS: [CF: {flags[CF]}, PF: {flags[PF]}, AF: {flags[AF]}, ZF: {flags[ZF]}, SF: {flags[SF]}, OF: {flags[OF]}]".format(flags=get_x86_eflags(self.ql.arch.regs.eflags)), color.END, sep="")

    @context_printer("[ DISASM ]", footer=True)
    def context_asm(self):
        past_list = []
        cur_addr = self.ql.arch.regs.arch_pc

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


class CtxManager_CORTEX_M(CtxManager):
    def __init__(self, ql):
        super().__init__(ql)

        self.regs = (
                "r0", "r1", "r2", "r3",
                "r4", "r5", "r6", "r7",
                "r8", "r9", "r10", "r11",
                "r12", "sp", "lr", "pc",
                "xpsr", "control", "primask", "basepri", "faultmask"
                )

    @context_printer("[ REGISTERS ]")
    def context_reg(self, saved_reg_dump):

        cur_regs.update({"sl": cur_regs.pop("r10")})
        cur_regs.update({"ip": cur_regs.pop("r12")})
        cur_regs.update({"fp": cur_regs.pop("r11")})

        regs_in_row = 3

        # for re-order
        cur_regs.update({"xpsr": cur_regs.pop("xpsr")})
        cur_regs.update({"control": cur_regs.pop("control")})
        cur_regs.update({"primask": cur_regs.pop("primask")})
        cur_regs.update({"faultmask": cur_regs.pop("faultmask")})
        cur_regs.update({"basepri": cur_regs.pop("basepri")})

        diff = None
        if saved_reg_dump is not None:
            reg_dump = copy.deepcopy(saved_reg_dump)
            reg_dump.update({"sl": reg_dump.pop("r10")})
            reg_dump.update({"ip": reg_dump.pop("r12")})
            reg_dump.update({"fp": reg_dump.pop("r11")})
            diff = [k for k in cur_regs if cur_regs[k] != reg_dump[k]]

        lines = ""
        for idx, r in enumerate(_cur_regs, 1):

            line = "{}{:}: 0x{{:08x}} {}  ".format(_colors[(idx-1) // regs_in_row], r, color.END)

            if _diff and r in _diff:
                line = "{}{}".format(color.UNDERLINE, color.BOLD) + line

            if idx % regs_in_row == 0:
                line += "\n"

            lines += line

        print(lines.format(cur_regs.values()))
        print(color.GREEN, "[{cpsr[mode]} mode], Thumb: {cpsr[thumb]}, FIQ: {cpsr[fiq]}, IRQ: {cpsr[irq]}, NEG: {cpsr[neg]}, ZERO: {cpsr[zero]}, Carry: {cpsr[carry]}, Overflow: {cpsr[overflow]}".format(cpsr=get_arm_flags(self.ql.arch.regs.cpsr)), color.END, sep="")


if __name__ == "__main__":
    pass
