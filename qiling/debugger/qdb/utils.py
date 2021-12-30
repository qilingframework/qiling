#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import Callable, Optional, Mapping
from functools import partial

from qiling.const import *

CODE_END = True


def dump_regs(ql: Qiling) -> Mapping[str, int]:

    if ql.archtype == QL_ARCH.MIPS:

        _reg_order = (
                "gp", "at", "v0", "v1",
                "a0", "a1", "a2", "a3",
                "t0", "t1", "t2", "t3",
                "t4", "t5", "t6", "t7",
                "t8", "t9", "sp", "s8",
                "s0", "s1", "s2", "s3",
                "s4", "s5", "s6", "s7",
                "ra", "k0", "k1", "pc",
                )

    elif ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB):

        _reg_order = (
                "r0", "r1", "r2", "r3",
                "r4", "r5", "r6", "r7",
                "r8", "r9", "r10", "r11",
                "r12", "sp", "lr", "pc",
                )

    elif ql.archtype == QL_ARCH.CORTEX_M:

        _reg_order = (
                "r0", "r1", "r2", "r3",
                "r4", "r5", "r6", "r7",
                "r8", "r9", "r10", "r11",
                "r12", "sp", "lr", "pc",
                "xpsr", "control", "primask", "basepri", "faultmask"
                )

    return {reg_name: getattr(ql.reg, reg_name) for reg_name in _reg_order}


def get_arm_flags(bits: int) -> Mapping[str, int]:

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


# parse unsigned integer from string
def _parse_int(s: str) -> int:
    return int(s, 0)


# function dectorator for parse argument as integer
def parse_int(func: Callable) -> Callable:
    def wrap(qdb, s: str) -> int:
        assert type(s) is str
        try:
            ret = _parse_int(s)
        except:
            ret = None
        return func(qdb, ret)
    return wrap

# check wether negative value or not
def is_negative(i: int) -> int:
    return i & (1 << 31)


# convert valu to signed
def signed_val(val: int) -> int:
    return (val-1 << 32) if is_negative(val) else val


# handle braches and jumps so we can set berakpoint properly
def handle_bnj(ql: Qiling, cur_addr: str) -> Callable[[Qiling, str], int]:
    return {
            QL_ARCH.MIPS     : handle_bnj_mips,
            QL_ARCH.ARM      : handle_bnj_arm,
            QL_ARCH.ARM_THUMB: handle_bnj_arm,
            QL_ARCH.CORTEX_M : handle_bnj_arm,
            }.get(ql.archtype)(ql, cur_addr)


def get_cpsr(bits: int) -> (bool, bool, bool, bool):
    return (
            bits & 0x10000000 != 0, # V, overflow flag
            bits & 0x20000000 != 0, # C, carry flag
            bits & 0x40000000 != 0, # Z, zero flag
            bits & 0x80000000 != 0, # N, sign flag
            )


def is_thumb(bits: int) -> bool:
    return bits & 0x00000020 != 0


def disasm(ql: Qiling, address: int, detail: bool = False) -> Optional[int]:

    md = ql.disassembler
    md.detail = detail
    try:
        ret = next(md.disasm(_read_inst(ql, address), address))

    except StopIteration:
        ret = None

    return ret


def _read_inst(ql: Qiling, addr: int) -> int:

    result = ql.mem.read(addr, 4)

    if ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB, QL_ARCH.CORTEX_M):
        if is_thumb(ql.reg.cpsr):

            first_two = ql.unpack16(ql.mem.read(addr, 2))
            result = ql.pack16(first_two)

            # to judge whether it's thumb mode or not
            if any([
                first_two & 0xf000 == 0xf000,
                first_two & 0xf800 == 0xf800,
                first_two & 0xe800 == 0xe800,
                 ]):

                latter_two = ql.unpack16(ql.mem.read(addr+2, 2))
                result += ql.pack16(latter_two)

    return result


def handle_bnj_arm(ql: Qiling, cur_addr: str) -> int:

    def _read_reg_val(regs, _reg):
        return getattr(ql.reg, _reg.replace("ip", "r12").replace("fp", "r11"))

    def regdst_eq_pc(op_str):
        return op_str.partition(", ")[0] == "pc"

    read_inst = partial(_read_inst, ql)
    read_reg_val = partial(_read_reg_val, ql.reg)

    ARM_INST_SIZE = 4
    ARM_THUMB_INST_SIZE = 2

    line = disasm(ql, cur_addr)
    ret_addr = cur_addr + line.size

    if line.mnemonic == "udf": # indicates program exited
        return CODE_END

    jump_table = {
            # unconditional branch
            "b"    : (lambda *_: True),
            "bl"   : (lambda *_: True),
            "bx"   : (lambda *_: True),
            "blx"  : (lambda *_: True),
            "b.w"  : (lambda *_: True),

            # branch on equal, Z == 1
            "beq"  : (lambda V, C, Z, N: Z == 1),
            "bxeq" : (lambda V, C, Z, N: Z == 1),
            "beq.w": (lambda V, C, Z, N: Z == 1),

            # branch on not equal, Z == 0
            "bne"  : (lambda V, C, Z, N: Z == 0),
            "bxne" : (lambda V, C, Z, N: Z == 0),
            "bne.w": (lambda V, C, Z, N: Z == 0),

            # branch on signed greater than, Z == 0 and N == V
            "bgt"  : (lambda V, C, Z, N: (Z == 0 and N == V)),
            "bgt.w": (lambda V, C, Z, N: (Z == 0 and N == V)),

            # branch on signed less than, N != V
            "blt"  : (lambda V, C, Z, N: N != V),

            # branch on signed greater than or equal, N == V
            "bge"  : (lambda V, C, Z, N: N == V),

            # branch on signed less than or queal
            "ble"  : (lambda V, C, Z, N: Z == 1 or N != V),

            # branch on unsigned higher or same (or carry set), C == 1
            "bhs"  : (lambda V, C, Z, N: C == 1),
            "bcs"  : (lambda V, C, Z, N: C == 1),

            # branch on unsigned lower (or carry clear), C == 0
            "bcc"  : (lambda V, C, Z, N: C == 0),
            "blo"  : (lambda V, C, Z, N: C == 0),
            "bxlo" : (lambda V, C, Z, N: C == 0),
            "blo.w": (lambda V, C, Z, N: C == 0),

            # branch on negative or minus, N == 1
            "bmi"  : (lambda V, C, Z, N: N == 1),

            # branch on positive or plus, N == 0
            "bpl"  : (lambda V, C, Z, N: N == 0),

            # branch on signed overflow
            "bvs"  : (lambda V, C, Z, N: V == 1),

            # branch on no signed overflow
            "bvc"  : (lambda V, C, Z, N: V == 0),

            # branch on unsigned higher
            "bhi"  : (lambda V, C, Z, N: (Z == 0 and C == 1)),
            "bxhi" : (lambda V, C, Z, N: (Z == 0 and C == 1)),
            "bhi.w": (lambda V, C, Z, N: (Z == 0 and C == 1)),

            # branch on unsigned lower
            "bls"  : (lambda V, C, Z, N: (C == 0 or Z == 1)),
            "bls.w": (lambda V, C, Z, N: (C == 0 or Z == 1)),
            }

    cb_table = {
            # branch on equal to zero
            "cbz" : (lambda r: r == 0),

            # branch on not equal to zero
            "cbnz": (lambda r: r != 0),
            }

    to_jump = False
    if line.mnemonic in jump_table:
        to_jump = jump_table.get(line.mnemonic)(*get_cpsr(ql.reg.cpsr))

    elif line.mnemonic in cb_table:
        to_jump = cb_table.get(line.mnemonic)(read_reg_val(line.op_str.split(", ")[0]))

    if to_jump:
        if "#" in line.op_str:
            ret_addr = _parse_int(line.op_str.split("#")[-1])
        else:
            ret_addr = read_reg_val(line.op_str)

            if regdst_eq_pc(line.op_str):
                next_addr = cur_addr + line.size
                n2_addr = next_addr + len(read_inst(next_addr))
                ret_addr += len(read_inst(n2_addr)) + len(read_inst(next_addr))

    elif line.mnemonic.startswith("it"):
        # handle IT block here

        cond_met = {
                "eq": lambda V, C, Z, N: (Z == 1),
                "ne": lambda V, C, Z, N: (Z == 0),
                "ge": lambda V, C, Z, N: (N == V),
                "hs": lambda V, C, Z, N: (C == 1),
                "lo": lambda V, C, Z, N: (C == 0),
                "mi": lambda V, C, Z, N: (N == 1),
                "pl": lambda V, C, Z, N: (N == 0),
                "ls": lambda V, C, Z, N: (C == 0 or Z == 1),
                "le": lambda V, C, Z, N: (Z == 1 or N != V),
                "hi": lambda V, C, Z, N: (Z == 0 and C == 1),
                }.get(line.op_str)(*get_cpsr(ql.reg.cpsr))

        it_block_range = [each_char for each_char in line.mnemonic[1:]]

        next_addr = cur_addr + ARM_THUMB_INST_SIZE
        for each in it_block_range:
            _inst = read_inst(next_addr)
            n2_addr = handle_bnj_arm(ql, next_addr)

            if (cond_met and each == "t") or (not cond_met and each == "e"):
                if n2_addr != (next_addr+len(_inst)): # branch detected
                    break

            next_addr += len(_inst)

        ret_addr = next_addr

    elif line.mnemonic in ("ldr",):

        if regdst_eq_pc(line.op_str):
            _, _, rn_offset = line.op_str.partition(", ")
            r, _, imm = rn_offset.strip("[]!").partition(", #")

            if "]" in rn_offset.split(", ")[1]: # pre-indexed immediate
                ret_addr = ql.unpack32(ql.mem.read(_parse_int(imm) + read_reg_val(r), ARM_INST_SIZE))

            else: # post-indexed immediate
                # FIXME: weired behavior, immediate here does not apply
                ret_addr = ql.unpack32(ql.mem.read(read_reg_val(r), ARM_INST_SIZE))

    elif line.mnemonic in ("addls", "addne", "add") and regdst_eq_pc(line.op_str):
        V, C, Z, N = get_cpsr(ql.reg.cpsr)
        r0, r1, r2, *imm = line.op_str.split(", ")

        # program counter is awalys 8 bytes ahead when it comes with pc, need to add extra 8 bytes
        extra = 8 if 'pc' in (r0, r1, r2) else 0

        if imm:
            expr = imm[0].split()
            # TODO: should support more bit shifting and rotating operation
            if expr[0] == "lsl": # logical shift left
                n = _parse_int(expr[-1].strip("#")) * 2

        if line.mnemonic == "addls" and (C == 0 or Z == 1):
            ret_addr = extra + read_reg_val(r1) + read_reg_val(r2) * n

        elif line.mnemonic == "add" or (line.mnemonic == "addne" and Z == 0):
            ret_addr = extra + read_reg_val(r1) + (read_reg_val(r2) * n if imm else read_reg_val(r2))

    elif line.mnemonic in ("tbh", "tbb"):

        cur_addr += ARM_INST_SIZE
        r0, r1, *imm = line.op_str.strip("[]").split(", ")

        if imm:
            expr = imm[0].split()
            if expr[0] == "lsl": # logical shift left
                n = _parse_int(expr[-1].strip("#")) * 2

        if line.mnemonic == "tbh":

            r1 = read_reg_val(r1) * n

        elif line.mnemonic == "tbb":

            r1 = read_reg_val(r1)

        to_add = int.from_bytes(ql.mem.read(cur_addr+r1, 2 if line.mnemonic == "tbh" else 1), byteorder="little") * n
        ret_addr = cur_addr + to_add

    elif line.mnemonic.startswith("pop") and "pc" in line.op_str:

        ret_addr = ql.stack_read(line.op_str.strip("{}").split(", ").index("pc") * ARM_INST_SIZE)
        if not { # step to next instruction if cond does not meet
                "pop"  : lambda *_: True,
                "pop.w": lambda *_: True,
                "popeq": lambda V, C, Z, N: (Z == 1),
                "popne": lambda V, C, Z, N: (Z == 0),
                "pophi": lambda V, C, Z, N: (C == 1),
                "popge": lambda V, C, Z, N: (N == V),
                "poplt": lambda V, C, Z, N: (N != V),
                }.get(line.mnemonic)(*get_cpsr(ql.reg.cpsr)):

            ret_addr = cur_addr + ARM_INST_SIZE

    elif line.mnemonic == "sub" and regdst_eq_pc(line.op_str):
        _, r, imm = line.op_str.split(", ")
        ret_addr = read_reg_val(r) - _parse_int(imm.strip("#"))

    elif line.mnemonic == "mov" and regdst_eq_pc(line.op_str):
        _, r = line.op_str.split(", ")
        ret_addr = read_reg_val(r)

    if ret_addr & 1:
        ret_addr -= 1

    return (to_jump, ret_addr)


def handle_bnj_mips(ql: Qiling, cur_addr: str) -> int:
    MIPS_INST_SIZE = 4

    def _read_reg(regs, _reg):
        return signed_val(getattr(regs, _reg.strip('$').replace("fp", "s8")))

    read_reg_val = partial(_read_reg, ql.reg)

    line = disasm(ql, cur_addr)

    if line.mnemonic == "break": # indicates program extied
        return CODE_END

    # default breakpoint address if no jumps and branches here
    ret_addr = cur_addr + MIPS_INST_SIZE

    to_jump = False
    if line.mnemonic.startswith('j') or line.mnemonic.startswith('b'):

        # make sure at least delay slot executed
        ret_addr += MIPS_INST_SIZE

        # get registers or memory address from op_str
        targets = [
                read_reg_val(each)
                if '$' in each else _parse_int(each)
                for each in line.op_str.split(", ")
                ]

        to_jump = {
                "j"       : (lambda _: True),             # uncontitional jump
                "jr"      : (lambda _: True),             # uncontitional jump
                "jal"     : (lambda _: True),             # uncontitional jump
                "jalr"    : (lambda _: True),             # uncontitional jump
                "b"       : (lambda _: True),             # unconditional branch
                "bl"      : (lambda _: True),             # unconditional branch
                "bal"     : (lambda _: True),             # unconditional branch
                "beq"     : (lambda r0, r1, _: r0 == r1), # branch on equal
                "bne"     : (lambda r0, r1, _: r0 != r1), # branch on not equal
                "blt"     : (lambda r0, r1, _: r0 < r1),  # branch on r0 less than r1
                "bgt"     : (lambda r0, r1, _: r0 > r1),  # branch on r0 greater than r1
                "ble"     : (lambda r0, r1, _: r0 <= r1), # brach on r0 less than or equal to r1
                "bge"     : (lambda r0, r1, _: r0 >= r1), # branch on r0 greater than or equal to r1
                "beqz"    : (lambda r, _: r == 0),        # branch on equal to zero
                "bnez"    : (lambda r, _: r != 0),        # branch on not equal to zero
                "bgtz"    : (lambda r, _: r > 0),         # branch on greater than zero
                "bltz"    : (lambda r, _: r < 0),         # branch on less than zero
                "bltzal"  : (lambda r, _: r < 0),         # branch on less than zero and link
                "blez"    : (lambda r, _: r <= 0),        # branch on less than or equal to zero
                "bgez"    : (lambda r, _: r >= 0),        # branch on greater than or equal to zero
                "bgezal"  : (lambda r, _: r >= 0),        # branch on greater than or equal to zero and link
                }.get(line.mnemonic)(*targets)

        if to_jump:
            # target address is always the rightmost one
            ret_addr = targets[-1]

    return (to_jump, ret_addr)

class Breakpoint(object):
    """
    dummy class for breakpoint
    """
    def __init__(self, address: int):
        self.addr = address
        self.hitted = False
        self.hook = None

class TempBreakpoint(Breakpoint):
    """
    dummy class for temporay breakpoint
    """
    def __init__(self, address):
        super().__init__(address)


if __name__ == "__main__":
    pass
