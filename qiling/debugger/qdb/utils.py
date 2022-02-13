#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import Callable, Optional, Mapping
import ast, re

from qiling.const import *


# parse unsigned integer from string
def read_int(s: str) -> int:
    return int(s, 0)


# function dectorator for parsing argument as integer
def parse_int(func: Callable) -> Callable:
    def wrap(qdb, s: str = "") -> int:
        assert type(s) is str
        try:
            ret = read_int(s)
        except:
            ret = None
        return func(qdb, ret)
    return wrap


# check wether negative value or not
def is_negative(i: int) -> int:
    return i & (1 << 31)


# signed value convertion
def signed_val(val: int) -> int:
    return (val-1 << 32) if is_negative(val) else val


def get_cpsr(bits: int) -> (bool, bool, bool, bool):
    return (
            bits & 0x10000000 != 0, # V, overflow flag
            bits & 0x20000000 != 0, # C, carry flag
            bits & 0x40000000 != 0, # Z, zero flag
            bits & 0x80000000 != 0, # N, sign flag
            )


def get_x86_eflags(bits: int) -> Dict[str, bool]:
    return {
            "CF" : bits & 0x0001 != 0, # CF, carry flag
            "PF" : bits & 0x0004 != 0, # PF, parity flag
            "AF" : bits & 0x0010 != 0, # AF, adjust flag
            "ZF" : bits & 0x0040 != 0, # ZF, zero flag
            "SF" : bits & 0x0080 != 0, # SF, sign flag
            "OF" : bits & 0x0800 != 0, # OF, overflow flag
            }


def is_thumb(bits: int) -> bool:
    return bits & 0x00000020 != 0


def disasm(ql: Qiling, address: int, detail: bool = False) -> Optional[int]:
    """
    helper function for disassembling
    """

    md = ql.disassembler
    md.detail = detail
    try:
        ret = next(md.disasm(read_insn(ql, address), address))

    except StopIteration:
        ret = None

    return ret


def read_insn(ql: Qiling, addr: int) -> int:
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

    elif ql.archtype in (QL_ARCH.X86, QL_ARCH.X8664):
        # due to the variadic lengh of x86 instructions ( 1~15 )
        # always assume the maxium size for disassembler to tell
        # what is it exactly.
        result = ql.mem.read(addr, 15)

    return result

"""
    Try to predict certian branch will be taken or not based on current context
"""

def setup_branch_predictor(ql: Qiling) -> BranchPredictor:
    return {
            QL_ARCH.X86: BranchPredictor_X86,
            QL_ARCH.ARM: BranchPredictor_ARM,
            QL_ARCH.ARM_THUMB: BranchPredictor_ARM,
            QL_ARCH.CORTEX_M: BranchPredictor_CORTEX_M,
            QL_ARCH.MIPS: BranchPredictor_MIPS,
            }.get(ql.archtype)(ql)


class Prophecy(object):
    def __init__(self):
        self.going = False
        self.where = None

    def __iter__(self):
        return iter((self.going, self.where))


class BranchPredictor(object):
    def __init__(self, ql):
        self.ql = ql

    def read_reg(self, reg_name):
        return getattr(self.ql.reg, reg_name)

    def predict(self):
        return NotImplementedError


class BranchPredictor_ARM(BranchPredictor):
    def __init__(self, ql):
        super().__init__(ql)

        self.INST_SIZE = 4
        self.THUMB_INST_SIZE = 2
        self.CODE_END = "udf"

    def read_reg(self, reg_name):
        reg_name = reg_name.replace("ip", "r12").replace("fp", "r11")
        return getattr(self.ql.reg, reg_name)

    def regdst_eq_pc(self, op_str):
        return op_str.partition(", ")[0] == "pc"

    def predict(self):
        prophecy = Prophecy()
        cur_addr = self.ql.reg.arch_pc
        line = disasm(self.ql, cur_addr)
        prophecy.where = cur_addr + line.size

        if line.mnemonic == self.CODE_END: # indicates program exited
            return True

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

        if line.mnemonic in jump_table:
            prophecy.going = jump_table.get(line.mnemonic)(*get_cpsr(self.ql.reg.cpsr))

        elif line.mnemonic in cb_table:
            prophecy.going = cb_table.get(line.mnemonic)(self.read_reg(line.op_str.split(", ")[0]))

        if prophecy.going:
            if "#" in line.op_str:
                prophecy.where = read_int(line.op_str.split("#")[-1])
            else:
                prophecy.where = self.read_reg(line.op_str)

                if self.regdst_eq_pc(line.op_str):
                    next_addr = cur_addr + line.size
                    n2_addr = next_addr + len(read_insn(next_addr))
                    prophecy.where += len(read_insn(n2_addr)) + len(read_insn(next_addr))

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

            next_addr = cur_addr + self.THUMB_INST_SIZE
            for each in it_block_range:
                _insn = read_insn(next_addr)
                n2_addr = handle_bnj_arm(ql, next_addr)

                if (cond_met and each == "t") or (not cond_met and each == "e"):
                    if n2_addr != (next_addr+len(_insn)): # branch detected
                        break

                next_addr += len(_insn)

            prophecy.where = next_addr

        elif line.mnemonic in ("ldr",):

            if self.regdst_eq_pc(line.op_str):
                _, _, rn_offset = line.op_str.partition(", ")
                r, _, imm = rn_offset.strip("[]!").partition(", #")

                if "]" in rn_offset.split(", ")[1]: # pre-indexed immediate
                    prophecy.where = ql.unpack32(ql.mem.read(read_int(imm) + self.read_reg(r), self.INST_SIZE))

                else: # post-indexed immediate
                    # FIXME: weired behavior, immediate here does not apply
                    prophecy.where = ql.unpack32(ql.mem.read(self.read_reg(r), self.INST_SIZE))

        elif line.mnemonic in ("addls", "addne", "add") and self.regdst_eq_pc(line.op_str):
            V, C, Z, N = get_cpsr(ql.reg.cpsr)
            r0, r1, r2, *imm = line.op_str.split(", ")

            # program counter is awalys 8 bytes ahead when it comes with pc, need to add extra 8 bytes
            extra = 8 if 'pc' in (r0, r1, r2) else 0

            if imm:
                expr = imm[0].split()
                # TODO: should support more bit shifting and rotating operation
                if expr[0] == "lsl": # logical shift left
                    n = read_int(expr[-1].strip("#")) * 2

            if line.mnemonic == "addls" and (C == 0 or Z == 1):
                prophecy.where = extra + self.read_reg(r1) + self.read_reg(r2) * n

            elif line.mnemonic == "add" or (line.mnemonic == "addne" and Z == 0):
                prophecy.where = extra + self.read_reg(r1) + (self.read_reg(r2) * n if imm else self.read_reg(r2))

        elif line.mnemonic in ("tbh", "tbb"):

            cur_addr += self.INST_SIZE
            r0, r1, *imm = line.op_str.strip("[]").split(", ")

            if imm:
                expr = imm[0].split()
                if expr[0] == "lsl": # logical shift left
                    n = read_int(expr[-1].strip("#")) * 2

            if line.mnemonic == "tbh":

                r1 = self.read_reg(r1) * n

            elif line.mnemonic == "tbb":

                r1 = self.read_reg(r1)

            to_add = int.from_bytes(ql.mem.read(cur_addr+r1, 2 if line.mnemonic == "tbh" else 1), byteorder="little") * n
            prophecy.where = cur_addr + to_add

        elif line.mnemonic.startswith("pop") and "pc" in line.op_str:

            prophecy.where = ql.stack_read(line.op_str.strip("{}").split(", ").index("pc") * self.INST_SIZE)
            if not { # step to next instruction if cond does not meet
                    "pop"  : lambda *_: True,
                    "pop.w": lambda *_: True,
                    "popeq": lambda V, C, Z, N: (Z == 1),
                    "popne": lambda V, C, Z, N: (Z == 0),
                    "pophi": lambda V, C, Z, N: (C == 1),
                    "popge": lambda V, C, Z, N: (N == V),
                    "poplt": lambda V, C, Z, N: (N != V),
                    }.get(line.mnemonic)(*get_cpsr(ql.reg.cpsr)):

                prophecy.where = cur_addr + self.INST_SIZE

        elif line.mnemonic == "sub" and self.regdst_eq_pc(line.op_str):
            _, r, imm = line.op_str.split(", ")
            prophecy.where = self.read_reg(r) - read_int(imm.strip("#"))

        elif line.mnemonic == "mov" and self.regdst_eq_pc(line.op_str):
            _, r = line.op_str.split(", ")
            prophecy.where = self.read_reg(r)

        if prophecy.where & 1:
            prophecy.where -= 1

        return prophecy

class BranchPredictor_MIPS(BranchPredictor):
    def __init__(self, ql):
        super().__init__(ql)
        self.CODE_END = "break"
        self.INST_SIZE = 4

    def read_reg(self, reg_name):
        reg_name = reg_name.strip("$").replace("fp", "s8")
        return signed_val(getattr(self.ql.reg, reg_name))

    def predict(self):
        prophecy = Prophecy()
        cur_addr = self.ql.reg.arch_pc
        line = disasm(self.ql, cur_addr)

        if line.mnemonic == self.CODE_END: # indicates program extied
            return True

        prophecy.where = cur_addr + self.INST_SIZE
        if line.mnemonic.startswith('j') or line.mnemonic.startswith('b'):

            # make sure at least delay slot executed
            prophecy.where += self.INST_SIZE

            # get registers or memory address from op_str
            targets = [
                    self.read_reg(each)
                    if '$' in each else read_int(each)
                    for each in line.op_str.split(", ")
                    ]

            prophecy.going = {
                    "j"       : (lambda _: True),             # unconditional jump
                    "jr"      : (lambda _: True),             # unconditional jump
                    "jal"     : (lambda _: True),             # unconditional jump
                    "jalr"    : (lambda _: True),             # unconditional jump
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

            if prophecy.going:
                # target address is always the rightmost one
                prophecy.where = targets[-1]

        return prophecy

class BranchPredictor_X86(BranchPredictor):
    def __init__(self, ql):
        super().__init__(ql)

    def predict(self):
        prophecy = Prophecy()
        cur_addr = self.ql.reg.arch_pc
        line = disasm(self.ql, cur_addr)

        jump_table = {
                # conditional jump

                "jo"   : (lambda C, P, A, Z, S, O: O == 1),
                "jno"  : (lambda C, P, A, Z, S, O: O == 0),

                "js"   : (lambda C, P, A, Z, S, O: S == 1),
                "jns"  : (lambda C, P, A, Z, S, O: S == 0),

                "je"   : (lambda C, P, A, Z, S, O: Z == 1),
                "jz"   : (lambda C, P, A, Z, S, O: Z == 1),

                "jne"  : (lambda C, P, A, Z, S, O: Z == 0),
                "jnz"  : (lambda C, P, A, Z, S, O: Z == 0),

                "jb"   : (lambda C, P, A, Z, S, O: C == 1),
                "jc"   : (lambda C, P, A, Z, S, O: C == 1),
                "jnae" : (lambda C, P, A, Z, S, O: C == 1),

                "jnb"  : (lambda C, P, A, Z, S, O: C == 0),
                "jnc"  : (lambda C, P, A, Z, S, O: C == 0),
                "jae"  : (lambda C, P, A, Z, S, O: C == 0),

                "jbe"  : (lambda C, P, A, Z, S, O: C == 1 or Z == 1),
                "jna"  : (lambda C, P, A, Z, S, O: C == 1 or Z == 1),

                "ja"   : (lambda C, P, A, Z, S, O: C == 0 and Z == 0),
                "jnbe" : (lambda C, P, A, Z, S, O: C == 0 and Z == 0),

                "jl"   : (lambda C, P, A, Z, S, O: S != O),
                "jnge" : (lambda C, P, A, Z, S, O: S != O),

                "jge"  : (lambda C, P, A, Z, S, O: S == O),
                "jnl"  : (lambda C, P, A, Z, S, O: S == O),

                "jle"  : (lambda C, P, A, Z, S, O: Z == 1 or S != O),
                "jng"  : (lambda C, P, A, Z, S, O: Z == 1 or S != O),

                "jg"   : (lambda C, P, A, Z, S, O: Z == 0 or S == O),
                "jnle" : (lambda C, P, A, Z, S, O: Z == 0 or S == O),

                "jp"   : (lambda C, P, A, Z, S, O: P == 1),
                "jpe"  : (lambda C, P, A, Z, S, O: P == 1),

                "jnp"  : (lambda C, P, A, Z, S, O: P == 0),
                "jpo"  : (lambda C, P, A, Z, S, O: P == 0),

                # unconditional jump

                "call" : (lambda *_: True),
                "jmp"  : (lambda *_: True),

                }

        jump_reg_table = {
                "jcxz"  : (lambda cx: cx == 0),
                "jecxz" : (lambda ecx: ecx == 0),
                "jrcxz" : (lambda rcx: rcx == 0),
                }

        if line.mnemonic in jump_table:
            eflags = get_x86_eflags(self.ql.reg.ef).values()
            prophecy.going = jump_table.get(line.mnemonic)(*eflags)

        elif line.mnemonic in jump_reg_table:
            prophecy.going = jump_reg_table.get(line.mnemonic)(self.ql.reg.ecx)

        if prophecy.going:
            takeaway_list = ["ptr", "dword", "[", "]"]
            class AST_checker(ast.NodeVisitor):
                def generic_visit(self, node):
                    if type(node) in (ast.Module, ast.Expr, ast.BinOp, ast.Constant, ast.Add, ast.Mult, ast.Sub):
                        ast.NodeVisitor.generic_visit(self, node)
                    else:
                        raise ParseError("malform or invalid ast node")

            if len(line.op_str.split()) > 1:
                new_line = line.op_str.replace(":", "+")
                for each in takeaway_list:
                    new_line = new_line.replace(each, " ")

                new_line = " ".join(new_line.split())
                for each_reg in filter(lambda r: len(r) == 3, self.ql.reg.register_mapping.keys()):
                    if each_reg in new_line:
                        new_line = re.sub(each_reg, hex(self.read_reg(each_reg)), new_line)
                        
                for each_reg in filter(lambda r: len(r) == 2, self.ql.reg.register_mapping.keys()):
                    if each_reg in new_line:
                        new_line = re.sub(each_reg, hex(self.read_reg(each_reg)), new_line)

                checker = AST_checker()
                ast_tree = ast.parse(new_line)

                checker.visit(ast_tree)

                prophecy.where = eval(new_line)

            elif line.op_str in self.ql.reg.register_mapping:
                prophecy.where = getattr(self.ql.reg, line.op_str)

            else:
                prophecy.where = read_int(line.op_str)
        else:
            prophecy.where = cur_addr + line.size

        return prophecy

class BranchPredictor_CORTEX_M(BranchPredictor_ARM):
    def __init__(self, ql):
        super().__init__(ql)

class Breakpoint(object):
    """
    dummy class for breakpoint
    """
    def __init__(self, addr):
        self.addr = addr
        self.hitted = False

class TempBreakpoint(Breakpoint):
    """
    dummy class for temporay breakpoint
    """
    def __init__(self, addr):
        super().__init__(addr)

class ParseError(Exception):
    pass

class SnapshotManager(object):
    """
    for functioning differential snapshot
    """

    class State(object):
        """
        internal container for storing snapshot state
        """

        def __init__(self, saved_state):
            self.reg, self.ram = SnapshotManager.transform(saved_state)

    @classmethod
    def transform(cls, st):
        reg = st["reg"] if "reg" in st else st[0]

        if "mem" not in st:
            return (reg, st[1])

        ram = []
        for mem_seg in st["mem"]["ram"]:
            lbound, ubound, perms, label, raw_bytes = mem_seg
            rb_set = {(idx, val) for idx, val in enumerate(raw_bytes)}
            ram.append((lbound, ubound, perms, label, rb_set))

        return (reg, ram)

    def __init__(self, ql):
        self.ql = ql
        self.layers = []

    def diff_reg(self, prev_reg, cur_reg):
        diffed_reg = {}

        for reg_name, reg_val in cur_reg.items():
            if prev_reg[reg_name] != reg_val:
                diffed_reg[reg_name] = prev_reg[reg_name]

        return diffed_reg

    def diff_ram(self, prev_ram, cur_ram):
        if any((cur_ram is None, prev_ram is None, prev_ram == cur_ram)):
            return

        ram = []
        paired = zip(prev_ram, cur_ram)
        for each in paired:
            # lbound, ubound, perm, label, data
            *prev_others, prev_rb_set = each[0]
            *cur_others, cur_rb_set = each[1]

            if prev_others == cur_others and cur_rb_set != prev_rb_set:
                diff_set = prev_rb_set - cur_rb_set
            else:
                continue

            ram.append((*cur_others, diff_set))

        return ram

    def diff(self, cur_st):
        last_st = self.layers.pop()
        diffed_reg = self.diff_reg(last_st.reg, cur_st.reg)
        diffed_ram = self.diff_ram(last_st.ram, cur_st.ram)
        return self.State((diffed_reg, diffed_ram))

    def _save(self) -> State:
        return self.State(self.ql.save())

    def save(self):
        """
        helper function for saving differential context
        """

        st = self._save()

        if len(self.layers) != 0 and isinstance(self.layers[-1], dict):
            st = self.diff(st)

        self.layers.append(st)

    def restore(self):
        prev_st = self.layers.pop()
        cur_st = self._save()

        for reg_name, reg_value in prev_st.reg.items():
            cur_st.reg[reg_name] = reg_value

        to_be_restored = {"reg": cur_st.reg}

        if getattr(prev_st, "ram", None) and prev_st.ram != cur_st.ram:

            ram = []
            # lbound, ubound, perm, label, data
            for each in prev_st.ram:
                *prev_others, prev_rb_set = each
                for *cur_others, cur_rb_set in cur_st.ram:
                    if prev_others == cur_others:
                        cur_rb_dict = dict(cur_rb_set)
                        for idx, val in prev_rb_set:
                            cur_rb_dict[idx] = val

                        bs = bytes(dict(sorted(cur_rb_dict.items())).values())
                        ram.append((*cur_others, bs))

            to_be_restored.update({"mem": {"ram": ram, "mmio": {}}})

        self.ql.restore(to_be_restored)

if __name__ == "__main__":
    pass
