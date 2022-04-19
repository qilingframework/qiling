#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#



from .branch_predictor import *
from ..arch import ArchARM, ArchCORTEX_M

class BranchPredictorARM(BranchPredictor, ArchARM):
    """
    predictor for ARM
    """

    def __init__(self, ql):
        super().__init__(ql)
        ArchARM.__init__(self)

        self.INST_SIZE = 4
        self.THUMB_INST_SIZE = 2
        self.CODE_END = "udf"

    def read_reg(self, reg_name):
        reg_name = reg_name.replace("ip", "r12").replace("fp", "r11")
        return getattr(self.ql.arch.regs, reg_name)

    def regdst_eq_pc(self, op_str):
        return op_str.partition(", ")[0] == "pc"

    @staticmethod
    def get_cpsr(bits: int) -> (bool, bool, bool, bool):
        """
        get flags from ql.reg.cpsr
        """
        return (
                bits & 0x10000000 != 0, # V, overflow flag
                bits & 0x20000000 != 0, # C, carry flag
                bits & 0x40000000 != 0, # Z, zero flag
                bits & 0x80000000 != 0, # N, sign flag
                )

    def predict(self):
        prophecy = self.Prophecy()
        cur_addr = self.cur_addr
        line = self.disasm(cur_addr)

        prophecy.where = cur_addr + line.size

        if line.mnemonic == self.CODE_END: # indicates program exited
            prophecy.where = True
            return prophecy

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
            prophecy.going = jump_table.get(line.mnemonic)(*self.get_cpsr(self.ql.arch.regs.cpsr))

        elif line.mnemonic in cb_table:
            prophecy.going = cb_table.get(line.mnemonic)(self.read_reg(line.op_str.split(", ")[0]))

        if prophecy.going:
            if "#" in line.op_str:
                prophecy.where = read_int(line.op_str.split("#")[-1])
            else:
                prophecy.where = self.read_reg(line.op_str)

                if self.regdst_eq_pc(line.op_str):
                    next_addr = cur_addr + line.size
                    n2_addr = next_addr + len(self.read_insn(next_addr))
                    prophecy.where += len(self.read_insn(n2_addr)) + len(self.read_insn(next_addr))

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
                    }.get(line.op_str)(*self.get_cpsr(self.ql.arch.regs.cpsr))

            it_block_range = [each_char for each_char in line.mnemonic[1:]]

            next_addr = cur_addr + self.THUMB_INST_SIZE
            for each in it_block_range:
                _insn = self.read_insn(next_addr)
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
                    prophecy.where = self.unpack32(self.read_mem(read_int(imm) + self.read_reg(r), self.INST_SIZE))

                else: # post-indexed immediate
                    # FIXME: weired behavior, immediate here does not apply
                    prophecy.where = self.unpack32(self.read_mem(self.read_reg(r), self.INST_SIZE))

        elif line.mnemonic in ("addls", "addne", "add") and self.regdst_eq_pc(line.op_str):
            V, C, Z, N = self.get_cpsr(self.ql.arch.regs.cpsr)
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

            to_add = int.from_bytes(self.read_mem(cur_addr+r1, 2 if line.mnemonic == "tbh" else 1), byteorder="little") * n
            prophecy.where = cur_addr + to_add

        elif line.mnemonic.startswith("pop") and "pc" in line.op_str:

            prophecy.where = self.ql.stack_read(line.op_str.strip("{}").split(", ").index("pc") * self.INST_SIZE)
            if not { # step to next instruction if cond does not meet
                    "pop"  : lambda *_: True,
                    "pop.w": lambda *_: True,
                    "popeq": lambda V, C, Z, N: (Z == 1),
                    "popne": lambda V, C, Z, N: (Z == 0),
                    "pophi": lambda V, C, Z, N: (C == 1),
                    "popge": lambda V, C, Z, N: (N == V),
                    "poplt": lambda V, C, Z, N: (N != V),
                    }.get(line.mnemonic)(*self.get_cpsr(self.ql.arch.regs.cpsr)):

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

class BranchPredictorCORTEX_M(BranchPredictorARM):
    def __init__(self, ql):
        super().__init__(ql)
