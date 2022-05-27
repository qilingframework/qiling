#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#



import ast, re

from .branch_predictor import *
from ..arch import ArchX86
from ..misc import check_and_eval

class BranchPredictorX86(BranchPredictor, ArchX86):
    """
    predictor for X86
    """

    class ParseError(Exception):
        """
        indicate parser error
        """
        pass

    def __init__(self, ql):
        super().__init__(ql)
        ArchX86.__init__(self)

    def predict(self):
        prophecy = self.Prophecy()
        line = self.disasm(self.cur_addr)

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
            eflags = self.get_flags(self.ql.arch.regs.eflags).values()
            prophecy.going = jump_table.get(line.mnemonic)(*eflags)

        elif line.mnemonic in jump_reg_table:
            prophecy.going = jump_reg_table.get(line.mnemonic)(self.ql.arch.regs.ecx)

        if prophecy.going:
            takeaway_list = ["ptr", "dword", "[", "]"]

            if len(line.op_str.split()) > 1:
                new_line = line.op_str.replace(":", "+")
                for each in takeaway_list:
                    new_line = new_line.replace(each, " ")

                new_line = " ".join(new_line.split())
                for each_reg in filter(lambda r: len(r) == 3, self.ql.arch.regs.register_mapping.keys()):
                    if each_reg in new_line:
                        new_line = re.sub(each_reg, hex(self.read_reg(each_reg)), new_line)
                        
                for each_reg in filter(lambda r: len(r) == 2, self.ql.arch.regs.register_mapping.keys()):
                    if each_reg in new_line:
                        new_line = re.sub(each_reg, hex(self.read_reg(each_reg)), new_line)


                prophecy.where = check_and_eval(new_line)

            elif line.op_str in self.ql.arch.regs.register_mapping:
                prophecy.where = self.ql.arch.regs.read(line.op_str)

            else:
                prophecy.where = read_int(line.op_str)
        else:
            prophecy.where = self.cur_addr + line.size

        return prophecy
