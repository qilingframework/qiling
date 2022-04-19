#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#



from .branch_predictor import *
from ..arch import ArchMIPS

class BranchPredictorMIPS(BranchPredictor, ArchMIPS):
    """
    predictor for MIPS
    """

    def __init__(self, ql):
        super().__init__(ql)
        ArchMIPS.__init__(self)
        self.CODE_END = "break"
        self.INST_SIZE = 4

    @staticmethod
    def signed_val(val: int) -> int:
        """
        signed value convertion
        """

        def is_negative(i: int) -> int:
            """
            check wether negative value or not
            """

            return i & (1 << 31)

        return (val-1 << 32) if is_negative(val) else val

    def read_reg(self, reg_name):
        reg_name = reg_name.strip("$").replace("fp", "s8")
        return self.signed_val(getattr(self.ql.arch.regs, reg_name))

    def predict(self):
        prophecy = self.Prophecy()
        line = self.disasm(self.cur_addr)

        if line.mnemonic == self.CODE_END: # indicates program extied
            prophecy.where = True
            return prophecy

        prophecy.where = self.cur_addr + self.INST_SIZE
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
