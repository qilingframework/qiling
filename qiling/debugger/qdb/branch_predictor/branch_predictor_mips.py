#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Optional
from capstone.mips import MipsOp, MIPS_OP_REG, MIPS_OP_IMM

from .branch_predictor import BranchPredictor, Prophecy
from ..arch import ArchMIPS
from ..misc import InvalidInsn


class BranchPredictorMIPS(BranchPredictor, ArchMIPS):
    """Branch Predictor for MIPS 32.
    """

    stop = 'break'

    def predict(self):
        insn = self.disasm(self.cur_addr, True)

        going = False
        where = 0

        # invalid instruction; nothing to predict
        if isinstance(insn, InvalidInsn):
            return Prophecy(going, where)

        unconditional = ('j', 'jr', 'jal', 'jalr', 'b', 'bl', 'bal')

        conditional = {
            'beq'   : lambda r0, r1: r0 == r1,  # branch on equal
            'bne'   : lambda r0, r1: r0 != r1,  # branch on not equal
            'blt'   : lambda r0, r1: r0 < r1,   # branch on r0 less than r1
            'bgt'   : lambda r0, r1: r0 > r1,   # branch on r0 greater than r1
            'ble'   : lambda r0, r1: r0 <= r1,  # branch on r0 less than or equal to r1
            'bge'   : lambda r0, r1: r0 >= r1,  # branch on r0 greater than or equal to r1

            'beqz'  : lambda r: r == 0,         # branch on equal to zero
            'bnez'  : lambda r: r != 0,         # branch on not equal to zero
            'bgtz'  : lambda r: r > 0,          # branch on greater than zero
            'bltz'  : lambda r: r < 0,          # branch on less than zero
            'bltzal': lambda r: r < 0,          # branch on less than zero and link
            'blez'  : lambda r: r <= 0,         # branch on less than or equal to zero
            'bgez'  : lambda r: r >= 0,         # branch on greater than or equal to zero
            'bgezal': lambda r: r >= 0          # branch on greater than or equal to zero and link
        }

        def __as_signed(val: int) -> int:
            """Get the signed integer representation of a given value.
            """

            msb = 0b1 << 31

            return (val & ~msb) - (val & msb)

        def __read_reg(reg: int) -> Optional[int]:
            """Read register value where register is provided as a Unicorn constant.
            """

            # name will be None in case of an illegal or unknown register
            name = insn.reg_name(reg)

            return name and __as_signed(self.read_reg(self.unalias(name)))

        def __parse_op(op: MipsOp) -> Optional[int]:
            """Parse an operand and return its value.
            """

            if op.type == MIPS_OP_REG:
                value = __read_reg(op.reg)

            elif op.type == MIPS_OP_IMM:
                value = op.imm

            else:
                raise RuntimeError(f'unexpected operand type: {op.type}')

            return value

        # get operands. target address is always the rightmost one
        if insn.operands:
            *operands, target = insn.operands

        if insn.mnemonic in unconditional:
            going = True

        elif insn.mnemonic in conditional:
            predict = conditional[insn.mnemonic]

            going = predict(*(__parse_op(op) for op in operands))

        if going:
            where = __parse_op(target)

        return Prophecy(going, where)
