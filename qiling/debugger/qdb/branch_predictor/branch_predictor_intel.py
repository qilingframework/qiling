#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Callable, Dict, List, Optional, Tuple

from capstone.x86 import X86Op
from capstone.x86_const import X86_OP_REG, X86_OP_IMM, X86_OP_MEM, X86_INS_LEA

from .branch_predictor import Prophecy, BranchPredictor
from ..arch import ArchX86, ArchX64
from ..misc import InvalidInsn


class BranchPredictorIntel(BranchPredictor):
    """Branch Predictor base class for Intel architecture.
    """

    stop = 'hlt'

    def get_eflags(self) -> Tuple[int, int, int, int, int]:
        eflags = self.read_reg('eflags')

        return (
            (eflags & (0b1 <<  0)) != 0,  # carry
            (eflags & (0b1 <<  2)) != 0,  # parity
            (eflags & (0b1 <<  6)) != 0,  # zero
            (eflags & (0b1 <<  7)) != 0,  # sign
            (eflags & (0b1 << 11)) != 0   # overflow
        )

    def predict(self) -> Prophecy:
        insn = self.disasm(self.cur_addr, True)

        going = False
        where = 0

        # invalid instruction; nothing to predict
        if isinstance(insn, InvalidInsn):
            return Prophecy(going, where)

        mnem: str = insn.mnemonic
        operands: List[X86Op] = insn.operands

        # unconditional branches
        unconditional = ('call', 'jmp')

        # flags-based conditional branches
        conditional: Dict[str, Callable[..., bool]] = {
            'jb'  : lambda C, P, Z, S, O: C,
            'jc'  : lambda C, P, Z, S, O: C,
            'jnae': lambda C, P, Z, S, O: C,

            'jnb' : lambda C, P, Z, S, O: not C,
            'jnc' : lambda C, P, Z, S, O: not C,
            'jae' : lambda C, P, Z, S, O: not C,

            'jp'  : lambda C, P, Z, S, O: P,
            'jpe' : lambda C, P, Z, S, O: P,

            'jnp' : lambda C, P, Z, S, O: not P,
            'jpo' : lambda C, P, Z, S, O: not P,

            'je'  : lambda C, P, Z, S, O: Z,
            'jz'  : lambda C, P, Z, S, O: Z,

            'jne' : lambda C, P, Z, S, O: not Z,
            'jnz' : lambda C, P, Z, S, O: not Z,

            'js'  : lambda C, P, Z, S, O: S,
            'jns' : lambda C, P, Z, S, O: not S,

            'jo'  : lambda C, P, Z, S, O: O,
            'jno' : lambda C, P, Z, S, O: not O,

            'jbe' : lambda C, P, Z, S, O: C or Z,
            'jna' : lambda C, P, Z, S, O: C or Z,

            'ja'  : lambda C, P, Z, S, O: (not C) and (not Z),
            'jnbe': lambda C, P, Z, S, O: (not C) and (not Z),

            'jl'  : lambda C, P, Z, S, O: S != O,
            'jnge': lambda C, P, Z, S, O: S != O,

            'jge' : lambda C, P, Z, S, O: S == O,
            'jnl' : lambda C, P, Z, S, O: S == O,

            'jle' : lambda C, P, Z, S, O: Z or (S != O),
            'jng' : lambda C, P, Z, S, O: Z or (S != O),

            'jg'  : lambda C, P, Z, S, O: (not Z) or (not S),
            'jnle': lambda C, P, Z, S, O: (not Z) or (not S)
        }

        # reg-based conditional branches
        conditional_reg = {
            "jcxz"  : 'cx',
            "jecxz" : 'ecx',
            "jrcxz" : 'rcx'
        }

        def __read_reg(reg: int) -> Optional[int]:
            """Read register value where register is provided as a Unicorn constant.
            """

            # name will be None in case of an illegal or unknown register
            name = insn.reg_name(reg)

            return name and self.read_reg(name)

        def __parse_op(op: X86Op) -> Optional[int]:
            """Parse an operand and return its value. Memory dereferences will be
            substitued by the effective address they refer to.
            """

            if op.type == X86_OP_REG:
                value = __read_reg(op.reg)

            elif op.type == X86_OP_IMM:
                value = op.imm

            elif op.type == X86_OP_MEM:
                mem = op.mem

                base  = __read_reg(mem.base) or 0
                index = __read_reg(mem.index) or 0
                scale = mem.scale
                disp  = mem.disp

                seg = __read_reg(mem.segment) or 0
                ea = seg * 0x10 + (base + index * scale + disp)

                # lea does not really dereference memory
                value = ea if insn.id == X86_INS_LEA else self.try_read_pointer(ea)

            else:
                raise RuntimeError(f'unexpected operand type: {op.type}')

            return value

        # is this an unconditional branch?
        if mnem in unconditional:
            going = True
            where = __parse_op(operands[0])

        # is this a return from a function call?
        elif mnem == 'ret':
            going = True
            where = self.ql.arch.stack_read(0)

        # is this a flags-based branch?
        elif mnem in conditional:
            predict = conditional[mnem]
            eflags = self.get_eflags()

            going = predict(*eflags)

            if going:
                where = __parse_op(operands[0])

        elif mnem in conditional_reg:
            reg = conditional_reg[mnem]
            predict = lambda c: c == 0

            going = predict(self.read_reg(reg))

            if going:
                where = __parse_op(operands[0])

        return Prophecy(going, where)


class BranchPredictorX86(BranchPredictorIntel, ArchX86):
    """Branch Predictor for x86.
    """


class BranchPredictorX64(BranchPredictorIntel, ArchX64):
    """Branch Predictor for x86-64.
    """
