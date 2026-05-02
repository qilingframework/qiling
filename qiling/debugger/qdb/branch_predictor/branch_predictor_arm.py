#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Callable, Dict, List, Optional, Tuple

from capstone import CS_OP_IMM, CS_OP_MEM, CS_OP_REG
from capstone.arm import ArmOp, ArmOpMem
from capstone.arm_const import (
    ARM_CC_EQ, ARM_CC_NE, ARM_CC_HS, ARM_CC_LO,
    ARM_CC_MI, ARM_CC_PL, ARM_CC_VS, ARM_CC_VC,
    ARM_CC_HI, ARM_CC_LS, ARM_CC_GE, ARM_CC_LT,
    ARM_CC_GT, ARM_CC_LE, ARM_CC_AL
)

from unicorn.arm_const import UC_ARM_REG_PC

from .branch_predictor import BranchPredictor, Prophecy
from ..arch import ArchARM, ArchCORTEX_M
from ..misc import InvalidInsn


class BranchPredictorARM(BranchPredictor, ArchARM):
    """Branch Predictor for ARM.
    """

    stop = 'udf'

    def get_cond_flags(self) -> Tuple[bool, bool, bool, bool]:
        """Get condition status flags from CPSR / xPSR.
        """

        cpsr = self.read_reg(self._flags_reg)

        return (
            (cpsr & (0b1 << 28)) != 0,  # V, overflow flag
            (cpsr & (0b1 << 29)) != 0,  # C, carry flag
            (cpsr & (0b1 << 30)) != 0,  # Z, zero flag
            (cpsr & (0b1 << 31)) != 0   # N, sign flag
        )

    def predict(self) -> Prophecy:
        insn = self.disasm(self.cur_addr, True)

        going = False
        where = 0

        # invalid instruction; nothing to predict
        if isinstance(insn, InvalidInsn):
            return Prophecy(going, where)

        # iname is the instruction's basename stripped from all optional suffixes.
        # this greatly simplifies the case handling
        iname: str = insn.insn_name() or ''
        operands: List[ArmOp] = insn.operands

        # branch instructions
        branches = ('b', 'bl', 'bx', 'blx')

        # reg-based conditional branches
        conditional_reg: Dict[str, Callable[[int], bool]] = {
            'cbz' : lambda r: r == 0,
            'cbnz': lambda r: r != 0
        }

        def __read_reg(reg: int) -> Optional[int]:
            """[internal] Read register value where register is provided as a Unicorn constant.
            """

            # name will be None in case of an invalid register. this is expected in some cases
            # and should not raise an exception, but rather silently dropped
            name = insn.reg_name(reg)

            # pc reg value needs adjustment
            adj = (2 * self.isize) if reg == UC_ARM_REG_PC else 0

            return name and self.read_reg(self.unalias(name)) + adj

        def __read_mem(mem: ArmOpMem, size: int = 0, *, signed: bool = False) -> Optional[int]:
            """[internal] Attempt to read memory contents. By default memory accesses are in
            native size and values are unsigned.
            """

            base  = __read_reg(mem.base) or 0
            index = __read_reg(mem.index) or 0
            scale = mem.scale
            disp  = mem.disp

            return self.try_read_pointer(base + index * scale + disp, size, signed=signed)

        def __parse_op(op: ArmOp, *args, **kwargs) -> Optional[int]:
            """[internal] Parse an operand and return its value. Register references will be
            substitued with the corresponding register value, while memory dereferences will
            be substitued by the effective address they refer to.
            """

            if op.type == CS_OP_REG:
                value = __read_reg(op.reg)

            elif op.type == CS_OP_IMM:
                value = op.imm

            elif op.type == CS_OP_MEM:
                value = __read_mem(op.mem, *args, **kwargs)

            else:
                # we are not expecting any other operand type, including floating point (CS_OP_FP)
                raise RuntimeError(f'unexpected operand type: {op.type}')

            # LSR
            if op.shift.type == 1:
                value *= (1 >> op.shift.value)

            # LSL
            elif op.shift.type == 2:
                value *= (1 << op.shift.value)

            # ROR ?

            return value

        def __is_taken(cc: int) -> Tuple[bool, Tuple[bool, ...]]:
            pred = predicate[cc]
            flags = self.get_cond_flags()

            return pred(*flags), flags

        # conditions predicate selector
        predicate: Dict[int, Callable[..., bool]] = {
            ARM_CC_EQ: lambda V, C, Z, N: Z,
            ARM_CC_NE: lambda V, C, Z, N: not Z,
            ARM_CC_HS: lambda V, C, Z, N: C,
            ARM_CC_LO: lambda V, C, Z, N: not C,
            ARM_CC_MI: lambda V, C, Z, N: N,
            ARM_CC_PL: lambda V, C, Z, N: not N,
            ARM_CC_VS: lambda V, C, Z, N: V,
            ARM_CC_VC: lambda V, C, Z, N: not V,
            ARM_CC_HI: lambda V, C, Z, N: (not Z) and C,
            ARM_CC_LS: lambda V, C, Z, N: (not C) or Z,
            ARM_CC_GE: lambda V, C, Z, N: (N == V),
            ARM_CC_LT: lambda V, C, Z, N: (N != V),
            ARM_CC_GT: lambda V, C, Z, N: not Z and (N == V),
            ARM_CC_LE: lambda V, C, Z, N: Z or (N != V),
            ARM_CC_AL: lambda V, C, Z, N: True
        }

        # implementation of simple binary arithmetic and bitwise operations
        binop: Dict[str, Callable[[int, int, int], int]] = {
            'add': lambda a, b, _: a + b,
            'adc': lambda a, b, c: a + b + c,
            'sub': lambda a, b, _: a - b,
            'rsb': lambda a, b, _: b - a,
            'sbc': lambda a, b, c: a - b - (1 - c),
            'rsc': lambda a, b, c: b - a - (1 - c),
            'mul': lambda a, b, _: a * b,
            'and': lambda a, b, _: a & b,
            'orr': lambda a, b, _: a | b,
            'eor': lambda a, b, _: a ^ b
        }

        # is this a branch?
        if iname in branches:
            going, _ = __is_taken(insn.cc)

            if going:
                where = __parse_op(operands[0])

            return Prophecy(going, where)

        if iname in conditional_reg:
            is_taken = conditional_reg[iname]
            reg = __parse_op(operands[0])
            assert reg is not None, 'unrecognized reg'

            going = is_taken(reg)

            if going:
                where = __parse_op(operands[1])

            return Prophecy(going, where)

        # instruction is not a branch; check whether pc is affected by this instruction.
        #
        # insn.regs_write doesn't work well, so we use insn.regs_access instead
        if UC_ARM_REG_PC in insn.regs_access()[1]:

            if iname == 'mov':
                going = True
                where = __parse_op(operands[1])

            elif iname.startswith('ldr'):
                suffix: str = insn.mnemonic[3:]

                # map possible ldr suffixes to kwargs required for the memory access.
                #
                # to improve readability we also address the case where ldr has no suffix
                # and no special kwargs are required. all strings start with '', so it
                # serves as a safe default case
                msize: Dict[str, Dict] = {
                    'b' : {'size': 1, 'signed': False},
                    'h' : {'size': 2, 'signed': False},
                    'sb': {'size': 1, 'signed': True},
                    'sh': {'size': 2, 'signed': True},
                    ''  : {}
                }

                # ldr has different variations that affect the memory access size and
                # whether the value should be signed or not.
                suffix = next(s for s in msize if suffix.startswith(s))

                going, _ = __is_taken(insn.cc)

                if going:
                    where = __parse_op(operands[1], **msize[suffix])

            elif iname in binop:
                going, flags = __is_taken(insn.cc)

                if going:
                    operator = binop[iname]
                    op1 = __parse_op(operands[1])
                    op2 = __parse_op(operands[2])
                    carry = int(flags[1])

                    where = (op1 and op2) and operator(op1, op2, carry)

            elif iname == 'pop':
                going, _ = __is_taken(insn.cc)

                if going:
                    # find pc position within pop regs list
                    idx = next(i for i, op in enumerate(operands) if (op.type == CS_OP_REG) and (op.reg == UC_ARM_REG_PC))

                    # read the corresponding stack entry
                    where = self.ql.stack_read(idx * self.asize)

            else:
                # left here for users to provide feedback when encountered
                raise RuntimeWarning(f'instruction affects pc but was not considered: {insn.mnemonic}')

        # for some reason capstone does not consider pc to be affected by 'tbb' and 'tbh'
        # so we need to test for them specifically

        # table branch byte
        elif iname == 'tbb':
            offset = __read_mem(operands[0].mem, 1)
            pc = __read_reg(UC_ARM_REG_PC)

            going = True
            where = (offset and pc) and (pc + offset * 2)

        # table branch half-word
        elif iname == 'tbh':
            offset = __read_mem(operands[0].mem, 2)
            pc = __read_reg(UC_ARM_REG_PC)

            going = True
            where = (offset and pc) and (pc + offset * 2)

        return Prophecy(going, where)


class BranchPredictorCORTEX_M(BranchPredictorARM, ArchCORTEX_M):
    """Branch Predictor for ARM Cortex-M.
    """
