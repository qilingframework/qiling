#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Set

from capstone import CS_OP_IMM, CS_OP_MEM, CS_OP_REG

from .branch_predictor import BranchPredictor, Prophecy
from ..arch import ArchRISCV, ArchRISCV64
from ..misc import InvalidInsn


class BranchPredictorRISCV(BranchPredictor, ArchRISCV):
    """Branch Predictor for RISC-V 32-bit.
    """

    stop = 'ebreak'
    xlen = 32
    supports_c_jal = True

    def _unconditional_branches(self) -> Set[str]:
        branches = {'j', 'jal', 'jalr', 'jr', 'ret'}

        if self.supports_c_jal:
            branches.add('c.jal')

        return branches

    def _normalize_mnemonic(self, mnemonic: str) -> str:
        return (mnemonic or '').lower()

    def _signed(self, val: int) -> int:
        mask = (1 << self.xlen) - 1
        sign = 1 << (self.xlen - 1)

        val &= mask
        return (val ^ sign) - sign

    def _unsigned(self, val: int) -> int:
        return val & ((1 << self.xlen) - 1)

    def predict(self) -> Prophecy:
        insn = self.disasm(self.cur_addr, True)

        going = False
        where = 0

        if isinstance(insn, InvalidInsn):
            return Prophecy(going, where)

        mnemonic = self._normalize_mnemonic(insn.mnemonic)
        base = mnemonic[2:] if mnemonic.startswith('c.') else mnemonic
        operands: List[object] = list(insn.operands)

        conditional: Dict[str, Callable[..., bool]] = {
            'beq' : lambda a, b: a == b,
            'bne' : lambda a, b: a != b,
            'blt' : lambda a, b: a < b,
            'bge' : lambda a, b: a >= b,
            'bltu': lambda a, b: a < b,
            'bgeu': lambda a, b: a >= b,
            'beqz': lambda a: a == 0,
            'bnez': lambda a: a != 0,
            'bgez': lambda a: a >= 0,
            'bltz': lambda a: a < 0,
            'bgtz': lambda a: a > 0,
            'blez': lambda a: a <= 0,
        }

        def __read_reg(reg: int) -> Optional[int]:
            name = insn.reg_name(reg)

            return name and self.read_reg(self.unalias(name))

        def __parse_op(op: object) -> Optional[int]:
            if getattr(op, 'type', None) == CS_OP_REG:
                return __read_reg(op.reg)

            if getattr(op, 'type', None) == CS_OP_IMM:
                return op.imm

            if getattr(op, 'type', None) == CS_OP_MEM:
                mem = op.mem
                base_reg = __read_reg(mem.base) or 0
                index = __read_reg(mem.index) or 0
                return base_reg + index * mem.scale + mem.disp

            return None

        def __direct_target() -> Optional[int]:
            imms = [op for op in operands if getattr(op, 'type', None) == CS_OP_IMM]

            if not imms:
                return None

            return self.cur_addr + imms[-1].imm

        def __indirect_target() -> Optional[int]:
            memop = next((op for op in operands if getattr(op, 'type', None) == CS_OP_MEM), None)
            if memop is not None:
                return __parse_op(memop)

            regs = [op for op in operands if getattr(op, 'type', None) == CS_OP_REG]
            imms = [op for op in operands if getattr(op, 'type', None) == CS_OP_IMM]

            if regs and imms:
                return (__parse_op(regs[-1]) or 0) + imms[-1].imm

            if regs:
                return __parse_op(regs[-1])

            return None

        unconditional = self._unconditional_branches()
        is_unconditional = mnemonic in unconditional or base in unconditional

        if mnemonic == 'c.jal' and not self.supports_c_jal:
            is_unconditional = False

        if is_unconditional:
            going = True

            if base == 'ret' and not operands:
                where = self.read_reg('ra')
            elif base in {'jalr', 'jr', 'ret'}:
                where = __indirect_target() or 0
            else:
                where = __direct_target() or 0

            if base in {'jalr', 'jr', 'ret'}:
                where &= ~1

        elif base in conditional:
            predicate = conditional[base]

            if base in {'beqz', 'bnez', 'bgez', 'bltz', 'bgtz', 'blez'}:
                reg = __parse_op(operands[0]) if operands else None
                going = reg is not None and predicate(self._signed(reg))
            else:
                lhs = __parse_op(operands[0]) if len(operands) > 0 else None
                rhs = __parse_op(operands[1]) if len(operands) > 1 else None

                if base in {'blt', 'bge'}:
                    lhs = None if lhs is None else self._signed(lhs)
                    rhs = None if rhs is None else self._signed(rhs)

                if base in {'bltu', 'bgeu'}:
                    lhs = None if lhs is None else self._unsigned(lhs)
                    rhs = None if rhs is None else self._unsigned(rhs)

                going = lhs is not None and rhs is not None and predicate(lhs, rhs)

            if going:
                where = __direct_target() or 0

        return Prophecy(going, where)


class BranchPredictorRISCV64(BranchPredictorRISCV, ArchRISCV64):
    """Branch Predictor for RISC-V 64-bit.
    """

    xlen = 64
    supports_c_jal = False
