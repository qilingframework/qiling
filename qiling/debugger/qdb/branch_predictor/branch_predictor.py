#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from abc import abstractmethod
from typing import ClassVar, NamedTuple, Optional

from capstone import CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_BRANCH_RELATIVE

from ..context import Context
from ..misc import InvalidInsn


class Prophecy(NamedTuple):
    """Simple container for storing prediction results.
    """

    going: bool
    """Indicate whether the certian branch is taken or not.
    """

    where: Optional[int]
    """Branch target in case it is taken.
    Target may be `None` if it should have been read from memory, but that memory location
    could not be reached.
    """


class BranchPredictor(Context):
    """Branch predictor base class.
    """

    stop: ClassVar[str]
    """Instruction mnemonic that can be used to determine program's end.
    """

    def has_ended(self) -> bool:
        """Determine whether the program has ended by inspecting the currnet instruction.
        """

        insn = self.disasm_lite(self.cur_addr)

        if not insn:
            return False

        # (address, size, mnemonic, op_str)
        return insn[2] == self.stop

    def is_branch(self) -> bool:
        """Determine whether the current instruction is a branching instruction.
        This does not provide indication whether the branch is going to be taken or not.
        """

        insn = self.disasm(self.cur_addr, True)

        # invalid instruction; definitely not a branch
        if isinstance(insn, InvalidInsn):
            return False

        branching = (
            CS_GRP_JUMP,
            CS_GRP_CALL,
            CS_GRP_RET,
            CS_GRP_BRANCH_RELATIVE
        )

        return any(grp in branching for grp in insn.groups)

    def is_fcall(self) -> bool:
        """Determine whether the current instruction is a function call.
        """

        insn = self.disasm(self.cur_addr, True)

        # invalid instruction; definitely not a function call
        if isinstance(insn, InvalidInsn):
            return False

        return insn.group(CS_GRP_CALL)

    @abstractmethod
    def predict(self) -> Prophecy:
        """Predict whether a certian branch will be taken or not based on current context.
        """
