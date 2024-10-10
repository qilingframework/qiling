#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

import weakref

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unicorn import Uc


class QlCpr64Manager:
    """Enables access to ARM64 coprocessor registers.
    """

    # for more information about various aarch32 coprocessor register, pelase refer to:
    # https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers

    def __init__(self, uc: Uc) -> None:
        self.uc: Uc = weakref.proxy(uc)

    def read(self, op0: int, op1: int, crn: int, crm: int, op2: int) -> int:
        """Read a coprocessor register value.

        Args:
            op0 : opcode 0, value varies between 0 and 3
            op1 : opcode 1, value varies between 0 and 7
            crn : coprocessor register to access (CRn), value varies between 0 and 15
            crm : additional coprocessor register to access (CRm), value varies between 0 and 15
            op2 : opcode 2, value varies between 0 and 7

        Returns: value of coprocessor register
        """

        return self.uc.cpr_read(op0, op1, crn, crm, op2)

    def write(self, op0: int, op1: int, crn: int, crm: int, op2: int, value: int) -> None:
        """Write a coprocessor register value.

        Args:
            op0   : opcode 0, value varies between 0 and 3
            op1   : opcode 1, value varies between 0 and 7
            crn   : coprocessor register to access (CRn), value varies between 0 and 15
            crm   : additional coprocessor register to access (CRm), value varies between 0 and 15
            op2   : opcode 2, value varies between 0 and 7
            value : value to write
        """

        self.uc.cpr_write(op0, op1, crn, crm, op2, value)


__all__ = ['QlCpr64Manager']
