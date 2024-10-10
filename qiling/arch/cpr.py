#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

import weakref

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unicorn import Uc


class QlCprManager:
    """Enables access to ARM coprocessor registers.
    """

    # for more information about various aarch32 coprocessor register, pelase refer to:
    # https://developer.arm.com/documentation/ddi0601/latest/AArch32-Registers

    def __init__(self, uc: Uc) -> None:
        self.uc: Uc = weakref.proxy(uc)

    def read(self, coproc: int, opc1: int, crn: int, crm: int, opc2: int, el: int, is_64: bool) -> int:
        """Read a coprocessor register value.

        Args:
            coproc : coprocessor to access, value varies between 0 and 15
            opc1   : opcode 1, value varies between 0 and 7
            crn    : coprocessor register to access (CRn), value varies between 0 and 15
            crm    : additional coprocessor register to access (CRm), value varies between 0 and 15
            opc2   : opcode 2, value varies between 0 and 7
            el     : the exception level the coprocessor register belongs to, value varies between 0 and 3
            is_64  : indicates whether this is a 64-bit register

        Returns: value of coprocessor register
        """

        return self.uc.cpr_read(coproc, opc1, crn, crm, opc2, el, is_64)

    def write(self, coproc: int, opc1: int, crn: int, crm: int, opc2: int, el: int, is_64: bool, value: int) -> None:
        """Write a coprocessor register value.

        Args:
            coproc : coprocessor to access, value varies between 0 and 15
            opc1   : opcode 1, value varies between 0 and 7
            crn    : coprocessor register to access (CRn), value varies between 0 and 15
            crm    : additional coprocessor register to access (CRm), value varies between 0 and 15
            opc2   : opcode 2, value varies between 0 and 7
            el     : the exception level the coprocessor register belongs to, value varies between 0 and 3
            is_64  : indicates whether this is a 64-bit register
            value  : value to write
        """

        self.uc.cpr_write(coproc, opc1, crn, crm, opc2, el, is_64, value)


__all__ = ['QlCprManager']
