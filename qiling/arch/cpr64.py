#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

import weakref

from typing import TYPE_CHECKING, Dict, Mapping, Tuple

if TYPE_CHECKING:
    from unicorn import Uc

_CPR_T = Tuple[int, int, int, int, int]


class QlCpr64Manager:
    """Enables access to ARM64 coprocessor registers.
    """

    # for more information about various aarch32 coprocessor register, pelase refer to:
    # https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers

    def __init__(self, uc: Uc, regs_map: Mapping[str, _CPR_T]) -> None:
        """Initialize the coprocessor registers manager.
        """

        # this funny way of initialization is used to avoid calling self setattr and
        # getattr upon init. if it did, it would go into an endless recursion
        self.register_mapping: Dict[str, _CPR_T]
        super().__setattr__('register_mapping', regs_map)

        self.uc: Uc = weakref.proxy(uc)

    def __getattr__(self, name: str) -> int:
        if name in self.register_mapping:
            return self.read(*self.register_mapping[name])

        else:
            return super().__getattribute__(name)

    def __setattr__(self, name: str, value: int) -> None:
        if name in self.register_mapping:
            self.write(*self.register_mapping[name], value)

        else:
            super().__setattr__(name, value)

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

    def save(self) -> Dict[str, int]:
        """Save registers.
        """

        return dict((name, self.read(*reg)) for name, reg in self.register_mapping.items())

    def restore(self, context: Mapping[str, int]) -> None:
        """Restore registers.
        """

        for name, val in context.items():
            self.write(*self.register_mapping[name], val)


__all__ = ['QlCpr64Manager']
