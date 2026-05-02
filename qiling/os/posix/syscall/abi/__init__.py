#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Sequence, Tuple


if TYPE_CHECKING:
    from qiling.arch.arch import QlArch


class QlSyscallABI:
    """System call ABI common implementation.
    """

    _idreg: ClassVar[int]
    _argregs: ClassVar[Sequence[int]]
    _retreg: ClassVar[int]

    def __init__(self, arch: QlArch) -> None:
        """Initialize a system call ABI instance.

        Args:
            arch: underlying architecture instance
        """

        self.arch = arch

    def get_id(self) -> int:
        """Read system call ID number.

        Returns: system call number
        """

        return self.arch.regs.read(self._idreg)  # type: ignore [uc funny annot]

    def get_params(self, count: int) -> Tuple[int, ...]:
        """Read system call arguments.

        Args:
            count: number of arguments to read

        Returns: a tuple containing system call arguments values
        """

        if count > len(self._argregs):
            raise ValueError(f'requested {count} arguments but only {len(self._argregs)} slots are defined')

        return tuple(self.arch.regs.read(reg) for reg in self._argregs[:count])  # type: ignore [uc funny annot]

    def set_return_value(self, value: int) -> None:
        """Set the system call return value.

        Args:
            value: a numeric value to set
        """

        self.arch.regs.write(self._retreg, value)
