#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Optional, Union

from dataclasses import dataclass
from capstone import CsInsn


@dataclass
class InvalidInsn:
    """
    class for displaying invalid instruction
    """

    bytes: bytes
    address: int
    mnemonic: str = '(invalid)'
    op_str: str = ''

    def __post_init__(self):
        self.size = len(self.bytes) if self.bytes else 1


class Breakpoint:
    """Dummy class for breakpoints.
    """

    # monotonically increasing index counter
    _counter = 0

    def __init__(self, addr: int, temp: bool = False):
        """Initialize a breakpoint object.

        Args:
            addr: address to break upon arrival
            temp: whether this is a temporary breakpoint. temporary breakpoints
            get removed after they get hit for the first time
        """

        self.index = Breakpoint._counter
        Breakpoint._counter += 1

        self.addr = addr
        self.temp = temp
        self.enabled = True


def read_int(s: str, /) -> int:
    """Turn a numerical string into its integer value.
    """

    return int(s, 0)


def try_read_int(s: str, /) -> Optional[int]:
    """Attempt to convert string to an integer value.
    """

    try:
        val = read_int(s)
    except (ValueError, TypeError):
        val = None

    return val


InsnLike = Union[CsInsn, InvalidInsn]
