#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import functools

from ...vm.computation import BaseComputation


def swap_XX(computation: BaseComputation, position: int) -> None:
    """
    Stack item swapping
    """
    computation.stack_swap(position)


swap1 = functools.partial(swap_XX, position=1)
swap2 = functools.partial(swap_XX, position=2)
swap3 = functools.partial(swap_XX, position=3)
swap4 = functools.partial(swap_XX, position=4)
swap5 = functools.partial(swap_XX, position=5)
swap6 = functools.partial(swap_XX, position=6)
swap7 = functools.partial(swap_XX, position=7)
swap8 = functools.partial(swap_XX, position=8)
swap9 = functools.partial(swap_XX, position=9)
swap10 = functools.partial(swap_XX, position=10)
swap11 = functools.partial(swap_XX, position=11)
swap12 = functools.partial(swap_XX, position=12)
swap13 = functools.partial(swap_XX, position=13)
swap14 = functools.partial(swap_XX, position=14)
swap15 = functools.partial(swap_XX, position=15)
swap16 = functools.partial(swap_XX, position=16)
