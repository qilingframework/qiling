#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import functools

from ...vm.computation import BaseComputation


def dup_XX(computation: BaseComputation, position: int) -> None:
    """
    Stack item duplication.
    """
    computation.stack_dup(position)


dup1 = functools.partial(dup_XX, position=1)
dup2 = functools.partial(dup_XX, position=2)
dup3 = functools.partial(dup_XX, position=3)
dup4 = functools.partial(dup_XX, position=4)
dup5 = functools.partial(dup_XX, position=5)
dup6 = functools.partial(dup_XX, position=6)
dup7 = functools.partial(dup_XX, position=7)
dup8 = functools.partial(dup_XX, position=8)
dup9 = functools.partial(dup_XX, position=9)
dup10 = functools.partial(dup_XX, position=10)
dup11 = functools.partial(dup_XX, position=11)
dup12 = functools.partial(dup_XX, position=12)
dup13 = functools.partial(dup_XX, position=13)
dup14 = functools.partial(dup_XX, position=14)
dup15 = functools.partial(dup_XX, position=15)
dup16 = functools.partial(dup_XX, position=16)
