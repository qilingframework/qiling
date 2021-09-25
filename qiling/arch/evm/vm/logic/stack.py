#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import functools

from ...vm.computation import BaseComputation


def pop(computation: BaseComputation) -> None:
    computation.stack_pop1_any()


def push_XX(computation: BaseComputation, size: int) -> None:
    raw_value = computation.code.read(size)

    # This is a performance-sensitive area.
    # Calling raw_value.ljust() when size == len(raw_value) is more expensive than
    # calling len(raw_value) and raw_len is typically the correct size already,
    # so this saves a bit of time:
    raw_len = len(raw_value)
    if raw_len == size:
        computation.stack_push_bytes(raw_value)
    else:
        padded_value = raw_value.ljust(size, b'\x00')
        computation.stack_push_bytes(padded_value)


push1 = functools.partial(push_XX, size=1)
push2 = functools.partial(push_XX, size=2)
push3 = functools.partial(push_XX, size=3)
push4 = functools.partial(push_XX, size=4)
push5 = functools.partial(push_XX, size=5)
push6 = functools.partial(push_XX, size=6)
push7 = functools.partial(push_XX, size=7)
push8 = functools.partial(push_XX, size=8)
push9 = functools.partial(push_XX, size=9)
push10 = functools.partial(push_XX, size=10)
push11 = functools.partial(push_XX, size=11)
push12 = functools.partial(push_XX, size=12)
push13 = functools.partial(push_XX, size=13)
push14 = functools.partial(push_XX, size=14)
push15 = functools.partial(push_XX, size=15)
push16 = functools.partial(push_XX, size=16)
push17 = functools.partial(push_XX, size=17)
push18 = functools.partial(push_XX, size=18)
push19 = functools.partial(push_XX, size=19)
push20 = functools.partial(push_XX, size=20)
push21 = functools.partial(push_XX, size=21)
push22 = functools.partial(push_XX, size=22)
push23 = functools.partial(push_XX, size=23)
push24 = functools.partial(push_XX, size=24)
push25 = functools.partial(push_XX, size=25)
push26 = functools.partial(push_XX, size=26)
push27 = functools.partial(push_XX, size=27)
push28 = functools.partial(push_XX, size=28)
push29 = functools.partial(push_XX, size=29)
push30 = functools.partial(push_XX, size=30)
push31 = functools.partial(push_XX, size=31)
push32 = functools.partial(push_XX, size=32)
