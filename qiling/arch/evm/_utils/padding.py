#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from eth_utils.toolz import (
    curry,
)


ZERO_BYTE = b'\x00'


@curry
def zpad_right(value: bytes, to_size: int) -> bytes:
    return value.ljust(to_size, ZERO_BYTE)


@curry
def zpad_left(value: bytes, to_size: int) -> bytes:
    return value.rjust(to_size, ZERO_BYTE)


pad32 = zpad_left(to_size=32)
pad32r = zpad_right(to_size=32)
