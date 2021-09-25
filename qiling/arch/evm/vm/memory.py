#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import itertools
import logging

from ..validation import (
    validate_is_bytes,
    validate_length,
    validate_lte,
    validate_uint256,
)

from .._utils.numeric import (
    ceil32,
)
from ..abc import MemoryAPI


class Memory(MemoryAPI):
    __slots__ = ['_bytes']
    logger = logging.getLogger('eth.vm.memory.Memory')

    def __init__(self) -> None:
        self._bytes = bytearray()

    def extend(self, start_position: int, size: int) -> None:
        if size == 0:
            return

        new_size = ceil32(start_position + size)
        if new_size <= len(self):
            return

        size_to_extend = new_size - len(self)
        try:
            self._bytes.extend(itertools.repeat(0, size_to_extend))
        except BufferError:
            # we can't extend the buffer (which might involve relocating it) if a
            # memoryview (which stores a pointer into the buffer) has been created by
            # read() and not released. Callers of read() will never try to write to the
            # buffer so we're not missing anything by making a new buffer and forgetting
            # about the old one. We're keeping too much memory around but this is still a
            # net savings over having read() return a new bytes() object every time.
            self._bytes = self._bytes + bytearray(size_to_extend)

    def __len__(self) -> int:
        return len(self._bytes)

    def write(self, start_position: int, size: int, value: bytes) -> None:
        if size:
            validate_uint256(start_position)
            validate_uint256(size)
            validate_is_bytes(value)
            validate_length(value, length=size)
            validate_lte(start_position + size, maximum=len(self))

            for idx, v in enumerate(value):
                self._bytes[start_position + idx] = v

    def read(self, start_position: int, size: int) -> memoryview:
        return memoryview(self._bytes)[start_position:start_position + size]

    def read_bytes(self, start_position: int, size: int) -> bytes:
        return bytes(self._bytes[start_position:start_position + size])
