#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

##############################################
# These are part of the core.py Qiling class #
# handling structure packing and unpacking   #
# for different architecture bits            #
##############################################

import struct
from typing import Union

from .const import QL_ENDIAN
from .exception import QlErrorStructConversion

ReadableBuffer = Union[bytes, bytearray, memoryview]

# Don't assume self is Qiling.
class QlCoreStructs:
    def __init__(self, endian: QL_ENDIAN, bit: int):
        modifier = {
            QL_ENDIAN.EL: '<',
            QL_ENDIAN.EB: '>'
        }[endian]

        self._fmt8   = struct.Struct(f'{modifier}B')
        self._fmt8s  = struct.Struct(f'{modifier}b')
        self._fmt16  = struct.Struct(f'{modifier}H')
        self._fmt16s = struct.Struct(f'{modifier}h')
        self._fmt32  = struct.Struct(f'{modifier}I')
        self._fmt32s = struct.Struct(f'{modifier}i')
        self._fmt64  = struct.Struct(f'{modifier}Q')
        self._fmt64s = struct.Struct(f'{modifier}q')

        handlers = {
            64 : (self.pack64, self.pack64s, self.unpack64, self.unpack64s),
            32 : (self.pack32, self.pack32s, self.unpack32, self.unpack32s),
            16 : (self.pack16, self.pack16s, self.unpack16, self.unpack16s),
        }

        if bit not in handlers:
            raise QlErrorStructConversion("Unsupported Qiling struct conversion")

        p, ps, up, ups = handlers[bit]

        self.pack    = p
        self.packs   = ps
        self.unpack  = up
        self.unpacks = ups

    def pack64(self, x: int, /) -> bytes:
        return self._fmt64.pack(x)

    def pack64s(self, x: int, /) -> bytes:
        return self._fmt64s.pack(x)

    def unpack64(self, x: ReadableBuffer, /) -> int:
        return self._fmt64.unpack(x)[0]

    def unpack64s(self, x: ReadableBuffer, /) -> int:
        return self._fmt64s.unpack(x)[0]

    def pack32(self, x: int, /) -> bytes:
        return self._fmt32.pack(x)

    def pack32s(self, x: int, /) -> bytes:
        return self._fmt32s.pack(x)

    def unpack32(self, x: ReadableBuffer, /) -> int:
        return self._fmt32.unpack(x)[0]

    def unpack32s(self, x: ReadableBuffer, /) -> int:
        return self._fmt32s.unpack(x)[0]

    def pack16(self, x: int, /) -> bytes:
        return self._fmt16.pack(x)

    def pack16s(self, x: int, /) -> bytes:
        return self._fmt16s.pack(x)

    def unpack16(self, x: ReadableBuffer, /) -> int:
        return self._fmt16.unpack(x)[0]

    def unpack16s(self, x: ReadableBuffer, /) -> int:
        return self._fmt16s.unpack(x)[0]

    def pack8(self, x: int, /) -> bytes:
        return self._fmt8.pack(x)

    def pack8s(self, x: int, /) -> bytes:
        return self._fmt8s.pack(x)

    def unpack8(self, x: ReadableBuffer, /) -> int:
        return self._fmt8.unpack(x)[0]

    def unpack8s(self, x: ReadableBuffer, /) -> int:
        return self._fmt8s.unpack(x)[0]
