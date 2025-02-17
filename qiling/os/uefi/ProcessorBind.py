#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

import ctypes

from functools import lru_cache
from typing import Mapping, Sequence, Union

from qiling.os.struct import BaseStructEL


bits = 64
psize = bits // 8

@lru_cache(maxsize=None)
def PTR(ptype: Union[type, None]) -> type:
    """Generate a pseudo pointer type.
    """

    pname = 'c_void' if ptype is None else ptype.__name__

    return type(f'LP_{psize}_{pname}', (UINTN,), {})


def FUNCPTR(rettype: Union[type, None], *argtypes: type) -> type:
    """Generate a pseudo function pointer type.
    """

    return PTR(ctypes.CFUNCTYPE(rettype, *argtypes))


VOID = None
INT8  = ctypes.c_int8
INT16 = ctypes.c_int16
INT32 = ctypes.c_int32
INT64 = ctypes.c_int64
INTN  = INT64

UINT8  = ctypes.c_uint8
UINT16 = ctypes.c_uint16
UINT32 = ctypes.c_uint32
UINT64 = ctypes.c_uint64
UINTN  = UINT64

BOOLEAN = UINT8
CHAR8 = UINT8
CHAR16 = UINT16

STRUCT = BaseStructEL
UNION = ctypes.Union

CPU_STACK_ALIGNMENT = 16
PAGE_SIZE = 0x1000


class EnumMeta(type(ctypes.c_int)):
    def __getattr__(self, key):
        return self._members_.index(key)


class ENUM(ctypes.c_int, metaclass=EnumMeta):
    """An abstract class for continuous C enums.
    """

    # a list or tuple of names (strings)
    # names will be enumerate by their corresponding index in the list
    _members_: Sequence[str] = []


class EnumUCMeta(type(ctypes.c_int)):
    def __getattr__(self, key):
        return self._members_[key]


class ENUM_UC(ctypes.c_int, metaclass=EnumUCMeta):
    """An abstract class for uncontinuous C enums.
    """

    # a dictionary of (names : str, value : int) tuples
    # names will be enumerate by their paired value
    _members_: Mapping[str, int] = {}


__all__ = [
    'VOID',
    'INT8',
    'INT16',
    'INT32',
    'INT64',
    'INTN',
    'UINT8',
    'UINT16',
    'UINT32',
    'UINT64',
    'UINTN',
    'BOOLEAN',
    'CHAR8',
    'CHAR16',

    'PTR',
    'FUNCPTR',
    'STRUCT',
    'UNION',
    'ENUM',
    'ENUM_UC',

    'CPU_STACK_ALIGNMENT',
    'PAGE_SIZE'
]
