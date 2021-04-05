#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from typing import Mapping, MutableMapping, Sequence, Optional

from qiling import Qiling

bits = 64
psize = bits // 8

dummy_ptr_type = {
	32 : ctypes.c_uint32,
	64 : ctypes.c_uint64
}[bits]

_pointer_type_cache: MutableMapping[str, type] = {}

def PTR(ptype: Optional[type]) -> type:
	pname = 'c_void' if ptype is None else ptype.__name__

	if pname not in _pointer_type_cache:
		_pointer_type_cache[pname] = type(f'LP_{psize}_{pname}', (dummy_ptr_type,), {})

	return _pointer_type_cache[pname]

VOID = None
INT8  = ctypes.c_byte
INT16 = ctypes.c_int16
INT32 = ctypes.c_int32
INT64 = ctypes.c_int64
INTN  = INT64

UINT8  = ctypes.c_ubyte
UINT16 = ctypes.c_uint16
UINT32 = ctypes.c_uint32
UINT64 = ctypes.c_uint64
UINTN  = UINT64

BOOLEAN = UINT8
CHAR8 = UINT8
CHAR16 = UINT16

FUNCPTR = lambda *args: PTR(ctypes.CFUNCTYPE(*args))
UNION = ctypes.Union
# SIZEOF = lambda t: ctypes.sizeof(t)
# OFFSETOF = lambda cls, fname: getattr(cls, fname).offset

CPU_STACK_ALIGNMENT = 16
PAGE_SIZE = 0x1000

class STRUCT(ctypes.LittleEndianStructure):
	"""An abstract class for C structures.
	"""

	# Structures are packed by default; when needed, padding should be added
	# manually through placeholder fields
	_pack_ = 1

	def __init__(self):
		pass

	def saveTo(self, ql: Qiling, address: int) -> None:
		"""Store self contents to a specified memory address.
		"""

		data = bytes(self)

		ql.mem.write(address, data)

	@classmethod
	def loadFrom(cls, ql: Qiling, address: int) -> 'STRUCT':
		"""Construct an instance of the structure from saved contents.
		"""

		data = bytes(ql.mem.read(address, cls.sizeof()))

		return cls.from_buffer_copy(data)

	@classmethod
	def sizeof(cls) -> int:
		"""Get the C structure size in bytes.
		"""

		return ctypes.sizeof(cls)

	@classmethod
	def offsetof(cls, fname: str) -> int:
		"""Get the offset of a field in the C structure.
		"""

		return getattr(cls, fname).offset

	@classmethod
	def memberat(cls, offset: int) -> Optional[str]:
		for fname, _ in cls._fields_:
			if cls.offsetof(fname) == offset:
				return fname

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