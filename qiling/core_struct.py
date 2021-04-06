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

from .const import QL_ENDIAN
from .exception import QlErrorStructConversion

# Don't assume self is Qiling.
class QlCoreStructs:
	def __init__(self, endian: QL_ENDIAN, bit: int):
		modifier = {
			QL_ENDIAN.EL: '<',
			QL_ENDIAN.EB: '>'
		}[endian]

		self._fmt8   = f'{modifier}B'
		self._fmt8s  = f'{modifier}b'
		self._fmt16  = f'{modifier}H'
		self._fmt16s = f'{modifier}h'
		self._fmt32  = f'{modifier}I'
		self._fmt32s = f'{modifier}i'
		self._fmt64  = f'{modifier}Q'
		self._fmt64s = f'{modifier}q'

		handlers = {
			64 : (self.pack64, self.pack64s, self.unpack64, self.unpack64s),
			32 : (self.pack32, self.pack32s, self.unpack32, self.unpack32s),
			16 : (self.pack16, self.pack16s, self.unpack16, self.unpack16s),
			1  : (       None,         None,          None,           None)
		}

		if bit not in handlers:
			raise QlErrorStructConversion("Unsupported Qiling struct conversion")

		p, ps, up, ups = handlers[bit]

		self.pack    = p
		self.packs   = ps
		self.unpack  = up
		self.unpacks = ups

	def pack64(self, x):
		return struct.pack(self._fmt64, x)

	def pack64s(self, x):
		return struct.pack(self._fmt64s, x)

	def unpack64(self, x):
		return struct.unpack(self._fmt64, x)[0]

	def unpack64s(self, x):
		return struct.unpack(self._fmt64s, x)[0]

	def pack32(self, x):
		return struct.pack(self._fmt32, x)

	def pack32s(self, x):
		return struct.pack(self._fmt32s, x)

	def unpack32(self, x):
		return struct.unpack(self._fmt32, x)[0]

	def unpack32s(self, x):
		return struct.unpack(self._fmt32s, x)[0]

	def pack16(self, x):
		return struct.pack(self._fmt16, x)

	def pack16s(self, x):
		return struct.pack(self._fmt16s, x)

	def unpack16(self, x):
		return struct.unpack(self._fmt16, x)[0]

	def unpack16s(self, x):
		return struct.unpack(self._fmt16s, x)[0]

	def pack8(self, x):
		return struct.pack(self._fmt8, x)

	def pack8s(self, x):
		return struct.pack(self._fmt8s, x)

	def unpack8(self, x):
		return struct.unpack(self._fmt8, x)[0]

	def unpack8s(self, x):
		return struct.unpack(self._fmt8s, x)[0]
