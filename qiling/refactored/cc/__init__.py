#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from typing import Callable, Tuple

from qiling import Qiling

class QlCC:
	"""Calling convention base class.
	"""

	def __init__(self, ql: Qiling) -> None:
		"""Initialize a calling convention instance.

		Args:
			ql: qiling instance
		"""

		self.ql = ql

	@staticmethod
	def getNumSlots(argbits: int) -> int:
		"""Get the number of slots allocated for an argument of width `argbits`.
		"""

		raise NotImplementedError

	def getRawParam8(self, slot: int) -> int:
		"""Read a 8 bits value from the specified argument slot.

		Note that argument slots and argument indexes are not the same. Though they often correlate
		to each other, some implementations might use more than one slot to represent a sigle argument.

		Args:
			slot: argument slot to read

		Returns: 8 bits raw value
		"""

		raise NotImplementedError

	def getRawParam16(self, slot: int) -> int:
		"""Read a 16 bits value from the specified argument slot.

		Note that argument slots and argument indexes are not the same. Though they often correlate
		to each other, some implementations might use more than one slot to represent a sigle argument.

		Args:
			slot: argument slot to read

		Returns: 16 bits raw value
		"""

		raise NotImplementedError

	def getRawParam32(self, slot: int) -> int:
		"""Read a 32 bits value from the specified argument slot.

		Note that argument slots and argument indexes are not the same. Though they often correlate
		to each other, some implementations might use more than one slot to represent a sigle argument.

		Args:
			slot: argument slot to read

		Returns: 32 bits raw value
		"""

		raise NotImplementedError

	def getRawParam64(self, slot: int) -> int:
		"""Read a 64 bits value from the specified argument slot.

		Note that argument slots and argument indexes are not the same. Though they often correlate
		to each other, some implementations might use more than one slot to represent a sigle argument.

		Args:
			slot: argument slot to read

		Returns: 64 bits raw value
		"""

		raise NotImplementedError

	def getRawParam(self, slot: int) -> int:
		"""Read a value of native size from the specified argument slot.

		Note that argument slots and argument indexes are not the same. Though they often correlate
		to each other, some implementations might use more than one slot to represent a sigle argument.

		Args:
			slot: argument slot to read

		Returns: raw value
		"""

		raise NotImplementedError

	def setRawParam(self, slot: int, value: int) -> None:
		"""Replace the value in the specified argument slot.

		Note that argument slots and argument indexes are not the same. Though they often correlate
		to each other, some implementations might use more than one slot to represent a sigle argument.

		Args:
			slot: argument slot to read
			value: new raw value to write
		"""

		raise NotImplementedError

	def getReturnValue(self) -> int:
		"""Get function return value.
		"""

		raise NotImplementedError

	def setReturnValue(self, val: int) -> None:
		"""Set function return value.

		Args:
			val: a value to set
		"""

		raise NotImplementedError

	def unwind(self) -> int:
		"""Unwind frame and return from function call.

		Returns: return address
		"""

		raise NotImplementedError

class QlCommonBaseCC(QlCC):
	"""Calling convention base class that implements parameters access through both
	registers and the stack. The extending class is resopnsible to implement the rest
	of the QlCC interface.
	"""

	_argregs = ()
	_shadow = 0

	def __init__(self, ql: Qiling, retreg: int):
		super().__init__(ql)

		# native address size in bytes
		self._asize = self.ql.pointersize

		# return value register
		self._retreg = retreg

	def __access_param(self, index: int, stack_access: Callable, reg_access: Callable) -> Tuple[Callable, int]:
		"""[private] Generic accessor to function call parameters by their index.

		This method will determine whether the parameter should be accessed on the stack or in a
		register, and return the appropriate accessor along with the location to access (either a
		register id or stack address)

		Args:
			index: parameter index to access
			stack_access: stack accessor method (either read or write)
			reg_access: regs accessor method (either read or write)

		Returns: a tuple of the accessor method to use and the location to access
		"""

		if index >= len(self._argregs):
			raise IndexError(f'tried to access arg {index}, but only {len(self._argregs) - 1} args are supported')

		reg = self._argregs[index]

		# should arg be read from a reg or the stack?
		if reg is None:
			# get matching stack item
			si = index - self._argregs.index(None)

			# skip return address and shadow space
			return stack_access, (1 + self._shadow + si) * self._asize
		else:
			return reg_access, reg

	def getRawParam8(self, slot: int) -> int:
		return self.getRawParam(slot) & 0xff

	def getRawParam16(self, slot: int) -> int:
		return self.getRawParam(slot) & 0xffff

	def getRawParam32(self, slot: int) -> int:
		return self.getRawParam(slot) & 0xffffffff

	def getRawParam(self, index: int) -> int:
		read, loc = self.__access_param(index, self.ql.stack_read, self.ql.reg.read)

		return read(loc)

	def setRawParam(self, index: int, value: int) -> None:
		write, loc = self.__access_param(index, self.ql.stack_write, self.ql.reg.write)

		write(loc, value)

	def getReturnValue(self) -> int:
		return self.ql.reg.read(self._retreg)

	def setReturnValue(self, value: int) -> None:
		self.ql.reg.write(self._retreg, value)
