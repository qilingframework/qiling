#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

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

	# def setRawParam(self, slot: int, value: int) -> None:
	# 	"""Replace the value in the specified argument slot.
	# 
	# 	Note that argument slots and argument indexes are not the same. Though they often correlate
	# 	to each other, some implementations might use more than one slot to represent a sigle argument.
	# 
	# 	Args:
	# 		slot: argument slot to read
	# 		value: new raw value to write
	# 	"""
	# 
	# 	raise NotImplementedError

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
