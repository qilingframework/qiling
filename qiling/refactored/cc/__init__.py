#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from typing import Any, Callable, Optional, Mapping, Tuple

from qiling import Qiling

Resolver = Callable[[int], Tuple[Any, int]]

class QlCC:
	"""Calling convention base class.
	"""

	def __init__(self, ql: Qiling) -> None:
		"""Initialize a calling convention instance.

		Args:
			ql: qiling instance
		"""

		self.ql = ql

	def getRawParam(self, index: int) -> int:
		"""Read argument's raw value.
		It is the caller responsibility to make sure the argument exists.

		Args:
			index: argument index to read

		Returns: argument raw value
		"""

		raise NotImplementedError

	def setRawParam(self, index: int, value: int) -> None:
		"""Replace argument's raw value.
		It is the caller responsibility to make sure the argument exists.

		Args:
			index: argument index to replace
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
