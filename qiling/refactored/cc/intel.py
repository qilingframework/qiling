#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from typing import Callable, Tuple
from unicorn.x86_const import (
	UC_X86_REG_AX,	UC_X86_REG_EAX,	UC_X86_REG_RAX, UC_X86_REG_RCX,
	UC_X86_REG_RDI,	UC_X86_REG_RDX,	UC_X86_REG_RSI,	UC_X86_REG_R8,
	UC_X86_REG_R9,	UC_X86_REG_R10
)

from . import QlCC

class QlIntelBaseCC(QlCC):
	"""Calling convention base class for Intel-based systems.
	Supports arguments passing over registers and stack.
	"""

	_argregs = ()
	_shadow = 0

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		bits = self.ql.archbit

		# native address size in bytes
		self._asize = bits // 8

		# return value register
		self._retreg = {
			16: UC_X86_REG_AX,
			32: UC_X86_REG_EAX,
			64: UC_X86_REG_RAX
		}[bits]

	def __access_param(self, index: int, stack_access: Callable, reg_access: Callable) -> Tuple[Callable, int]:
		"""[private] Generic accessor to function call parameters by their index.

		This method will determine whether the parameter should be accessed on the stack or in
		a register, and return the appropriate accessor along with the location to access (either a
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

	def unwind(self) -> int:
		# no cleanup; just pop out the return address
		return self.ql.arch.stack_pop()

class amd64(QlIntelBaseCC):
	"""Default calling convention for POSIX (x86-64).
	First 6 arguments are passed in regs, the rest are passed on the stack.
	"""

	_argregs = (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9) + (None, ) * 10

class ms64(QlIntelBaseCC):
	"""Default calling convention for Windows and UEFI (x86-64).
	First 4 arguments are passed in regs, the rest are passed on the stack.

	Each stack frame starts with a shadow space in size of 4 items, corresponding
	to the first arguments passed in regs.
	"""

	_argregs = (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9) + (None, ) * 12
	_shadow = 4

class macosx64(QlIntelBaseCC):
	"""Default calling convention for Mac OS (x86-64).
	First 6 arguments are passed in regs, the rest are passed on the stack.
	"""

	_argregs = (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9) + (None, ) * 10

class cdecl(QlIntelBaseCC):
	"""Calling convention used by all operating systems (x86).
	All arguments are passed on the stack.

	The caller is resopnsible to unwind the stack.
	"""

	_argregs = (None, ) * 16

class stdcall(QlIntelBaseCC):
	"""Calling convention used by all operating systems (x86).
	All arguments are passed on the stack.

	The callee is resopnsible to unwind the stack.
	"""

	# TODO: the stack frame size to uwind is fcall-specific. should think how
	# it would be determined
	def unwind(self) -> int:
		retaddr = super().unwind()

		self.ql.reg.arch_sp += (param_num * self._asize)

		return retaddr
