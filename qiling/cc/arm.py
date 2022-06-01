#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3
from unicorn.arm64_const import (
	UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
	UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7
)

from qiling.cc import QlCommonBaseCC

class QlArmBaseCC(QlCommonBaseCC):
	"""Calling convention base class for ARM-based systems.
	Supports arguments passing over registers and stack.
	"""

	@staticmethod
	def getNumSlots(argbits: int) -> int:
		return 1

	def setReturnAddress(self, addr: int) -> None:
		# TODO: do we need to update LR?
		self.arch.stack_push(addr)

	def unwind(self, nslots: int) -> int:
		# TODO: cleanup?
		return self.arch.stack_pop()

class aarch64(QlArmBaseCC):
	_retreg = UC_ARM64_REG_X0
	_argregs = (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7) + (None, ) * 8

class aarch32(QlArmBaseCC):
	_retreg = UC_ARM_REG_R0
	_argregs = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3) + (None, ) * 12
