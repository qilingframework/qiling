#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3
from unicorn.arm64_const import (
	UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
	UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7
)

from qiling import Qiling
from . import QlCommonBaseCC

class aarch64(QlCommonBaseCC):
	_argregs = (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7) + (None, ) * 8

	def __init__(self, ql: Qiling) -> None:
		super().__init__(ql, UC_ARM64_REG_X0)

	@staticmethod
	def getNumSlots(argbits: int) -> int:
		return 1

	def unwind(self, nslots: int) -> int:
		# TODO: cleanup?
		return self.ql.arch.stack_pop()

class aarch32(QlCommonBaseCC):
	_argregs = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3) + (None, ) * 12

	def __init__(self, ql: Qiling) -> None:
		super().__init__(ql, UC_ARM_REG_R0)

	@staticmethod
	def getNumSlots(argbits: int) -> int:
		return 1

	def unwind(self, nslots: int) -> int:
		# TODO: cleanup?
		return self.ql.arch.stack_pop()
