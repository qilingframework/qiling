#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from unicorn.mips_const import UC_MIPS_REG_V0, UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3

from qiling.cc import QlCommonBaseCC

class mipso32(QlCommonBaseCC):
	_retreg = UC_MIPS_REG_V0
	_argregs = (UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3) + (None, ) * 12
	_shadow = 4
	_retaddr_on_stack = False

	@staticmethod
	def getNumSlots(argbits: int):
		return 1

	def unwind(self, nslots: int) -> int:
		# TODO: stack frame unwiding?
		return self.arch.regs.ra
