#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.core import Qiling
from qiling.hw.peripheral import QlPeripheral


class STM32F4xxPwr(QlPeripheral):
	class Type(ctypes.Structure):
		""" the structure available in :
			stm32f413xx.h
			stm32f407xx.h
			stm32f469xx.h
			stm32f446xx.h
			stm32f427xx.h
			stm32f401xc.h
			stm32f415xx.h
			stm32f412cx.h
			stm32f410rx.h
			stm32f410tx.h
			stm32f439xx.h
			stm32f412vx.h
			stm32f417xx.h
			stm32f479xx.h
			stm32f429xx.h
			stm32f412rx.h
			stm32f423xx.h
			stm32f437xx.h
			stm32f412zx.h
			stm32f401xe.h
			stm32f410cx.h
			stm32f405xx.h
			stm32f411xe.h 
		"""

		_fields_ = [
			('CR' , ctypes.c_uint32),  # PWR power control register,        Address offset: 0x00
			('CSR', ctypes.c_uint32),  # PWR power control/status register, Address offset: 0x04
		]

	def __init__(self, ql: Qiling, label: str):
		super().__init__(ql, label)

		self.pwr = self.struct()

	@QlPeripheral.monitor()
	def read(self, offset: int, size: int) -> int:		
		buf = ctypes.create_string_buffer(size)
		ctypes.memmove(buf, ctypes.addressof(self.pwr) + offset, size)
		return int.from_bytes(buf.raw, byteorder='little')
    
	@QlPeripheral.monitor()
	def write(self, offset: int, size: int, value: int):
		data = (value).to_bytes(size, 'little')
		ctypes.memmove(ctypes.addressof(self.pwr) + offset, data, size)