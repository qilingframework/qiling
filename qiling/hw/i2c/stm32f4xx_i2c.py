#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.hw.peripheral import QlPeripheral


class STM32F4xxI2c(QlPeripheral):
	class Type(ctypes.Structure):
		""" the structure is available in :
			stm32f423xx.h
			stm32f469xx.h
			stm32f427xx.h
			stm32f479xx.h
			stm32f413xx.h
			stm32f429xx.h
			stm32f439xx.h
			stm32f412cx.h
			stm32f412rx.h
			stm32f410tx.h
			stm32f410cx.h
			stm32f412zx.h
			stm32f446xx.h
			stm32f401xc.h
			stm32f437xx.h
			stm32f401xe.h
			stm32f412vx.h
			stm32f410rx.h
			stm32f411xe.h 
		"""

		_fields_ = [
			('CR1'  , ctypes.c_uint32),  # I2C Control register 1,     Address offset: 0x00
			('CR2'  , ctypes.c_uint32),  # I2C Control register 2,     Address offset: 0x04
			('OAR1' , ctypes.c_uint32),  # I2C Own address register 1, Address offset: 0x08
			('OAR2' , ctypes.c_uint32),  # I2C Own address register 2, Address offset: 0x0C
			('DR'   , ctypes.c_uint32),  # I2C Data register,          Address offset: 0x10
			('SR1'  , ctypes.c_uint32),  # I2C Status register 1,      Address offset: 0x14
			('SR2'  , ctypes.c_uint32),  # I2C Status register 2,      Address offset: 0x18
			('CCR'  , ctypes.c_uint32),  # I2C Clock control register, Address offset: 0x1C
			('TRISE', ctypes.c_uint32),  # I2C TRISE register,         Address offset: 0x20
			('FLTR' , ctypes.c_uint32),  # I2C FLTR register,          Address offset: 0x24
		]

	def __init__(self, ql, label, ev_intn=None, er_intn=None):
		super().__init__(ql, label)

		self.i2c = self.struct(
			TRISE = 0x0002
		)

		self.ev_intn = ev_intn
		self.er_intn = er_intn

	def read(self, offset, size):
		buf = ctypes.create_string_buffer(size)
		ctypes.memmove(buf, ctypes.addressof(self.i2c) + offset, size)
		return int.from_bytes(buf.raw, byteorder='little')

	def write(self, offset, size, value):
		data = (value).to_bytes(size, 'little')
		ctypes.memmove(ctypes.addressof(self.i2c) + offset, data, size)
