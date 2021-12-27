#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.hw.peripheral import QlPeripheral


class STM32F4xxCrc(QlPeripheral):
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
			('DR'       , ctypes.c_uint32),  # CRC Data register,             Address offset: 0x00
			('IDR'      , ctypes.c_uint8),   # CRC Independent data register, Address offset: 0x04
			('RESERVED0', ctypes.c_uint8),   # Reserved, 0x05
			('RESERVED1', ctypes.c_uint8),   # Reserved, 0x06
			('CR'       , ctypes.c_uint32),  # CRC Control register,          Address offset: 0x08
		]

	def __init__(self, ql, label):
		super().__init__(ql, label)

		self.crc = self.struct(
            DR    =  0xffffffff,
        )

	@QlPeripheral.monitor()
	def read(self, offset: int, size: int) -> int:
		buf = ctypes.create_string_buffer(size)
		ctypes.memmove(buf, ctypes.addressof(self.crc) + offset, size)
		return int.from_bytes(buf.raw, byteorder='little')
    
	@QlPeripheral.monitor()
	def write(self, offset: int, size: int, value: int):
		if offset == self.struct.CR.offset:
			if value & 1: # RESET bit
				self.crc.DR = 0xffffffff
			return
		
		elif offset == self.struct.DR.offset:
			for i in range(31, -1, -1):
				if self.crc.DR & 0x80000000:
					self.crc.DR <<= 1
					self.crc.DR ^= 0x04c11db7
				else:
					self.crc.DR <<= 1

				if value & (1 << i):
					self.crc.DR ^= 0x04c11db7
