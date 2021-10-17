#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.stm32f4xx_rcc import RCC_CR, RCC_CFGR


class STM32F4xxRcc(QlPeripheral):
	class Type(ctypes.Structure):
		""" the structure available in :
			stm32f401xc.h
			stm32f401xe.h
			stm32f411xe.h 
		"""

		_fields_ = [
			('CR'        , ctypes.c_uint32),      # RCC clock control register,                                  Address offset: 0x00
			('PLLCFGR'   , ctypes.c_uint32),      # RCC PLL configuration register,                              Address offset: 0x04
			('CFGR'      , ctypes.c_uint32),      # RCC clock configuration register,                            Address offset: 0x08
			('CIR'       , ctypes.c_uint32),      # RCC clock interrupt register,                                Address offset: 0x0C
			('AHB1RSTR'  , ctypes.c_uint32),      # RCC AHB1 peripheral reset register,                          Address offset: 0x10
			('AHB2RSTR'  , ctypes.c_uint32),      # RCC AHB2 peripheral reset register,                          Address offset: 0x14
			('AHB3RSTR'  , ctypes.c_uint32),      # RCC AHB3 peripheral reset register,                          Address offset: 0x18
			('RESERVED0' , ctypes.c_uint32),      # Reserved, 0x1C
			('APB1RSTR'  , ctypes.c_uint32),      # RCC APB1 peripheral reset register,                          Address offset: 0x20
			('APB2RSTR'  , ctypes.c_uint32),      # RCC APB2 peripheral reset register,                          Address offset: 0x24
			('RESERVED1' , ctypes.c_uint32 * 2),  # Reserved, 0x28-0x2C
			('AHB1ENR'   , ctypes.c_uint32),      # RCC AHB1 peripheral clock register,                          Address offset: 0x30
			('AHB2ENR'   , ctypes.c_uint32),      # RCC AHB2 peripheral clock register,                          Address offset: 0x34
			('AHB3ENR'   , ctypes.c_uint32),      # RCC AHB3 peripheral clock register,                          Address offset: 0x38
			('RESERVED2' , ctypes.c_uint32),      # Reserved, 0x3C
			('APB1ENR'   , ctypes.c_uint32),      # RCC APB1 peripheral clock enable register,                   Address offset: 0x40
			('APB2ENR'   , ctypes.c_uint32),      # RCC APB2 peripheral clock enable register,                   Address offset: 0x44
			('RESERVED3' , ctypes.c_uint32 * 2),  # Reserved, 0x48-0x4C
			('AHB1LPENR' , ctypes.c_uint32),      # RCC AHB1 peripheral clock enable in low power mode register, Address offset: 0x50
			('AHB2LPENR' , ctypes.c_uint32),      # RCC AHB2 peripheral clock enable in low power mode register, Address offset: 0x54
			('AHB3LPENR' , ctypes.c_uint32),      # RCC AHB3 peripheral clock enable in low power mode register, Address offset: 0x58
			('RESERVED4' , ctypes.c_uint32),      # Reserved, 0x5C
			('APB1LPENR' , ctypes.c_uint32),      # RCC APB1 peripheral clock enable in low power mode register, Address offset: 0x60
			('APB2LPENR' , ctypes.c_uint32),      # RCC APB2 peripheral clock enable in low power mode register, Address offset: 0x64
			('RESERVED5' , ctypes.c_uint32 * 2),  # Reserved, 0x68-0x6C
			('BDCR'      , ctypes.c_uint32),      # RCC Backup domain control register,                          Address offset: 0x70
			('CSR'       , ctypes.c_uint32),      # RCC clock control & status register,                         Address offset: 0x74
			('RESERVED6' , ctypes.c_uint32 * 2),  # Reserved, 0x78-0x7C
			('SSCGR'     , ctypes.c_uint32),      # RCC spread spectrum clock generation register,               Address offset: 0x80
			('PLLI2SCFGR', ctypes.c_uint32),      # RCC PLLI2S configuration register,                           Address offset: 0x84
			('RESERVED7' , ctypes.c_uint32),      # Reserved, 0x88
			('DCKCFGR'   , ctypes.c_uint32),      # RCC Dedicated Clocks configuration register,                 Address offset: 0x8C
		]

	def __init__(self, ql, label, intn=None):
		super().__init__(ql, label)

		self.rcc = self.struct(
			CR         = 0x00000083,
			PLLCFGR    = 0x24003010,
			AHB1LPENR  = 0x0061900F,
			AHB2LPENR  = 0x00000080,
			APB1LPENR  = 0x10E2C80F,
			APB2LPENR  = 0x00077930,
			CSR        = 0x0E000000,
			PLLI2SCFGR = 0x24003000,
		)

		self.cr_rdyon = [
			(RCC_CR.HSIRDY   , RCC_CR.HSION   ),
			(RCC_CR.HSERDY   , RCC_CR.HSEON   ),
			(RCC_CR.PLLRDY   , RCC_CR.PLLON   ),
			(RCC_CR.PLLI2SRDY, RCC_CR.PLLI2SON),
		]

		self.cfgr_rdyon = [
			(RCC_CFGR.SWS_0, RCC_CFGR.SW_0),
			(RCC_CFGR.SWS_1, RCC_CFGR.SW_1),
		]

		self.intn = intn

	def read(self, offset: int, size: int) -> int:
		self.ql.log.debug(f'[{self.label.upper()}] [R] {self.find_field(offset, size):10s}')
		
		buf = ctypes.create_string_buffer(size)
		ctypes.memmove(buf, ctypes.addressof(self.rcc) + offset, size)
		return int.from_bytes(buf.raw, byteorder='little')

	def write(self, offset: int, size: int, value: int):
		self.ql.log.debug(f'[{self.label.upper()}] [W] {self.find_field(offset, size):10s} = {hex(value)}')

		if offset == self.struct.CR.offset:
			value = (self.rcc.CR & RCC_CR.RO_MASK) | (value & RCC_CR.RW_MASK)
		elif offset == self.struct.CFGR.offset:
			value = (self.rcc.CFGR & RCC_CFGR.RO_MASK) | (value & RCC_CFGR.RW_MASK)

		data = (value).to_bytes(size, 'little')
		ctypes.memmove(ctypes.addressof(self.rcc) + offset, data, size)

	def step(self):
		for rdy, on in self.cr_rdyon:
			if self.rcc.CR & on:
				self.rcc.CR |= rdy
			else:
				self.rcc.CR &= ~rdy

		for rdy, on in self.cfgr_rdyon:
			if self.rcc.CFGR & on:
				self.rcc.CFGR |= rdy
			else:
				self.rcc.CFGR &= ~rdy
