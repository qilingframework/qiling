#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from enum import IntEnum

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.connectivity import QlConnectivityPeripheral
from qiling.hw.const.stm32f4xx_i2c import I2C_CR1, I2C_CR2, I2C_SR1, I2C_SR2, I2C_DR, I2C_OAR1, I2C_OAR2
from qiling.hw.utils.access import Access, AccessSequence, Op


class STM32F4xxI2c(QlConnectivityPeripheral):
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
		super().__init__(ql, label, 2)		

		self.history = AccessSequence()

		self.ev_intn = ev_intn # event interrupt
		self.er_intn = er_intn # error interrupt		
		
		self.reset()

	def reset(self):
		self.i2c = self.struct(
			TRISE = 0x0002
		)

	@QlPeripheral.recorder()
	@QlPeripheral.monitor()
	def read(self, offset: int, size: int) -> int:	
		buf = ctypes.create_string_buffer(size)
		ctypes.memmove(buf, ctypes.addressof(self.i2c) + offset, size)

		if self.history.match([
			Access(Op.READ, self.struct.SR1.offset),
			Access(Op.READ, self.struct.SR2.offset)
		]):				
			self.i2c.SR1 &= ~I2C_SR1.ADDR

		return int.from_bytes(buf.raw, byteorder='little')

	@QlPeripheral.recorder()
	@QlPeripheral.monitor()
	def write(self, offset: int, size: int, value: int):
		if offset in [self.struct.SR1.offset, self.struct.SR2.offset]:
			return		

		if offset == self.struct.CR1.offset:
			self.i2c.CR1 = value & I2C_CR1.RW_MASK

			if value & I2C_CR1.START:
				self.generate_start()

			if value & I2C_CR1.STOP:
				self.generate_stop()

			return

		if offset == self.struct.DR.offset:
			self.i2c.DR = value & I2C_DR.DR
			self.i2c.SR1 &= ~I2C_SR1.TXE

			if self.is_master_mode():
				if self.is_7bit_mode():	
					if self.i2c.SR2 & I2C_SR2.TRA:
						self.send_data()

					else:
						self.send_address()					

				# TODO 10-bit mode

			return

		data = (value).to_bytes(size, 'little')
		ctypes.memmove(ctypes.addressof(self.i2c) + offset, data, size)

	## I2C Control register 2 (I2C_CR2)
	def send_event_interrupt(self):
		"""
			ITBUFEN: Buffer interrupt enable
				0: TxE = 1 or RxNE = 1 does not generate any interrupt.
				1: TxE = 1 or RxNE = 1 generates Event Interrupt (whatever the state of DMAEN)

			ITEVTEN: Event interrupt enable
				0: Event interrupt disabled
				1: Event interrupt enabled
				This interrupt is generated when:
				- SB = 1 (Master)
				- ADDR = 1 (Master/Slave)
				- ADD10= 1 (Master)
				- STOPF = 1 (Slave)
				- BTF = 1 with no TxE or RxNE event
				- TxE event to 1 if ITBUFEN = 1
				- RxNE event to 1if ITBUFEN = 1
		"""
		if self.ev_intn is None:
			return
		
		if not self.i2c.CR2 & I2C_CR2.ITEVTEN:
			return

		BUF_IT = I2C_SR1.TXE|I2C_SR1.RXNE
		SLAVE_IT = I2C_SR1.STOPF|I2C_SR1.ADDR|I2C_SR1.BTF
		MASTER_IT = I2C_SR1.SB|I2C_SR1.ADDR|I2C_SR1.ADD10|I2C_SR1.BTF

		if  (self.i2c.CR2 & I2C_CR2.ITBUFEN and self.i2c.SR1 & BUF_IT) or \
			(self.is_slave_mode()           and self.i2c.SR1 & SLAVE_IT) or \
			(self.is_master_mode()          and self.i2c.SR1 & MASTER_IT):
			self.ql.hw.nvic.set_pending(self.ev_intn)

	## I2C Status register 1 (I2C_SR1)
	def generate_start(self):
		"""
		  	SB: Start bit (Master mode)
			0: No Start condition
			1: Start condition generated.
		- Set when a Start condition generated.
		- Cleared by software by reading the SR1 register followed by writing the DR register, or by hardware when PE=0
		"""

		# TODO: generate a start condition
		self.fetch_device_address()
		self.i2c.SR1 |= I2C_SR1.SB
		self.i2c.CR1 &= ~I2C_CR1.START

		self.set_master_mode()

	def generate_stop(self):
		# TODO: generate a stop condition
		self.i2c.CR1 &= ~I2C_CR1.STOP
		
		self.i2c.SR1 |= I2C_SR1.STOPF
		self.i2c.SR1 &= ~I2C_SR1.ADDR
		
		self.set_slave_mode()
		self.i2c.SR2 &= ~I2C_SR2.TRA
	
	def send_address(self):
		if self.i2c.DR == self.i2c.OAR1 >> 1:
			
			# TODO: send ACK
			self.i2c.SR1 &= ~I2C_SR1.SB
			self.i2c.SR1 |= I2C_SR1.ADDR | I2C_SR1.TXE
			self.i2c.SR2 |= I2C_SR2.TRA

	def send_data(self):
		self.i2c.SR1 |= I2C_SR1.BTF | I2C_SR1.TXE

		self.send_to_user(self.i2c.DR)

	## I2C Status register 2 (I2C_SR2)
	def is_master_mode(self):
		"""
		  	I2C Status register 2 (I2C_SR2) MSL bit
			0: Slave Mode
			1: Master Mode
		"""
		return self.i2c.SR2 & I2C_SR2.MSL

	def is_slave_mode(self):
		return not self.is_master_mode()

	def set_master_mode(self):
		"""
			I2C Status register 2 (I2C_SR2) MSL bit
			- Set by hardware as soon as the interface is in Master mode (SB=1)			
		"""
		self.i2c.SR2 |= I2C_SR2.MSL
	
	def set_slave_mode(self):		
		"""
			I2C Status register 2 (I2C_SR2) MSL bit
			- Cleared by hardware after detecting a Stop condition on the bus 
			  or a loss of arbitration (ARLO=1), or by hardware when PE=0.
		"""
		self.i2c.SR2 &= ~I2C_SR2.MSL

	## I2C Own address register 1 (I2C_OAR1)
	def is_7bit_mode(self):
		return self.i2c.OAR2 & I2C_OAR2.ENDUAL or not self.i2c.OAR1 & I2C_OAR1.ADDMODE

	def fetch_device_address(self):
		# dual addressing mode
		if self.i2c.OAR2 & I2C_OAR2.ENDUAL:
			self.i2c.OAR1 = self.device_list[0].address << 1
			self.i2c.OAR2 = I2C_OAR2.ENDUAL | (self.device_list[1].address << 1)

		# single device, 10-bit slave address
		elif self.i2c.OAR1 & I2C_OAR1.ADDMODE: 
			self.i2c.OAR1 = I2C_OAR1.ADDMODE | self.device_list[0].address
		
		# single device, 7-bit slave address
		else:
			self.i2c.OAR1 = self.device_list[0].address << 1

	@QlConnectivityPeripheral.device_handler
	def step(self):
		self.send_event_interrupt()
