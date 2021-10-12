#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.hw.peripheral import QlPeripheral


class STM32F4xxSyscfg(QlPeripheral):
    class Type(ctypes.Structure):
        """ the structure available in :
			stm32f407xx.h
			stm32f469xx.h
			stm32f427xx.h
			stm32f401xc.h
			stm32f415xx.h
			stm32f439xx.h
			stm32f417xx.h
			stm32f479xx.h
			stm32f429xx.h
			stm32f437xx.h
			stm32f401xe.h
			stm32f405xx.h
			stm32f411xe.h 
		"""

        _fields_ = [
			('MEMRMP'  , ctypes.c_uint32),      # SYSCFG memory remap register,                      Address offset: 0x00
			('PMC'     , ctypes.c_uint32),      # SYSCFG peripheral mode configuration register,     Address offset: 0x04
			('EXTICR'  , ctypes.c_uint32 * 4),  # SYSCFG external interrupt configuration registers, Address offset: 0x08-0x14
			('RESERVED', ctypes.c_uint32 * 2),  # Reserved, 0x18-0x1C
			('CMPCR'   , ctypes.c_uint32),      # SYSCFG Compensation cell control register,         Address offset: 0x20
		]