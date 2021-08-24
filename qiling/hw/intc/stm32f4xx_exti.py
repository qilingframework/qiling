#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.hw.peripheral import QlPeripheral


class STM32F4xxExti(QlPeripheral):
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
			('IMR'  , ctypes.c_uint32),  # EXTI Interrupt mask register,            Address offset: 0x00
			('EMR'  , ctypes.c_uint32),  # EXTI Event mask register,                Address offset: 0x04
			('RTSR' , ctypes.c_uint32),  # EXTI Rising trigger selection register,  Address offset: 0x08
			('FTSR' , ctypes.c_uint32),  # EXTI Falling trigger selection register, Address offset: 0x0C
			('SWIER', ctypes.c_uint32),  # EXTI Software interrupt event register,  Address offset: 0x10
			('PR'   , ctypes.c_uint32),  # EXTI Pending register,                   Address offset: 0x14
        ]
