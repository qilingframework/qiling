#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.gpio.stm32f1xx_gpio import STM32F1xxGpio
from qiling.hw.peripheral import QlPeripheral
from qiling.hw.gpio.hooks import GpioHooks


class STM32F4xxGpio(STM32F1xxGpio):
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
            ('MODER'  , ctypes.c_uint32),      # GPIO port mode register,               Address offset: 0x00
            ('OTYPER' , ctypes.c_uint32),      # GPIO port output type register,        Address offset: 0x04
            ('OSPEEDR', ctypes.c_uint32),      # GPIO port output speed register,       Address offset: 0x08
            ('PUPDR'  , ctypes.c_uint32),      # GPIO port pull-up/pull-down register,  Address offset: 0x0C
            ('IDR'    , ctypes.c_uint32),      # GPIO port input data register,         Address offset: 0x10
            ('ODR'    , ctypes.c_uint32),      # GPIO port output data register,        Address offset: 0x14
            ('BSRR'   , ctypes.c_uint32),      # GPIO port bit set/reset register,      Address offset: 0x18
            ('LCKR'   , ctypes.c_uint32),      # GPIO port configuration lock register, Address offset: 0x1C
            ('AFRL'   , ctypes.c_uint32),      # GPIO alternate function registers,     Address offset: 0x20-0x24
            ('AFRH'   , ctypes.c_uint32),      # GPIO alternate function registers,     Address offset: 0x20-0x24
        ]

    def __init__(self, ql, label, 
            moder_reset   = 0x00, 
            ospeedr_reset = 0x00,
            pupdr_reset    = 0x00
        ):
        QlPeripheral.__init__(self, ql, label)
        GpioHooks.__init__(self, ql, 16)

        self.gpio = self.struct(
            MODER   = moder_reset,
            OSPEEDR = ospeedr_reset,
            PUPDR   = pupdr_reset,
        )        
