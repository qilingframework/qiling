#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes


from qiling.hw.peripheral import QlPeripheral
from .stm32f4xx_i2c import STM32F4xxI2c


class STM32F1xxI2c(STM32F4xxI2c):
    class Type(ctypes.Structure):
        """ the structure available in :
                stm32f100xb
                stm32f100xe
                stm32f101xb
                stm32f101xe
                stm32f101xg
                stm32f102xb
                stm32f103xb
                stm32f103xe
                stm32f103xg
                stm32f105xc
                stm32f107xc
        """

        _fields_ = [
            ("CR1"  , ctypes.c_uint32),
            ("CR2"  , ctypes.c_uint32),
            ("OAR1" , ctypes.c_uint32),
            ("OAR2" , ctypes.c_uint32),
            ("DR"   , ctypes.c_uint32),
            ("SR1"  , ctypes.c_uint32),
            ("SR2"  , ctypes.c_uint32),
            ("CCR"  , ctypes.c_uint32),
            ("TRISE", ctypes.c_uint32),
        ]
