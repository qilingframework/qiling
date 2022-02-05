#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.intc.stm32f4xx_exti import STM32F4xxExti


class STM32F1xxExti(STM32F4xxExti):
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
            ("IMR"  , ctypes.c_uint32),
            ("EMR"  , ctypes.c_uint32),
            ("RTSR" , ctypes.c_uint32),
            ("FTSR" , ctypes.c_uint32),
            ("SWIER", ctypes.c_uint32),
            ("PR"   , ctypes.c_uint32),
        ]
