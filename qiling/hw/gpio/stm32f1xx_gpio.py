#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.gpio.hooks import GpioHooks


class STM32F1xxGpio(QlPeripheral, GpioHooks):
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
            ("CRL" , ctypes.c_uint32),
            ("CRH" , ctypes.c_uint32),
            ("IDR" , ctypes.c_uint32),
            ("ODR" , ctypes.c_uint32),
            ("BSRR", ctypes.c_uint32),
            ("BRR" , ctypes.c_uint32),
            ("LCKR", ctypes.c_uint32),
        ]

    def __init__(self, ql, label):
        QlPeripheral.__init__(self, ql, label)
        GpioHooks.__init__(self, ql, 16)

        self.gpio = self.struct()
