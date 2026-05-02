#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.core import Qiling
from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.stm32f4xx_pwr import PWR_CR, PWR_CSR


class STM32F4xxPwr(QlPeripheral):
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
            ('CR' , ctypes.c_uint32),  # PWR power control register,        Address offset: 0x00
            ('CSR', ctypes.c_uint32),  # PWR power control/status register, Address offset: 0x04
        ]

    def __init__(self, ql: Qiling, label: str):
        super().__init__(ql, label)

        self.instance = self.struct()

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        if offset == self.struct.CR.offset:
            if value & PWR_CR.ODEN:
                self.instance.CSR |= PWR_CSR.ODRDY
            if value & PWR_CR.ODSWEN:
                self.instance.CSR |= PWR_CSR.ODSWRDY

        self.raw_write(offset, size, value)