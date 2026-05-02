#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class STM32F4xxDac(QlPeripheral):
    class Type(ctypes.Structure):
        """ the structure available in :
                stm32f405xx
                stm32f407xx
                stm32f410cx
                stm32f410rx
                stm32f410tx
                stm32f413xx
                stm32f415xx
                stm32f417xx
                stm32f423xx
                stm32f427xx
                stm32f429xx
                stm32f437xx
                stm32f439xx
                stm32f446xx
                stm32f469xx
                stm32f479xx
        """

        _fields_ = [
            ("CR"     , ctypes.c_uint32), # DAC control register,                                    Address offset: 0x00
            ("SWTRIGR", ctypes.c_uint32), # DAC software trigger register,                           Address offset: 0x04
            ("DHR12R1", ctypes.c_uint32), # DAC channel1 12-bit right-aligned data holding register, Address offset: 0x08
            ("DHR12L1", ctypes.c_uint32), # DAC channel1 12-bit left aligned data holding register,  Address offset: 0x0C
            ("DHR8R1" , ctypes.c_uint32), # DAC channel1 8-bit right aligned data holding register,  Address offset: 0x10
            ("DHR12R2", ctypes.c_uint32), # DAC channel2 12-bit right aligned data holding register, Address offset: 0x14
            ("DHR12L2", ctypes.c_uint32), # DAC channel2 12-bit left aligned data holding register,  Address offset: 0x18
            ("DHR8R2" , ctypes.c_uint32), # DAC channel2 8-bit right-aligned data holding register,  Address offset: 0x1C
            ("DHR12RD", ctypes.c_uint32), # Dual DAC 12-bit right-aligned data holding register,     Address offset: 0x20
            ("DHR12LD", ctypes.c_uint32), # DUAL DAC 12-bit left aligned data holding register,      Address offset: 0x24
            ("DHR8RD" , ctypes.c_uint32), # DUAL DAC 8-bit right aligned data holding register,      Address offset: 0x28
            ("DOR1"   , ctypes.c_uint32), # DAC channel1 data output register,                       Address offset: 0x2C
            ("DOR2"   , ctypes.c_uint32), # DAC channel2 data output register,                       Address offset: 0x30
            ("SR"     , ctypes.c_uint32), # DAC status register,                                     Address offset: 0x34
        ]
