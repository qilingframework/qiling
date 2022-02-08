#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral


class STM32F1xxExti(QlPeripheral):
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

    def __init__(self, ql, label, 
        exti0_intn = None,
        exti1_intn = None,
        exti2_intn = None,
        exti3_intn = None,
        exti4_intn = None,
        exti9_5_intn = None,
        exti15_10_intn = None,
    ):
        super().__init__(ql, label)

        self.exti = self.struct()
        self.intn = [
            exti0_intn    , exti1_intn    , exti2_intn    , exti3_intn,
            exti4_intn    , exti9_5_intn  , exti9_5_intn  , exti9_5_intn,
            exti9_5_intn  , exti9_5_intn  , exti15_10_intn, exti15_10_intn,
            exti15_10_intn, exti15_10_intn, exti15_10_intn, exti15_10_intn
        ]
    
    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:		
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.exti) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        if offset == self.struct.SWIER.offset:
            value = value & self.exti.IMR & 0x7ffff
            for i in range(20):
                if ((self.exti.SWIER >> i) & 1) == 0 and ((value >> i) & 1) == 1:
                    self.send_interrupt(i)
        
        elif offset == self.struct.PR.offset:
            for i in range(20):
                if (value >> i) & 1:
                    self.exti.PR &= ~(1 << i)
                    self.exti.SWIER &= ~(1 << i)

            return

        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.exti) + offset, data, size)

    def send_interrupt(self, index):
        if 0 <= index < 20 and (self.exti.IMR >> index) & 1:
            self.exti.PR |= 1 << index

            if index < 16:
                self.ql.hw.afio.exti(index).set_pin(index)
                self.ql.hw.nvic.set_pending(self.intn[index])
