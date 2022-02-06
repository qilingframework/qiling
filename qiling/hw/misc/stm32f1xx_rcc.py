#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.stm32fxxx_rcc import RCC_CR, RCC_CFGR, RCC_CSR


class STM32F1xxRcc(QlPeripheral):
    class Type(ctypes.Structure):
        """ the structure is available in :
                stm32f101xb
                stm32f101xe
                stm32f101xg
                stm32f102xb
                stm32f103xb
                stm32f103xe
                stm32f103xg
        """

        _fields_ = [
            ("CR"      , ctypes.c_uint32),
            ("CFGR"    , ctypes.c_uint32),
            ("CIR"     , ctypes.c_uint32),
            ("APB2RSTR", ctypes.c_uint32),
            ("APB1RSTR", ctypes.c_uint32),
            ("AHBENR"  , ctypes.c_uint32),
            ("APB2ENR" , ctypes.c_uint32),
            ("APB1ENR" , ctypes.c_uint32),
            ("BDCR"    , ctypes.c_uint32),
            ("CSR"     , ctypes.c_uint32),
        ]
    
    def __init__(self, ql, label, intn=None):
        super().__init__(ql, label)

        self.rcc = self.struct(
            CR     = 0x00000083,
            AHBENR = 0x00000014,
            CSR    = 0x0C000000,
        )

        self.rdyon = {
			'CR': [
				(RCC_CR.HSIRDY   , RCC_CR.HSION   ),
				(RCC_CR.HSERDY   , RCC_CR.HSEON   ),
				(RCC_CR.PLLRDY   , RCC_CR.PLLON   ),
				(RCC_CR.PLLI2SRDY, RCC_CR.PLLI2SON),
			],
			'CFGR': [
				(RCC_CFGR.SWS_0, RCC_CFGR.SW_0),
				(RCC_CFGR.SWS_1, RCC_CFGR.SW_1),
			],
			'CSR': [
				(RCC_CSR.LSIRDY, RCC_CSR.LSION)
			]
		}

        self.intn = intn

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:		
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.rcc) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.rcc) + offset, data, size)

    def step(self):
        for reg, rdyon in self.rdyon.items():
            value = getattr(self.rcc, reg)
            for rdy, on in rdyon:
                if value & on:
                    value |= rdy
                else:
                    value &= ~rdy
            setattr(self.rcc, reg, value)
