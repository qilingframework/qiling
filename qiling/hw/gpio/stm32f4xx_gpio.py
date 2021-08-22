import ctypes

from enum import IntEnum
from qiling.hw.gpio.gpio import BaseGPIO


class STM32F4xxGpio(BaseGPIO):
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

    def __init__(self, ql, tag, **kwargs):
        super().__init__(ql, tag, **kwargs)

        self.gpio = self.struct()

        self.mode_reset = 0x00, 
        self.ospeed_reset = 0x00,
        self.pupd_reset = 0x00

        mode_value = kwargs.get('mode_reset', None)
        ospeed_value = kwargs.get('ospeed_reset', None)
        pupd_value = kwargs.get('pupd_reset', None)

        if mode_value:
            self.gpio.MODER = mode_value
        if ospeed_value:
            self.gpio.OSPEEDR = ospeed_value
        if pupd_value:
            self.gpio.OSPEEDR = ospeed_value            

        self.reset()

    def read(self, offset, size):
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.gpio) + offset, size)
        data = int.from_bytes(buf.raw, byteorder='little')
        mock_data = self.mock_read(offset)
        if mock_data != data:
            self.ql.log.warning(f'[{self.tag}] mock_data {hex(mock_data)} != data {hex(data)} when read {hex(offset)}')
            # data = mock_data
        self.ql.log.warning(f'[{self.tag}] Read [{hex(self.ql.hw._region[self.tag][0][0] + offset)}] = {hex(data)}')
        return data

    def mock_read(self, offset:int) -> int:
        val = 0
        if offset == self.struct.MODER.offset:
            val = self.gpiox_mode
        elif offset == self.struct.OTYPER.offset:
            val = self.gpiox_otyper
        elif offset == self.struct.OSPEEDR.offset:
            val = self.gpiox_ospeedr
        elif offset == self.struct.PUPDR.offset:
            val = self.gpiox_pupdr
        elif offset == self.struct.IDR.offset:
            value = 0
            for i in len(self.states):
                if self.states[i]:
                    value |= 1 << i
            val = value
        elif offset == self.struct.ODR.offset:
            val = self.gpiox_odr
        elif offset == self.struct.BSRR.offset:
            val = self.gpiox_bsrr
        elif offset == self.struct.LCKR.offset:
            val = self.gpiox_lckr
        elif offset == self.struct.AFRL.offset:
            val = self.gpiox_afrl
        elif offset == self.struct.AFRH.offset:
            val = self.gpiox_afrh
        else:
            raise

        return val

    def write(self, offset, size, value):
        self.mock_write(offset, value)

        for ofs in range(offset, offset + size):
            data = (value & 0xff).to_bytes(size, byteorder='little')
            ctypes.memmove(ctypes.addressof(self.gpio) + ofs, data, 1)
            value >>= 8
        
        self.ql.log.warning(f'[{self.tag}] Write [{hex(self.ql.hw._region[self.tag][0][0] + offset)}] = {hex(value)}')

    def mock_write(self, offset:int, value:int):
        if offset == self.struct.MODER.offset:
            self.gpiox_mode = value
        elif offset == self.struct.OTYPER.offset:
            self.gpiox_otyper = value
        elif offset == self.struct.OSPEEDR.offset:
            self.gpiox_ospeedr = value
        elif offset == self.struct.PUPDR.offset:
            self.gpiox_pupdr = value
        elif offset == self.struct.IDR.offset:
            pass
        elif offset == self.struct.ODR.offset:
            self.gpiox_odr = value
            #TODO
        elif offset == self.struct.BSRR.offset:
            self.gpiox_bsrr = value
            #TODO
        elif offset == self.struct.LCKR.offset:
            self.gpiox_lckr = value
        elif offset == self.struct.AFRL.offset:
            self.gpiox_afrl = value
        elif offset == self.struct.AFRH.offset:
            self.gpiox_afrh = value
        else:
            raise

    def reset(self):
        super().reset()
        self.gpiox_mode = self.mode_reset
        self.gpiox_otyper = 0
        self.gpiox_ospeedr = self.ospeed_reset
        self.gpiox_pupdr = self.pupd_reset
        self.gpiox_odr = 0
        self.gpiox_bsrr = 0
        self.gpiox_lckr = 0
        self.gpiox_afrl = 0
        self.gpiox_afrh = 0


