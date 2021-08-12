import ctypes

from enum import IntEnum
from qiling.hw.gpio.gpio import BaseGPIO


class GPIOx(IntEnum):
    MODE      = 0x00  # GPIO port mode register - Read-Write
    OTYPER    = 0x04  # GPIO port output type register - Read-Write
    OSPEEDR   = 0x08  # GPIO port output speed register - Read-Write
    PUPDR     = 0x0C  # GPIO port pull-up/pull-down register - Read-Write
    IDR       = 0x10  # GPIO port input data register - Read-only
    ODR       = 0x14  # GPIO port output data register - Read-Write
    BSRR      = 0x18  # GPIO port bit set/reset register - Write-Only
    LCKR      = 0x1C  # GPIO port configuration lock register - Read-Write
    AFRL      = 0x20  # GPIO alternate function low register - Read-Write
    AFRH      = 0x24  # GPIO alternate function high register - Read-Write


class STM32F4GPIO(BaseGPIO):
    class Type(ctypes.Structure):
        _fields_ = [
            ('MODER', ctypes.c_uint32),
            ('OTYPER', ctypes.c_uint32),
            ('OSPEEDR', ctypes.c_uint32),
            ('PUPDR', ctypes.c_uint32),
            ('IDR', ctypes.c_uint32),
            ('ODR', ctypes.c_uint32),
            ('BSRR', ctypes.c_uint32),
            ('LCKR', ctypes.c_uint32),
            ('AFR', ctypes.c_uint32 * 2)
        ]

    def __init__(self, ql, tag, **kwargs):
        super().__init__(ql, tag, **kwargs)

        GPIO_Type = type(self).Type
        self.gpio = GPIO_Type()

        self.mode_reset = 0x00, 
        self.ospeed_reset = 0x00,
        self.pupd_reset = 0x00

        mode_value = kwargs.get('mode_reset', None)
        ospeed_value = kwargs.get('ospeed_reset', None)
        pupd_value = kwargs.get('pupd_reset', None)

        if mode_value:
            self.mode_reset = mode_value
            self.write(GPIOx.MODE, 4, mode_value)
        if ospeed_value:
            self.ospeed_reset = ospeed_value
            self.write(GPIOx.OSPEEDR, 4, ospeed_value)
        if pupd_value:
            self.pupd_reset = pupd_value
            self.write(GPIOx.PUPDR, 4, pupd_value)

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
        if offset == GPIOx.MODE:
            val = self.gpiox_mode
        elif offset == GPIOx.OTYPER:
            val = self.gpiox_otyper
        elif offset == GPIOx.OSPEEDR:
            val = self.gpiox_ospeedr
        elif offset == GPIOx.PUPDR:
            val = self.gpiox_pupdr
        elif offset == GPIOx.IDR:
            value = 0
            for i in len(self.states):
                if self.states[i]:
                    value |= 1 << i
            val = value
        elif offset == GPIOx.ODR:
            val = self.gpiox_odr
        elif offset == GPIOx.BSRR:
            val = self.gpiox_bsrr
        elif offset == GPIOx.LCKR:
            val = self.gpiox_lckr
        elif offset == GPIOx.AFRL:
            val = self.gpiox_afrl
        elif offset == GPIOx.AFRH:
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
        if offset == GPIOx.MODE:
            self.gpiox_mode = value
        elif offset == GPIOx.OTYPER:
            self.gpiox_otyper = value
        elif offset == GPIOx.OSPEEDR:
            self.gpiox_ospeedr = value
        elif offset == GPIOx.PUPDR:
            self.gpiox_pupdr = value
        elif offset == GPIOx.IDR:
            pass
        elif offset == GPIOx.ODR:
            self.gpiox_odr = value
            #TODO
        elif offset == GPIOx.BSRR:
            self.gpiox_bsrr = value
            #TODO
        elif offset == GPIOx.LCKR:
            self.gpiox_lckr = value
        elif offset == GPIOx.AFRL:
            self.gpiox_afrl = value
        elif offset == GPIOx.AFRH:
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


