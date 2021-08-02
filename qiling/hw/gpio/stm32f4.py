from enum import Enum
from qiling.hw.peripheral import QlPeripheral


class Register(Enum):
    GPIOx_MODE      = 0x00  # GPIO port mode register - Read-Write
    GPIOx_OTYPER    = 0x04  # GPIO port output type register - Read-Write
    GPIOx_OSPEEDR   = 0x08  # GPIO port output speed register - Read-Write
    GPIOx_PUPDR     = 0x0C  # GPIO port pull-up/pull-down register - Read-Write
    GPIOx_IDR       = 0x10  # GPIO port input data register - Read-only
    GPIOx_ODR       = 0x14  # GPIO port output data register - Read-Write
    GPIOx_BSRR      = 0x18  # GPIO port bit set/reset register - Write-Only
    GPIOx_LCKR      = 0x1C  # GPIO port configuration lock register - Read-Write
    GPIOx_AFRL      = 0x20  # GPIO alternate function low register - Read-Write
    GPIOx_AFRH      = 0x24  # GPIO alternate function high register - Read-Write


class STM32F4GPIO(QlPeripheral):
    def __init__(self, ql, tag, **kwargs):
        super().__init__(ql, tag, **kwargs)
        self.mode_reset = 0x00, 
        self.ospeed_reset = 0x00,
        self.pupd_reset = 0x00

        mode_value = kwargs.get('mode_reset', None)
        ospeed_value = kwargs.get('ospeed_reset', None)
        pupd_value = kwargs.get('pupd_reset', None)

        if mode_value:
            self.mode_reset = mode_value
        if ospeed_value:
            self.ospeed_reset = ospeed_value
        if pupd_value:
            self.ospeed_reset = pupd_value

        self.base_addr = self.ql.hw.base_addr(tag)

        self.create_gpiox_registers()


    def create_gpiox_registers(self):
        self.add_register(self.base_addr, 0x00, 'MODER', self.mode_reset)


