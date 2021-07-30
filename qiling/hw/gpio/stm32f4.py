from enum import Enum


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


# class 


