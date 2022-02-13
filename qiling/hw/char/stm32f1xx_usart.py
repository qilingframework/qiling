import ctypes

from qiling.hw.char.stm32f4xx_usart import STM32F4xxUsart


class STM32F1xxUsart(STM32F4xxUsart):
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
            ("SR"  , ctypes.c_uint32), #USART Status register,                   Address offset: 0x00
            ("DR"  , ctypes.c_uint32), #USART Data register,                     Address offset: 0x04
            ("BRR" , ctypes.c_uint32), #USART Baud rate register,                Address offset: 0x08
            ("CR1" , ctypes.c_uint32), #USART Control register 1,                Address offset: 0x0C
            ("CR2" , ctypes.c_uint32), #USART Control register 2,                Address offset: 0x10
            ("CR3" , ctypes.c_uint32), #USART Control register 3,                Address offset: 0x14
            ("GTPR", ctypes.c_uint32), #USART Guard time and prescaler register, Address offset: 0x18
        ]
