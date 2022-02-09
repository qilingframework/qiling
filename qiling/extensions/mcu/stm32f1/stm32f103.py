#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

stm32f103 = {
    "SRAM BB": {
        "alias": 0x22000000,
        "base": 0x20000000,
        "size": 0x100000,
        "type": "bitband"
    },
    "PERIP BB": {
        "alias": 0x42000000,
        "base": 0x40000000,
        "size": 0x100000,
        "type": "bitband"
    },
    "SYSTICK": {
        "base": 0xe000e010,
        "struct": "CortexM3SysTick",
        "type": "core"
    },
    "NVIC": {
        "base": 0xe000e100,
        "struct": "CortexM3Nvic",
        "type": "core"
    },
    "SCB": {
        "base": 0xe000ed00,
        "struct": "CortexM3Scb",
        "type": "core"
    },
    "FLASH": {
        "base": 0x8000000,
        "size": 0x20000,
        "type": "memory"
    },
    "SYSTEM": {
        "base": 0x1ffff000,
        "size": 0x1000,
        "type": "memory"
    },
    "SRAM": {
        "base": 0x20000000,
        "size": 0x5000,
        "type": "memory"
    },
    "PERIP": {
        "base": 0x40000000,
        "size": 0x100000,
        "type": "mmio"
    },
    "PPB": {
        "base": 0xe0000000,
        "size": 0x100000,
        "type": "mmio"
    },
    "TIM2": {
        "type": "peripheral",
        "base": 0x40000000,
        "struct": "STM32F1xxTim",
        "kwargs": {
            "intn": 0x1c
        }
    },
    "TIM3": {
        "type": "peripheral",
        "base": 0x40000400,
        "struct": "STM32F1xxTim",
        "kwargs": {
            "intn": 0x1d
        }
    },
    "TIM4": {
        "type": "peripheral",
        "base": 0x40000800,
        "struct": "STM32F1xxTim",
        "kwargs": {
            "intn": 0x1e
        }
    },
    "RTC": {
        "type": "peripheral",
        "base": 0x40002800,
        "struct": "STM32F1xxRtc",
        "kwargs": {
            "intn": 0x3,
            "alarm_intn": 0x29
        }
    },
    "WWDG": {
        "type": "peripheral",
        "base": 0x40002c00,
        "struct": "STM32F1xxWwdg",
        "kwargs": {
            "intn": 0x0
        }
    },
    "IWDG": {
        "type": "peripheral",
        "base": 0x40003000,
        "struct": "STM32F1xxIwdg"
    },
    "SPI2": {
        "type": "peripheral",
        "base": 0x40003800,
        "struct": "STM32F1xxSpi",
        "kwargs": {
            "intn": 0x24
        }
    },
    "USART2": {
        "type": "peripheral",
        "base": 0x40004400,
        "struct": "STM32F1xxUsart",
        "kwargs": {
            "intn": 0x26
        }
    },
    "USART3": {
        "type": "peripheral",
        "base": 0x40004800,
        "struct": "STM32F1xxUsart",
        "kwargs": {
            "intn": 0x27
        }
    },
    "I2C1": {
        "type": "peripheral",
        "base": 0x40005400,
        "struct": "STM32F1xxI2c",
        "kwargs": {
            "ev_intn": 0x1f,
            "er_intn": 0x20
        }
    },
    "I2C2": {
        "type": "peripheral",
        "base": 0x40005800,
        "struct": "STM32F1xxI2c",
        "kwargs": {
            "ev_intn": 0x21,
            "er_intn": 0x22
        }
    },
    "USB": {
        "type": "peripheral",
        "base": 0x40005c00,
        "struct": "STM32F1xxUsb",
        "kwargs": {
            "hp_can1_tx_intn": 0x13,
            "lp_can1_rx0_intn": 0x14,
            "hp_intn": 0x13,
            "lp_intn": 0x14
        }
    },
    "CAN1": {
        "type": "peripheral",
        "base": 0x40006400,
        "struct": "STM32F1xxCan",
        "kwargs": {
            "rx1_intn": 0x15,
            "sce_intn": 0x16,
            "tx_intn": 0x13,
            "rx0_intn": 0x14
        }
    },
    "BKP": {
        "type": "peripheral",
        "base": 0x40006c00,
        "struct": "STM32F1xxBkp"
    },
    "PWR": {
        "type": "peripheral",
        "base": 0x40007000,
        "struct": "STM32F1xxPwr"
    },
    "AFIO": {
        "type": "peripheral",
        "base": 0x40010000,
        "struct": "STM32F1xxAfio"
    },
    "EXTI": {
        "type": "peripheral",
        "base": 0x40010400,
        "struct": "STM32F1xxExti",
        "kwargs": {
            "exti0_intn": 6,
            "exti1_intn": 7,
            "exti2_intn": 8,
            "exti3_intn": 9,
            "exti4_intn": 10,
            "exti9_5_intn": 23,
            "exti15_10_intn": 40,
        }
    },
    "GPIOA": {
        "type": "peripheral",
        "base": 0x40010800,
        "struct": "STM32F1xxGpio"
    },
    "GPIOB": {
        "type": "peripheral",
        "base": 0x40010c00,
        "struct": "STM32F1xxGpio"
    },
    "GPIOC": {
        "type": "peripheral",
        "base": 0x40011000,
        "struct": "STM32F1xxGpio"
    },
    "GPIOD": {
        "type": "peripheral",
        "base": 0x40011400,
        "struct": "STM32F1xxGpio"
    },
    "GPIOE": {
        "type": "peripheral",
        "base": 0x40011800,
        "struct": "STM32F1xxGpio"
    },
    "ADC1": {
        "type": "peripheral",
        "base": 0x40012400,
        "struct": "STM32F1xxAdc",
        "kwargs": {
            "intn": 0x12
        }
    },
    "ADC2": {
        "type": "peripheral",
        "base": 0x40012800,
        "struct": "STM32F1xxAdc"
    },
    "TIM1": {
        "type": "peripheral",
        "base": 0x40012c00,
        "struct": "STM32F1xxTim",
        "kwargs": {
            "brk_intn": 0x18,
            "up_intn": 0x19,
            "trg_com_intn": 0x1a,
            "cc_intn": 0x1b,
            "brk_tim15_intn": 0x18,
            "brk_tim9_intn": 0x18,
            "trg_com_tim17_intn": 0x1a,
            "trg_com_tim11_intn": 0x1a,
            "up_tim16_intn": 0x19,
            "up_tim10_intn": 0x19
        }
    },
    "SPI1": {
        "type": "peripheral",
        "base": 0x40013000,
        "struct": "STM32F1xxSpi",
        "kwargs": {
            "intn": 0x23
        }
    },
    "USART1": {
        "type": "peripheral",
        "base": 0x40013800,
        "struct": "STM32F1xxUsart",
        "kwargs": {
            "intn": 0x25
        }
    },
    "DMA1": {
        "type": "peripheral",
        "base": 0x40020000,
        "struct": "STM32F1xxDma",
        "kwargs": {
            "stream0_intn": 0xb,
            "stream1_intn": 0xc,
            "stream2_intn": 0xd,
            "stream3_intn": 0xe,
            "stream4_intn": 0xf,
            "stream5_intn": 0x10,
            "stream6_intn": 0x11,
            "stream7_intn": 0x2f
        },
    },
    "RCC": {
        "type": "peripheral",
        "base": 0x40021000,
        "struct": "STM32F1xxRcc",
        "kwargs": {
            "intn": 0x5
        }
    },
    "FLASH INTERFACE": {
        "type": "peripheral",
        "base": 0x40022000,
        "struct": "STM32F1xxFlash",
        "kwargs": {
            "intn": 0x4
        }
    },
    "CRC": {
        "type": "peripheral",
        "base": 0x40023000,
        "struct": "STM32F1xxCrc"
    },
    "DBGMCU": {
        "type": "peripheral",
        "base": 0xe0042000,
        "struct": "STM32F1xxDbgmcu"
    },
    "CODE": {
        "base": 0x8000000,
        "size": 0x80000,
        "alias": 0x0,
        "type": "remap"
    }
}