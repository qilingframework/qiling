#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

stm32f417 = {
    "ADC1": {
        "base": 0x40012000,
        "struct": "STM32F4xxAdc",
        "type": "periperal"
    },
    "ADC2": {
        "base": 0x40012100,
        "struct": "STM32F4xxAdc",
        "type": "periperal"
    },
    "ADC3": {
        "base": 0x40012200,
        "struct": "STM32F4xxAdc",
        "type": "periperal"
    },
    "CAN1": {
        "base": 0x40006400,
        "struct": "STM32F4xxCan",
        "kwargs": {
            "rx0_intn": 20,
            "rx1_intn": 21,
            "sce_intn": 22,
            "tx_intn": 19
        },
        "type": "periperal"
    },
    "CAN2": {
        "base": 0x40006800,
        "struct": "STM32F4xxCan",
        "kwargs": {
            "rx0_intn": 64,
            "rx1_intn": 65,
            "sce_intn": 66,
            "tx_intn": 63
        },
        "type": "periperal"
    },
    "CRC": {
        "base": 0x40023000,
        "struct": "STM32F4xxCrc",
        "type": "periperal"
    },
    "CRYP": {
        "base": 0x50060000,
        "struct": "STM32F4xxCryp",
        "kwargs": {
            "intn": 79
        },
        "type": "periperal"
    },
    "DAC1": {
        "base": 0x40007400,
        "struct": "STM32F4xxDac",
        "type": "periperal"
    },
    "DBGMCU": {
        "base": 0xe0042000,
        "struct": "STM32F4xxDbgmcu",
        "type": "periperal"
    },
    "DCMI": {
        "base": 0x50050000,
        "struct": "STM32F4xxDcmi",
        "kwargs": {
            "intn": 78
        },
        "type": "periperal"
    },
    "DMA1": {
        "base": 0x40026000,
        "struct": "STM32F4xxDma",
        "kwargs": {
            "stream0_intn": 11,
            "stream1_intn": 12,
            "stream2_intn": 13,
            "stream3_intn": 14,
            "stream4_intn": 15,
            "stream5_intn": 16,
            "stream6_intn": 17,
            "stream7_intn": 47
        },
        "type": "periperal"
    },
    "DMA2": {
        "base": 0x40026400,
        "struct": "STM32F4xxDma",
        "kwargs": {
            "stream0_intn": 56,
            "stream1_intn": 57,
            "stream2_intn": 58,
            "stream3_intn": 59,
            "stream4_intn": 60,
            "stream5_intn": 68,
            "stream6_intn": 69,
            "stream7_intn": 70
        },
        "type": "periperal"
    },
    "ETH": {
        "base": 0x40028000,
        "struct": "STM32F4xxEth",
        "kwargs": {
            "intn": 61,
            "wkup_intn": 62
        },
        "type": "periperal"
    },
    "EXTI": {
        "base": 0x40013c00,
        "struct": "STM32F4xxExti",
        "type": "periperal"
    },
    "FLASH": {
        "base": 0x8000000,
        "size": 0x100000,
        "type": "memory"
    },
    "FLASH OTP": {
        "base": 0x1fff7800,
        "size": 0x400,
        "type": "memory"
    },
    "GPIOA": {
        "base": 0x40020000,
        "struct": "STM32F4xxGpio",
        "type": "periperal"
    },
    "GPIOB": {
        "base": 0x40020400,
        "struct": "STM32F4xxGpio",
        "type": "periperal"
    },
    "GPIOC": {
        "base": 0x40020800,
        "struct": "STM32F4xxGpio",
        "type": "periperal"
    },
    "GPIOD": {
        "base": 0x40020c00,
        "struct": "STM32F4xxGpio",
        "type": "periperal"
    },
    "GPIOE": {
        "base": 0x40021000,
        "struct": "STM32F4xxGpio",
        "type": "periperal"
    },
    "GPIOF": {
        "base": 0x40021400,
        "struct": "STM32F4xxGpio",
        "type": "periperal"
    },
    "GPIOG": {
        "base": 0x40021800,
        "struct": "STM32F4xxGpio",
        "type": "periperal"
    },
    "GPIOH": {
        "base": 0x40021c00,
        "struct": "STM32F4xxGpio",
        "type": "periperal"
    },
    "GPIOI": {
        "base": 0x40022000,
        "struct": "STM32F4xxGpio",
        "type": "periperal"
    },
    "HASH": {
        "base": 0x50060400,
        "struct": "STM32F4xxHash",
        "kwargs": {
            "rng_intn": 80
        },
        "type": "periperal"
    },
    "I2C1": {
        "base": 0x40005400,
        "struct": "STM32F4xxI2cV1",
        "kwargs": {
            "er_intn": 32,
            "ev_intn": 31
        },
        "type": "periperal"
    },
    "I2C2": {
        "base": 0x40005800,
        "struct": "STM32F4xxI2cV1",
        "kwargs": {
            "er_intn": 34,
            "ev_intn": 33
        },
        "type": "periperal"
    },
    "I2C3": {
        "base": 0x40005c00,
        "struct": "STM32F4xxI2cV1",
        "kwargs": {
            "er_intn": 73,
            "ev_intn": 72
        },
        "type": "periperal"
    },
    "I2S2ext": {
        "base": 0x40003400,
        "struct": "STM32F4xxSpi",
        "type": "periperal"
    },
    "I2S3ext": {
        "base": 0x40004000,
        "struct": "STM32F4xxSpi",
        "type": "periperal"
    },
    "IWDG": {
        "base": 0x40003000,
        "struct": "STM32F4xxIwdg",
        "type": "periperal"
    },
    "NVIC": {
        "base": 0xe000e100,
        "struct": "CortexM4Nvic",
        "type": "core peripheral"
    },
    "PERIP": {
        "base": 0x40000000,
        "size": 0x100000,
        "type": "mmio"
    },
    "PERIP BB": {
        "alias": 0x42000000,
        "base": 0x40000000,
        "size": 0x100000,
        "type": "bitband"
    },
    "PPB": {
        "base": 0xe0000000,
        "size": 0x10000,
        "type": "mmio"
    },
    "PWR": {
        "base": 0x40007000,
        "struct": "STM32F4xxPwr",
        "type": "periperal"
    },
    "RCC": {
        "base": 0x40023800,
        "struct": "STM32F4xxRccV2",
        "kwargs": {
            "intn": 5
        },
        "type": "periperal"
    },
    "RNG": {
        "base": 0x50060800,
        "struct": "STM32F4xxRng",
        "type": "periperal"
    },
    "RTC": {
        "base": 0x40002800,
        "struct": "STM32F4xxRtc",
        "kwargs": {
            "alarm_intn": 41,
            "wkup_intn": 3
        },
        "type": "periperal"
    },
    "SCB": {
        "base": 0xe000ed00,
        "struct": "CortexM4Scb",
        "type": "core peripheral"
    },
    "SDIO": {
        "base": 0x40012c00,
        "struct": "STM32F4xxSdio",
        "kwargs": {
            "intn": 49
        },
        "type": "periperal"
    },
    "SPI1": {
        "base": 0x40013000,
        "struct": "STM32F4xxSpi",
        "kwargs": {
            "intn": 35
        },
        "type": "periperal"
    },
    "SPI2": {
        "base": 0x40003800,
        "struct": "STM32F4xxSpi",
        "kwargs": {
            "intn": 36
        },
        "type": "periperal"
    },
    "SPI3": {
        "base": 0x40003c00,
        "struct": "STM32F4xxSpi",
        "kwargs": {
            "intn": 51
        },
        "type": "periperal"
    },
    "SRAM": {
        "base": 0x20000000,
        "size": 0x20000,
        "type": "memory"
    },
    "SRAM BB": {
        "alias": 0x22000000,
        "base": 0x20000000,
        "size": 0x100000,
        "type": "bitband"
    },
    "SYSCFG": {
        "base": 0x40013800,
        "struct": "STM32F4xxSyscfg",
        "type": "periperal"
    },
    "SYSTEM": {
        "base": 0x1fff0000,
        "size": 0x7800,
        "type": "memory"
    },
    "SYSTICK": {
        "base": 0xe000e010,
        "struct": "CortexM4SysTick",
        "type": "core peripheral"
    },
    "TIM1": {
        "base": 0x40010000,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "brk_tim9_intn": 24,
            "cc_intn": 27,
            "trg_com_tim11_intn": 26,
            "up_tim10_intn": 25
        },
        "type": "periperal"
    },
    "TIM10": {
        "base": 0x40014400,
        "struct": "STM32F4xxTim",
        "type": "periperal"
    },
    "TIM11": {
        "base": 0x40014800,
        "struct": "STM32F4xxTim",
        "type": "periperal"
    },
    "TIM12": {
        "base": 0x40001800,
        "struct": "STM32F4xxTim",
        "type": "periperal"
    },
    "TIM13": {
        "base": 0x40001c00,
        "struct": "STM32F4xxTim",
        "type": "periperal"
    },
    "TIM14": {
        "base": 0x40002000,
        "struct": "STM32F4xxTim",
        "type": "periperal"
    },
    "TIM2": {
        "base": 0x40000000,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "intn": 28
        },
        "type": "periperal"
    },
    "TIM3": {
        "base": 0x40000400,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "intn": 29
        },
        "type": "periperal"
    },
    "TIM4": {
        "base": 0x40000800,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "intn": 30
        },
        "type": "periperal"
    },
    "TIM5": {
        "base": 0x40000c00,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "intn": 50
        },
        "type": "periperal"
    },
    "TIM6": {
        "base": 0x40001000,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "dac_intn": 54
        },
        "type": "periperal"
    },
    "TIM7": {
        "base": 0x40001400,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "intn": 55
        },
        "type": "periperal"
    },
    "TIM8": {
        "base": 0x40010400,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "brk_tim12_intn": 43,
            "cc_intn": 46,
            "trg_com_tim14_intn": 45,
            "up_tim13_intn": 44
        },
        "type": "periperal"
    },
    "TIM9": {
        "base": 0x40014000,
        "struct": "STM32F4xxTim",
        "type": "periperal"
    },
    "UART4": {
        "base": 0x40004c00,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 52
        },
        "type": "periperal"
    },
    "UART5": {
        "base": 0x40005000,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 53
        },
        "type": "periperal"
    },
    "USART1": {
        "base": 0x40011000,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 37
        },
        "type": "periperal"
    },
    "USART2": {
        "base": 0x40004400,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 38
        },
        "type": "periperal"
    },
    "USART3": {
        "base": 0x40004800,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 39
        },
        "type": "periperal"
    },
    "USART6": {
        "base": 0x40011400,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 71
        },
        "type": "periperal"
    },
    "WWDG": {
        "base": 0x40002c00,
        "struct": "STM32F4xxWwdg",
        "kwargs": {
            "intn": 0
        },
        "type": "periperal"
    }
}