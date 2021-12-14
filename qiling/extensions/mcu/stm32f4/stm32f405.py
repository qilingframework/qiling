#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

stm32f405 = {
    "ADC1": {
        "base": 0x40012000,
        "struct": "STM32F4xxAdc",
        "type": "peripheral"
    },
    "ADC2": {
        "base": 0x40012100,
        "struct": "STM32F4xxAdc",
        "type": "peripheral"
    },
    "ADC3": {
        "base": 0x40012200,
        "struct": "STM32F4xxAdc",
        "type": "peripheral"
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
        "type": "peripheral"
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
        "type": "peripheral"
    },
    "CRC": {
        "base": 0x40023000,
        "struct": "STM32F4xxCrc",
        "type": "peripheral"
    },
    "DAC1": {
        "base": 0x40007400,
        "struct": "STM32F4xxDac",
        "type": "peripheral"
    },
    "DBGMCU": {
        "base": 0xe0042000,
        "struct": "STM32F4xxDbgmcu",
        "kwargs": {
            "dev_id": 0x413,
        },
        "type": "core peripheral"
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
        "type": "peripheral"
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
        "type": "peripheral"
    },
    "EXTI": {
        "base": 0x40013c00,
        "struct": "STM32F4xxExti",
        "type": "peripheral"
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
    "FLASH INTERFACE": {
        "base": 0x40023c00,
        "struct": "STM32F4xxFlash",
        "kwargs": {
            "intn": 4,
        },
        "type": "peripheral"
    },
    "GPIOA": {
        "base": 0x40020000,
        "struct": "STM32F4xxGpio",
        "type": "peripheral"
    },
    "GPIOB": {
        "base": 0x40020400,
        "struct": "STM32F4xxGpio",
        "type": "peripheral"
    },
    "GPIOC": {
        "base": 0x40020800,
        "struct": "STM32F4xxGpio",
        "type": "peripheral"
    },
    "GPIOD": {
        "base": 0x40020c00,
        "struct": "STM32F4xxGpio",
        "type": "peripheral"
    },
    "GPIOE": {
        "base": 0x40021000,
        "struct": "STM32F4xxGpio",
        "type": "peripheral"
    },
    "GPIOF": {
        "base": 0x40021400,
        "struct": "STM32F4xxGpio",
        "type": "peripheral"
    },
    "GPIOG": {
        "base": 0x40021800,
        "struct": "STM32F4xxGpio",
        "type": "peripheral"
    },
    "GPIOH": {
        "base": 0x40021c00,
        "struct": "STM32F4xxGpio",
        "type": "peripheral"
    },
    "GPIOI": {
        "base": 0x40022000,
        "struct": "STM32F4xxGpio",
        "type": "peripheral"
    },
    "I2C1": {
        "base": 0x40005400,
        "struct": "STM32F4xxI2cV1",
        "kwargs": {
            "er_intn": 32,
            "ev_intn": 31
        },
        "type": "peripheral"
    },
    "I2C2": {
        "base": 0x40005800,
        "struct": "STM32F4xxI2cV1",
        "kwargs": {
            "er_intn": 34,
            "ev_intn": 33
        },
        "type": "peripheral"
    },
    "I2C3": {
        "base": 0x40005c00,
        "struct": "STM32F4xxI2cV1",
        "kwargs": {
            "er_intn": 73,
            "ev_intn": 72
        },
        "type": "peripheral"
    },
    "I2S2ext": {
        "base": 0x40003400,
        "struct": "STM32F4xxSpi",
        "type": "peripheral"
    },
    "I2S3ext": {
        "base": 0x40004000,
        "struct": "STM32F4xxSpi",
        "type": "peripheral"
    },
    "IWDG": {
        "base": 0x40003000,
        "struct": "STM32F4xxIwdg",
        "type": "peripheral"
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
        "size": 0x100000,
        "type": "mmio"
    },
    "PWR": {
        "base": 0x40007000,
        "struct": "STM32F4xxPwr",
        "type": "peripheral"
    },
    "RCC": {
        "base": 0x40023800,
        "struct": "STM32F4xxRccV2",
        "kwargs": {
            "intn": 5
        },
        "type": "peripheral"
    },
    "RNG": {
        "base": 0x50060800,
        "struct": "STM32F4xxRng",
        "kwargs": {
            "intn": 80
        },
        "type": "peripheral"
    },
    "RTC": {
        "base": 0x40002800,
        "struct": "STM32F4xxRtc",
        "kwargs": {
            "alarm_intn": 41,
            "wkup_intn": 3
        },
        "type": "peripheral"
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
        "type": "peripheral"
    },
    "SPI1": {
        "base": 0x40013000,
        "struct": "STM32F4xxSpi",
        "kwargs": {
            "intn": 35
        },
        "type": "peripheral"
    },
    "SPI2": {
        "base": 0x40003800,
        "struct": "STM32F4xxSpi",
        "kwargs": {
            "intn": 36
        },
        "type": "peripheral"
    },
    "SPI3": {
        "base": 0x40003c00,
        "struct": "STM32F4xxSpi",
        "kwargs": {
            "intn": 51
        },
        "type": "peripheral"
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
        "type": "peripheral"
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
        "type": "peripheral"
    },
    "TIM10": {
        "base": 0x40014400,
        "struct": "STM32F4xxTim",
        "type": "peripheral"
    },
    "TIM11": {
        "base": 0x40014800,
        "struct": "STM32F4xxTim",
        "type": "peripheral"
    },
    "TIM12": {
        "base": 0x40001800,
        "struct": "STM32F4xxTim",
        "type": "peripheral"
    },
    "TIM13": {
        "base": 0x40001c00,
        "struct": "STM32F4xxTim",
        "type": "peripheral"
    },
    "TIM14": {
        "base": 0x40002000,
        "struct": "STM32F4xxTim",
        "type": "peripheral"
    },
    "TIM2": {
        "base": 0x40000000,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "intn": 28
        },
        "type": "peripheral"
    },
    "TIM3": {
        "base": 0x40000400,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "intn": 29
        },
        "type": "peripheral"
    },
    "TIM4": {
        "base": 0x40000800,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "intn": 30
        },
        "type": "peripheral"
    },
    "TIM5": {
        "base": 0x40000c00,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "intn": 50
        },
        "type": "peripheral"
    },
    "TIM6": {
        "base": 0x40001000,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "dac_intn": 54
        },
        "type": "peripheral"
    },
    "TIM7": {
        "base": 0x40001400,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "intn": 55
        },
        "type": "peripheral"
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
        "type": "peripheral"
    },
    "TIM9": {
        "base": 0x40014000,
        "struct": "STM32F4xxTim",
        "type": "peripheral"
    },
    "UART4": {
        "base": 0x40004c00,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 52
        },
        "type": "peripheral"
    },
    "UART5": {
        "base": 0x40005000,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 53
        },
        "type": "peripheral"
    },
    "USART1": {
        "base": 0x40011000,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 37
        },
        "type": "peripheral"
    },
    "USART2": {
        "base": 0x40004400,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 38
        },
        "type": "peripheral"
    },
    "USART3": {
        "base": 0x40004800,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 39
        },
        "type": "peripheral"
    },
    "USART6": {
        "base": 0x40011400,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 71
        },
        "type": "peripheral"
    },
    "WWDG": {
        "base": 0x40002c00,
        "struct": "STM32F4xxWwdg",
        "kwargs": {
            "intn": 0
        },
        "type": "peripheral"
    }
}