#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

stm32f410 = {
    "ADC1": {
        "base": 0x40012000,
        "struct": "STM32F4xxAdc",
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
    "CODE": {
        "base": 0x08000000,
        "size": 0x20000,
        "alias": 0x0,
        "type": "remap"
    }, 
    "FLASH": {
        "base": 0x08000000,
        "size": 0x20000,
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
    "FMPI2C1": {
        "base": 0x40006000,
        "struct": "STM32F4xxFmpi2c",
        "kwargs": {
            "er_intn": 96,
            "ev_intn": 95
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
    "GPIOH": {
        "base": 0x40021c00,
        "struct": "STM32F4xxGpio",
        "type": "peripheral"
    },
    "I2C1": {
        "base": 0x40005400,
        "struct": "STM32F4xxI2c",
        "kwargs": {
            "er_intn": 32,
            "ev_intn": 31
        },
        "type": "peripheral"
    },
    "I2C2": {
        "base": 0x40005800,
        "struct": "STM32F4xxI2c",
        "kwargs": {
            "er_intn": 34,
            "ev_intn": 33
        },
        "type": "peripheral"
    },
    "IWDG": {
        "base": 0x40003000,
        "struct": "STM32F4xxIwdg",
        "type": "peripheral"
    },
    "LPTIM1": {
        "base": 0x40002400,
        "struct": "STM32F4xxLptim",
        "kwargs": {
            "intn": 97
        },
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
        "struct": "STM32F4xxRccV4",
        "kwargs": {
            "intn": 5
        },
        "type": "peripheral"
    },
    "RNG": {
        "base": 0x40080000,
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
    "SPI5": {
        "base": 0x40015000,
        "struct": "STM32F4xxSpi",
        "kwargs": {
            "intn": 85
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
        "struct": "STM32F4xxSyscfgV2",
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
            "up_intn": 25
        },
        "type": "peripheral"
    },
    "TIM11": {
        "base": 0x40014800,
        "struct": "STM32F4xxTim",
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
    "TIM9": {
        "base": 0x40014000,
        "struct": "STM32F4xxTim",
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