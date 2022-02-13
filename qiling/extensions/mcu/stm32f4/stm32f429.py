#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

stm32f429 = {
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
        "struct": "CortexM4SysTick",
        "type": "core"
    },
    "NVIC": {
        "base": 0xe000e100,
        "struct": "CortexM4Nvic",
        "type": "core"
    },
    "SCB": {
        "base": 0xe000ed00,
        "struct": "CortexM4Scb",
        "type": "core"
    },
    "FLASH": {
        "base": 0x8000000,
        "size": 0x200000,
        "type": "memory"
    },
    "SYSTEM": {
        "base": 0x1fff0000,
        "size": 0x7800,
        "type": "memory"
    },
    "FLASH OTP": {
        "base": 0x1fff7800,
        "size": 0x400,
        "type": "memory"
    },
    "SRAM": {
        "base": 0x20000000,
        "size": 0x20000,
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
        "base": 0x40000000,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "intn": 0x1c
        },
        "type": "peripheral"
    },
    "TIM3": {
        "base": 0x40000400,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "intn": 0x1d
        },
        "type": "peripheral"
    },
    "TIM4": {
        "base": 0x40000800,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "intn": 0x1e
        },
        "type": "peripheral"
    },
    "TIM5": {
        "base": 0x40000c00,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "intn": 0x32
        },
        "type": "peripheral"
    },
    "TIM6": {
        "base": 0x40001000,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "dac_intn": 0x36
        },
        "type": "peripheral"
    },
    "TIM7": {
        "base": 0x40001400,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "intn": 0x37
        },
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
    "RTC": {
        "base": 0x40002800,
        "struct": "STM32F4xxRtc",
        "kwargs": {
            "alarm_intn": 0x29,
            "wkup_intn": 0x3
        },
        "type": "peripheral"
    },
    "WWDG": {
        "base": 0x40002c00,
        "struct": "STM32F4xxWwdg",
        "kwargs": {
            "intn": 0x0
        },
        "type": "peripheral"
    },
    "IWDG": {
        "base": 0x40003000,
        "struct": "STM32F4xxIwdg",
        "type": "peripheral"
    },
    "I2S2ext": {
        "base": 0x40003400,
        "struct": "STM32F4xxSpi",
        "type": "peripheral"
    },
    "SPI2": {
        "base": 0x40003800,
        "struct": "STM32F4xxSpi",
        "kwargs": {
            "intn": 0x24
        },
        "type": "peripheral"
    },
    "SPI3": {
        "base": 0x40003c00,
        "struct": "STM32F4xxSpi",
        "kwargs": {
            "intn": 0x33
        },
        "type": "peripheral"
    },
    "I2S3ext": {
        "base": 0x40004000,
        "struct": "STM32F4xxSpi",
        "type": "peripheral"
    },
    "USART2": {
        "base": 0x40004400,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 0x26
        },
        "type": "peripheral"
    },
    "USART3": {
        "base": 0x40004800,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 0x27
        },
        "type": "peripheral"
    },
    "UART4": {
        "base": 0x40004c00,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 0x34
        },
        "type": "peripheral"
    },
    "UART5": {
        "base": 0x40005000,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 0x35
        },
        "type": "peripheral"
    },
    "I2C1": {
        "base": 0x40005400,
        "struct": "STM32F4xxI2c",
        "kwargs": {
            "er_intn": 0x20,
            "ev_intn": 0x1f
        },
        "type": "peripheral"
    },
    "I2C2": {
        "base": 0x40005800,
        "struct": "STM32F4xxI2c",
        "kwargs": {
            "er_intn": 0x22,
            "ev_intn": 0x21
        },
        "type": "peripheral"
    },
    "I2C3": {
        "base": 0x40005c00,
        "struct": "STM32F4xxI2c",
        "kwargs": {
            "er_intn": 0x49,
            "ev_intn": 0x48
        },
        "type": "peripheral"
    },
    "CAN1": {
        "base": 0x40006400,
        "struct": "STM32F4xxCan",
        "kwargs": {
            "rx0_intn": 0x14,
            "rx1_intn": 0x15,
            "sce_intn": 0x16,
            "tx_intn": 0x13
        },
        "type": "peripheral"
    },
    "CAN2": {
        "base": 0x40006800,
        "struct": "STM32F4xxCan",
        "kwargs": {
            "rx0_intn": 0x40,
            "rx1_intn": 0x41,
            "sce_intn": 0x42,
            "tx_intn": 0x3f
        },
        "type": "peripheral"
    },
    "PWR": {
        "base": 0x40007000,
        "struct": "STM32F4xxPwr",
        "type": "peripheral"
    },
    "DAC1": {
        "base": 0x40007400,
        "struct": "STM32F4xxDac",
        "type": "peripheral"
    },
    "UART7": {
        "base": 0x40007800,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 0x52
        },
        "type": "peripheral"
    },
    "UART8": {
        "base": 0x40007c00,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 0x53
        },
        "type": "peripheral"
    },
    "TIM1": {
        "base": 0x40010000,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "brk_tim9_intn": 0x18,
            "cc_intn": 0x1b,
            "trg_com_tim11_intn": 0x1a,
            "up_tim10_intn": 0x19
        },
        "type": "peripheral"
    },
    "TIM8": {
        "base": 0x40010400,
        "struct": "STM32F4xxTim",
        "kwargs": {
            "brk_tim12_intn": 0x2b,
            "cc_intn": 0x2e,
            "trg_com_tim14_intn": 0x2d,
            "up_tim13_intn": 0x2c
        },
        "type": "peripheral"
    },
    "USART1": {
        "base": 0x40011000,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 0x25
        },
        "type": "peripheral"
    },
    "USART6": {
        "base": 0x40011400,
        "struct": "STM32F4xxUsart",
        "kwargs": {
            "intn": 0x47
        },
        "type": "peripheral"
    },
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
    "SDIO": {
        "base": 0x40012c00,
        "struct": "STM32F4xxSdio",
        "kwargs": {
            "intn": 0x31
        },
        "type": "peripheral"
    },
    "SPI1": {
        "base": 0x40013000,
        "struct": "STM32F4xxSpi",
        "kwargs": {
            "intn": 0x23
        },
        "type": "peripheral"
    },
    "SPI4": {
        "base": 0x40013400,
        "struct": "STM32F4xxSpi",
        "kwargs": {
            "intn": 0x54
        },
        "type": "peripheral"
    },
    "SYSCFG": {
        "base": 0x40013800,
        "struct": "STM32F4xxSyscfg",
        "type": "peripheral"
    },
    "EXTI": {
        "base": 0x40013c00,
        "struct": "STM32F4xxExti",
        "type": "peripheral"
    },
    "TIM9": {
        "base": 0x40014000,
        "struct": "STM32F4xxTim",
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
    "SPI5": {
        "base": 0x40015000,
        "struct": "STM32F4xxSpi",
        "kwargs": {
            "intn": 0x55
        },
        "type": "peripheral"
    },
    "SPI6": {
        "base": 0x40015400,
        "struct": "STM32F4xxSpi",
        "kwargs": {
            "intn": 0x56
        },
        "type": "peripheral"
    },
    "SAI1": {
        "base": 0x40015800,
        "struct": "STM32F4xxSai",
        "kwargs": {
            "intn": 0x57
        },
        "type": "peripheral"
    },
    "LTDC": {
        "base": 0x40016800,
        "struct": "STM32F4xxLtdc",
        "kwargs": {
            "er_intn": 0x59,
            "intn": 0x58
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
    "GPIOJ": {
        "base": 0x40022400,
        "struct": "STM32F4xxGpio",
        "type": "peripheral"
    },
    "GPIOK": {
        "base": 0x40022800,
        "struct": "STM32F4xxGpio",
        "type": "peripheral"
    },
    "CRC": {
        "base": 0x40023000,
        "struct": "STM32F4xxCrc",
        "type": "peripheral"
    },
    "RCC": {
        "base": 0x40023800,
        "struct": "STM32F4xxRccV3",
        "kwargs": {
            "intn": 0x5
        },
        "type": "peripheral"
    },
    "FLASH INTERFACE": {
        "base": 0x40023c00,
        "struct": "STM32F4xxFlash",
        "kwargs": {
            "intn": 0x4
        },
        "type": "peripheral"
    },
    "DMA1": {
        "base": 0x40026000,
        "struct": "STM32F4xxDma",
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
        "type": "peripheral"
    },
    "DMA2": {
        "base": 0x40026400,
        "struct": "STM32F4xxDma",
        "kwargs": {
            "stream0_intn": 0x38,
            "stream1_intn": 0x39,
            "stream2_intn": 0x3a,
            "stream3_intn": 0x3b,
            "stream4_intn": 0x3c,
            "stream5_intn": 0x44,
            "stream6_intn": 0x45,
            "stream7_intn": 0x46
        },
        "type": "peripheral"
    },
    "ETH": {
        "base": 0x40028000,
        "struct": "STM32F4xxEth",
        "kwargs": {
            "intn": 0x3d,
            "wkup_intn": 0x3e
        },
        "type": "peripheral"
    },
    "DMA2D": {
        "base": 0x4002b000,
        "struct": "STM32F4xxDma2d",
        "kwargs": {
            "intn": 0x5a
        },
        "type": "peripheral"
    },
    "DCMI": {
        "base": 0x50050000,
        "struct": "STM32F4xxDcmi",
        "kwargs": {
            "intn": 0x4e
        },
        "type": "peripheral"
    },
    "RNG": {
        "base": 0x50060800,
        "struct": "STM32F4xxRng",
        "type": "peripheral"
    },
    "DBGMCU": {
        "base": 0xe0042000,
        "struct": "STM32F4xxDbgmcu",
        "kwargs": {
            "dev_id": 0x413
        },
        "type": "peripheral"
    },
    "CODE": {
        "base": 0x8000000,
        "size": 0x200000,
        "alias": 0x0,
        "type": "remap"
    }
}