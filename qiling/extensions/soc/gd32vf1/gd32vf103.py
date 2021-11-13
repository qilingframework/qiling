#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

gd32vf103_env = {
    "ADC0": {
        "base": 0x40012400,
        "struct": "GD32VF1xxAdc",
        "kwargs": {
            "intn": 37
        },
        "type": "peripheral"
    },
    "ADC1": {
        "base": 0x40012800,
        "struct": "GD32VF1xxAdc",
        "kwargs": {
            "intn": 37
        },
        "type": "peripheral"
    },
    "AFIO": {
        "base": 0x40010000,
        "struct": "GD32VF1xxAfio",
        "type": "peripheral"
    },
    "BKP": {
        "base": 0x40006c00,
        "struct": "GD32VF1xxBkp",
        "type": "peripheral"
    },
    "BOOT": {
        "base": 0x1fffb000,
        "size": 0x5000,
        "type": "memory"
    },
    "CAN0": {
        "base": 0x40006400,
        "struct": "GD32VF1xxCan",
        "kwargs": {
            "ewmc_intn": 41,
            "rx0_intn": 39,
            "rx1_intn": 40,
            "tx_intn": 38
        },
        "type": "peripheral"
    },
    "CAN1": {
        "base": 0x40006800,
        "struct": "GD32VF1xxCan",
        "kwargs": {
            "ewmc_intn": 85,
            "rx0_intn": 83,
            "rx1_intn": 84,
            "tx_intn": 82
        },
        "type": "peripheral"
    },
    "CRC": {
        "base": 0x40023000,
        "struct": "GD32VF1xxCrc",
        "type": "peripheral"
    },
    "DAC": {
        "base": 0x40007400,
        "struct": "GD32VF1xxDac",
        "type": "peripheral"
    },
    "DBG": {
        "base": 0xe0042000,
        "struct": "GD32VF1xxDbg",
        "type": "peripheral"
    },
    "DMA0": {
        "base": 0x40020000,
        "struct": "GD32VF1xxDma",
        "kwargs": {
            "stream0_intn": 30,
            "stream1_intn": 31,
            "stream2_intn": 32,
            "stream3_intn": 33,
            "stream4_intn": 34,
            "stream5_intn": 35,
            "stream6_intn": 36
        },
        "type": "peripheral"
    },
    "DMA1": {
        "base": 0x40020400,
        "struct": "GD32VF1xxDma",
        "kwargs": {
            "stream0_intn": 75,
            "stream1_intn": 76,
            "stream2_intn": 77,
            "stream3_intn": 78,
            "stream4_intn": 79
        },
        "type": "peripheral"
    },
    "ECLIC": {
        "base": 0xd2000000,
        "struct": "GD32VF1xxEclic",
        "type": "core peripheral"
    },
    "EXMC": {
        "base": 0xa0000000,
        "struct": "GD32VF1xxExmc",
        "type": "peripheral"
    },
    "EXTI": {
        "base": 0x40010400,
        "struct": "GD32VF1xxExti",
        "kwargs": {
            "line0_intn": 25,
            "line15_10_intn": 59,
            "line1_intn": 26,
            "line2_intn": 27,
            "line3_intn": 28,
            "line4_intn": 29,
            "line9_5_intn": 42
        },
        "type": "peripheral"
    },
    "FLASH": {
        "base": 0x08000000,
        "size": 0x20000,
        "type": "memory"
    },
    "FMC": {
        "base": 0x40022000,
        "struct": "GD32VF1xxFmc",
        "kwargs": {
            "intn": 23
        },
        "type": "peripheral"
    },
    "FWDGT": {
        "base": 0x40003000,
        "struct": "GD32VF1xxFwdgt",
        "type": "peripheral"
    },
    "GPIOA": {
        "base": 0x40010800,
        "struct": "GD32VF1xxGpio",
        "type": "peripheral"
    },
    "GPIOB": {
        "base": 0x40010c00,
        "struct": "GD32VF1xxGpio",
        "type": "peripheral"
    },
    "GPIOC": {
        "base": 0x40011000,
        "struct": "GD32VF1xxGpio",
        "type": "peripheral"
    },
    "GPIOD": {
        "base": 0x40011400,
        "struct": "GD32VF1xxGpio",
        "type": "peripheral"
    },
    "GPIOE": {
        "base": 0x40011800,
        "struct": "GD32VF1xxGpio",
        "type": "peripheral"
    },
    "I2C0": {
        "base": 0x40005400,
        "struct": "GD32VF1xxI2c",
        "kwargs": {
            "er_intn": 51,
            "ev_intn": 50
        },
        "type": "peripheral"
    },
    "I2C1": {
        "base": 0x40005800,
        "struct": "GD32VF1xxI2c",
        "kwargs": {
            "er_intn": 53,
            "ev_intn": 52
        },
        "type": "peripheral"
    },
    "PERIP": {
        "base": 0x40000000,
        "size": 0x40000,
        "type": "mmio"
    },
    "PMU": {
        "base": 0x40007000,
        "struct": "GD32VF1xxPmu",
        "type": "peripheral"
    },
    "RCU": {
        "base": 0x40021000,
        "struct": "GD32VF1xxRcu",
        "kwargs": {
            "intn": 24
        },
        "type": "peripheral"
    },
    "RTC": {
        "base": 0x40002800,
        "struct": "GD32VF1xxRtc",
        "kwargs": {
            "alarm_intn": 60,
            "intn": 22
        },
        "type": "peripheral"
    },
    "SPI0": {
        "base": 0x40013000,
        "struct": "GD32VF1xxSpi",
        "kwargs": {
            "intn": 54
        },
        "type": "peripheral"
    },
    "SPI1": {
        "base": 0x40003800,
        "struct": "GD32VF1xxSpi",
        "kwargs": {
            "intn": 55
        },
        "type": "peripheral"
    },
    "SPI2": {
        "base": 0x40003c00,
        "struct": "GD32VF1xxSpi",
        "kwargs": {
            "intn": 70
        },
        "type": "peripheral"
    },
    "SRAM": {
        "base": 0x20000000,
        "size": 0x18000,
        "type": "memory"
    },
    "TIMER0": {
        "base": 0x40012c00,
        "struct": "GD32VF1xxTimer",
        "kwargs": {
            "brk_intn": 43,
            "channel_intn": 46,
            "trg_cmt_intn": 45,
            "up_intn": 44
        },
        "type": "peripheral"
    },
    "TIMER1": {
        "base": 0x40000000,
        "struct": "GD32VF1xxTimer",
        "kwargs": {
            "intn": 47
        },
        "type": "peripheral"
    },
    "TIMER2": {
        "base": 0x40000400,
        "struct": "GD32VF1xxTimer",
        "kwargs": {
            "intn": 48
        },
        "type": "peripheral"
    },
    "TIMER3": {
        "base": 0x40000800,
        "struct": "GD32VF1xxTimer",
        "kwargs": {
            "intn": 49
        },
        "type": "peripheral"
    },
    "TIMER4": {
        "base": 0x40000c00,
        "struct": "GD32VF1xxTimer",
        "kwargs": {
            "intn": 69
        },
        "type": "peripheral"
    },
    "TIMER5": {
        "base": 0x40001000,
        "struct": "GD32VF1xxTimer",
        "kwargs": {
            "intn": 73
        },
        "type": "peripheral"
    },
    "TIMER6": {
        "base": 0x40001400,
        "struct": "GD32VF1xxTimer",
        "kwargs": {
            "intn": 74
        },
        "type": "peripheral"
    },
    "UART3": {
        "base": 0x40004c00,
        "struct": "GD32VF1xxUart",
        "kwargs": {
            "intn": 71
        },
        "type": "peripheral"
    },
    "UART4": {
        "base": 0x40005000,
        "struct": "GD32VF1xxUart",
        "kwargs": {
            "intn": 72
        },
        "type": "peripheral"
    },
    "USART0": {
        "base": 0x40013800,
        "struct": "GD32VF1xxUsart",
        "kwargs": {
            "intn": 56
        },
        "type": "peripheral"
    },
    "USART1": {
        "base": 0x40004400,
        "struct": "GD32VF1xxUsart",
        "kwargs": {
            "intn": 57
        },
        "type": "peripheral"
    },
    "USART2": {
        "base": 0x40004800,
        "struct": "GD32VF1xxUsart",
        "kwargs": {
            "intn": 58
        },
        "type": "peripheral"
    },
    "USBFS": {
        "base": 0x50000000,
        "size": 0x40000,
        "type": "mmio"
    },
    "USBFS_DEVICE": {
        "base": 0x50000800,
        "struct": "GD32VF1xxUsbfs",
        "type": "peripheral"
    },
    "USBFS_GLOBAL": {
        "base": 0x50000000,
        "struct": "GD32VF1xxUsbfs",
        "type": "peripheral"
    },
    "USBFS_HOST": {
        "base": 0x50000400,
        "struct": "GD32VF1xxUsbfs",
        "type": "peripheral"
    },
    "USBFS_PWRCLK": {
        "base": 0x50000e00,
        "struct": "GD32VF1xxUsbfs",
        "type": "peripheral"
    },
    "WWDGT": {
        "base": 0x40002c00,
        "struct": "GD32VF1xxWwdgt",
        "kwargs": {
            "intn": 0
        },
        "type": "peripheral"
    }
}