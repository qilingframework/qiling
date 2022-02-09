#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

gd32vf103 = {
    "ECLIC": {
        "base": 0xd2000000,
        "struct": "GD32VF1xxEclic",
        "type": "core"
    },
    "FLASH": {
        "base": 0x8000000,
        "size": 0x20000,
        "type": "memory"
    },
    "BOOT": {
        "base": 0x1fffb000,
        "size": 0x5000,
        "type": "memory"
    },
    "SRAM": {
        "base": 0x20000000,
        "size": 0x18000,
        "type": "memory"
    },
    "PERIP": {
        "base": 0x40000000,
        "size": 0x40000,
        "type": "mmio"
    },
    "USBFS": {
        "base": 0x50000000,
        "size": 0x40000,
        "type": "mmio"
    },
    "TIMER1": {
        "base": 0x40000000,
        "struct": "GD32VF1xxTimer",
        "kwargs": {
            "intn": 0x2f
        },
        "type": "peripheral"
    },
    "TIMER2": {
        "base": 0x40000400,
        "struct": "GD32VF1xxTimer",
        "kwargs": {
            "intn": 0x30
        },
        "type": "peripheral"
    },
    "TIMER3": {
        "base": 0x40000800,
        "struct": "GD32VF1xxTimer",
        "kwargs": {
            "intn": 0x31
        },
        "type": "peripheral"
    },
    "TIMER4": {
        "base": 0x40000c00,
        "struct": "GD32VF1xxTimer",
        "kwargs": {
            "intn": 0x45
        },
        "type": "peripheral"
    },
    "TIMER5": {
        "base": 0x40001000,
        "struct": "GD32VF1xxTimer",
        "kwargs": {
            "intn": 0x49
        },
        "type": "peripheral"
    },
    "TIMER6": {
        "base": 0x40001400,
        "struct": "GD32VF1xxTimer",
        "kwargs": {
            "intn": 0x4a
        },
        "type": "peripheral"
    },
    "RTC": {
        "base": 0x40002800,
        "struct": "GD32VF1xxRtc",
        "kwargs": {
            "alarm_intn": 0x3c,
            "intn": 0x16
        },
        "type": "peripheral"
    },
    "WWDGT": {
        "base": 0x40002c00,
        "struct": "GD32VF1xxWwdgt",
        "kwargs": {
            "intn": 0x0
        },
        "type": "peripheral"
    },
    "FWDGT": {
        "base": 0x40003000,
        "struct": "GD32VF1xxFwdgt",
        "type": "peripheral"
    },
    "SPI1": {
        "base": 0x40003800,
        "struct": "GD32VF1xxSpi",
        "kwargs": {
            "intn": 0x37
        },
        "type": "peripheral"
    },
    "SPI2": {
        "base": 0x40003c00,
        "struct": "GD32VF1xxSpi",
        "kwargs": {
            "intn": 0x46
        },
        "type": "peripheral"
    },
    "USART1": {
        "base": 0x40004400,
        "struct": "GD32VF1xxUsart",
        "kwargs": {
            "intn": 0x39
        },
        "type": "peripheral"
    },
    "USART2": {
        "base": 0x40004800,
        "struct": "GD32VF1xxUsart",
        "kwargs": {
            "intn": 0x3a
        },
        "type": "peripheral"
    },
    "UART3": {
        "base": 0x40004c00,
        "struct": "GD32VF1xxUart",
        "kwargs": {
            "intn": 0x47
        },
        "type": "peripheral"
    },
    "UART4": {
        "base": 0x40005000,
        "struct": "GD32VF1xxUart",
        "kwargs": {
            "intn": 0x48
        },
        "type": "peripheral"
    },
    "I2C0": {
        "base": 0x40005400,
        "struct": "GD32VF1xxI2c",
        "kwargs": {
            "er_intn": 0x33,
            "ev_intn": 0x32
        },
        "type": "peripheral"
    },
    "I2C1": {
        "base": 0x40005800,
        "struct": "GD32VF1xxI2c",
        "kwargs": {
            "er_intn": 0x35,
            "ev_intn": 0x34
        },
        "type": "peripheral"
    },
    "CAN0": {
        "base": 0x40006400,
        "struct": "GD32VF1xxCan",
        "kwargs": {
            "ewmc_intn": 0x29,
            "rx0_intn": 0x27,
            "rx1_intn": 0x28,
            "tx_intn": 0x26
        },
        "type": "peripheral"
    },
    "CAN1": {
        "base": 0x40006800,
        "struct": "GD32VF1xxCan",
        "kwargs": {
            "ewmc_intn": 0x55,
            "rx0_intn": 0x53,
            "rx1_intn": 0x54,
            "tx_intn": 0x52
        },
        "type": "peripheral"
    },
    "BKP": {
        "base": 0x40006c00,
        "struct": "GD32VF1xxBkp",
        "type": "peripheral"
    },
    "PMU": {
        "base": 0x40007000,
        "struct": "GD32VF1xxPmu",
        "type": "peripheral"
    },
    "DAC": {
        "base": 0x40007400,
        "struct": "GD32VF1xxDac",
        "type": "peripheral"
    },
    "AFIO": {
        "base": 0x40010000,
        "struct": "GD32VF1xxAfio",
        "type": "peripheral"
    },
    "EXTI": {
        "base": 0x40010400,
        "struct": "GD32VF1xxExti",
        "kwargs": {
            "line0_intn": 0x19,
            "line15_10_intn": 0x3b,
            "line1_intn": 0x1a,
            "line2_intn": 0x1b,
            "line3_intn": 0x1c,
            "line4_intn": 0x1d,
            "line9_5_intn": 0x2a
        },
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
    "ADC0": {
        "base": 0x40012400,
        "struct": "GD32VF1xxAdc",
        "kwargs": {
            "intn": 0x25
        },
        "type": "peripheral"
    },
    "ADC1": {
        "base": 0x40012800,
        "struct": "GD32VF1xxAdc",
        "kwargs": {
            "intn": 0x25
        },
        "type": "peripheral"
    },
    "TIMER0": {
        "base": 0x40012c00,
        "struct": "GD32VF1xxTimer",
        "kwargs": {
            "brk_intn": 0x2b,
            "channel_intn": 0x2e,
            "trg_cmt_intn": 0x2d,
            "up_intn": 0x2c
        },
        "type": "peripheral"
    },
    "SPI0": {
        "base": 0x40013000,
        "struct": "GD32VF1xxSpi",
        "kwargs": {
            "intn": 0x36
        },
        "type": "peripheral"
    },
    "USART0": {
        "base": 0x40013800,
        "struct": "GD32VF1xxUsart",
        "kwargs": {
            "intn": 0x38
        },
        "type": "peripheral"
    },
    "DMA0": {
        "base": 0x40020000,
        "struct": "GD32VF1xxDma",
        "kwargs": {
            "stream0_intn": 0x1e,
            "stream1_intn": 0x1f,
            "stream2_intn": 0x20,
            "stream3_intn": 0x21,
            "stream4_intn": 0x22,
            "stream5_intn": 0x23,
            "stream6_intn": 0x24
        },
        "type": "peripheral"
    },
    "DMA1": {
        "base": 0x40020400,
        "struct": "GD32VF1xxDma",
        "kwargs": {
            "stream0_intn": 0x4b,
            "stream1_intn": 0x4c,
            "stream2_intn": 0x4d,
            "stream3_intn": 0x4e,
            "stream4_intn": 0x4f
        },
        "type": "peripheral"
    },
    "RCU": {
        "base": 0x40021000,
        "struct": "GD32VF1xxRcu",
        "kwargs": {
            "intn": 0x18
        },
        "type": "peripheral"
    },
    "FMC": {
        "base": 0x40022000,
        "struct": "GD32VF1xxFmc",
        "kwargs": {
            "intn": 0x17
        },
        "type": "peripheral"
    },
    "CRC": {
        "base": 0x40023000,
        "struct": "GD32VF1xxCrc",
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
    "USBFS_DEVICE": {
        "base": 0x50000800,
        "struct": "GD32VF1xxUsbfs",
        "type": "peripheral"
    },
    "USBFS_PWRCLK": {
        "base": 0x50000e00,
        "struct": "GD32VF1xxUsbfs",
        "type": "peripheral"
    },
    "EXMC": {
        "base": 0xa0000000,
        "struct": "GD32VF1xxExmc",
        "type": "peripheral"
    },
    "DBG": {
        "base": 0xe0042000,
        "struct": "GD32VF1xxDbg",
        "type": "peripheral"
    }
}