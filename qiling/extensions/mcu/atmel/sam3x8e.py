#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

sam3x8e = {
    "SRAM BB": {
        "alias": 0x22000000,
        "base": 0x20000000,
        "size": 0x200000,
        "type": "bitband"
    },
    "PERIP BB": {
        "alias": 0x42000000,
        "base": 0x40000000  ,
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
        "base": 0x80000,
        "size": 0x80000,
        "type": "memory"
    },
    "SRAM": {
        "base": 0x20000000,
        "size": 0x10000,
        "type": "memory"
    },
    "RAM": {
        "base": 0x20070000,
        "size": 0x18000,
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
    "HSMCI": {
        "base": 0x40000000,
        "struct": "SAM3xaHsmci",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x15
        }
    },
    "SSC": {
        "base": 0x40004000,
        "struct": "SAM3xaSsc",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x1a
        }
    },
    "SPI0": {
        "base": 0x40008000,
        "struct": "SAM3xaSpi",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x18
        }
    },
    "TC0": {
        "base": 0x40080000,
        "struct": "SAM3xaTc",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x1b
        }
    },
    "TC1": {
        "base": 0x40084000,
        "struct": "SAM3xaTc",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x1c
        }
    },
    "TC2": {
        "base": 0x40088000,
        "struct": "SAM3xaTc",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x1d
        }
    },
    "TWI0": {
        "base": 0x4008c000,
        "struct": "SAM3xaTwi",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x16
        }
    },
    "PDC_TWI0": {
        "base": 0x4008c100,
        "struct": "SAM3xaPdc",
        "type": "peripheral"
    },
    "TWI1": {
        "base": 0x40090000,
        "struct": "SAM3xaTwi",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x17
        }
    },
    "PDC_TWI1": {
        "base": 0x40090100,
        "struct": "SAM3xaPdc",
        "type": "peripheral"
    },
    "PWM": {
        "base": 0x40094000,
        "struct": "SAM3xaPwm",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x24
        }
    },
    "PDC_PWM": {
        "base": 0x40094100,
        "struct": "SAM3xaPdc",
        "type": "peripheral"
    },
    "USART0": {
        "base": 0x40098000,
        "struct": "SAM3xaUsart",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x11
        }
    },
    "PDC_USART0": {
        "base": 0x40098100,
        "struct": "SAM3xaPdc",
        "type": "peripheral"
    },
    "USART1": {
        "base": 0x4009c000,
        "struct": "SAM3xaUsart",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x12
        }
    },
    "PDC_USART1": {
        "base": 0x4009c100,
        "struct": "SAM3xaPdc",
        "type": "peripheral"
    },
    "USART2": {
        "base": 0x400a0000,
        "struct": "SAM3xaUsart",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x13
        }
    },
    "PDC_USART2": {
        "base": 0x400a0100,
        "struct": "SAM3xaPdc",
        "type": "peripheral"
    },
    "USART3": {
        "base": 0x400a4000,
        "struct": "SAM3xaUsart",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x14
        }
    },
    "PDC_USART3": {
        "base": 0x400a4100,
        "struct": "SAM3xaPdc",
        "type": "peripheral"
    },
    "UOTGHS": {
        "base": 0x400ac000,
        "struct": "SAM3xaUotghs",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x28
        }
    },
    "EMAC": {
        "base": 0x400b0000,
        "struct": "SAM3xaEmac",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x2a
        }
    },
    "CAN0": {
        "base": 0x400b4000,
        "struct": "SAM3xaCan",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x2b
        }
    },
    "CAN1": {
        "base": 0x400b8000,
        "struct": "SAM3xaCan",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x2c
        }
    },
    "TRNG": {
        "base": 0x400bc000,
        "struct": "SAM3xaTrng",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x29
        }
    },
    "ADC": {
        "base": 0x400c0000,
        "struct": "SAM3xaAdc",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x25
        }
    },
    "PDC_ADC": {
        "base": 0x400c0100,
        "struct": "SAM3xaPdc",
        "type": "peripheral"
    },
    "DMAC": {
        "base": 0x400c4000,
        "struct": "SAM3xaDmac",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x27
        }
    },
    "DACC": {
        "base": 0x400c8000,
        "struct": "SAM3xaDacc",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x26
        }
    },
    "PDC_DACC": {
        "base": 0x400c8100,
        "struct": "SAM3xaPdc",
        "type": "peripheral"
    },
    "SMC": {
        "base": 0x400e0000,
        "struct": "SAM3xaSmc",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x9
        }
    },
    "MATRIX": {
        "base": 0x400e0400,
        "struct": "SAM3xaMatrix",
        "type": "peripheral"
    },
    "PMC": {
        "base": 0x400e0600,
        "struct": "SAM3xaPmc",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x5
        }
    },
    "UART": {
        "base": 0x400e0800,
        "struct": "SAM3xaUart",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x8
        }
    },
    "PDC_UART": {
        "base": 0x400e0900,
        "struct": "SAM3xaPdc",
        "type": "peripheral"
    },
    "CHIPID": {
        "base": 0x400e0940,
        "struct": "SAM3xaChipid",
        "type": "peripheral"
    },
    "EFC0": {
        "base": 0x400e0a00,
        "struct": "SAM3xaEfc",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x6
        }
    },
    "EFC1": {
        "base": 0x400e0c00,
        "struct": "SAM3xaEfc",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x7
        }
    },
    "PIOA": {
        "base": 0x400e0e00,
        "struct": "SAM3xaPio",
        "type": "peripheral",
        "kwargs": {
            "intn": 0xb
        }
    },
    "PIOB": {
        "base": 0x400e1000,
        "struct": "SAM3xaPio",
        "type": "peripheral",
        "kwargs": {
            "intn": 0xc
        }
    },
    "PIOC": {
        "base": 0x400e1200,
        "struct": "SAM3xaPio",
        "type": "peripheral",
        "kwargs": {
            "intn": 0xd
        }
    },
    "PIOD": {
        "base": 0x400e1400,
        "struct": "SAM3xaPio",
        "type": "peripheral",
        "kwargs": {
            "intn": 0xe
        }
    },
    "RSTC": {
        "base": 0x400e1a00,
        "struct": "SAM3xaRstc",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x1
        }
    },
    "SUPC": {
        "base": 0x400e1a10,
        "struct": "SAM3xaSupc",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x0
        }
    },
    "RTT": {
        "base": 0x400e1a30,
        "struct": "SAM3xaRtt",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x3
        }
    },
    "WDT": {
        "base": 0x400e1a50,
        "struct": "SAM3xaWdt",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x4
        }
    },
    "RTC": {
        "base": 0x400e1a60,
        "struct": "SAM3xaRtc",
        "type": "peripheral",
        "kwargs": {
            "intn": 0x2
        }
    },
    "GPBR": {
        "base": 0x400e1a90,
        "struct": "SAM3xaGpbr",
        "type": "peripheral"
    },
    "CODE": {
        "base": 0x80000,
        "size": 0x80000,
        "alias": 0x0,
        "type": "remap"
    }
}