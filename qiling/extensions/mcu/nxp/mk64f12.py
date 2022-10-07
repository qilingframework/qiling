#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

mk64f12 = {
    "BME": {
        "base": 0x44000000,
        "struct": "KinetisBME",
        "type": "core",
        "kwargs": {
            "base": 0x40000000,
            "size": 0x70000,
        }
    },
    "PERIP BB": {
        "base": 0x42000000,
        "struct": "CortexMBitband",
        "type": "core",
        "kwargs":  {
            "base": 0x40000000,
            "size": 0x100000,
        }
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
        "base": 0x00000000,
        "size": 0x100000,
        "type": "memory",
    },
    "SRAM": {
        "base": 0x1fff0000,
        "size": 0x00040000,
        "type": "memory",
    },
    "PERIP": {
        "base": 0x40000000,
        "size": 0x100000,
        "type": "mmio"
    },
    "PERIP BBR": {
        "base": 0x42000000,
        "size": 0x2000000,
        "type": "mmio"
    },
    "PPB": {
        "base": 0xe0000000,
        "size": 0x100000,
        "type": "mmio"
    },
    "BME AND REGION": {
        "base": 0x44000000,
        "size": 0x70000,
        "type": "mmio"
    },
    "BME OR REGION": {
        "base": 0x48000000,
        "size": 0x70000,
        "type": "mmio"
    },
    "FTFE": {
        "type": "peripheral",
        "base": 0x400,
        "struct": "MK64F12Ftfe"
    },
    "AIPS0": {
        "type": "peripheral",
        "base": 0x40000000,
        "struct": "MK64F12Aips"
    },
    "AIPS1": {
        "type": "peripheral",
        "base": 0x40080000,
        "struct": "MK64F12Aips"
    },
    "AXBS": {
        "type": "peripheral",
        "base": 0x40004000,
        "struct": "MK64F12Axbs"
    },
    "DMA": {
        "type": "peripheral",
        "base": 0x40008000,
        "struct": "MK64F12Dma",
        "kwargs": {
            "dma0_intn": 0x0,
            "dma1_intn": 0x1,
            "dma2_intn": 0x2,
            "dma3_intn": 0x3,
            "dma4_intn": 0x4,
            "dma5_intn": 0x5,
            "dma6_intn": 0x6,
            "dma7_intn": 0x7,
            "dma8_intn": 0x8,
            "dma9_intn": 0x9,
            "dma10_intn": 0xa,
            "dma11_intn": 0xb,
            "dma12_intn": 0xc,
            "dma13_intn": 0xd,
            "dma14_intn": 0xe,
            "dma15_intn": 0xf,
            "error_intn": 0x10
        }
    },
    "FB": {
        "type": "peripheral",
        "base": 0x4000c000,
        "struct": "MK64F12Fb"
    },
    "SYSMPU": {
        "type": "peripheral",
        "base": 0x4000d000,
        "struct": "MK64F12Sysmpu"
    },
    "FMC": {
        "type": "peripheral",
        "base": 0x4001f000,
        "struct": "MK64F12Fmc"
    },
    "FTFE": {
        "type": "peripheral",
        "base": 0x40020000,
        "struct": "MK64F12Ftfe",
        "kwargs": {
            "intn": 0x12,
            "read_collision_intn": 0x13
        }
    },
    "DMAMUX": {
        "type": "peripheral",
        "base": 0x40021000,
        "struct": "MK64F12Dmamux"
    },
    "CAN0": {
        "type": "peripheral",
        "base": 0x40024000,
        "struct": "MK64F12Can",
        "kwargs": {
            "ored_message_buffer_intn": 0x4b,
            "bus_off_intn": 0x4c,
            "error_intn": 0x4d,
            "tx_warning_intn": 0x4e,
            "rx_warning_intn": 0x4f,
            "wake_up_intn": 0x50
        }
    },
    "RNG": {
        "type": "peripheral",
        "base": 0x40029000,
        "struct": "MK64F12Rng",
        "kwargs": {
            "intn": 0x17
        }
    },
    "SPI0": {
        "type": "peripheral",
        "base": 0x4002c000,
        "struct": "MK64F12Spi",
        "kwargs": {
            "intn": 0x1a
        }
    },
    "SPI1": {
        "type": "peripheral",
        "base": 0x4002d000,
        "struct": "MK64F12Spi",
        "kwargs": {
            "intn": 0x1b
        }
    },
    "SPI2": {
        "type": "peripheral",
        "base": 0x400ac000,
        "struct": "MK64F12Spi",
        "kwargs": {
            "intn": 0x41
        }
    },
    "I2S0": {
        "type": "peripheral",
        "base": 0x4002f000,
        "struct": "MK64F12I2s",
        "kwargs": {
            "tx_intn": 0x1c,
            "rx_intn": 0x1d
        }
    },
    "CRC": {
        "type": "peripheral",
        "base": 0x40032000,
        "struct": "MK64F12Crc"
    },
    "USBDCD": {
        "type": "peripheral",
        "base": 0x40035000,
        "struct": "MK64F12Usbdcd",
        "kwargs": {
            "intn": 0x36
        }
    },
    "PDB0": {
        "type": "peripheral",
        "base": 0x40036000,
        "struct": "MK64F12Pdb",
        "kwargs": {
            "intn": 0x34
        }
    },
    "PIT": {
        "type": "peripheral",
        "base": 0x40037000,
        "struct": "MK64F12Pit",
        "kwargs": {
            "pit0_intn": 0x30,
            "pit1_intn": 0x31,
            "pit2_intn": 0x32,
            "pit3_intn": 0x33
        }
    },
    "FTM0": {
        "type": "peripheral",
        "base": 0x40038000,
        "struct": "MK64F12Ftm",
        "kwargs": {
            "intn": 0x2a
        }
    },
    "FTM1": {
        "type": "peripheral",
        "base": 0x40039000,
        "struct": "MK64F12Ftm",
        "kwargs": {
            "intn": 0x2b
        }
    },
    "FTM2": {
        "type": "peripheral",
        "base": 0x4003a000,
        "struct": "MK64F12Ftm",
        "kwargs": {
            "intn": 0x2c
        }
    },
    "FTM3": {
        "type": "peripheral",
        "base": 0x400b9000,
        "struct": "MK64F12Ftm",
        "kwargs": {
            "intn": 0x47
        }
    },
    "ADC0": {
        "type": "peripheral",
        "base": 0x4003b000,
        "struct": "MK64F12Adc",
        "kwargs": {
            "intn": 0x27
        }
    },
    "ADC1": {
        "type": "peripheral",
        "base": 0x400bb000,
        "struct": "MK64F12Adc",
        "kwargs": {
            "intn": 0x49
        }
    },
    "RTC": {
        "type": "peripheral",
        "base": 0x4003d000,
        "struct": "MK64F12Rtc",
        "kwargs": {
            "intn": 0x2e,
            "seconds_intn": 0x2f
        }
    },
    "RFVBAT": {
        "type": "peripheral",
        "base": 0x4003e000,
        "struct": "MK64F12Rfvbat"
    },
    "LPTMR0": {
        "type": "peripheral",
        "base": 0x40040000,
        "struct": "MK64F12Lptmr",
        "kwargs": {
            "intn": 0x3a
        }
    },
    "RFSYS": {
        "type": "peripheral",
        "base": 0x40041000,
        "struct": "MK64F12Rfsys"
    },
    "SIM": {
        "type": "peripheral",
        "base": 0x40047000,
        "struct": "MK64F12Sim"
    },
    "PORTA": {
        "type": "peripheral",
        "base": 0x40049000,
        "struct": "MK64F12Port",
        "kwargs": {
            "intn": 0x3b
        }
    },
    "PORTB": {
        "type": "peripheral",
        "base": 0x4004a000,
        "struct": "MK64F12Port",
        "kwargs": {
            "intn": 0x3c
        }
    },
    "PORTC": {
        "type": "peripheral",
        "base": 0x4004b000,
        "struct": "MK64F12Port",
        "kwargs": {
            "intn": 0x3d
        }
    },
    "PORTD": {
        "type": "peripheral",
        "base": 0x4004c000,
        "struct": "MK64F12Port",
        "kwargs": {
            "intn": 0x3e
        }
    },
    "PORTE": {
        "type": "peripheral",
        "base": 0x4004d000,
        "struct": "MK64F12Port",
        "kwargs": {
            "intn": 0x3f
        }
    },
    "WDOG": {
        "type": "peripheral",
        "base": 0x40052000,
        "struct": "MK64F12Wdog",
        "kwargs": {
            "ewm_intn": 0x16
        }
    },
    "EWM": {
        "type": "peripheral",
        "base": 0x40061000,
        "struct": "MK64F12Ewm",
        "kwargs": {
            "wdog_ewm_intn": 0x16
        }
    },
    "CMT": {
        "type": "peripheral",
        "base": 0x40062000,
        "struct": "MK64F12Cmt",
        "kwargs": {
            "intn": 0x2d
        }
    },
    "MCG": {
        "type": "peripheral",
        "base": 0x40064000,
        "struct": "MK64F12Mcg"
    },
    "OSC": {
        "type": "peripheral",
        "base": 0x40065000,
        "struct": "MK64F12Osc"
    },
    "I2C0": {
        "type": "peripheral",
        "base": 0x40066000,
        "struct": "MK64F12I2c",
        "kwargs": {
            "intn": 0x18
        }
    },
    "I2C1": {
        "type": "peripheral",
        "base": 0x40067000,
        "struct": "MK64F12I2c",
        "kwargs": {
            "intn": 0x19
        }
    },
    "I2C2": {
        "type": "peripheral",
        "base": 0x400e6000,
        "struct": "MK64F12I2c",
        "kwargs": {
            "intn": 0x4a
        }
    },
    "UART0": {
        "type": "peripheral",
        "base": 0x4006a000,
        "struct": "MK64F12Uart",
        "kwargs": {
            "lon_intn": 0x1e,
            "rx_tx_intn": 0x1f,
            "err_intn": 0x20
        }
    },
    "UART1": {
        "type": "peripheral",
        "base": 0x4006b000,
        "struct": "MK64F12Uart",
        "kwargs": {
            "rx_tx_intn": 0x21,
            "err_intn": 0x22
        }
    },
    "UART2": {
        "type": "peripheral",
        "base": 0x4006c000,
        "struct": "MK64F12Uart",
        "kwargs": {
            "rx_tx_intn": 0x23,
            "err_intn": 0x24
        }
    },
    "UART3": {
        "type": "peripheral",
        "base": 0x4006d000,
        "struct": "MK64F12Uart",
        "kwargs": {
            "rx_tx_intn": 0x25,
            "err_intn": 0x26
        }
    },
    "UART4": {
        "type": "peripheral",
        "base": 0x400ea000,
        "struct": "MK64F12Uart",
        "kwargs": {
            "rx_tx_intn": 0x42,
            "err_intn": 0x43
        }
    },
    "UART5": {
        "type": "peripheral",
        "base": 0x400eb000,
        "struct": "MK64F12Uart",
        "kwargs": {
            "rx_tx_intn": 0x44,
            "err_intn": 0x45
        }
    },
    "USB0": {
        "type": "peripheral",
        "base": 0x40072000,
        "struct": "MK64F12Usb",
        "kwargs": {
            "intn": 0x35
        }
    },
    "CMP0": {
        "type": "peripheral",
        "base": 0x40073000,
        "struct": "MK64F12Cmp",
        "kwargs": {
            "intn": 0x28
        }
    },
    "CMP1": {
        "type": "peripheral",
        "base": 0x40073008,
        "struct": "MK64F12Cmp",
        "kwargs": {
            "intn": 0x29
        }
    },
    "CMP2": {
        "type": "peripheral",
        "base": 0x40073010,
        "struct": "MK64F12Cmp",
        "kwargs": {
            "intn": 0x46
        }
    },
    "VREF": {
        "type": "peripheral",
        "base": 0x40074000,
        "struct": "MK64F12Vref"
    },
    "LLWU": {
        "type": "peripheral",
        "base": 0x4007c000,
        "struct": "MK64F12Llwu",
        "kwargs": {
            "intn": 0x15
        }
    },
    "PMC": {
        "type": "peripheral",
        "base": 0x4007d000,
        "struct": "MK64F12Pmc",
        "kwargs": {
            "lvd_lvw_intn": 0x14
        }
    },
    "SMC": {
        "type": "peripheral",
        "base": 0x4007e000,
        "struct": "MK64F12Smc"
    },
    "RCM": {
        "type": "peripheral",
        "base": 0x4007f000,
        "struct": "MK64F12Rcm"
    },
    "SDHC": {
        "type": "peripheral",
        "base": 0x400b1000,
        "struct": "MK64F12Sdhc",
        "kwargs": {
            "intn": 0x51
        }
    },
    "ENET": {
        "type": "peripheral",
        "base": 0x400c0000,
        "struct": "MK64F12Enet",
        "kwargs": {
            "1588_timer_intn": 0x52,
            "transmit_intn": 0x53,
            "receive_intn": 0x54,
            "error_intn": 0x55
        }
    },
    "DAC0": {
        "type": "peripheral",
        "base": 0x400cc000,
        "struct": "MK64F12Dac",
        "kwargs": {
            "intn": 0x38
        }
    },
    "DAC1": {
        "type": "peripheral",
        "base": 0x400cd000,
        "struct": "MK64F12Dac",
        "kwargs": {
            "intn": 0x48
        }
    },
    "GPIOA": {
        "type": "peripheral",
        "base": 0x400ff000,
        "struct": "MK64F12Gpio",
        "kwargs": {
            "intn": 0x3b
        }
    },
    "GPIOB": {
        "type": "peripheral",
        "base": 0x400ff040,
        "struct": "MK64F12Gpio",
        "kwargs": {
            "intn": 0x3c
        }
    },
    "GPIOC": {
        "type": "peripheral",
        "base": 0x400ff080,
        "struct": "MK64F12Gpio",
        "kwargs": {
            "intn": 0x3d
        }
    },
    "GPIOD": {
        "type": "peripheral",
        "base": 0x400ff0c0,
        "struct": "MK64F12Gpio",
        "kwargs": {
            "intn": 0x3e
        }
    },
    "GPIOE": {
        "type": "peripheral",
        "base": 0x400ff100,
        "struct": "MK64F12Gpio",
        "kwargs": {
            "intn": 0x3f
        }
    },
    "CAU": {
        "type": "peripheral",
        "base": 0xe0081000,
        "struct": "MK64F12Cau"
    }
}