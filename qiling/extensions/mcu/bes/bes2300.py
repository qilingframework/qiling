#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

bes2300 = {
    "ROM": {
        "base":0x0,
        "size":0xc000,
        "type": "memory"
    },
    "RAM": {
        "base":0x200a0000,
        "size":0x20000,
        "type": "memory"
    },
    "FLASH": {
        "base": 0x3C000000,
        "size": 0x100000,
        "type": "memory"
    },
    "CMU": {
        "struct": "BES2300Cmu",
        "base":0x40000000,
        "type": "peripheral"
    },
    "I2C0": {
        "struct": "BES2300I2c",
        "base":0x40005000,
        "type": "peripheral"
    },
    "I2C1": {
        "struct": "BES2300I2c",
        "base":0x40006000,
        "type": "peripheral"
    },
    "SPI": {
        "struct": "BES2300Spi",
        "base":0x40007000,
        "type": "peripheral"
    },
    "SPILCD": {
        "struct": "BES2300Spi",
        "base":0x40008000,
        "type": "peripheral"
    },
    "SPIPHY": {
        "struct": "BES2300Spi",
        "base":0x4000a000,
        "type": "peripheral"
    },
    "UART0": {
        "struct": "BES2300Uart",
        "base":0x4000b000,
        "type": "peripheral"
    },
    "UART1": {
        "struct": "BES2300Uart",
        "base":0x4000c000,
        "type": "peripheral"
    },
    "UART2": {
        "struct": "BES2300Uart",
        "base":0x4000d000,
        "type": "peripheral"
    },
    "BTPCM": {
        "struct": "BES2300Btpcm",
        "base":0x4000e000,
        "type": "peripheral"
    },
    "I2S0": {
        "struct": "BES2300I2s",
        "base":0x4000f000,
        "type": "peripheral"
    },
    "SPDIF0": {
        "struct": "BES2300Spdif",
        "base":0x40010000,
        "type": "peripheral"
    },
    "SDMMC": {
        "struct": "BES2300Sdmmc",
        "base":0x40110000,
        "type": "peripheral"
    },
    "I2C_SLAVE": {
        "struct": "BES2300I2c",
        "base":0x40160000,
        "type": "peripheral"
    },
    "USB": {
        "struct": "BES2300Usb",
        "base":0x40180000,
        "type": "peripheral"
    },
    "CODEC": {
        "struct": "BES2300Codec",
        "base":0x40300000,
        "type": "peripheral"
    },
    "IOMUX": {
        "struct": "BES2300Iomux",
        "base":0x40086000,
        "type": "peripheral"
    },
    "GPIO": {
        "struct": "BES2300Gpio",
        "base":0x40081000,
        "type": "peripheral"
    },
    "PWM": {
        "struct": "BES2300Pwm",
        "base":0x40083000,
        "type": "peripheral"
    },
    "TIMER0": {
        "struct": "BES2300Timer",
        "base":0x40002000,
        "type": "peripheral"
    },
    "TIMER1": {
        "struct": "BES2300Timer",
        "base":0x40003000,
        "type": "peripheral"
    }
}