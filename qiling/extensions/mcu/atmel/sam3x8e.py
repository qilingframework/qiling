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
    "CODE": {
        "base": 0x80000,
        "size": 0x80000,
        "alias": 0x0,
        "type": "remap"
    }
}