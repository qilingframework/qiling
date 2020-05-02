#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from unicorn.mips_const import *

reg_map = {
            "0": UC_MIPS_REG_0, 
            "1": UC_MIPS_REG_1, 
            "2": UC_MIPS_REG_2,
            "3": UC_MIPS_REG_3, 
            "4": UC_MIPS_REG_4, 
            "5": UC_MIPS_REG_5,
            "6": UC_MIPS_REG_6, 
            "7": UC_MIPS_REG_7, 
            "8": UC_MIPS_REG_8,
            "9": UC_MIPS_REG_9, 
            "10": UC_MIPS_REG_10, 
            "11": UC_MIPS_REG_11,
            "12": UC_MIPS_REG_12, 
            "13": UC_MIPS_REG_13, 
            "14": UC_MIPS_REG_14,
            "15": UC_MIPS_REG_15, 
            "16": UC_MIPS_REG_16,
            "17": UC_MIPS_REG_17,
            "18": UC_MIPS_REG_18, 
            "19": UC_MIPS_REG_19, 
            "20": UC_MIPS_REG_20,
            "21": UC_MIPS_REG_21, 
            "22": UC_MIPS_REG_22, 
            "23": UC_MIPS_REG_23,
            "24": UC_MIPS_REG_24, 
            "25": UC_MIPS_REG_25, 
            "26": UC_MIPS_REG_26,
            "27": UC_MIPS_REG_27, 
            "28": UC_MIPS_REG_28, 
            "SP": UC_MIPS_REG_29,
            "30": UC_MIPS_REG_30, 
            "31": UC_MIPS_REG_31, 
            "inv0": UC_MIPS_REG_INVALID,
            "lo": UC_MIPS_REG_LO, 
            "hi": UC_MIPS_REG_HI, 
            "inv1": UC_MIPS_REG_INVALID,
            "inv2":UC_MIPS_REG_INVALID,
            "pc": UC_MIPS_REG_PC,
}