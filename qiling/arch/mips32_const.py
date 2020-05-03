#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from unicorn.mips_const import *

reg_map = {
    "zero": UC_MIPS_REG_0, 
    "at": UC_MIPS_REG_1, 
    "v0": UC_MIPS_REG_2,
    "v1": UC_MIPS_REG_3, 
    "a0": UC_MIPS_REG_4, 
    "a1": UC_MIPS_REG_5,
    "a2": UC_MIPS_REG_6, 
    "a3": UC_MIPS_REG_7, 
    "t0": UC_MIPS_REG_8,
    "t1": UC_MIPS_REG_9, 
    "t2": UC_MIPS_REG_10, 
    "t3": UC_MIPS_REG_11,
    "t4": UC_MIPS_REG_12, 
    "t5": UC_MIPS_REG_13, 
    "t6": UC_MIPS_REG_14,
    "t7": UC_MIPS_REG_15, 
    "s0": UC_MIPS_REG_16,
    "s1": UC_MIPS_REG_17,
    "s2": UC_MIPS_REG_18, 
    "s3": UC_MIPS_REG_19, 
    "s4": UC_MIPS_REG_20,
    "s5": UC_MIPS_REG_21, 
    "s6": UC_MIPS_REG_22, 
    "s7": UC_MIPS_REG_23,
    "t8": UC_MIPS_REG_24, 
    "t9": UC_MIPS_REG_25, 
    "k0": UC_MIPS_REG_26,
    "k1": UC_MIPS_REG_27, 
    "gp": UC_MIPS_REG_28, 
    #"sp": UC_MIPS_REG_29,      #Conflict, with UC_MIPS_REG_SP
    "fp": UC_MIPS_REG_30, 
    "s8": UC_MIPS_REG_31, 
    "inv": UC_MIPS_REG_INVALID,
    "lo": UC_MIPS_REG_LO, 
    "hi": UC_MIPS_REG_HI, 
    "inv1": UC_MIPS_REG_INVALID,
    "inv2":UC_MIPS_REG_INVALID,
    "pc": UC_MIPS_REG_PC,
    "sp": UC_MIPS_REG_SP
}

reg_map_afpr128 = {
    "cp0_config3" : UC_MIPS_REG_CP0_CONFIG3,
    "cp0_userlocal": UC_MIPS_REG_CP0_USERLOCAL,
}