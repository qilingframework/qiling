#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from unicorn.mips_const import *

reg_map = {
    "zero": UC_MIPS_REG_ZERO, 
    "at": UC_MIPS_REG_AT, 
    "v0": UC_MIPS_REG_V0,
    "v1": UC_MIPS_REG_V1, 
    "a0": UC_MIPS_REG_A0, 
    "a1": UC_MIPS_REG_A1,
    "a2": UC_MIPS_REG_A2, 
    "a3": UC_MIPS_REG_A3, 
    "t0": UC_MIPS_REG_T0,
    "t1": UC_MIPS_REG_T1, 
    "t2": UC_MIPS_REG_T2, 
    "t3": UC_MIPS_REG_T3,
    "t4": UC_MIPS_REG_T4, 
    "t5": UC_MIPS_REG_T5, 
    "t6": UC_MIPS_REG_T6,
    "t7": UC_MIPS_REG_T7, 
    "s0": UC_MIPS_REG_S0,
    "s1": UC_MIPS_REG_S1,
    "s2": UC_MIPS_REG_S2, 
    "s3": UC_MIPS_REG_S3, 
    "s4": UC_MIPS_REG_S4,
    "s5": UC_MIPS_REG_S5, 
    "s6": UC_MIPS_REG_S6, 
    "s7": UC_MIPS_REG_S7,
    "t8": UC_MIPS_REG_T8, 
    "t9": UC_MIPS_REG_T9, 
    "k0": UC_MIPS_REG_K0,
    "k1": UC_MIPS_REG_K1,
    "gp": UC_MIPS_REG_GP, 
    "sp": UC_MIPS_REG_SP,
    "s8": UC_MIPS_REG_S8,
    "ra": UC_MIPS_REG_RA,
    "status": UC_MIPS_REG_INVALID, 
    "lo": UC_MIPS_REG_LO, 
    "hi": UC_MIPS_REG_HI, 
    "badvaddr": UC_MIPS_REG_INVALID,
    "cause":UC_MIPS_REG_INVALID,
    "pc": UC_MIPS_REG_PC,
}

reg_map_afpr128 = {
    "cp0_config3" : UC_MIPS_REG_CP0_CONFIG3,
    "cp0_userlocal": UC_MIPS_REG_CP0_USERLOCAL,
}