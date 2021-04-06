#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn.arm_const import *

reg_map = {
            "r0": UC_ARM_REG_R0,
            "r1": UC_ARM_REG_R1, 
            "r2": UC_ARM_REG_R2,
            "r3": UC_ARM_REG_R3, 
            "r4": UC_ARM_REG_R4,
            "r5": UC_ARM_REG_R5,
            "r6": UC_ARM_REG_R6, 
            "r7": UC_ARM_REG_R7, 
            "r8": UC_ARM_REG_R8,
            "r9": UC_ARM_REG_R9, 
            "r10": UC_ARM_REG_R10, 
            "r11": UC_ARM_REG_R11,
            "r12": UC_ARM_REG_R12, 
            "sp": UC_ARM_REG_SP, 
            "lr": UC_ARM_REG_LR,
            "pc": UC_ARM_REG_PC,
            # CPSR needs to be at offset 25 for GDB, see https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=gdb/arch/arm.h;h=fa589fd0582c0add627a068e6f4947a909c45e86;hb=HEAD#l34
            # The fp registers inbetween have become obsolete
            "f0": UC_ARM_REG_INVALID,
            "f1": UC_ARM_REG_INVALID,
            "f2": UC_ARM_REG_INVALID,
            "f3": UC_ARM_REG_INVALID,
            "f4": UC_ARM_REG_INVALID,
            "f5": UC_ARM_REG_INVALID,
            "f6": UC_ARM_REG_INVALID,
            "f7": UC_ARM_REG_INVALID,
            "fps": UC_ARM_REG_INVALID,
            "cpsr": UC_ARM_REG_CPSR,
            "c1_c0_2": UC_ARM_REG_C1_C0_2,
            "c13_c0_3": UC_ARM_REG_C13_C0_3,
            "fpexc": UC_ARM_REG_FPEXC,
}