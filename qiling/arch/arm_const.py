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

    "cpsr": UC_ARM_REG_CPSR,
    "c1_c0_2": UC_ARM_REG_C1_C0_2,
    "c13_c0_3": UC_ARM_REG_C13_C0_3,
    "fpexc": UC_ARM_REG_FPEXC
}

reg_vfp = {
    "d0" : UC_ARM_REG_D0,
    "d1" : UC_ARM_REG_D1,
    "d2" : UC_ARM_REG_D2,
    "d3" : UC_ARM_REG_D3,
    "d4" : UC_ARM_REG_D4,
    "d5" : UC_ARM_REG_D5,
    "d6" : UC_ARM_REG_D6,
    "d7" : UC_ARM_REG_D7,
    "d8" : UC_ARM_REG_D8,
    "d9" : UC_ARM_REG_D9,
    "d10" : UC_ARM_REG_D10,
    "d11" : UC_ARM_REG_D11,
    "d12" : UC_ARM_REG_D12,
    "d13" : UC_ARM_REG_D13,
    "d14" : UC_ARM_REG_D14,
    "d15" : UC_ARM_REG_D15,
    "d16" : UC_ARM_REG_D16,
    "d17" : UC_ARM_REG_D17,
    "d18" : UC_ARM_REG_D18,
    "d19" : UC_ARM_REG_D19,
    "d20" : UC_ARM_REG_D20,
    "d21" : UC_ARM_REG_D21,
    "d22" : UC_ARM_REG_D22,
    "d23" : UC_ARM_REG_D23,
    "d24" : UC_ARM_REG_D24,
    "d25" : UC_ARM_REG_D25,
    "d26" : UC_ARM_REG_D26,
    "d27" : UC_ARM_REG_D27,
    "d28" : UC_ARM_REG_D28,
    "d29" : UC_ARM_REG_D29,
    "d30" : UC_ARM_REG_D30,
    "d31" : UC_ARM_REG_D31,
    "fpscr" : UC_ARM_REG_FPSCR
}
