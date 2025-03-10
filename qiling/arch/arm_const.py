#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn.arm_const import *


# coprocessor registers
reg_cpr = {
    'CPACR':    (15, 0,  1, 0, 2, 0, False),
    'TPIDRURO': (15, 0, 13, 0, 3, 0, False)
}

reg_map = {
    "r0":  UC_ARM_REG_R0,
    "r1":  UC_ARM_REG_R1,
    "r2":  UC_ARM_REG_R2,
    "r3":  UC_ARM_REG_R3,
    "r4":  UC_ARM_REG_R4,
    "r5":  UC_ARM_REG_R5,
    "r6":  UC_ARM_REG_R6,
    "r7":  UC_ARM_REG_R7,
    "r8":  UC_ARM_REG_R8,
    "r9":  UC_ARM_REG_R9,
    "r10": UC_ARM_REG_R10,
    "r11": UC_ARM_REG_R11,
    "r12": UC_ARM_REG_R12,
    "sp":  UC_ARM_REG_SP,
    "lr":  UC_ARM_REG_LR,
    "pc":  UC_ARM_REG_PC,

    "apsr":  UC_ARM_REG_APSR,
    "cpsr":  UC_ARM_REG_CPSR,
    "spsr":  UC_ARM_REG_SPSR,
    "fpexc": UC_ARM_REG_FPEXC
}

reg_vfp = {
    "d0":  UC_ARM_REG_D0,
    "d1":  UC_ARM_REG_D1,
    "d2":  UC_ARM_REG_D2,
    "d3":  UC_ARM_REG_D3,
    "d4":  UC_ARM_REG_D4,
    "d5":  UC_ARM_REG_D5,
    "d6":  UC_ARM_REG_D6,
    "d7":  UC_ARM_REG_D7,
    "d8":  UC_ARM_REG_D8,
    "d9":  UC_ARM_REG_D9,
    "d10": UC_ARM_REG_D10,
    "d11": UC_ARM_REG_D11,
    "d12": UC_ARM_REG_D12,
    "d13": UC_ARM_REG_D13,
    "d14": UC_ARM_REG_D14,
    "d15": UC_ARM_REG_D15,
    "d16": UC_ARM_REG_D16,
    "d17": UC_ARM_REG_D17,
    "d18": UC_ARM_REG_D18,
    "d19": UC_ARM_REG_D19,
    "d20": UC_ARM_REG_D20,
    "d21": UC_ARM_REG_D21,
    "d22": UC_ARM_REG_D22,
    "d23": UC_ARM_REG_D23,
    "d24": UC_ARM_REG_D24,
    "d25": UC_ARM_REG_D25,
    "d26": UC_ARM_REG_D26,
    "d27": UC_ARM_REG_D27,
    "d28": UC_ARM_REG_D28,
    "d29": UC_ARM_REG_D29,
    "d30": UC_ARM_REG_D30,
    "d31": UC_ARM_REG_D31,
    "fpscr": UC_ARM_REG_FPSCR
}

reg_map_q = {
    "q0":  UC_ARM_REG_Q0,
    "q1":  UC_ARM_REG_Q1,
    "q2":  UC_ARM_REG_Q2,
    "q3":  UC_ARM_REG_Q3,
    "q4":  UC_ARM_REG_Q4,
    "q5":  UC_ARM_REG_Q5,
    "q6":  UC_ARM_REG_Q6,
    "q7":  UC_ARM_REG_Q7,
    "q8":  UC_ARM_REG_Q8,
    "q9":  UC_ARM_REG_Q9,
    "q10": UC_ARM_REG_Q10,
    "q11": UC_ARM_REG_Q11,
    "q12": UC_ARM_REG_Q12,
    "q13": UC_ARM_REG_Q13,
    "q14": UC_ARM_REG_Q14,
    "q15": UC_ARM_REG_Q15
}

reg_map_s = {
    "s0":  UC_ARM_REG_S0,
    "s1":  UC_ARM_REG_S1,
    "s2":  UC_ARM_REG_S2,
    "s3":  UC_ARM_REG_S3,
    "s4":  UC_ARM_REG_S4,
    "s5":  UC_ARM_REG_S5,
    "s6":  UC_ARM_REG_S6,
    "s7":  UC_ARM_REG_S7,
    "s8":  UC_ARM_REG_S8,
    "s9":  UC_ARM_REG_S9,
    "s10": UC_ARM_REG_S10,
    "s11": UC_ARM_REG_S11,
    "s12": UC_ARM_REG_S12,
    "s13": UC_ARM_REG_S13,
    "s14": UC_ARM_REG_S14,
    "s15": UC_ARM_REG_S15,
    "s16": UC_ARM_REG_S16,
    "s17": UC_ARM_REG_S17,
    "s18": UC_ARM_REG_S18,
    "s19": UC_ARM_REG_S19,
    "s20": UC_ARM_REG_S20,
    "s21": UC_ARM_REG_S21,
    "s22": UC_ARM_REG_S22,
    "s23": UC_ARM_REG_S23,
    "s24": UC_ARM_REG_S24,
    "s25": UC_ARM_REG_S25,
    "s26": UC_ARM_REG_S26,
    "s27": UC_ARM_REG_S27,
    "s28": UC_ARM_REG_S28,
    "s29": UC_ARM_REG_S29,
    "s30": UC_ARM_REG_S30,
    "s31": UC_ARM_REG_S31
}
