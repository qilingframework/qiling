#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn.ppc_const import *
from enum import IntEnum

reg_map = {
    "r0": UC_PPC_REG_0,
    "r1": UC_PPC_REG_1,
    "r2": UC_PPC_REG_2,
    "r3": UC_PPC_REG_3,
    "r4": UC_PPC_REG_4,
    "r5": UC_PPC_REG_5,
    "r6": UC_PPC_REG_6,
    "r7": UC_PPC_REG_7,
    "r8": UC_PPC_REG_8,
    "r9": UC_PPC_REG_9,
    "r10": UC_PPC_REG_10,
    "r11": UC_PPC_REG_11,
    "r12": UC_PPC_REG_12,
    "r13": UC_PPC_REG_13,
    "r14": UC_PPC_REG_14,
    "r15": UC_PPC_REG_15,
    "r16": UC_PPC_REG_16,
    "r17": UC_PPC_REG_17,
    "r18": UC_PPC_REG_18,
    "r19": UC_PPC_REG_19,
    "r20": UC_PPC_REG_20,
    "r21": UC_PPC_REG_21,
    "r22": UC_PPC_REG_22,
    "r23": UC_PPC_REG_23,
    "r24": UC_PPC_REG_24,
    "r25": UC_PPC_REG_25,
    "r26": UC_PPC_REG_26,
    "r27": UC_PPC_REG_27,
    "r28": UC_PPC_REG_28,
    "r29": UC_PPC_REG_29,
    "r30": UC_PPC_REG_30,
    "r31": UC_PPC_REG_31,
    "pc": UC_PPC_REG_PC,
    "msr": UC_PPC_REG_MSR,
    "cr": UC_PPC_REG_CR0,
    "lr": UC_PPC_REG_LR,
    "ctr": UC_PPC_REG_CTR,
    "xer": UC_PPC_REG_XER,
}

reg_float_map = {
    "f0": UC_PPC_REG_FPR0,
    "f1": UC_PPC_REG_FPR1,
    "f2": UC_PPC_REG_FPR2,
    "f3": UC_PPC_REG_FPR3,
    "f4": UC_PPC_REG_FPR4,
    "f5": UC_PPC_REG_FPR5,
    "f6": UC_PPC_REG_FPR6,
    "f7": UC_PPC_REG_FPR7,
    "f8": UC_PPC_REG_FPR8,
    "f9": UC_PPC_REG_FPR9,
    "f10": UC_PPC_REG_FPR10,
    "f11": UC_PPC_REG_FPR11,
    "f12": UC_PPC_REG_FPR12,
    "f13": UC_PPC_REG_FPR13,
    "f14": UC_PPC_REG_FPR14,
    "f15": UC_PPC_REG_FPR15,
    "f16": UC_PPC_REG_FPR16,
    "f17": UC_PPC_REG_FPR17,
    "f18": UC_PPC_REG_FPR18,
    "f19": UC_PPC_REG_FPR19,
    "f20": UC_PPC_REG_FPR20,
    "f21": UC_PPC_REG_FPR21,
    "f22": UC_PPC_REG_FPR22,
    "f23": UC_PPC_REG_FPR23,
    "f24": UC_PPC_REG_FPR24,
    "f25": UC_PPC_REG_FPR25,
    "f26": UC_PPC_REG_FPR26,
    "f27": UC_PPC_REG_FPR27,
    "f28": UC_PPC_REG_FPR28,
    "f29": UC_PPC_REG_FPR29,
    "f30": UC_PPC_REG_FPR30,
    "f31": UC_PPC_REG_FPR31,
}

class MSR(IntEnum):
    SF   = 1 << 63
    TAG  = 1 << 62
    ISF  = 1 << 61
    HV   = 1 << 60
    TS0  = 1 << 34
    TS1  = 1 << 33
    TM   = 1 << 32
    CM   = 1 << 31
    ICM  = 1 << 30
    GS   = 1 << 28
    UCLE = 1 << 26
    VR   = 1 << 25
    SPE  = 1 << 25
    AP   = 1 << 23
    VSX  = 1 << 23
    SA   = 1 << 22
    KEY  = 1 << 19
    POW  = 1 << 18
    TGPR = 1 << 17
    CE   = 1 << 17
    ILE  = 1 << 16
    EE   = 1 << 15
    PR   = 1 << 14
    FP   = 1 << 13
    ME   = 1 << 12
    FE0  = 1 << 11
    SE   = 1 << 10
    DWE  = 1 << 10
    UBLE = 1 << 10
    BE   = 1 << 9
    DE   = 1 << 9
    FE1  = 1 << 8
    AL   = 1 << 7
    EP   = 1 << 6
    IR   = 1 << 5
    DR   = 1 << 4
    IS   = 1 << 5
    DS   = 1 << 4
    PE   = 1 << 3
    PX   = 1 << 2
    PMM  = 1 << 2
    RI   = 1 << 1
    LE   = 1 << 0
