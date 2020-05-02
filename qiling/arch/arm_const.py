#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn.arm_const import *

reg_map = {
            "R0": UC_ARM_REG_R0,
            "R1": UC_ARM_REG_R1, 
            "R2": UC_ARM_REG_R2,
            "R3": UC_ARM_REG_R3, 
            "R4": UC_ARM_REG_R4,
            "R5": UC_ARM_REG_R5,
            "R6": UC_ARM_REG_R6, 
            "R7": UC_ARM_REG_R7, 
            "R8": UC_ARM_REG_R8,
            "R9": UC_ARM_REG_R9, 
            "R10": UC_ARM_REG_R10, 
            "R11": UC_ARM_REG_R11,
            "R12": UC_ARM_REG_R12, 
            "SP": UC_ARM_REG_SP, 
            "LR": UC_ARM_REG_LR,
            "PC": UC_ARM_REG_PC, 
            "CPSR": UC_ARM_REG_CPSR,
}