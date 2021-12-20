#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn.arm_const import *
from enum import IntEnum

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

    # cortex-M Special Register
    "msp": UC_ARM_REG_MSP,
    "psp": UC_ARM_REG_PSP,
    "xpsr": UC_ARM_REG_XPSR,    
    "apsr": UC_ARM_REG_APSR,
    "ipsr": UC_ARM_REG_IPSR,
    "epsr": UC_ARM_REG_EPSR,
    "primask": UC_ARM_REG_PRIMASK,
    "faultmask": UC_ARM_REG_FAULTMASK,
    "basepri": UC_ARM_REG_BASEPRI,
    "control": UC_ARM_REG_CONTROL,

    "xpsr_nzcvqg": UC_ARM_REG_XPSR_NZCVQG,
}

class IRQ(IntEnum):
    NMI = -14
    HARD_FAULT = -13
    MEMORY_MANAGEMENT_FAULT = -12
    BUS_FAULT = -11
    USAGE_FAULT = -10
    SVCALL = -5
    PENDSV = -2
    SYSTICK = -1
    NOTHING = 0

class CONTROL(IntEnum):
    FPCA  = 0b100
    SPSEL = 0b010
    PRIV  = 0b001

class EXC_RETURN(IntEnum):
    MASK        = 0xfffffff0
    RETURN_SP   = 0b0100
    RETURN_MODE = 0b1000

class EXCP(IntEnum):
    UDEF           =  1   # undefined instruction
    SWI            =  2   # software interrupt
    PREFETCH_ABORT =  3
    DATA_ABORT     =  4
    IRQ            =  5
    FIQ            =  6
    BKPT           =  7
    EXCEPTION_EXIT =  8   # Return from v7M exception. 
    KERNEL_TRAP    =  9   # Jumped to kernel code page. 
    HVC            = 11   # HyperVisor Call
    HYP_TRAP       = 12
    SMC            = 13   # Secure Monitor Call
    VIRQ           = 14
    VFIQ           = 15
    SEMIHOST       = 16   # semihosting call
    NOCP           = 17   # v7M NOCP UsageFault
    INVSTATE       = 18   # v7M INVSTATE UsageFault
    STKOF          = 19   # v8M STKOF UsageFault
    LAZYFP         = 20   # v7M fault during lazy FP stacking
    LSERR          = 21   # v8M LSERR SecureFault
    UNALIGNED      = 22   # v7M UNALIGNED UsageFault
