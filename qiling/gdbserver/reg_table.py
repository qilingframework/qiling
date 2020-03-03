#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from unicorn.arm64_const import *
from unicorn.arm_const import *
from unicorn.mips_const import *
from unicorn.x86_const import *
from qiling.arch.filetype import *

registers_x86 = [
    UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_EBX, UC_X86_REG_ESP, UC_X86_REG_EBP,
    UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EIP,
    UC_X86_REG_EFLAGS, UC_X86_REG_CS, UC_X86_REG_SS,
    UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_FS,
    UC_X86_REG_GS, UC_X86_REG_ST0, UC_X86_REG_ST1,
    UC_X86_REG_ST2, UC_X86_REG_ST3, UC_X86_REG_ST4,
    UC_X86_REG_ST5, UC_X86_REG_ST6, UC_X86_REG_ST7
]

registers_x8664 = [
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX,
    UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_RDI,
    UC_X86_REG_RBP, UC_X86_REG_RSP, UC_X86_REG_R8,
    UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
    UC_X86_REG_R15, UC_X86_REG_RIP, UC_X86_REG_EFLAGS,
    UC_X86_REG_CS, UC_X86_REG_SS, UC_X86_REG_DS,
    UC_X86_REG_ES, UC_X86_REG_FS, UC_X86_REG_GS,
    UC_X86_REG_ST0, UC_X86_REG_ST1,
    UC_X86_REG_ST2, UC_X86_REG_ST3, UC_X86_REG_ST4,
    UC_X86_REG_ST5, UC_X86_REG_ST6, UC_X86_REG_ST7
]

registers_arm = [
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
    UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
    UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8,
    UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
    UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR,
    UC_ARM_REG_PC, UC_ARM_REG_CPSR
]

arch_reg = {QL_X86: registers_x86, QL_X8664: registers_x8664, QL_ARM: registers_arm}


