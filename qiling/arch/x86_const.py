#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn.x86_const import *

QL_X86_F_GRANULARITY = 0x8
QL_X86_F_PROT_32 = 0x4
QL_X86_F_LONG = 0x2
QL_X86_F_AVAILABLE = 0x1

QL_X86_A_PRESENT = 0x80

QL_X86_A_PRIV_3 = 0x60
QL_X86_A_PRIV_2 = 0x40
QL_X86_A_PRIV_1 = 0x20
QL_X86_A_PRIV_0 = 0x0

QL_X86_A_CODE = 0x10
QL_X86_A_DATA = 0x10
QL_X86_A_TSS = 0x0
QL_X86_A_GATE = 0x0
QL_X86_A_EXEC = 0x8

QL_X86_A_DATA_WRITABLE = 0x2
QL_X86_A_CODE_READABLE = 0x2
QL_X86_A_DIR_CON_BIT = 0x4

QL_X86_S_GDT = 0x0
QL_X86_S_LDT = 0x4
QL_X86_S_PRIV_3 = 0x3
QL_X86_S_PRIV_2 = 0x2
QL_X86_S_PRIV_1 = 0x1
QL_X86_S_PRIV_0 = 0x0

QL_X86_GDT_ADDR = 0x3000
QL_X86_GDT_LIMIT = 0x1000
QL_X86_GDT_ENTRY_SIZE = 0x8

# These msr registers are x86 specific
FSMSR = 0xC0000100
GSMSR = 0xC0000101

# WINDOWS SETUP VALUE
GS_SEGMENT_ADDR = 0x6000
GS_SEGMENT_SIZE = 0x6000

FS_SEGMENT_ADDR = 0x6000
FS_SEGMENT_SIZE = 0x6000


reg_map_8 = {
    "ah": UC_X86_REG_AH,
    "al": UC_X86_REG_AL,
    "ch": UC_X86_REG_CH,
    "cl": UC_X86_REG_CL,
    "dh": UC_X86_REG_DH,
    "dl": UC_X86_REG_DL,
    "bh": UC_X86_REG_BH,
    "bl": UC_X86_REG_BL,
}

reg_map_16 = {
    "ax": UC_X86_REG_AX,
    "cx": UC_X86_REG_CX,
    "dx": UC_X86_REG_DX,
    "bx": UC_X86_REG_BX,
    "sp": UC_X86_REG_SP,
    "bp": UC_X86_REG_BP,
    "si": UC_X86_REG_SI,
    "di": UC_X86_REG_DI,
    "ip": UC_X86_REG_IP,
}

reg_map_32 = {
    "eax": UC_X86_REG_EAX, 
    "ecx": UC_X86_REG_ECX, 
    "edx": UC_X86_REG_EDX,
    "ebx": UC_X86_REG_EBX,
    "esp": UC_X86_REG_ESP, 
    "ebp": UC_X86_REG_EBP,
    "esi": UC_X86_REG_ESI, 
    "edi": UC_X86_REG_EDI, 
    "eip": UC_X86_REG_EIP,
}

reg_map_64 = {
    "rax": UC_X86_REG_RAX,
    "rbx": UC_X86_REG_RBX, 
    "rcx": UC_X86_REG_RCX, 
    "rdx": UC_X86_REG_RDX,
    "rsi": UC_X86_REG_RSI, 
    "rdi": UC_X86_REG_RDI,
    "rbp": UC_X86_REG_RBP,
    "rsp": UC_X86_REG_RSP, 
    "r8": UC_X86_REG_R8,
    "r9": UC_X86_REG_R9, 
    "r10": UC_X86_REG_R10,
    "r11": UC_X86_REG_R11,
    "r12": UC_X86_REG_R12, 
    "r13": UC_X86_REG_R13, 
    "r14": UC_X86_REG_R14,
    "r15": UC_X86_REG_R15,
    "rip": UC_X86_REG_RIP,
}

reg_map_cr = {
    "cr0": UC_X86_REG_CR0, 
    "cr1": UC_X86_REG_CR1,
    "cr2": UC_X86_REG_CR2, 
    "cr3": UC_X86_REG_CR3, 
    "cr4": UC_X86_REG_CR4,
    "cr5": UC_X86_REG_CR5, 
    "cr6": UC_X86_REG_CR6, 
    "cr7": UC_X86_REG_CR7,
    "cr8": UC_X86_REG_CR8,
    "cr9": UC_X86_REG_CR9,
    "cr10": UC_X86_REG_CR10,
    "cr11": UC_X86_REG_CR11,
    "cr12": UC_X86_REG_CR12,
    "cr13": UC_X86_REG_CR13,
    "cr14": UC_X86_REG_CR14,
    "cr15": UC_X86_REG_CR15,
}

reg_map_dr = {
    "dr0": UC_X86_REG_DR0, 
    "dr1": UC_X86_REG_DR1,
    "dr2": UC_X86_REG_DR2, 
    "dr3": UC_X86_REG_DR3, 
    "dr4": UC_X86_REG_DR4,
    "dr5": UC_X86_REG_DR5, 
    "dr6": UC_X86_REG_DR6, 
    "dr7": UC_X86_REG_DR7,
    "dr8": UC_X86_REG_DR8,
    "dr9": UC_X86_REG_DR9,
    "dr10": UC_X86_REG_DR10,
    "dr11": UC_X86_REG_DR11,
    "dr12": UC_X86_REG_DR12,
    "dr13": UC_X86_REG_DR13,
    "dr14": UC_X86_REG_DR14,
    "dr15": UC_X86_REG_DR15,
}

reg_map_st = {
    "st0": UC_X86_REG_ST0, 
    "st1": UC_X86_REG_ST1,
    "st2": UC_X86_REG_ST2, 
    "st3": UC_X86_REG_ST3, 
    "st4": UC_X86_REG_ST4,
    "st5": UC_X86_REG_ST5, 
    "st6": UC_X86_REG_ST6, 
    "st7": UC_X86_REG_ST7
}

reg_map_misc = {
    "ef" :UC_X86_REG_EFLAGS, 
    "cs": UC_X86_REG_CS, 
    "ss": UC_X86_REG_SS,
    "ds": UC_X86_REG_DS, 
    "es": UC_X86_REG_ES, 
    "fs": UC_X86_REG_FS,
    "gs": UC_X86_REG_GS, 
}

reg_map_xmm = {

}

reg_map_ymm = {

}

reg_map_zmm = {

}

