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

QL_X86_GDT_ADDR_PADDING = 0xe0000000
QL_X8664_GDT_ADDR_PADDING = 0x7effffff00000000

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

reg_r_map_8 = {
    UC_X86_REG_AH: "ah",
    UC_X86_REG_AL: "al",
    UC_X86_REG_CH: "ch",
    UC_X86_REG_CL: "cl",
    UC_X86_REG_DH: "dh",
    UC_X86_REG_DL: "dl",
    UC_X86_REG_BH: "bh",
    UC_X86_REG_BL: "bl",
}

reg_8 = [
    UC_X86_REG_AH,
    UC_X86_REG_AL,
    UC_X86_REG_CH,
    UC_X86_REG_CL,
    UC_X86_REG_DH,
    UC_X86_REG_DL,
    UC_X86_REG_BH,
    UC_X86_REG_BL,
]

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

reg_r_map_16 = {
    UC_X86_REG_AX: "ax",
    UC_X86_REG_CX: "cx",
    UC_X86_REG_DX: "dx",
    UC_X86_REG_BX: "bx",
    UC_X86_REG_SP: "sp",
    UC_X86_REG_BP: "bp",
    UC_X86_REG_SI: "si",
    UC_X86_REG_DI: "di",
    UC_X86_REG_IP: "ip",
}

reg_16 = {
    UC_X86_REG_AX,
    UC_X86_REG_CX,
    UC_X86_REG_DX,
    UC_X86_REG_BX,
    UC_X86_REG_SP,
    UC_X86_REG_BP,
    UC_X86_REG_SI,
    UC_X86_REG_DI,
    UC_X86_REG_IP,
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

reg_r_map_32 = {
    UC_X86_REG_EAX: "eax",  
    UC_X86_REG_ECX: "ecx",  
    UC_X86_REG_EDX: "edx", 
    UC_X86_REG_EBX: "ebx",  
    UC_X86_REG_ESP: "esp",  
    UC_X86_REG_EBP: "ebp", 
    UC_X86_REG_ESI: "esi",  
    UC_X86_REG_EDI: "edi",  
    UC_X86_REG_EIP: "eip", 
}

reg_32 = {
    UC_X86_REG_EAX, 
    UC_X86_REG_ECX, 
    UC_X86_REG_EDX,
    UC_X86_REG_EBX, 
    UC_X86_REG_ESP, 
    UC_X86_REG_EBP,
    UC_X86_REG_ESI, 
    UC_X86_REG_EDI, 
    UC_X86_REG_EIP,
}

reg_map_64 = {
    "rax": UC_X86_REG_RAX, 
    "rcx": UC_X86_REG_RCX, 
    "rdx": UC_X86_REG_RDX,
    "rbx": UC_X86_REG_RBX, 
    "rsp": UC_X86_REG_RSP, 
    "rbp": UC_X86_REG_RBP,
    "rsi": UC_X86_REG_RSI, 
    "rdi": UC_X86_REG_RDI, 
    "rip": UC_X86_REG_RIP,
    "r8": UC_X86_REG_R8,
    "r9": UC_X86_REG_R9, 
    "r10": UC_X86_REG_R10,
    "r11": UC_X86_REG_R11,
    "r12": UC_X86_REG_R12, 
    "r13": UC_X86_REG_R13, 
    "r14": UC_X86_REG_R14,
    "r15": UC_X86_REG_R15,
}

reg_r_map_64 = {
    UC_X86_REG_RAX: "rax",  
    UC_X86_REG_RCX: "rcx",  
    UC_X86_REG_RDX: "rdx", 
    UC_X86_REG_RBX: "rbx",  
    UC_X86_REG_RSP: "rsp",  
    UC_X86_REG_RBP: "rbp", 
    UC_X86_REG_RSI: "rsi",  
    UC_X86_REG_RDI: "rdi",  
    UC_X86_REG_RIP: "rip", 
    UC_X86_REG_R8: "r8", 
    UC_X86_REG_R9: "r9",  
    UC_X86_REG_R10: "r10", 
    UC_X86_REG_R11: "r11", 
    UC_X86_REG_R12: "r12",  
    UC_X86_REG_R13: "r13",  
    UC_X86_REG_R14: "r14", 
    UC_X86_REG_R15: "r15", 
}

reg_64 = {
    UC_X86_REG_RAX, 
    UC_X86_REG_RCX, 
    UC_X86_REG_RDX,
    UC_X86_REG_RBX, 
    UC_X86_REG_RSP, 
    UC_X86_REG_RBP,
    UC_X86_REG_RSI, 
    UC_X86_REG_RDI, 
    UC_X86_REG_RIP,
    UC_X86_REG_R8,
    UC_X86_REG_R9, 
    UC_X86_REG_R10,
    UC_X86_REG_R11,
    UC_X86_REG_R12, 
    UC_X86_REG_R13, 
    UC_X86_REG_R14,
    UC_X86_REG_R15,
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

reg_r_map_cr = {
    UC_X86_REG_CR0: "cr0", 
    UC_X86_REG_CR1: "cr1",
    UC_X86_REG_CR2: "cr2", 
    UC_X86_REG_CR3: "cr3", 
    UC_X86_REG_CR4: "cr4",
    UC_X86_REG_CR5: "cr5", 
    UC_X86_REG_CR6: "cr6", 
    UC_X86_REG_CR7: "cr7",
    UC_X86_REG_CR8: "cr8",
    UC_X86_REG_CR9: "cr9",
    UC_X86_REG_CR10: "cr10",
    UC_X86_REG_CR11: "cr11",
    UC_X86_REG_CR12: "cr12",
    UC_X86_REG_CR13: "cr13",
    UC_X86_REG_CR14: "cr14",
    UC_X86_REG_CR15: "cr15",
}

reg_cr = {
    UC_X86_REG_CR0, 
    UC_X86_REG_CR1,
    UC_X86_REG_CR2, 
    UC_X86_REG_CR3, 
    UC_X86_REG_CR4,
    UC_X86_REG_CR5, 
    UC_X86_REG_CR6, 
    UC_X86_REG_CR7,
    UC_X86_REG_CR8,
    UC_X86_REG_CR9,
    UC_X86_REG_CR10,
    UC_X86_REG_CR11,
    UC_X86_REG_CR12,
    UC_X86_REG_CR13,
    UC_X86_REG_CR14,
    UC_X86_REG_CR15,
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

reg_r_map_dr = {
    UC_X86_REG_DR0: "dr0", 
    UC_X86_REG_DR1: "dr1",
    UC_X86_REG_DR2: "dr2", 
    UC_X86_REG_DR3: "dr3", 
    UC_X86_REG_DR4: "dr4",
    UC_X86_REG_DR5: "dr5", 
    UC_X86_REG_DR6: "dr6", 
    UC_X86_REG_DR7: "dr7",
    UC_X86_REG_DR8: "dr8",
    UC_X86_REG_DR9: "dr9",
    UC_X86_REG_DR10: "dr10",
    UC_X86_REG_DR11: "dr11",
    UC_X86_REG_DR12: "dr12",
    UC_X86_REG_DR13: "dr13",
    UC_X86_REG_DR14: "dr14",
    UC_X86_REG_DR15: "dr15",
}

reg_dr = {
    UC_X86_REG_DR0, 
    UC_X86_REG_DR1,
    UC_X86_REG_DR2, 
    UC_X86_REG_DR3, 
    UC_X86_REG_DR4,
    UC_X86_REG_DR5, 
    UC_X86_REG_DR6, 
    UC_X86_REG_DR7,
    UC_X86_REG_DR8,
    UC_X86_REG_DR9,
    UC_X86_REG_DR10,
    UC_X86_REG_DR11,
    UC_X86_REG_DR12,
    UC_X86_REG_DR13,
    UC_X86_REG_DR14,
    UC_X86_REG_DR15,
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

reg_r_map_st = {
    UC_X86_REG_ST0: "st0", 
    UC_X86_REG_ST1: "st1",
    UC_X86_REG_ST2: "st2", 
    UC_X86_REG_ST3: "st3", 
    UC_X86_REG_ST4: "st4",
    UC_X86_REG_ST5: "st5", 
    UC_X86_REG_ST6: "st6", 
    UC_X86_REG_ST7: "st7"
    }

reg_st = {
    UC_X86_REG_ST0, 
    UC_X86_REG_ST1,
    UC_X86_REG_ST2, 
    UC_X86_REG_ST3, 
    UC_X86_REG_ST4,
    UC_X86_REG_ST5, 
    UC_X86_REG_ST6, 
    UC_X86_REG_ST7
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

reg_r_map_misc = {
    UC_X86_REG_EFLAGS: "ef",
    UC_X86_REG_CS: "cs", 
    UC_X86_REG_SS: "ss",
    UC_X86_REG_DS: "ds", 
    UC_X86_REG_ES: "es", 
    UC_X86_REG_FS: "fs",
    UC_X86_REG_GS: "gs", 
}

reg_misc = {
    UC_X86_REG_EFLAGS, 
    UC_X86_REG_CS, 
    UC_X86_REG_SS,
    UC_X86_REG_DS, 
    UC_X86_REG_ES, 
    UC_X86_REG_FS,
    UC_X86_REG_GS, 
}

reg_map_xmm = {

}

reg_map_ymm = {

}

reg_map_zmm = {

}

