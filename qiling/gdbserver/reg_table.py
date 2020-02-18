from unicorn.arm64_const import *
from unicorn.arm_const import *
from unicorn.mips_const import *
from unicorn.x86_const import *
from qiling.arch.filetype import *

registers_X86 = [
    UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_EBX, UC_X86_REG_ESP, UC_X86_REG_EBP,
    UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EIP,
    UC_X86_REG_EFLAGS, UC_X86_REG_CS, UC_X86_REG_SS,
    UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_FS,
    UC_X86_REG_GS
]

registers_X8664 = [
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX,
    UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_RDI,
    UC_X86_REG_RBP, UC_X86_REG_RSP, UC_X86_REG_R8,
    UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
    UC_X86_REG_R15, UC_X86_REG_RIP
]

registers_Segment = [
    UC_X86_REG_EFLAGS,
    UC_X86_REG_CS, UC_X86_REG_SS, UC_X86_REG_DS,
    UC_X86_REG_ES, UC_X86_REG_FS, UC_X86_REG_GS
]

arch_reg = {QL_X86: registers_X86, QL_X8664: registers_X8664}


def get_pc(arch):
    if arch == QL_X86:
        return UC_X86_REG_EIP
    elif arch == QL_X8664:
        return UC_X86_REG_RIP
    elif arch == QL_ARM:
        return UC_ARM_REG_PC
    elif arch == QL_ARM_THUMB:
        return UC_ARM_REG_PC
    elif arch == QL_ARM64:
        return UC_ARM64_REG_PC
    elif arch == QL_MIPS32EL:
        return UC_MIPS_REG_PC
