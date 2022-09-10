import unicorn
from qiling.arch import arm64, arm, x86



class ArchRegs():
    """
    Stores architecture's registers relevant to tracing in a format
    universally usable by different tracers
    """

    arm_registers = {
        '$r0': unicorn.arm_const.UC_ARM_REG_R0,
        '$r1': unicorn.arm_const.UC_ARM_REG_R1,
        '$r2': unicorn.arm_const.UC_ARM_REG_R2,
        '$r3': unicorn.arm_const.UC_ARM_REG_R3,
        '$r4': unicorn.arm_const.UC_ARM_REG_R4,
        '$r5': unicorn.arm_const.UC_ARM_REG_R5,
        '$r6': unicorn.arm_const.UC_ARM_REG_R6,
        '$r7': unicorn.arm_const.UC_ARM_REG_R7,
        '$r8': unicorn.arm_const.UC_ARM_REG_R8,
        '$r9': unicorn.arm_const.UC_ARM_REG_R9,
        '$r10': unicorn.arm_const.UC_ARM_REG_R10,
        '$r11': unicorn.arm_const.UC_ARM_REG_R11,
        '$r12': unicorn.arm_const.UC_ARM_REG_R12,
        '$sp': unicorn.arm_const.UC_ARM_REG_SP,
        '$lr': unicorn.arm_const.UC_ARM_REG_LR,
        '$pc': unicorn.arm_const.UC_ARM_REG_PC,
        '$cpsr': unicorn.arm_const.UC_ARM_REG_CPSR
    }
    arm64_registers = {
        "$pc": unicorn.arm64_const.UC_ARM64_REG_PC,
        "$sp": unicorn.arm64_const.UC_ARM64_REG_SP,
        "$x0": unicorn.arm64_const.UC_ARM64_REG_X0,
        "$x1": unicorn.arm64_const.UC_ARM64_REG_X1,
        "$x2": unicorn.arm64_const.UC_ARM64_REG_X2,
        "$x3": unicorn.arm64_const.UC_ARM64_REG_X3,
        "$x4": unicorn.arm64_const.UC_ARM64_REG_X4,
        "$x5": unicorn.arm64_const.UC_ARM64_REG_X5,
        "$x6": unicorn.arm64_const.UC_ARM64_REG_X6,
        "$x7": unicorn.arm64_const.UC_ARM64_REG_X7,
        "$x8": unicorn.arm64_const.UC_ARM64_REG_X8,
        "$x9": unicorn.arm64_const.UC_ARM64_REG_X9,
        "$x10": unicorn.arm64_const.UC_ARM64_REG_X10,
        "$x11": unicorn.arm64_const.UC_ARM64_REG_X11,
        "$x12": unicorn.arm64_const.UC_ARM64_REG_X12,
        "$x13": unicorn.arm64_const.UC_ARM64_REG_X13,
        "$x14": unicorn.arm64_const.UC_ARM64_REG_X14,
        "$x15": unicorn.arm64_const.UC_ARM64_REG_X15,
        "$x16": unicorn.arm64_const.UC_ARM64_REG_X16,
        "$x17": unicorn.arm64_const.UC_ARM64_REG_X17,
        "$x18": unicorn.arm64_const.UC_ARM64_REG_X18,
        "$x19": unicorn.arm64_const.UC_ARM64_REG_X19,
        "$x20": unicorn.arm64_const.UC_ARM64_REG_X20,
        "$x21": unicorn.arm64_const.UC_ARM64_REG_X21,
        "$x22": unicorn.arm64_const.UC_ARM64_REG_X22,
        "$x23": unicorn.arm64_const.UC_ARM64_REG_X23,
        "$x24": unicorn.arm64_const.UC_ARM64_REG_X24,
        "$x25": unicorn.arm64_const.UC_ARM64_REG_X25,
        "$x26": unicorn.arm64_const.UC_ARM64_REG_X26,
        "$x27": unicorn.arm64_const.UC_ARM64_REG_X27,
        "$x28": unicorn.arm64_const.UC_ARM64_REG_X28,
        "$x29": unicorn.arm64_const.UC_ARM64_REG_X29,
    }

    x86_registers = {
        '$eax': unicorn.x86_const.UC_X86_REG_EAX,
        '$ebx': unicorn.x86_const.UC_X86_REG_EBX,
        '$ecx': unicorn.x86_const.UC_X86_REG_ECX,
        '$edx': unicorn.x86_const.UC_X86_REG_ECX,
        '$ebp': unicorn.x86_const.UC_X86_REG_EBP,
        '$esp': unicorn.x86_const.UC_X86_REG_ESP,
        '$esi': unicorn.x86_const.UC_X86_REG_ESI,
        '$edi': unicorn.x86_const.UC_X86_REG_EDI,
        '$eip': unicorn.x86_const.UC_X86_REG_EIP,
    }
    x86_64_registers = {
        '$rax': unicorn.x86_const.UC_X86_REG_RAX ,
        '$rbx': unicorn.x86_const.UC_X86_REG_RBX,
        '$rcx': unicorn.x86_const.UC_X86_REG_RCX,
        '$rdx': unicorn.x86_const.UC_X86_REG_RCX,
        '$rbp': unicorn.x86_const.UC_X86_REG_RBP,
        '$rsp': unicorn.x86_const.UC_X86_REG_RSP,
        '$rsi': unicorn.x86_const.UC_X86_REG_RSI,
        '$rdi': unicorn.x86_const.UC_X86_REG_RDI,
        '$rip': unicorn.x86_const.UC_X86_REG_RIP,
        '$r8': unicorn.x86_const.UC_X86_REG_R8,
        '$r9': unicorn.x86_const.UC_X86_REG_R9,
        '$r10': unicorn.x86_const.UC_X86_REG_R10,
        '$r11': unicorn.x86_const.UC_X86_REG_R11,
        '$r12': unicorn.x86_const.UC_X86_REG_R12,
        '$r13': unicorn.x86_const.UC_X86_REG_R13,
        '$r14': unicorn.x86_const.UC_X86_REG_R14,
        '$r15': unicorn.x86_const.UC_X86_REG_R15,
    }

    def __init__(self, arch):
        if isinstance(arch, arm.QlArchARM):
            self.registers = self.arm_registers
            self.pc_key = "$pc"
        elif isinstance(arch,arm64.QlArchARM64):
            self.registers = self.arm64_registers
            self.pc_key = "$pc"
        elif isinstance(arch,x86.QlArchX86):
            self.registers = self.x86_registers
            self.pc_key = "$eip"
        elif isinstance(arch,x86.QlArchX8664):
            self.registers = self.x86_64_registers
            self.pc_key = "$rip"
        else:
            raise("Unsupported arch")
