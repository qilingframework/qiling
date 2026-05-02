#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from unicorn.arm64_const import (
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X8, UC_ARM64_REG_X16
)

from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R7, UC_ARM_REG_R12
)

from qiling.os.posix.syscall.abi import QlSyscallABI


class QlAArch32(QlSyscallABI):
    """System call ABI for ARM-based systems.
    """

    _idreg = UC_ARM_REG_R7
    _argregs = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5)
    _retreg = UC_ARM_REG_R0

    def get_id(self) -> int:
        # the syscall number of a svc / swi instruction needs to be manually extracted.
        # here we read the instruction we have just emulated and extract the immediate
        # number by masking off the the opcode

        isize = 2 if self.arch.is_thumb else self.arch.pointersize
        ibytes = self.arch.utils.ql.mem.read_ptr(self.arch.regs.arch_pc - isize, isize)

        # mask off the opcode, which is the most significant byte
        svc_imm = ibytes & ((1 << ((isize - 1) * 8)) - 1)

        # arm-oabi
        if svc_imm >= 0x900000:
            return svc_imm - 0x900000

        if svc_imm > 0:
            return svc_imm

        return super().get_id()


class QlAArch32QNX(QlAArch32):
    """QNX ABI override
    """

    _idreg = UC_ARM_REG_R12


class QlAArch64(QlSyscallABI):
    """System call ABI for ARM64-based systems.
    """

    _idreg = UC_ARM64_REG_X8
    _argregs = (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5)
    _retreg = UC_ARM64_REG_X0


class QlAArch64MacOS(QlAArch64):
    """MacOS ABI override
    """

    _idreg = UC_ARM64_REG_X16
