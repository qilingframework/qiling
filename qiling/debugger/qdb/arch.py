#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import Callable, Optional, Mapping

from qiling.const import QL_ARCH


class ArchX86():
    def __init__(self):

        self.archtype = QL_ARCH.X86

        self.regs = (
                "eax", "ebx", "ecx", "edx",
                "esp", "ebp", "esi", "edi",
                "eip", "ss", "cs", "ds", "es",
                "fs", "gs", "ef",
                )

    @staticmethod
    def get_flags(bits: int) -> Mapping[str, bool]:
        """
        get flags from ql.reg.ef
        """

        return {
                "CF" : bits & 0x0001 != 0, # CF, carry flag
                "PF" : bits & 0x0004 != 0, # PF, parity flag
                "AF" : bits & 0x0010 != 0, # AF, adjust flag
                "ZF" : bits & 0x0040 != 0, # ZF, zero flag
                "SF" : bits & 0x0080 != 0, # SF, sign flag
                "OF" : bits & 0x0800 != 0, # OF, overflow flag
                }


class ArchMIPS(object):
    def __init__(self):

        self.archtype = QL_ARCH.MIPS

        self.regs = (
                "gp", "at", "v0", "v1",
                "a0", "a1", "a2", "a3",
                "t0", "t1", "t2", "t3",
                "t4", "t5", "t6", "t7",
                "t8", "t9", "sp", "s8",
                "s0", "s1", "s2", "s3",
                "s4", "s5", "s6", "s7",
                "ra", "k0", "k1", "pc",
                )

        self.regs_need_swaped = {
                "fp": "s8",
                }


class ArchARM():
    def __init__(self):
        self.archtype = QL_ARCH.ARM
        self.regs = (
                "r0", "r1", "r2", "r3",
                "r4", "r5", "r6", "r7",
                "r8", "r9", "r10", "r11",
                "r12", "sp", "lr", "pc",
                )

        self.regs_need_swaped = {
                "sl": "r10",
                "ip": "r12",
                "fp": "r11",
                }

    @staticmethod
    def get_flags(bits: int) -> Mapping[str, int]:
        """
        get flags for ARM
        """

        def get_mode(bits):
            """
            get operating mode for ARM
            """
            return {
                    0b10000: "User",
                    0b10001: "FIQ",
                    0b10010: "IRQ",
                    0b10011: "Supervisor",
                    0b10110: "Monitor",
                    0b10111: "Abort",
                    0b11010: "Hypervisor",
                    0b11011: "Undefined",
                    0b11111: "System",
                    }.get(bits & 0x00001f)

        return {
                "mode":     get_mode(bits),
                "thumb":    bits & 0x00000020 != 0,
                "fiq":      bits & 0x00000040 != 0,
                "irq":      bits & 0x00000080 != 0,
                "neg":      bits & 0x80000000 != 0,
                "zero":     bits & 0x40000000 != 0,
                "carry":    bits & 0x20000000 != 0,
                "overflow": bits & 0x10000000 != 0,
                }


class ArchCORTEX_M(ArchARM):
    def __init__(self):
        super().__init__()
        self.archtype = QL_ARCH.CORTEX_M
        self.regs += ("xpsr", "control", "primask", "basepri", "faultmask")

if __name__ == "__main__":
    pass
