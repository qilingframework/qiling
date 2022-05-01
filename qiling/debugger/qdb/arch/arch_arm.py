#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Mapping

from .arch import Arch

class ArchARM(Arch):
    def __init__(self):
        super().__init__()

    @property
    def regs(self):
        return (
                "r0", "r1", "r2", "r3",
                "r4", "r5", "r6", "r7",
                "r8", "r9", "r10", "r11",
                "r12", "sp", "lr", "pc",
                )

    @property
    def regs_need_swapped(self):
        return {
                "sl": "r10",
                "ip": "r12",
                "fp": "r11",
                }

    @staticmethod
    def get_flags(bits: int) -> Mapping[str, bool]:
        """
        get flags for ARM
        """

        def get_mode(bits: int) -> int:
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

    @property
    def thumb_mode(self) -> bool:
        """
        helper function for checking thumb mode
        """

        return self.ql.arch.is_thumb


    def read_insn(self, address: int) -> bytes:
        """
        read instruction depending on current operating mode
        """

        def thumb_read(address: int) -> bytes:

            first_two = self.ql.mem.read_ptr(address, 2)
            result = self.ql.pack16(first_two)

            # to judge it's thumb mode or not
            if any([
                first_two & 0xf000 == 0xf000,
                first_two & 0xf800 == 0xf800,
                first_two & 0xe800 == 0xe800,
                 ]):

                latter_two = self.ql.mem.read_ptr(address+2, 2)
                result += self.ql.pack16(latter_two)

            return result

        return super().read_insn(address) if not self.thumb_mode else thumb_read(address)



class ArchCORTEX_M(ArchARM):
    def __init__(self):
        super().__init__()
        self.regs += ("xpsr", "control", "primask", "basepri", "faultmask")
