#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#



from .arch import Arch

class ArchMIPS(Arch):
    def __init__(self):
        super().__init__()

    @property
    def regs(self):
        return (
                "gp", "at", "v0", "v1",
                "a0", "a1", "a2", "a3",
                "t0", "t1", "t2", "t3",
                "t4", "t5", "t6", "t7",
                "t8", "t9", "sp", "s8",
                "s0", "s1", "s2", "s3",
                "s4", "s5", "s6", "s7",
                "ra", "k0", "k1", "pc",
                )

    @property
    def regs_need_swapped(self):
        return {
                "fp": "s8",
                }
