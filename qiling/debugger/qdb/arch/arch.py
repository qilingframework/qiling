#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#



class Arch:
    """
    base class for arch
    """
    def __init__(self, ql):
        self.ql = ql
        self.default_insn_size = 4

    @property
    def archtype(self):
        return self.ql.archtype

    def read_insn(self, address: int):
        return self.read_mem(address, self.default_insn_size)
