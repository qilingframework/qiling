#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#



class Arch:
    """
    base class for arch
    """
    def __init__(self):
        pass

    @property
    def archtype(self):
        return self.ql.archtype

    def read_insn(self, address: int , insn_size: int = 4):
        return self.read_mem(address, insn_size)
