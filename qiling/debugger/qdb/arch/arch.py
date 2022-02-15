#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations


class Arch(object):
    """
    base class for arch
    """
    def __init__(self: Arch):
        pass

    @property
    def archtype(self: Arch):
        return self.ql.archtype

    def read_insn(self: Arch, address: int , insn_size: int = 4):
        return self.read_mem(address, insn_size)

if __name__ == "__main__":
    pass
