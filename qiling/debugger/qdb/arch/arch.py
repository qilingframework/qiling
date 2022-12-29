#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from qiling.const import QL_ARCH
from unicorn import UC_ERR_READ_UNMAPPED
import unicorn


class Arch:
    """
    base class for arch
    """

    def __init__(self):
        pass

    @property
    def arch_insn_size(self):
        return 4

    @property
    def archbit(self):
        return 4

    def read_insn(self, address: int):
        try:
            result = self.read_mem(address, self.arch_insn_size)
        except unicorn.unicorn.UcError as err:
            result = None

        return result
