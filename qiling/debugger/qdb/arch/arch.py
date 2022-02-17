#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#



class Arch:
    """
    base class for arch
    """

    _SUPPORTED_ARCH = ["ArchARM", "ArchCORTEX_M", "ArchMIPS", "ArchX86"]

    # FIXME: this is a dirty hack for setup archtype at initialization phase
    @staticmethod
    def set_archtype(self):
        for archtype in self._SUPPORTED_ARCH:
            for each_type in type(self).mro():
                if archtype in str(each_type):
                    return archtype

    def __init__(self):
        self.arch_insn_size = 4
        self.archtype = self.set_archtype(self)

    def read_insn(self, address: int):
        return self.read_mem(address, self.arch_insn_size)
