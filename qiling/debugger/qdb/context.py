#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Optional

import unicorn
from unicorn import UC_ERR_READ_UNMAPPED

class Context:
    """
    base class for accessing context of running qiling instance
    """

    def __init__(self, ql):
        self.ql = ql
        self.unpack = ql.unpack
        self.unpack16 = ql.unpack16
        self.unpack32 = ql.unpack32

    @property
    def cur_addr(self):
        """
        program counter of qiling instance
        """

        return self.ql.reg.arch_pc

    def read_mem(self, address: int, size: int):
        """
        read data from memory of qiling instance
        """

        return self.ql.mem.read(address, size)

    def disasm(self, address: int, detail: bool = False) -> Optional[int]:
        """
        helper function for disassembling
        """

        md = self.ql.disassembler
        md.detail = detail

        return next(md.disasm(self.read_insn(address), address), None)

    def try_read(self, address: int, size: int) -> Optional[bytes]:
        """
        try to read data from ql.mem
        """

        result = None
        err_msg = ""
        try:
            result = self.read_mem(address, size)

        except unicorn.unicorn.UcError as err:
            if err.errno == UC_ERR_READ_UNMAPPED: # Invalid memory read (UC_ERR_READ_UNMAPPED)
                err_msg = f"Can not access memory at address 0x{address:08x}"

        except:
            pass

        return (result, err_msg)

    def try_read_pointer(self, address: int) -> Optional[bytes]:
        """
        try to read pointer size of data from ql.mem
        """

        return self.try_read(address, self.ql.pointersize)

    def read_string(self, address: int) -> Optional[str]:
        """
        read string from memory of qiling instance
        """

        return self.ql.mem.string(address)

    def try_read_string(self, address: int) -> Optional[str]:
        """
        try to read string from memory of qiling instance
        """

        s = None
        try:
            s = self.read_string(address)
        except:
            pass

if __name__ == "__main__":
    pass
