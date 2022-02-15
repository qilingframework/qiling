#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import Callable, Optional, Mapping
import os

from qiling.const import QL_ARCH
import unicorn


class Breakpoint(object):
    """
    dummy class for breakpoint
    """
    def __init__(self, addr):
        self.addr = addr
        self.hitted = False

class TempBreakpoint(Breakpoint):
    """
    dummy class for temporay breakpoint
    """
    def __init__(self, addr):
        super().__init__(addr)


def get_terminal_size() -> Iterable:
    """
    get terminal window height and width
    """
    return map(int, os.popen('stty size', 'r').read().split())


def try_read(ql: Qiling, address: int, size: int) -> Optional[bytes]:
    """
    try to read data from ql.mem
    """

    result = None
    err_msg = ""
    try:
        result = ql.mem.read(address, size)

    except unicorn.unicorn.UcError as err:
        if err.errno == 6: # Invalid memory read (UC_ERR_READ_UNMAPPED)
            err_msg = f"Can not access memory at address 0x{address:08x}"

    except:
        pass

    return (result, err_msg)


def read_int(s: str) -> int:
    """
    parse unsigned integer from string
    """
    return int(s, 0)


def parse_int(func: Callable) -> Callable:
    """
    function dectorator for parsing argument as integer
    """
    def wrap(qdb, s: str = "") -> int:
        assert type(s) is str
        try:
            ret = read_int(s)
        except:
            ret = None
        return func(qdb, ret)
    return wrap


def is_thumb(bits: int) -> bool:
    """
    helper function for checking thumb mode
    """

    return bits & 0x00000020 != 0


def disasm(ql: Qiling, address: int, detail: bool = False) -> Optional[int]:
    """
    helper function for disassembling
    """

    md = ql.disassembler
    md.detail = detail
    try:
        ret = next(md.disasm(read_insn(ql, address), address))

    except StopIteration:
        ret = None

    return ret


def read_insn(ql: Qiling, addr: int) -> int:
    """
    read instruction from running qiling instance 
    """
    result = ql.mem.read(addr, 4)

    if ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB, QL_ARCH.CORTEX_M):
        if is_thumb(ql.reg.cpsr):

            first_two = ql.unpack16(ql.mem.read(addr, 2))
            result = ql.pack16(first_two)

            # to judge whether it's thumb mode or not
            if any([
                first_two & 0xf000 == 0xf000,
                first_two & 0xf800 == 0xf800,
                first_two & 0xe800 == 0xe800,
                 ]):

                latter_two = ql.unpack16(ql.mem.read(addr+2, 2))
                result += ql.pack16(latter_two)

    elif ql.archtype in (QL_ARCH.X86, QL_ARCH.X8664):
        # due to the variadic lengh of x86 instructions ( 1~15 )
        # always assume the maxium size for disassembler to tell
        # what is it exactly.
        result = ql.mem.read(addr, 15)

    return result

if __name__ == "__main__":
    pass
