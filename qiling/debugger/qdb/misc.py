#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import Callable, Optional, Mapping
import os

from qiling.const import QL_ARCH
import unicorn



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


def is_negative(i: int) -> int:
    """
    check wether negative value or not
    """
    return i & (1 << 31)


def signed_val(val: int) -> int:
    """
    signed value convertion
    """
    return (val-1 << 32) if is_negative(val) else val


def get_cpsr(bits: int) -> (bool, bool, bool, bool):
    """
    get flags from ql.reg.cpsr
    """
    return (
            bits & 0x10000000 != 0, # V, overflow flag
            bits & 0x20000000 != 0, # C, carry flag
            bits & 0x40000000 != 0, # Z, zero flag
            bits & 0x80000000 != 0, # N, sign flag
            )


def is_thumb(bits: int) -> bool:
    """
    helper function for checking thumb mode
    """

    return bits & 0x00000020 != 0


def get_x86_eflags(bits: int) -> Dict[str, bool]:
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
