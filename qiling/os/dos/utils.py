#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling

def BIN2BCD(val: int) -> int:
    return (((val //    1) % 10) <<  0) \
         + (((val //   10) % 10) <<  4) \
         + (((val //  100) % 10) <<  8) \
         + (((val // 1000) % 10) << 12)

def BCD2BIN(val: int) -> int:
    return ((val >>  0) & 0xf) *    1 \
         + ((val >>  4) & 0xf) *   10 \
         + ((val >>  8) & 0xf) *  100 \
         + ((val >> 12) & 0xf) * 1000

def linaddr(seg: int, off: int) -> int:
    """Convert a segmented address into a 20 bits linear address.

    Args:
        seg: segment value
        off: offset value

    Returns: effective linear address
    """

    return (seg << 4) + off

def read_dos_string(ql: Qiling, address: int):
    """Read a DOS string from memory.

    Args:
        ql: qiling instance
        address: linear address to read from

    Returns: an ascii string
    """

    ba = bytearray()

    while True:
        ch = ql.mem.read(address, 1)

        if ch == b'$':
            break

        ba.extend(ch)
        address += 1

    return ba.decode('ascii')

def read_dos_string_from_ds_dx(ql: Qiling):
    address = linaddr(ql.reg.ds, ql.reg.dx)

    return read_dos_string(ql, address)
