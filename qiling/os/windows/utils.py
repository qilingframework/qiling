#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ntpath

from qiling import Qiling

def ql_x86_windows_hook_mem_error(ql: Qiling, access, addr: int, size: int, value: int):
    ql.log.debug(f'ERROR: unmapped memory access at {addr:#x}')
    return False


def is_file_library(string: str) -> bool:
    string = string.lower()
    extension = string.rpartition('.')[-1]
    return extension in ("dll", "exe", "sys", "drv")


def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)

# FIXME: determining a function size by locating 'ret' opcodes in its code is a very unreliable way, to say
# the least. not only that 'ret' instructions may appear more than once in a single function, they not are
# necessarily located at the last function basic block: think of a typical nested loop spaghetty.
#
# also, there is no telling whether a 0xC3 value found in function code is actually a 'ret' instruction, or
# just part of a magic value (e.g. "mov eax, 0xffffffc3").
#
# finally, if this method happens to find the correct function size, by any chance, that would be a pure luck.
def find_size_function(ql: Qiling, func_addr: int):
    # We have to retrieve the return address position
    code = ql.mem.read(func_addr, 0x100)
    return_procedures = [b"\xc3", b"\xc2", b"\xcb", b"\xca"]
    min_index = min([code.index(return_value) for return_value in return_procedures if return_value in code])
    return min_index
