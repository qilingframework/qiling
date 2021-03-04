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


def string_appearance(ql, string):
    strings = string.split(" ")
    for string in strings:
        val = ql.os.appeared_strings.get(string, set())
        val.add(ql.os.syscalls_counter)
        ql.os.appeared_strings[string] = val


def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


def find_size_function(ql, func_addr):
    # We have to retrieve the return address position
    code = ql.mem.read(func_addr, 0x100)
    return_procedures = [b"\xc3", b"\xc2", b"\xcb", b"\xca"]
    min_index = min([code.index(return_value) for return_value in return_procedures if return_value in code])
    return min_index
