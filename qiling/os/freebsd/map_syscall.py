#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

# cols = ("x86_64")

from qiling.const import *

def map_syscall(ql, syscall_num):
    for k,v in syscall_table.items():
        
        if ql.archtype == QL_ARCH.X8664 and v == syscall_num:
            return "ql_syscall_" + k

syscall_table = {
    "exit":(0x01),
    "read":(0x03),
    "write":(0x04),
    "accept":(0x1E),
    "readlink":(0x3A),
    "execve":(0x3B),
    "munmap": (0x49),
    "madvise": (0x4B),
    "dup2": (0x5A),
    "socket": (0x61),
    "bind": (0x68),
    "listen": (0x6A),
    "sysarch": (0xA5),
    "_sysctl": (0xCA),
    "clock_gettime": (0xE8),
    "issetugid": (0xFD),
    "getcwd": (0x0146),
    "mmap2": (0x01DD),
}