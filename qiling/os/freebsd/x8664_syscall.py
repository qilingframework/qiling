#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

def map_syscall(syscall_num):
    adapter = {
        0x01 : "ql_syscall_exit",
        0x03 : "ql_syscall_read",
        0x04 : "ql_syscall_write",
        0x1E : "ql_syscall_accept",
        0x3A : "ql_syscall_readlink",
        0x3B : "ql_syscall_execve",
        0x49 : "ql_syscall_munmap",
        0x4B : "ql_syscall_madvise",
        0x5A : "ql_syscall_dup2",
        0x61 : "ql_syscall_socket",
        0x68 : "ql_syscall_bind",
        0x6A : "ql_syscall_listen",
        0xA5 : "ql_syscall_sysarch",
        0xCA : "ql_syscall__sysctl",
        0xE8 : "ql_syscall_clock_gettime",
        0xFD : "ql_syscall_issetugid",
        0x0146 : "ql_syscall_getcwd",
        0x01DD : "ql_syscall_mmap2",
    }
    return adapter.get(syscall_num)
