#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

def map_syscall(syscall_num):
    adapter = {
        0x01 : "ql_syscall_exit",
        0x03 : "ql_syscall_read",
        0x04 : "ql_syscall_write",
        0x05 : "ql_syscall_open",
        0x06 : "ql_syscall_close",
        0x0A : "ql_syscall_unlink",
        0x0B : "ql_syscall_execve",
        0x14 : "ql_syscall_getpid",
        0x1a : "ql_syscall_ptrace",
        0x21 : "ql_syscall_access",
        0x2D : "ql_syscall_brk",
        0x30 : "ql_syscall_signal",
        0x55 : "ql_syscall_readlink",
        0x5A : "ql_syscall_old_mmap",
        0x5B : "ql_syscall_munmap",
        0x5C : "ql_syscall_truncate",
        0x5D : "ql_syscall_ftruncate",
        0x66 : "ql_syscall_socketcall",
        0x6B : "ql_syscall_lstat",
        0x78 : "ql_syscall_clone",
        0x7A : "ql_syscall_uname",
        0x7D : "ql_syscall_mprotect",
        0x8D : "ql_syscall_getdents",
        0x92 : "ql_syscall_writev",
        0xA2 : "ql_syscall_nanosleep",
        0xAE : "ql_syscall_rt_sigaction",
        0xAF : "ql_syscall_rt_sigprocmask",
        0xBF : "ql_syscall_ugetrlimit",
        0xC0 : "ql_syscall_mmap2",
        0xC3 : "ql_syscall_stat64",
        0xC5 : "ql_syscall_fstat64",
        0xDB : "ql_syscall_madvise",
        0xDD : "ql_syscall_fcntl64",
        0xF0 : "ql_syscall_futex",
        0xF3 : "ql_x86_syscall_set_thread_area",
        0xFC : "ql_syscall_exit_group",
        0x0102 : "ql_syscall_set_tid_address",
        0x0127 : "ql_syscall_openat",
        0x0137 : "ql_syscall_set_robust_list",
    }
    return adapter.get(syscall_num)
