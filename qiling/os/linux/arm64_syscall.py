#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

def map_syscall(syscall_num):
    adapter = {
        0x18 : "ql_syscall_dup3",
        0x21 : "ql_syscall_mknodat",
        0x23 : "ql_syscall_unlinkat",
        0x30 : "ql_syscall_faccessat",
        0x38 : "ql_syscall_openat",
        0x39 : "ql_syscall_close",
        0x3F : "ql_syscall_read",
        0x40 : "ql_syscall_write",
        0x42 : "ql_syscall_writev",
        0x4E : "ql_syscall_readlinkat",
        0x4F : "ql_syscall_fstatat64",
        0x50 : "ql_syscall_fstat64",
        0x5D : "ql_syscall_exit",
        0x5E : "ql_syscall_exit_group",
        0x60 : "ql_syscall_set_tid_address",
        0x62 : "ql_syscall_futex",
        0x63 : "ql_syscall_set_robust_list",
        0x65 : "ql_syscall_nanosleep",
        0x86 : "ql_syscall_rt_sigaction",
        0x87 : "ql_syscall_rt_sigprocmask",
        0xA0 : "ql_syscall_uname",
        0xA6 : "ql_syscall_umask",
        0xA9 : "ql_syscall_gettimeofday",
        0xAC : "ql_syscall_getpid",
        0xB2 : "ql_syscall_gettid",
        0xC6 : "ql_syscall_socket",
        0xC8 : "ql_syscall_bind",
        0xC9 : "ql_syscall_listen",
        0xCB : "ql_syscall_connect",
        0xD6 : "ql_syscall_brk",
        0xDC : "ql_syscall_clone",
        0xDD : "ql_syscall_execve",
        0xDE : "ql_syscall_mmap2",
        0xE2 : "ql_syscall_mprotect",
        0x041A : "ql_syscall_lstat",
        0x0105 : "ql_syscall_prlimit64",
        0x0400 : "ql_syscall_open",
        0x0409 : "ql_syscall_access",
        0x040E : "ql_syscall_stat64",
    }
    return adapter.get(syscall_num)
