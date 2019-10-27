#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
#
# LAU kaijern (xwings) <kj@qiling.io>
# NGUYEN Anh Quynh <aquynh@gmail.com>
# DING tianZe (D1iv3) <dddliv3@gmail.com>
# SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
# CHEN huitao (null) <null@qiling.io>
# YU tong (sp1ke) <spikeinhouse@gmail.com>

X8664_MACOS_MACH_SYSCALL_TASK_SELF_TRAP         =   [0x100001c, "ql_x86_syscall_task_self_trap"]
X8664_MACOS_MACH_SYSCALL_MACH_REPLY_PORT        =   [0x100001a, "ql_x86_syscall_mach_reply_port"]

X8664_MACOS_POSIX_SYSCALL_EXIT                  =   [0x2000001, "ql_syscall_exit"]
X8664_MACOS_POSIX_SYSCALL_READ                  =   [0x2000003, "ql_syscall_read"]
X8664_MACOS_POSIX_SYSCALL_WRITE                 =   [0x2000004, "ql_syscall_write"]
X8664_MACOS_POSIX_SYSCALL_OPEN                  =   [0x2000005, "ql_syscall_open"]
X8664_MACOS_POSIX_SYSCALL_CLOSE                 =   [0x2000006, "ql_syscall_close"]
X8664_MACOS_POSIX_SYSCALL_SIGPROCMASK           =   [0x2000030, "ql_syscall_sigprocmask"]
X8664_MACOS_POSIX_SYSCALL_MUNMAP                =   [0x2000049, "ql_syscall_munmap"]
X8664_MACOS_POSIX_SYSCALL_FCNTL64               =   [0x200005c, "ql_syscall_fcntl64"]
X8664_MACOS_POSIX_SYSCALL_MMAP                  =   [0x20000c5, "ql_syscall_mmap2"]
X8664_MACOS_POSIX_SYSCALL_LSEEK                 =   [0x20000c7, "ql_syscall_lseek"]
X8664_MACOS_POSIX_SYSCALL_EXECVE                =   [0x200003b, "ql_syscall_execve"]
X8664_MACOS_POSIX_SYSCALL_STAT64                =   [0x2000152, "ql_syscall_stat64"]
X8664_MACOS_POSIX_SYSCALL_FSTAT64               =   [0x2000153, "ql_syscall_fstat64"]
X8664_MACOS_POSIX_SYSCALL_THREAD_SELFID         =   [0x2000174, "ql_syscall_thread_selfid"]
X8664_MACOS_POSIX_SYSCALL_GETENTROPY            =   [0x20001f4, "ql_syscall_getentropy"]

X8664_MACOS_MDEP_SYSCALL_THREAD_SET_TSD_BASE    =   [0x3000003, "ql_x86_syscall_thread_set_tsd_base"]

X8664_MACOS_SYSCALL = [
    X8664_MACOS_MACH_SYSCALL_TASK_SELF_TRAP,
    X8664_MACOS_MACH_SYSCALL_MACH_REPLY_PORT,

    X8664_MACOS_POSIX_SYSCALL_EXIT,
    X8664_MACOS_POSIX_SYSCALL_READ,
    X8664_MACOS_POSIX_SYSCALL_WRITE,
    X8664_MACOS_POSIX_SYSCALL_OPEN,
    X8664_MACOS_POSIX_SYSCALL_CLOSE,
    X8664_MACOS_POSIX_SYSCALL_SIGPROCMASK,
    X8664_MACOS_POSIX_SYSCALL_MUNMAP,
    X8664_MACOS_POSIX_SYSCALL_FCNTL64,
    X8664_MACOS_POSIX_SYSCALL_MMAP,
    X8664_MACOS_POSIX_SYSCALL_LSEEK,
    X8664_MACOS_POSIX_SYSCALL_EXECVE,
    X8664_MACOS_POSIX_SYSCALL_STAT64,
    X8664_MACOS_POSIX_SYSCALL_FSTAT64,
    X8664_MACOS_POSIX_SYSCALL_THREAD_SELFID,
    X8664_MACOS_POSIX_SYSCALL_GETENTROPY,

    X8664_MACOS_MDEP_SYSCALL_THREAD_SET_TSD_BASE,
    ]