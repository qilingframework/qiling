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

ARM64_LINUX_SYSCALL_EXIT                = [0x5D, "ql_syscall_exit"]
ARM64_LINUX_SYSCALL_WRITE               = [0x40, "ql_syscall_write"]
ARM64_LINUX_SYSCALL_OPEN                = [0x400, "ql_syscall_open"]
ARM64_LINUX_SYSCALL_OPENAT              = [0x38, "ql_syscall_openat"]
ARM64_LINUX_SYSCALL_CLOSE               = [0x39, "ql_syscall_close"]
ARM64_LINUX_SYSCALL_READ                = [0x3F, "ql_syscall_read"]
ARM64_LINUX_SYSCALL_ACCESS              = [0x409, "ql_syscall_access"]
ARM64_LINUX_SYSCALL_SOCKET              = [0xC6, "ql_syscall_socket"]
ARM64_LINUX_SYSCALL_BRK                 = [0xD6, "ql_syscall_brk"]
ARM64_LINUX_SYSCALL_UNAME               = [0xA0, "ql_syscall_uname"]
ARM64_LINUX_SYSCALL_MPROTECT            = [0xE2, "ql_syscall_mprotect"]
ARM64_LINUX_SYSCALL_WRITEV              = [0x42, "ql_syscall_writev"]
ARM64_LINUX_SYSCALL_STAT64              = [0x40E, "ql_syscall_stat64"]
ARM64_LINUX_SYSCALL_EXECVE              = [0xDD, "ql_syscall_execve"]
ARM64_LINUX_SYSCALL_MMAP2               = [0xDE, "ql_syscall_mmap2"]
ARM64_LINUX_SYSCALL_FSTAT64             = [0x50, "ql_syscall_fstat64"]
ARM64_LINUX_SYSCALL_EXITGROUP           = [0x5E, "ql_syscall_exit_group"]
ARM64_LINUX_SYSCALL_FACCESSAT           = [0x30, "ql_syscall_faccessat"]
ARM64_LINUX_SYSCALL_READLINKAT          = [0x4E, "ql_syscall_readlinkat"]
ARM64_LINUX_SYSCALL_FSTATAT64           = [0x4F, "ql_syscall_fstatat64"]
ARM64_LINUX_SYSCALL_CONNECT             = [0xCB, "ql_syscall_connect"]
ARM64_LINUX_SYSCALL_DUP3                = [0x18, "ql_syscall_dup3"]
ARM64_LINUX_SYSCALL_RT_SIGACTION        = [0x86, "ql_syscall_rt_sigaction"]
ARM64_LINUX_SYSCALL_RT_SIGPROCMASK      = [0x87, "ql_syscall_rt_sigprocmask"]
ARM64_LINUX_SYSCALL_GETPID              = [0xAC, "ql_syscall_getpid"]
ARM64_LINUX_SYSCALL_GETTIMEOFDAY        = [0xA9, "ql_syscall_gettimeofday"]
ARM64_LINUX_SYSCALL_FUTEX        = [0x62, "ql_syscall_futex"]


ARM64_LINUX_SYSCALL = [
    ARM64_LINUX_SYSCALL_EXIT,
    ARM64_LINUX_SYSCALL_WRITE,
    ARM64_LINUX_SYSCALL_OPEN,
    ARM64_LINUX_SYSCALL_OPENAT,
    ARM64_LINUX_SYSCALL_CLOSE,
    ARM64_LINUX_SYSCALL_READ,
    ARM64_LINUX_SYSCALL_ACCESS,
    ARM64_LINUX_SYSCALL_SOCKET,
    ARM64_LINUX_SYSCALL_BRK,
    ARM64_LINUX_SYSCALL_UNAME,
    ARM64_LINUX_SYSCALL_MPROTECT,
    ARM64_LINUX_SYSCALL_WRITEV,
    ARM64_LINUX_SYSCALL_STAT64,
    ARM64_LINUX_SYSCALL_EXECVE,
    ARM64_LINUX_SYSCALL_MMAP2,
    ARM64_LINUX_SYSCALL_FSTAT64,
    ARM64_LINUX_SYSCALL_EXITGROUP,
    ARM64_LINUX_SYSCALL_FACCESSAT,
    ARM64_LINUX_SYSCALL_READLINKAT,
    ARM64_LINUX_SYSCALL_FSTATAT64,
    ARM64_LINUX_SYSCALL_CONNECT,
    ARM64_LINUX_SYSCALL_DUP3,
    ARM64_LINUX_SYSCALL_RT_SIGACTION,
    ARM64_LINUX_SYSCALL_RT_SIGPROCMASK,
    ARM64_LINUX_SYSCALL_GETPID,
    ARM64_LINUX_SYSCALL_GETTIMEOFDAY,
    ARM64_LINUX_SYSCALL_FUTEX
    ]
