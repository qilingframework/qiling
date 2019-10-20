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

X8664_MACOS_SYSCALL_EXIT        =   [0x2000001, "ql_syscall_exit"]
X8664_MACOS_SYSCALL_READ        =   [0x2000003, "ql_syscall_read"]
X8664_MACOS_SYSCALL_WRITE       =   [0x2000004, "ql_syscall_write"]
X8664_MACOS_SYSCALL_OPEN        =   [0x2000005, "ql_syscall_open"]
X8664_MACOS_SYSCALL_CLOSE       =   [0x2000006, "ql_syscall_close"]
X8664_MACOS_SYSCALL_MUNMAP      =   [0x2000049, "ql_syscall_munmap"]
X8664_MACOS_SYSCALL_MMAP        =   [0x20000c5, "ql_syscall_mmap2"]
X8664_MACOS_SYSCALL_LSEEK       =   [0x20000c7, "ql_syscall_lseek"]
X8664_MACOS_SYSCALL_EXECVE      =   [0x200003b, "ql_syscall_execve"]


X8664_MACOS_SYSCALL = [
    X8664_MACOS_SYSCALL_EXIT,
    X8664_MACOS_SYSCALL_READ,
    X8664_MACOS_SYSCALL_WRITE,
    X8664_MACOS_SYSCALL_OPEN,
    X8664_MACOS_SYSCALL_CLOSE,
    X8664_MACOS_SYSCALL_MUNMAP,
    X8664_MACOS_SYSCALL_MMAP,
    X8664_MACOS_SYSCALL_LSEEK,
    X8664_MACOS_SYSCALL_EXECVE
    ]