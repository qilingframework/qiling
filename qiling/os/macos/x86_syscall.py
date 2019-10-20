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

X86_MACOS_SYSCALL_EXIT                      = [1, "ql_syscall_exit"]
X86_MACOS_SYSCALL_READ                      = [3, "ql_syscall_read"]
X86_MACOS_SYSCALL_WRITE                     = [4, "ql_syscall_write"]
X86_MACOS_SYSCALL_OPEN                      = [5, "ql_syscall_open"]
X86_MACOS_SYSCALL_CLOSE                     = [6, "ql_syscall_close"]
X86_MACOS_SYSCALL_MUNMAP                    = [73, "ql_syscall_munmap"]
X86_MACOS_SYSCALL_MMAP                      = [197, "ql_syscall_mmap2"]
X86_MACOS_SYSCALL_LSEEK                     = [199, "ql_syscall_lseek"]
X86_MACOS_SYSCALL_SET_TF_CTHREAD_SELF       = [0x8203, "ql_x86_syscall_set_thread_area"]
# X86_MACOS_SYSCALL_BIND = [104, "ql_syscall_bind"]
# X86_MACOS_SYSCALL_LISTEN = [106, "ql_syscall_listen"]
# X86_MACOS_SYSCALL_ACCEPT = [30, "ql_syscall_accept"]
# X86_MACOS_SYSCALL_DUP2 = [90, "ql_syscall_dup2"]
# X86_MACOS_SYSCALL_EXECVE = [59, "ql_syscall_execve"]
# X86_MACOS_SYSCALL_READLINK = [58, "ql_syscall_readlink"]
# X86_MACOS_SYSCALL_ISSETUGID = [327, "ql_syscall_issetugid"]
# X86_MACOS_SYSCALL_SYSCTL = [202, "ql_syscall_sysctl"]
# X86_MACOS_SYSCALL_MADVISE = [75, "ql_syscall_madvise"]


X86_MACOS_SYSCALL = [
    X86_MACOS_SYSCALL_EXIT,
    X86_MACOS_SYSCALL_READ,
    X86_MACOS_SYSCALL_WRITE,
    X86_MACOS_SYSCALL_OPEN,
    X86_MACOS_SYSCALL_CLOSE,
    X86_MACOS_SYSCALL_MUNMAP,
    X86_MACOS_SYSCALL_MMAP,
    X86_MACOS_SYSCALL_LSEEK,
    X86_MACOS_SYSCALL_SET_TF_CTHREAD_SELF
    # X86_MACOS_SYSCALL_SOCKET,
    # X86_MACOS_SYSCALL_BIND,
    # X86_MACOS_SYSCALL_LISTEN,
    # X86_MACOS_SYSCALL_ACCEPT,
    # X86_MACOS_SYSCALL_DUP2,
    # X86_MACOS_SYSCALL_EXECVE,
    # X86_MACOS_SYSCALL_READLINK,
    # X86_MACOS_SYSCALL_ISSETUGID,
    # X86_MACOS_SYSCALL_SYSCTL,
    # X86_MACOS_SYSCALL_MADVISE,
    ]