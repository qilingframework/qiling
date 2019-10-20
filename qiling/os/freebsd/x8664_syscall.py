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

X8664_FREEBSD_SYSCALL_EXIT              = [0x1, "ql_syscall_exit"]
X8664_FREEBSD_SYSCALL_WRITE             = [0x04, "ql_syscall_write"]
X8664_FREEBSD_SYSCALL_SOCKET            = [0x61, "ql_syscall_socket"]
X8664_FREEBSD_SYSCALL_BIND              = [0x68, "ql_syscall_bind"]
X8664_FREEBSD_SYSCALL_LISTEN            = [0x6a, "ql_syscall_listen"]
X8664_FREEBSD_SYSCALL_ACCEPT            = [0x1e, "ql_syscall_accept"]
X8664_FREEBSD_SYSCALL_READ              = [0x03, "ql_syscall_read"]
X8664_FREEBSD_SYSCALL_DUP2              = [0x5a, "ql_syscall_dup2"]
X8664_FREEBSD_SYSCALL_EXECVE            = [0x3b, "ql_syscall_execve"]
X8664_FREEBSD_SYSCALL_READLINK          = [0x3a, "ql_syscall_readlink"]
X8664_FREEBSD_SYSCALL_ISSETUGID         = [0xfd, "ql_syscall_issetugid"]
X8664_FREEBSD_SYSCALL_SYSCTL            = [0xca, "ql_syscall_sysctl"]
X8664_FREEBSD_SYSCALL_MMAP              = [0x1dd, "ql_syscall_mmap2"]
X8664_FREEBSD_SYSCALL_MADVISE           = [0x4b, "ql_syscall_madvise"]
X8664_FREEBSD_SYSCALL_MUNMAP            = [0x49, "ql_syscall_munmap"]
X8664_FREEBSD_SYSCALL_CLOCKGETTIME      = [0xe8, "ql_syscall_clock_gettime"]

X8664_FREEBSD_SYSCALL = [
    X8664_FREEBSD_SYSCALL_EXIT,
    X8664_FREEBSD_SYSCALL_WRITE,
    X8664_FREEBSD_SYSCALL_SOCKET,
    X8664_FREEBSD_SYSCALL_BIND,
    X8664_FREEBSD_SYSCALL_LISTEN,
    X8664_FREEBSD_SYSCALL_ACCEPT,
    X8664_FREEBSD_SYSCALL_READ,
    X8664_FREEBSD_SYSCALL_DUP2,
    X8664_FREEBSD_SYSCALL_EXECVE,
    X8664_FREEBSD_SYSCALL_READLINK,
    X8664_FREEBSD_SYSCALL_ISSETUGID,
    X8664_FREEBSD_SYSCALL_SYSCTL,
    X8664_FREEBSD_SYSCALL_MMAP,
    X8664_FREEBSD_SYSCALL_MADVISE,
    X8664_FREEBSD_SYSCALL_MUNMAP,
    X8664_FREEBSD_SYSCALL_CLOCKGETTIME
    ]