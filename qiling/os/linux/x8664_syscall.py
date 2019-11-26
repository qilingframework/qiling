#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

X8664_LINUX_SYSCALL_EXIT                = [0x3C, "ql_syscall_exit"]
X8664_LINUX_SYSCALL_WRITE               = [0x01, "ql_syscall_write"]
X8664_LINUX_SYSCALL_OPEN                = [0x02, "ql_syscall_open"]
X8664_LINUX_SYSCALL_OPENAT              = [0x101, "ql_syscall_openat"]
X8664_LINUX_SYSCALL_CLOSE               = [0x03, "ql_syscall_close"]
X8664_LINUX_SYSCALL_READ                = [0x00, "ql_syscall_read"]
X8664_LINUX_SYSCALL_ACCESS              = [0x15, "ql_syscall_access"]
X8664_LINUX_SYSCALL_EXECVE              = [0x3B, "ql_syscall_execve"]
X8664_LINUX_SYSCALL_BRK                 = [0x0C, "ql_syscall_brk"]
X8664_LINUX_SYSCALL_UNAME               = [0x3F, "ql_syscall_uname"]
X8664_LINUX_SYSCALL_MPROTECT            = [0x0A, "ql_syscall_mprotect"]
X8664_LINUX_SYSCALL_WRITEV              = [0x14, "ql_syscall_writev"]
X8664_LINUX_SYSCALL_MMAP                = [0x09, "ql_syscall_mmap2"]
X8664_LINUX_SYSCALL_EXITGROUP           = [0xE7, "ql_syscall_exit_group"]
X8664_LINUX_SYSCALL_FACCESSAT           = [0x10D, "ql_syscall_faccessat"]
X8664_LINUX_SYSCALL_READLINK            = [0x59, "ql_syscall_readlink"]
X8664_LINUX_SYSCALL_MUNMAP              = [0x0B, "ql_syscall_munmap"]
X8664_LINUX_SYSCALL_FSTAT               = [0x05, "ql_syscall_fstat"]
X8664_LINUX_SYSCALL_STAT                = [0x04, "ql_syscall_stat"]
X8664_LINUX_SYSCALL_ARCHPRCTL           = [0x9E, "ql_syscall_archprctl"]
X8664_LINUX_SYSCALL_GETUID              = [0x66, "ql_syscall_getuid" ]
X8664_LINUX_SYSCALL_GETGID              = [0x68, "ql_syscall_getgid" ]
X8664_LINUX_SYSCALL_GETPID              = [0x27, "ql_syscall_getpid" ]
X8664_LINUX_SYSCALL_RT_SIGACTION        = [0xD, "ql_syscall_rt_sigaction" ]
X8664_LINUX_SYSCALL_GETEUID             = [0x6B, "ql_syscall_geteuid" ]
X8664_LINUX_SYSCALL_GETEPPID            = [0x6E, "ql_syscall_getppid" ]
X8664_LINUX_SYSCALL_GETECWD             = [0x4F, "ql_syscall_getcwd" ]
X8664_LINUX_SYSCALL_MPROTECT            = [0xA, "ql_syscall_mprotect" ]
X8664_LINUX_SYSCALL_IOCTL               = [0x10, "ql_syscall_ioctl" ]
X8664_LINUX_SYSCALL_GETEGID             = [0x6C, "ql_syscall_getegid" ]
X8664_LINUX_SYSCALL_FCNTL               = [0x48, "ql_syscall_fcntl" ]

X8664_LINUX_SYSCALL = [
    X8664_LINUX_SYSCALL_EXIT,
    X8664_LINUX_SYSCALL_WRITE,
    X8664_LINUX_SYSCALL_OPEN,
    X8664_LINUX_SYSCALL_OPENAT,
    X8664_LINUX_SYSCALL_CLOSE,
    X8664_LINUX_SYSCALL_READ,
    X8664_LINUX_SYSCALL_ACCESS,
    X8664_LINUX_SYSCALL_EXECVE,
    X8664_LINUX_SYSCALL_BRK,
    X8664_LINUX_SYSCALL_UNAME,
    X8664_LINUX_SYSCALL_MPROTECT,
    X8664_LINUX_SYSCALL_WRITEV,
    X8664_LINUX_SYSCALL_MMAP,
    X8664_LINUX_SYSCALL_EXITGROUP,
    X8664_LINUX_SYSCALL_FACCESSAT,
    X8664_LINUX_SYSCALL_READLINK,
    X8664_LINUX_SYSCALL_MUNMAP,
    X8664_LINUX_SYSCALL_FSTAT,
    X8664_LINUX_SYSCALL_STAT,
    X8664_LINUX_SYSCALL_ARCHPRCTL,
    X8664_LINUX_SYSCALL_GETUID,
    X8664_LINUX_SYSCALL_GETGID,
    X8664_LINUX_SYSCALL_GETPID,
    X8664_LINUX_SYSCALL_RT_SIGACTION,
    X8664_LINUX_SYSCALL_GETEUID,
    X8664_LINUX_SYSCALL_GETEPPID,
    X8664_LINUX_SYSCALL_GETECWD,
    X8664_LINUX_SYSCALL_MPROTECT,
    X8664_LINUX_SYSCALL_IOCTL,
    X8664_LINUX_SYSCALL_GETEGID,
    X8664_LINUX_SYSCALL_FCNTL
    ]