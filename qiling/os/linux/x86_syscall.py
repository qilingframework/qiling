#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


X86_LINUX_SYSCALL_EXIT                      = [0x01, "ql_syscall_exit"]
X86_LINUX_SYSCALL_WRITE                     = [0x04, "ql_syscall_write"]
X86_LINUX_SYSCALL_OPEN                      = [0x05, "ql_syscall_open"]
X86_LINUX_SYSCALL_EXECVE                    = [0x0B, "ql_syscall_execve"]
X86_LINUX_SYSCALL_GETPID                    = [0x14, "ql_syscall_getpid"]
X86_LINUX_SYSCALL_OPENAT                    = [0x127, "ql_syscall_openat"]
X86_LINUX_SYSCALL_CLOSE                     = [0x06, "ql_syscall_close"]
X86_LINUX_SYSCALL_READ                      = [0x03, "ql_syscall_read"]
X86_LINUX_SYSCALL_ACCESS                    = [0x21, "ql_syscall_access"]
X86_LINUX_SYSCALL_BRK                       = [0x2D, "ql_syscall_brk"]
X86_LINUX_SYSCALL_UNAME                     = [0x7A, "ql_syscall_uname"]
X86_LINUX_SYSCALL_MPROTECT                  = [0x7D, "ql_syscall_mprotect"]
X86_LINUX_SYSCALL_WRITEV                    = [0x92, "ql_syscall_writev"]
X86_LINUX_SYSCALL_MMAP                      = [0xC0, "ql_syscall_mmap2"]
X86_LINUX_SYSCALL_EXITGROUP                 = [0xFC, "ql_syscall_exit_group"]
X86_LINUX_SYSCALL_READLINK                  = [0x55, "ql_syscall_readlink"]
X86_LINUX_SYSCALL_MUNMAP                    = [0x5B, "ql_syscall_munmap"]
X86_LINUX_SYSCALL_FSTAT64                   = [0xC5, "ql_syscall_fstat64"]
X86_LINUX_SYSCALL_SETTHREADAREA             = [0xF3, "ql_x86_syscall_set_thread_area"]
X86_LINUX_SYSCALL_STAT64                    = [0xc3, "ql_syscall_stat64"]
X86_LINUX_SYSCALL_SET_TID_ADDRESS           = [0x102, "ql_syscall_set_tid_address"]
X86_LINUX_SYSCALL_SET_ROBUST_LIST           = [0x137, "ql_syscall_set_robust_list"]
X86_LINUX_SYSCALL_RT_SIGACTION              = [0xae, "ql_syscall_rt_sigaction"]
X86_LINUX_SYSCALL_RT_SIGPROCMASK            = [0xaf, "ql_syscall_rt_sigprocmask"]
X86_LINUX_SYSCALL_UGETRLIMIT                = [0xbf, "ql_syscall_ugetrlimit"]
X86_LINUX_SYSCALL_CLONE                     = [0x78, "ql_syscall_clone"]
X86_LINUX_SYSCALL_NANOSLEEP                 = [0xa2, "ql_syscall_nanosleep"]
X86_LINUX_SYSCALL_FUTEX                     = [0xf0, "ql_syscall_futex"]
X86_LINUX_SYSCALL_MADVISE                   = [0xdb, "ql_syscall_madvise"]

X86_LINUX_SYSCALL = [
    X86_LINUX_SYSCALL_EXIT,
    X86_LINUX_SYSCALL_WRITE,
    X86_LINUX_SYSCALL_OPEN,
    X86_LINUX_SYSCALL_EXECVE,
    X86_LINUX_SYSCALL_GETPID,
    X86_LINUX_SYSCALL_OPENAT,
    X86_LINUX_SYSCALL_CLOSE,
    X86_LINUX_SYSCALL_READ,
    X86_LINUX_SYSCALL_ACCESS,
    X86_LINUX_SYSCALL_BRK,
    X86_LINUX_SYSCALL_UNAME,
    X86_LINUX_SYSCALL_MPROTECT,
    X86_LINUX_SYSCALL_WRITEV,
    X86_LINUX_SYSCALL_MMAP,
    X86_LINUX_SYSCALL_EXITGROUP,
    X86_LINUX_SYSCALL_READLINK,
    X86_LINUX_SYSCALL_MUNMAP,
    X86_LINUX_SYSCALL_FSTAT64,
    X86_LINUX_SYSCALL_SETTHREADAREA,
    X86_LINUX_SYSCALL_STAT64,
    X86_LINUX_SYSCALL_SET_TID_ADDRESS,
    X86_LINUX_SYSCALL_SET_ROBUST_LIST,
    X86_LINUX_SYSCALL_RT_SIGACTION,
    X86_LINUX_SYSCALL_RT_SIGPROCMASK,
    X86_LINUX_SYSCALL_UGETRLIMIT,
    X86_LINUX_SYSCALL_CLONE,
    X86_LINUX_SYSCALL_NANOSLEEP,
    X86_LINUX_SYSCALL_FUTEX,
    X86_LINUX_SYSCALL_MADVISE
    ]