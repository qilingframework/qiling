#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

ARM_LINUX_SYSCALL_ARMSETTLS                 = [0xF0005, "ql_syscall_arm_settls"]
ARM_LINUX_SYSCALL_EXIT                      = [0x1, "ql_syscall_exit"]
ARM_LINUX_SYSCALL_WRITE                     = [0x4, "ql_syscall_write"]
ARM_LINUX_SYSCALL_OPEN                      = [0x5, "ql_syscall_open"]
ARM_LINUX_SYSCALL_OPENAT                    = [0x142, "ql_syscall_openat"]
ARM_LINUX_SYSCALL_CLOSE                     = [0x6, "ql_syscall_close"]
ARM_LINUX_SYSCALL_READ                      = [0x3, "ql_syscall_read"]
ARM_LINUX_SYSCALL_ACCESS                    = [0x21, "ql_syscall_access"]
ARM_LINUX_SYSCALL_BRK                       = [0x2D, "ql_syscall_brk"]
ARM_LINUX_SYSCALL_DUP2                      = [0x3F, "ql_syscall_dup2"]
ARM_LINUX_SYSCALL_UNAME                     = [0x7A, "ql_syscall_uname"]
ARM_LINUX_SYSCALL_MPROTECT                  = [0x7D, "ql_syscall_mprotect"]
ARM_LINUX_SYSCALL_WRITEV                    = [0x92, "ql_syscall_writev"]
ARM_LINUX_SYSCALL_STAT64                    = [0xC3, "ql_syscall_stat64"]
ARM_LINUX_SYSCALL_MMAP2                     = [0xC0, "ql_syscall_mmap2"]
ARM_LINUX_SYSCALL_FSTAT64                   = [0xC5, "ql_syscall_fstat64"]
ARM_LINUX_SYSCALL_EXITGROUP                 = [0xF8, "ql_syscall_exit_group"]
ARM_LINUX_SYSCALL_FACCESSAT                 = [0x14E, "ql_syscall_faccessat"]
ARM_LINUX_SYSCALL_READLINK                  = [0x55, "ql_syscall_readlink"]
ARM_LINUX_SYSCALL_READLINKAT                = [0x14C, "ql_syscall_readlinkat"]
ARM_LINUX_SYSCALL_FSTATAT64                 = [0x147, "ql_syscall_fstatat64"]
ARM_LINUX_SYSCALL_LSEEK                     = [0x13, "ql_syscall_lseek"]
ARM_LINUX_SYSCALL_UGETRLIMIT                = [0xbf, "ql_syscall_ugetrlimit"]
ARM_LINUX_SYSCALL_SETRLIMIT                 = [0x4b, "ql_syscall_setrlimit"]
ARM_LINUX_SYSCALL_RT_SIGACTION              = [0xae, "ql_syscall_rt_sigaction"]
ARM_LINUX_SYSCALL_FSTAT                     = [0x6c, "ql_syscall_fstat"]
ARM_LINUX_SYSCALL_STAT                      = [0x6a, "ql_syscall_stat"]
ARM_LINUX_SYSCALL_MUNMAP                    = [0x5b, "ql_syscall_munmap"]
ARM_LINUX_SYSCALL_IOCTL                     = [0x36, "ql_syscall_ioctl"]
ARM_LINUX_SYSCALL_GETPID                    = [0x14, "ql_syscall_getpid"]
ARM_LINUX_SYSCALL_RT_SIGPROCMASK            = [0xaf, "ql_syscall_rt_sigprocmask"]
ARM_LINUX_SYSCALL_VFORK                     = [0xbe, "ql_syscall_vfork"]
ARM_LINUX_SYSCALL_WAIT4                     = [0x72, "ql_syscall_wait4"]
ARM_LINUX_SYSCALL_EXECVE                    = [0x0b, "ql_syscall_execve"]
ARM_LINUX_SYSCALL_SOCKET                    = [0x119, "ql_syscall_socket"]
ARM_LINUX_SYSCALL_NANOSLEEP                 = [0xa2, "ql_syscall_nanosleep"]
ARM_LINUX_SYSCALL_CONNECT                   = [0x11b, "ql_syscall_connect"]
ARM_LINUX_SYSCALL_SETSOCKOPT                = [0x126, "ql_syscall_setsockopt"]
ARM_LINUX_SYSCALL_FCNTL                     = [0x37, "ql_syscall_fcntl"]
ARM_LINUX_SYSCALL_BIND                      = [0x11a, "ql_syscall_bind"]
ARM_LINUX_SYSCALL_LISTEN                    = [0x11c, "ql_syscall_listen"]
ARM_LINUX_SYSCALL_SHUTDOWN                  = [0x125, "ql_syscall_shutdown"]
ARM_LINUX_SYSCALL_SETITIMER                 = [0x68, "ql_syscall_setitimer"]
ARM_LINUX_SYSCALL__NEWSELECT                = [0x8e, "ql_syscall__newselect"]
ARM_LINUX_SYSCALL_ACCEPT                    = [0x11d, "ql_syscall_accept"]
ARM_LINUX_SYSCALL_TIMES                     = [0x2b, "ql_syscall_times"]
ARM_LINUX_SYSCALL_GETTIMEOFDAY              = [0x4e, "ql_syscall_gettimeofday"]
ARM_LINUX_SYSCALL_RECV                      = [0x123, "ql_syscall_recv"]
ARM_LINUX_SYSCALL_SEND                      = [0x121, "ql_syscall_send"]
ARM_LINUX_SYSCALL_FCNTL64                   = [0xdd, "ql_syscall_fcntl64"]
ARM_LINUX_SYSCALL_SET_TID_ADDRESS           = [0x100, "ql_syscall_set_tid_address"]
ARM_LINUX_SYSCALL_SET_ROBUST_LIST           = [0x152, "ql_syscall_set_robust_list"]
ARM_LINUX_SYSCALL_GETTID                    = [0xe0, "ql_syscall_gettid"]
ARM_LINUX_SYSCALL_CLONE                     = [0x78, "ql_syscall_clone"]
ARM_LINUX_SYSCALL_SYSINFO                   = [0x74, "ql_syscall_sysinfo"]



ARM_LINUX_SYSCALL = [
    ARM_LINUX_SYSCALL_ARMSETTLS,
    ARM_LINUX_SYSCALL_EXIT,
    ARM_LINUX_SYSCALL_WRITE,
    ARM_LINUX_SYSCALL_OPEN,
    ARM_LINUX_SYSCALL_OPENAT,
    ARM_LINUX_SYSCALL_CLOSE,
    ARM_LINUX_SYSCALL_READ,
    ARM_LINUX_SYSCALL_ACCESS,
    ARM_LINUX_SYSCALL_BRK,
    ARM_LINUX_SYSCALL_DUP2,
    ARM_LINUX_SYSCALL_UNAME,
    ARM_LINUX_SYSCALL_MPROTECT,
    ARM_LINUX_SYSCALL_WRITEV,
    ARM_LINUX_SYSCALL_STAT64,
    ARM_LINUX_SYSCALL_MMAP2,
    ARM_LINUX_SYSCALL_FSTAT64,
    ARM_LINUX_SYSCALL_EXITGROUP,
    ARM_LINUX_SYSCALL_FACCESSAT,
    ARM_LINUX_SYSCALL_READLINK,
    ARM_LINUX_SYSCALL_READLINKAT,
    ARM_LINUX_SYSCALL_FSTATAT64,
    ARM_LINUX_SYSCALL_LSEEK,
    ARM_LINUX_SYSCALL_UGETRLIMIT,
    ARM_LINUX_SYSCALL_SETRLIMIT,
    ARM_LINUX_SYSCALL_RT_SIGACTION,
    ARM_LINUX_SYSCALL_FSTAT,
    ARM_LINUX_SYSCALL_STAT,
    ARM_LINUX_SYSCALL_MUNMAP,
    ARM_LINUX_SYSCALL_IOCTL,
    ARM_LINUX_SYSCALL_GETPID,
    ARM_LINUX_SYSCALL_RT_SIGPROCMASK,
    ARM_LINUX_SYSCALL_VFORK,
    ARM_LINUX_SYSCALL_WAIT4,
    ARM_LINUX_SYSCALL_EXECVE,
    ARM_LINUX_SYSCALL_SOCKET,
    ARM_LINUX_SYSCALL_NANOSLEEP,
    ARM_LINUX_SYSCALL_CONNECT,
    ARM_LINUX_SYSCALL_SETSOCKOPT,
    ARM_LINUX_SYSCALL_FCNTL,
    ARM_LINUX_SYSCALL_BIND,
    ARM_LINUX_SYSCALL_LISTEN,
    ARM_LINUX_SYSCALL_SHUTDOWN,
    ARM_LINUX_SYSCALL_SETITIMER,
    ARM_LINUX_SYSCALL__NEWSELECT,
    ARM_LINUX_SYSCALL_ACCEPT,
    ARM_LINUX_SYSCALL_TIMES,
    ARM_LINUX_SYSCALL_GETTIMEOFDAY,
    ARM_LINUX_SYSCALL_RECV,
    ARM_LINUX_SYSCALL_SEND,
    ARM_LINUX_SYSCALL_FCNTL64,
    ARM_LINUX_SYSCALL_SET_TID_ADDRESS,
    ARM_LINUX_SYSCALL_SET_ROBUST_LIST,
    ARM_LINUX_SYSCALL_GETTID,
    ARM_LINUX_SYSCALL_CLONE,
    ARM_LINUX_SYSCALL_SYSINFO
    ]