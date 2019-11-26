#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
MIPS32EL_LINUX_SYSCALL_SETTHREADAREA            = [4283, "ql_syscall_mips32el_set_thread_area"]
MIPS32EL_LINUX_SYSCALL_EXIT                     = [4001, "ql_syscall_exit"]
MIPS32EL_LINUX_SYSCALL_WRITE                    = [4004, "ql_syscall_write"]
MIPS32EL_LINUX_SYSCALL_OPEN                     = [4005, "ql_syscall_open"]
MIPS32EL_LINUX_SYSCALL_CLOSE                    = [4006, "ql_syscall_close"]
MIPS32EL_LINUX_SYSCALL_READ                     = [4003, "ql_syscall_read"]
MIPS32EL_LINUX_SYSCALL_EXECVE                   = [4011, "ql_syscall_execve"]
MIPS32EL_LINUX_SYSCALL_ACCESS                   = [4033, "ql_syscall_access"]
MIPS32EL_LINUX_SYSCALL_BRK                      = [4045, "ql_syscall_brk"]
MIPS32EL_LINUX_SYSCALL_UNAME                    = [4122, "ql_syscall_uname"]
MIPS32EL_LINUX_SYSCALL_MPROTECT                 = [4125, "ql_syscall_mprotect"]
MIPS32EL_LINUX_SYSCALL_WRITEV                   = [4146, "ql_syscall_writev"]
MIPS32EL_LINUX_SYSCALL_STAT64                   = [4213, "ql_syscall_stat64"]
MIPS32EL_LINUX_SYSCALL_MMAP2                    = [4210, "ql_syscall_mmap2"]
MIPS32EL_LINUX_SYSCALL_MMAP                     = [4090, "ql_syscall_mmap"]
MIPS32EL_LINUX_SYSCALL_FSTAT64                  = [4215, "ql_syscall_fstat64"]
MIPS32EL_LINUX_SYSCALL_EXITGROUP                = [4246, "ql_syscall_exit_group"]
MIPS32EL_LINUX_SYSCALL_READLINK                 = [4085, "ql_syscall_readlink"]
MIPS32EL_LINUX_SYSCALL_STAT                     = [4106, "ql_syscall_stat"]
MIPS32EL_LINUX_SYSCALL_MUNMAP                   = [4091, "ql_syscall_munmap"]
MIPS32EL_LINUX_SYSCALL_FSTAT                    = [4108, "ql_syscall_fstat"]
MIPS32EL_LINUX_SYSCALL_LSEEK                    = [4019, "ql_syscall_lseek"]
MIPS32EL_LINUX_SYSCALL_IOCTL                    = [4054, "ql_syscall_ioctl"]
MIPS32EL_LINUX_SYSCALL_SOCKET                   = [4183, "ql_syscall_socket"]
MIPS32EL_LINUX_SYSCALL_FCNTL64                  = [4220, "ql_syscall_fcntl64"]
MIPS32EL_LINUX_SYSCALL_FCNTL                    = [4055, "ql_syscall_fcntl"]
MIPS32EL_LINUX_SYSCALL_SETSOCKOPT               = [4181, "ql_syscall_setsockopt"]
MIPS32EL_LINUX_SYSCALL_BIND                     = [4169, "ql_syscall_bind"]
MIPS32EL_LINUX_SYSCALL_LISTEN                   = [4174, "ql_syscall_listen"]
MIPS32EL_LINUX_SYSCALL_FORK                     = [4002, "ql_syscall_vfork"]
MIPS32EL_LINUX_SYSCALL_SETSID                   = [4066, "ql_syscall_setsid"]
MIPS32EL_LINUX_SYSCALL_TIME                     = [4013, "ql_syscall_time"]
MIPS32EL_LINUX_SYSCALL_GETUID                   = [4024, "ql_syscall_getuid"]
MIPS32EL_LINUX_SYSCALL_GETCWD                   = [4203, "ql_syscall_getcwd"]
MIPS32EL_LINUX_SYSCALL_RT_SIGACTION             = [4194, "ql_syscall_rt_sigaction"]
MIPS32EL_LINUX_SYSCALL__NEWSELECT               = [4142, "ql_syscall__newselect"]
MIPS32EL_LINUX_SYSCALL_SETGROUPS                = [4081, "ql_syscall_setgroups"]
MIPS32EL_LINUX_SYSCALL_SETGID                   = [4046, "ql_syscall_setgid"]
MIPS32EL_LINUX_SYSCALL_SETUID                   = [4023, "ql_syscall_setuid"]
MIPS32EL_LINUX_SYSCALL_RT_SIGPROCMASK           = [4195, "ql_syscall_rt_sigprocmask"]
MIPS32EL_LINUX_SYSCALL_NANOSLEEP                = [4166, "ql_syscall_nanosleep"]
MIPS32EL_LINUX_SYSCALL_CHDIR                    = [4012, "ql_syscall_chdir"]
MIPS32EL_LINUX_SYSCALL_ACCEPT                   = [4168, "ql_syscall_accept"]
MIPS32EL_LINUX_SYSCALL_SYSINFO                  = [4116, "ql_syscall_sysinfo"]
MIPS32EL_LINUX_SYSCALL_ALARM                    = [4027, "ql_syscall_alarm"]
MIPS32EL_LINUX_SYSCALL_GETPID                   = [4020, "ql_syscall_getpid"]
MIPS32EL_LINUX_SYSCALL_CONNECT                  = [4170, "ql_syscall_connect"]
MIPS32EL_LINUX_SYSCALL_DUP2                     = [4063, "ql_syscall_dup2"]
MIPS32EL_LINUX_SYSCALL_PIPE                     = [4042, "ql_syscall_pipe"]
MIPS32EL_LINUX_SYSCALL_NICE                     = [4034, "ql_syscall_nice"]
MIPS32EL_LINUX_SYSCALL_GETPIORITY               = [4096, "ql_syscall_getpriority"]
MIPS32EL_LINUX_SYSCALL_SHUTDOWN                 = [4182, "ql_syscall_shutdown"]
MIPS32EL_LINUX_SYSCALL_SENDFILE64               = [4237, "ql_syscall_sendfile64"]
MIPS32EL_LINUX_SYSCALL_WAIT4                    = [4114, "ql_syscall_wait4"]


MIPS32EL_LINUX_SYSCALL = [
    MIPS32EL_LINUX_SYSCALL_SETTHREADAREA,
    MIPS32EL_LINUX_SYSCALL_EXIT,
    MIPS32EL_LINUX_SYSCALL_WRITE,
    MIPS32EL_LINUX_SYSCALL_OPEN,
    MIPS32EL_LINUX_SYSCALL_CLOSE,
    MIPS32EL_LINUX_SYSCALL_READ,
    MIPS32EL_LINUX_SYSCALL_EXECVE,
    MIPS32EL_LINUX_SYSCALL_ACCESS,
    MIPS32EL_LINUX_SYSCALL_BRK,
    MIPS32EL_LINUX_SYSCALL_UNAME,
    MIPS32EL_LINUX_SYSCALL_MPROTECT,
    MIPS32EL_LINUX_SYSCALL_WRITEV,
    MIPS32EL_LINUX_SYSCALL_STAT64,
    MIPS32EL_LINUX_SYSCALL_MMAP2,
    MIPS32EL_LINUX_SYSCALL_FSTAT64,
    MIPS32EL_LINUX_SYSCALL_EXITGROUP,
    MIPS32EL_LINUX_SYSCALL_READLINK,
    MIPS32EL_LINUX_SYSCALL_MMAP,
    MIPS32EL_LINUX_SYSCALL_STAT,
    MIPS32EL_LINUX_SYSCALL_MUNMAP,
    MIPS32EL_LINUX_SYSCALL_FSTAT,
    MIPS32EL_LINUX_SYSCALL_LSEEK,
    MIPS32EL_LINUX_SYSCALL_IOCTL,
    MIPS32EL_LINUX_SYSCALL_SOCKET,
    MIPS32EL_LINUX_SYSCALL_FCNTL64,
    MIPS32EL_LINUX_SYSCALL_FCNTL,
    MIPS32EL_LINUX_SYSCALL_SETSOCKOPT,
    MIPS32EL_LINUX_SYSCALL_BIND,
    MIPS32EL_LINUX_SYSCALL_LISTEN,
    MIPS32EL_LINUX_SYSCALL_FORK,
    MIPS32EL_LINUX_SYSCALL_SETSID,
    MIPS32EL_LINUX_SYSCALL_TIME,
    MIPS32EL_LINUX_SYSCALL_GETUID,
    MIPS32EL_LINUX_SYSCALL_GETCWD,
    MIPS32EL_LINUX_SYSCALL_RT_SIGACTION,
    MIPS32EL_LINUX_SYSCALL__NEWSELECT,
    MIPS32EL_LINUX_SYSCALL_SETGROUPS,
    MIPS32EL_LINUX_SYSCALL_SETGID,
    MIPS32EL_LINUX_SYSCALL_SETUID,
    MIPS32EL_LINUX_SYSCALL_RT_SIGPROCMASK,
    MIPS32EL_LINUX_SYSCALL_NANOSLEEP,
    MIPS32EL_LINUX_SYSCALL_CHDIR,
    MIPS32EL_LINUX_SYSCALL_ACCEPT,
    MIPS32EL_LINUX_SYSCALL_SYSINFO,
    MIPS32EL_LINUX_SYSCALL_ALARM,
    MIPS32EL_LINUX_SYSCALL_GETPID,
    MIPS32EL_LINUX_SYSCALL_CONNECT,
    MIPS32EL_LINUX_SYSCALL_DUP2,
    MIPS32EL_LINUX_SYSCALL_PIPE,
    MIPS32EL_LINUX_SYSCALL_NICE,
    MIPS32EL_LINUX_SYSCALL_GETPIORITY,
    MIPS32EL_LINUX_SYSCALL_SHUTDOWN,
    MIPS32EL_LINUX_SYSCALL_SENDFILE64,
    MIPS32EL_LINUX_SYSCALL_WAIT4
    ]
