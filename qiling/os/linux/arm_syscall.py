#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

dict_arm_linux_syscall = {
    0x01 : "ql_syscall_exit",
    0x03 : "ql_syscall_read",
    0x04 : "ql_syscall_write",
    0x05 : "ql_syscall_open",
    0x06 : "ql_syscall_close",
    0x0B : "ql_syscall_execve",
    0xf  : "ql_syscall_chmod",
    0x13 : "ql_syscall_lseek",
    0x14 : "ql_syscall_getpid",
    0x21 : "ql_syscall_access",
    0x2A : "ql_syscall_pipe", 
    0x2B : "ql_syscall_times",
    0x2D : "ql_syscall_brk",
    0x36 : "ql_syscall_ioctl",
    0x37 : "ql_syscall_fcntl",
    0x3F : "ql_syscall_dup2",
    0x4B : "ql_syscall_setrlimit",
    0x4E : "ql_syscall_gettimeofday",
    0x55 : "ql_syscall_readlink",
    0x5B : "ql_syscall_munmap",
    0x68 : "ql_syscall_setitimer",
    0x6A : "ql_syscall_stat",
    0x6C : "ql_syscall_fstat",
    0x72 : "ql_syscall_wait4",
    0x74 : "ql_syscall_sysinfo",
    0x78 : "ql_syscall_clone",
    0x7A : "ql_syscall_uname",
    0x7D : "ql_syscall_mprotect",
    0x8E : "ql_syscall__newselect",
    0x92 : "ql_syscall_writev",
    0xA2 : "ql_syscall_nanosleep",
    0xAE : "ql_syscall_rt_sigaction",
    0xAF : "ql_syscall_rt_sigprocmask",
    0xBE : "ql_syscall_vfork",
    0xBF : "ql_syscall_ugetrlimit",
    0xC0 : "ql_syscall_mmap2",
    0xC3 : "ql_syscall_stat64",
    0xC7 : "ql_syscall_getuid32",
    0xC8 : "ql_syscall_getgid32",
    0xC5 : "ql_syscall_fstat64",
    0xDD : "ql_syscall_fcntl64",
    0xE0 : "ql_syscall_gettid",
    0xF8 : "ql_syscall_exit_group",
    0x0100 : "ql_syscall_set_tid_address",
    0x0119 : "ql_syscall_socket",
    0x011A : "ql_syscall_bind",
    0x011B : "ql_syscall_connect",
    0x011C : "ql_syscall_listen",
    0x011D : "ql_syscall_accept",
    0x0121 : "ql_syscall_send",
    0x0123 : "ql_syscall_recv",
    0x0125 : "ql_syscall_shutdown",
    0x0126 : "ql_syscall_setsockopt",
    0x0142 : "ql_syscall_openat",
    0x0147 : "ql_syscall_fstatat64",
    0x014C : "ql_syscall_readlinkat",
    0x014E : "ql_syscall_faccessat",
    0x0152 : "ql_syscall_set_robust_list",
    0x0F0005 : "ql_syscall_arm_settls",
}
