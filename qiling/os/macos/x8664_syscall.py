#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

dict_x8664_macos_syscall = {
    0x100001a : "ql_x86_syscall_mach_reply_port",
    0x100001c : "ql_x86_syscall_task_self_trap",
    0x100001d : "ql_x86_syscall_host_self_trap",
    0x100001f : "ql_x86_syscall_mach_msg_trap",
    0x2000001 : "ql_syscall_exit",
    0x2000003 : "ql_syscall_read",
    0x2000004 : "ql_syscall_write",
    0x2000005 : "ql_syscall_open",
    0x2000006 : "ql_syscall_close",
    0x2000014 : "ql_syscall_getpid",
    0x2000030 : "ql_syscall_sigprocmask",
    0x200003b : "ql_syscall_execve",
    0x2000049 : "ql_syscall_munmap",
    0x200005c : "ql_syscall_fcntl64",
    0x20000a9 : "ql_syscall_csops",
    0x20000c5 : "ql_syscall_mmap2",
    0x20000c7 : "ql_syscall_lseek",
    0x2000147 : "ql_syscall_issetugid",
    0x2000152 : "ql_syscall_stat64",
    0x2000153 : "ql_syscall_fstat64",
    0x2000174 : "ql_syscall_thread_selfid",
    0x20001e3 : "ql_syscall_csrctl",
    0x20001f4 : "ql_syscall_getentropy",
    0x2000208 : "ql_syscall_terminate_with_payload",
    0x2000209 : "ql_syscall_abort_with_payload",
    0x3000003 : "ql_x86_syscall_thread_set_tsd_base",
}
