#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

dict_x86_macos_syscall = dict({
    1 : "ql_syscall_exit",
    3 : "ql_syscall_read",
    4 : "ql_syscall_write",
    5 : "ql_syscall_open",
    6 : "ql_syscall_close",
    73 : "ql_syscall_munmap",
    197 : "ql_syscall_mmap2",
    199 : "ql_syscall_lseek",
    0x8203 : "ql_x86_syscall_set_thread_area",
})
