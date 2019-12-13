#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

dict_arm64_ios_syscall = {
    0x2000001 : "ql_syscall_exit",
    0x2000003 : "ql_syscall_read",
    0x2000004 : "ql_syscall_write",
    0x2000005 : "ql_syscall_open",
    0x2000006 : "ql_syscall_close",
    0x200003B : "ql_syscall_execve",
    0x2000049 : "ql_syscall_munmap",
    0x20000C5 : "ql_syscall_mmap2",
    0x20000C7 : "ql_syscall_lseek",
}
