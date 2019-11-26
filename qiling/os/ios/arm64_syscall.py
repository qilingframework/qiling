  
#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
ARM64_IOS_SYSCALL_EXIT    =   [0x2000001, "ql_syscall_exit"]
ARM64_IOS_SYSCALL_READ    =   [0x2000003, "ql_syscall_read"]
ARM64_IOS_SYSCALL_WRITE   =   [0x2000004, "ql_syscall_write"]
ARM64_IOS_SYSCALL_OPEN    =   [0x2000005, "ql_syscall_open"]
ARM64_IOS_SYSCALL_CLOSE   =   [0x2000006, "ql_syscall_close"]
ARM64_IOS_SYSCALL_MUNMAP  =   [0x2000049, "ql_syscall_munmap"]
ARM64_IOS_SYSCALL_MMAP    =   [0x20000c5, "ql_syscall_mmap2"]
ARM64_IOS_SYSCALL_LSEEK   =   [0x20000c7, "ql_syscall_lseek"]
ARM64_IOS_SYSCALL_EXECVE   =   [0x200003b, "ql_syscall_execve"]


ARM64_IOS_SYSCALL = [
    ARM64_IOS_SYSCALL_EXIT,
    ARM64_IOS_SYSCALL_READ,
    ARM64_IOS_SYSCALL_WRITE,
    ARM64_IOS_SYSCALL_OPEN,
    ARM64_IOS_SYSCALL_CLOSE,
    ARM64_IOS_SYSCALL_MUNMAP,
    ARM64_IOS_SYSCALL_MMAP,
    ARM64_IOS_SYSCALL_LSEEK,
    ARM64_IOS_SYSCALL_EXECVE
    ]