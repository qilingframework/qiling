#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

# cols = ("x86_64", "arm64")

from qiling.const import *

def map_syscall(ql, syscall_num):
    for k,v in syscall_table.items():
        
        if ql.archtype == QL_ARCH.X8664 and v[0] == syscall_num:
            return "ql_syscall_" + k
        
        elif ql.archtype == QL_ARCH.ARM64 and v[1] == syscall_num:
            return "ql_syscall_" + k            

syscall_table = {
    "fgetattrlist": (-1, 0xffffffffffffffe4),
    "poll": (-1, 0xffffffffffffffe6),
    "thread_selfid": (-1, 0x174),
    "kernelrpc_mach_vm_allocate_trap": (0x100000a, -1),
    "kernelrpc_mach_vm_deallocate_trap": (0x100000c, -1),
    "kernelrpc_mach_vm_map_trap": (0x100000f, -1),
    "kernelrpc_mach_port_deallocate_trap": (0x1000012, -1),
    "kernelrpc_mach_port_mod_refs_trap": (0x1000013, -1),
    "kernelrpc_mach_port_construct_trap": (0x1000018, -1),
    "mach_reply_port": (0x100001a, -1),
    "thread_self_trap": (0x100001b, -1),
    "task_self_trap": (0x100001c, -1),
    "host_self_trap": (0x100001d, -1),
    "mach_msg_trap": (0x100001f, -1),
    "exit": (0x2000001, -1),
    "read": (0x2000003, -1),
    "write": (0x2000004, -1),
    "open": (0x2000005, -1),
    "close": (0x2000006, -1),
    "getpid": (0x2000014, -1),
    "access_macos": (0x2000021, -1),
    "sigprocmask": (0x2000030, -1),
    "execve": (0x200003b, -1),
    "munmap": (0x2000049, -1),
    "mprotect": (0x200004a, -1),
    "fcntl64_macos": (0x200005c, -1),
    "socket": (0x2000061, -1),
    "connect": (0x2000062, -1),
    "pread": (0x2000099, -1),
    "csops": (0x20000a9, -1),
    "getrlimit": (0x20000c2, -1),
    "sysctl": (0x20000ca, -1),
    "mmap2_macos": (0x20000c5, -1),
    "lseek": (0x20000c7, -1),
    "getattrlist": (0x20000dc, -1),
    "sysctlbyname": (0x2000112, -1),
    "shared_region_check_np": (0x2000126, -1),
    "issetugid": (0x2000147, -1),
    "proc_info": (0x2000150, -1),
    "stat64_macos": (0x2000152, -1),
    "fstat64_macos": (0x2000153, -1),
    "bsdthread_register": (0x200016e, -1),
    "shared_region_map_and_slide_np": (0x20001b6, -1),
    "thread_selfid": (0x2000174, -1),
    "write": (0x200018d, -1),
    "open_nocancel": (0x200018e, -1),
    "csrctl": (0x20001e3, -1),
    "getentropy": (0x20001f4, -1),
    "terminate_with_payload": (0x2000208, -1),
    "abort_with_payload": (0x2000209, -1),
    "thread_fast_set_cthread_self64": (0x3000003, -1),
}