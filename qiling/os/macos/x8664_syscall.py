#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

# mach trap syscall table (0x1000000 + syscallnum): osfmk/kern/syscall_sw.c
# posix syscall table     (0x2000000 + syscallnum): bsd/kern/syscalls.master
# mdep syscall table      (0x3000000 + syscallnum): osfmk/i386/machdep_call.c

def map_syscall(syscall_num):
    adapter = {
        0x100000a : "ql_x86_syscall_kernelrpc_mach_vm_allocate_trap",
        0x100000c : "ql_x86_syscall_kernelrpc_mach_vm_deallocate_trap",
        0x100000f : "ql_x86_syscall_kernelrpc_mach_vm_map_trap",
        0x1000012 : "ql_x86_syscall_kernelrpc_mach_port_deallocate_trap",
        0x1000013 : "ql_x86_syscall_kernelrpc_mach_port_mod_refs_trap",
        0x1000018 : "ql_x86_syscall_kernelrpc_mach_port_construct_trap",
        0x100001a : "ql_x86_syscall_mach_reply_port",
        0x100001b : "ql_x86_syscall_thread_self_trap",
        0x100001c : "ql_x86_syscall_task_self_trap",
        0x100001d : "ql_x86_syscall_host_self_trap",
        0x100001f : "ql_x86_syscall_mach_msg_trap",

        0x2000001 : "ql_syscall_exit",
        0x2000003 : "ql_syscall_read",
        0x2000004 : "ql_syscall_write",
        0x2000005 : "ql_syscall_open",
        0x2000006 : "ql_syscall_close",
        0x2000014 : "ql_syscall_getpid",
        0x2000021 : "ql_syscall_access_macos",
        0x2000030 : "ql_syscall_sigprocmask",
        0x200003b : "ql_syscall_execve",
        0x2000049 : "ql_syscall_munmap",
        0x200004a : "ql_syscall_mprotect",
        0x200005c : "ql_syscall_fcntl64_macos",
        0x2000061 : "ql_syscall_socket",
        0x2000062 : "ql_syscall_connect",
        0x2000099 : "ql_syscall_pread",
        0x20000a9 : "ql_syscall_csops",
        0x20000c2 : "ql_syscall_getrlimit",
        0x20000ca : "ql_syscall_sysctl",
        0x20000c5 : "ql_syscall_mmap2_macos",
        0x20000c7 : "ql_syscall_lseek",
        0x20000dc : "ql_syscall_getattrlist",
        0x2000112 : "ql_syscall_sysctlbyname",
        0x2000126 : "ql_syscall_shared_region_check_np",
        0x2000147 : "ql_syscall_issetugid",
        0x2000150 : "ql_syscall_proc_info",
        0x2000152 : "ql_syscall_stat64_macos",
        0x2000153 : "ql_syscall_fstat64_macos",
        0x200016e : "ql_syscall_bsdthread_register",
        0x20001b6 : "ql_syscall_shared_region_map_and_slide_np",
        0x2000174 : "ql_syscall_thread_selfid",
        0x200018d : "ql_syscall_write",
        0x200018e : "ql_syscall_open_nocancel",
        0x20001e3 : "ql_syscall_csrctl",
        0x20001f4 : "ql_syscall_getentropy",
        0x2000208 : "ql_syscall_terminate_with_payload",
        0x2000209 : "ql_syscall_abort_with_payload",

        0x3000003 : "ql_x86_syscall_thread_fast_set_cthread_self64",
    }
    return adapter.get(syscall_num)
