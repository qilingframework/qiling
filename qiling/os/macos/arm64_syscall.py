#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

def map_syscall(syscall_num):
    adapter = {
        0xffffffffffffffe4 : "ql_arm64_fgetattrlist",
        0xffffffffffffffe6 : "ql_arm64_poll",
        0x174: "ql_syscall_thread_selfid",
    }
    return adapter.get(syscall_num)
