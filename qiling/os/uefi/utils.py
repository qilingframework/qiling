#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import ctypes

def convert_struct_to_bytes(st):
    buffer = ctypes.create_string_buffer(ctypes.sizeof(st))
    ctypes.memmove(buffer, ctypes.addressof(st), ctypes.sizeof(st))
    return buffer.raw

def check_and_notify_protocols(ql):
    if len(ql.loader.notify_list) > 0:
        event_id, notify_func, notify_context = ql.loader.notify_list.pop(0)
        ql.nprint(f'Notify event:{event_id} calling:{notify_func:x} context:{notify_context:x}')
        ql.stack_push(ql.end_of_execution_ptr)
        ql.reg.rcx = notify_context
        ql.reg.arch_pc = notify_func
        return True
    return False